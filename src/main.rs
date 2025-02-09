use std::{env, time::Duration};

use actix_cors::Cors;
use actix_web::{
    web::{self},
    App, HttpRequest, HttpResponse, HttpServer, Responder, ResponseError,
};
use chrono::NaiveDateTime;
use dotenv::dotenv;
use error::ServerError;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rand::{distr::Alphanumeric, rng, Rng};
use rusqlite::{params, Connection};
use sha2::{Digest, Sha512};
use tokio::{signal, sync::broadcast, time::sleep};

mod error;
mod utils;

use serde::{ser::SerializeStruct, Deserialize, Serialize};

#[derive(Debug, Deserialize)]
struct User {
    name: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct Account {
    name: String,
}

#[derive(Serialize)]
struct UserInfo {
    user_name: String,
    accounts: Vec<AccountInfo>,
}

#[derive(Serialize)]
struct AccountInfo {
    name: String,
    balance: f32,
    transactions: Vec<TransactionInfo>,
}

struct TransactionInfo {
    amount: f32,
    from_id: i32,
    to_id: i32,
    message: String,
    timestamp: NaiveDateTime,
}

impl Serialize for TransactionInfo {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("TransactionInfo", 4)?;
        state.serialize_field("amount", &self.amount)?;
        state.serialize_field("from_id", &self.from_id)?;
        state.serialize_field("to_id", &self.to_id)?;
        state.serialize_field("message", &self.message)?;
        state.serialize_field(
            "timestamp",
            &self.timestamp.format("%Y-%m-%d %H:%M:%S").to_string(),
        )?;
        state.end()
    }
}

fn cors_middle_ware() -> Cors {
    let frontend_url = env::var("FRONTEND_URL").expect("No frontend Url set");

    Cors::default()
        .allowed_origin(&frontend_url)
        .allowed_methods(vec!["GET", "POST", "PUT", "DELETE"])
        .allowed_headers(vec![
            actix_web::http::header::AUTHORIZATION,
            actix_web::http::header::CONTENT_TYPE,
        ])
        .supports_credentials()
}

fn generate_salt(length: usize) -> String {
    rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

fn hash_password(password: &str, salt: String) -> String {
    let mut hasher = Sha512::new();
    hasher.update(salt);
    hasher.update(password);
    let hash = hasher.finalize();
    return hex::encode(hash);
}

async fn secure_hash_eq(hash1: &str, hash2: &str) -> bool {
    tokio::time::sleep(Duration::from_millis(rng().random_range(1..200))).await;
    return *hash1 == *hash2;
}

async fn login_endpoint(
    pool: web::Data<Pool<SqliteConnectionManager>>,
    user: web::Json<User>,
) -> impl Responder {
    match login(user, pool).await {
        Ok(token) => HttpResponse::Ok().json(serde_json::json!({ "session_token": token})),
        Err(e) => e.error_response(),
    }
}

async fn login(
    user: web::Json<User>,
    pool: web::Data<Pool<SqliteConnectionManager>>,
) -> Result<String, ServerError> {
    let conn = pool.get()?;

    let mut stmt = conn.prepare("SELECT user_id FROM users WHERE name = (?)")?;

    let possible_user_ids: Vec<String> = stmt
        .query_map(params![user.name], |row| row.get::<usize, String>(0))?
        .collect::<Result<Vec<String>, _>>()?;

    let mut user_id_option: Option<String> = None;

    for id in possible_user_ids {
        let (stored_hash, salt): (String, String) = conn.query_row(
            "SELECT hashed_password, salt FROM users WHERE user_id = (?)",
            params![id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;

        let computed_hash = hash_password(&user.password, salt);

        if secure_hash_eq(&computed_hash, &stored_hash).await {
            user_id_option = Some(id);
            break;
        };
    }

    let user_id = user_id_option.ok_or(ServerError::User("Invalid credentials".to_string()))?;

    let session_token = uuid::Uuid::new_v4().to_string();
    let cookie_id = uuid::Uuid::new_v4().to_string();

    let _ = conn.execute(
        r#"INSER INTO cookies (cookie_id, user_id, value, type) VALUES (?, ?, ?, "session")"#,
        params![cookie_id, user_id, session_token],
    )?;

    Ok(session_token)
}

async fn get_csrf_token_endpoint(
    req: HttpRequest,
    pool: web::Data<Pool<SqliteConnectionManager>>,
) -> impl Responder {
    match get_csrf_token(req, pool) {
        Ok(token) => HttpResponse::Ok().json(serde_json::json!({"csrf_token": token})),
        Err(e) => e.error_response(),
    }
}

fn get_csrf_token(
    req: HttpRequest,
    pool: web::Data<Pool<SqliteConnectionManager>>,
) -> Result<String, ServerError> {
    let conn = pool.get()?;

    let user_id: String = conn.query_row(
        "SELECT user_id FROM cookies WHERE cookie_id = (?)",
        params![req
            .headers()
            .get("session_token")
            .ok_or(ServerError::User("No session token".to_string()))?
            .to_str()?],
        |row| Ok(row.get::<usize, String>(0)?),
    )?;

    let token = uuid::Uuid::new_v4().to_string();
    let cookie_id = uuid::Uuid::new_v4().to_string();

    let _ = conn.execute(
        "INSERT INTO cookies (cookie_id, user_id, value, type) VALUES (?, ?, ?, ?)",
        params![cookie_id, user_id, token, "csrf"],
    )?;

    Ok(token)
}

async fn create_user_endpoint(
    pool: web::Data<Pool<SqliteConnectionManager>>,
    user: web::Json<User>,
) -> impl Responder {
    match create_user(pool, user) {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!("status: success")),
        Err(e) => e.error_response(),
    }
}

fn create_user(
    pool: web::Data<Pool<SqliteConnectionManager>>,
    user: web::Json<User>,
) -> Result<(), ServerError> {
    let conn = pool.get()?;

    let salt = generate_salt(32);
    let hashed_password = hash_password(&user.password, salt.clone());
    let user_id = uuid::Uuid::new_v4().to_string();

    let _ = conn.execute(
        "INSERT INTO users user_id, name, hashed_password, salt (?, ?, ?, ?)",
        params![user_id, user.name, hashed_password, salt],
    )?;

    Ok(())
}
async fn get_user_info_endpoint(
    req: HttpRequest,
    pool: web::Data<Pool<SqliteConnectionManager>>,
) -> impl Responder {
    match get_user_info(req, pool) {
        Ok(user_info) => HttpResponse::Ok().json(user_info),
        Err(e) => e.error_response(),
    }
}

fn get_user_info(
    req: HttpRequest,
    pool: web::Data<Pool<SqliteConnectionManager>>,
) -> Result<UserInfo, ServerError> {
    let conn = pool.get()?;

    let cookie = req
        .cookie("session_token")
        .ok_or(ServerError::User("No session token".to_owned()))?;

    let user_id: String = conn.query_row(
        "SELECT user_id FROM cookies WHERE value = (?)",
        params![cookie.value()],
        |row| row.get(0),
    )?;

    let user_name: String = conn.query_row(
        "SELECT name FROM users WHERE user_id = (?)",
        params![user_id],
        |row| row.get(0),
    )?;

    let mut stmt = conn.prepare("SELECT account_id FROM accounts WHERE owner_id = (?)")?;

    let account_ids: Vec<String> = stmt
        .query_map(params![user_id], |row| row.get::<_, String>(0))?
        .filter_map(|result| result.ok())
        .collect::<Vec<String>>();

    let mut accounts: Vec<AccountInfo> = Vec::with_capacity(account_ids.len());

    for account_id in account_ids {
        let mut stmt = conn.prepare("SELECT amount, sender_account_id, reciver_account_id, message, timestamp FROM transactions WHERE sender_account_id = (?) OR receiver_account_id = (?)")?;
        let transactions = stmt
            .query_map(params![account_id, account_id], |row| {
                let amount = row.get(0)?;
                let from_id = row.get(1)?;
                let to_id = row.get(2)?;
                let message = row.get(3)?;
                let timestamp_str: String = row.get(4)?;

                let timestamp =
                    chrono::NaiveDateTime::parse_from_str(&timestamp_str, "%Y-%m-%d %H:%M:%S")
                        .map_err(|e| {
                            rusqlite::Error::FromSqlConversionFailure(
                                4,
                                rusqlite::types::Type::Text,
                                Box::new(e),
                            )
                        })?;

                Ok(TransactionInfo {
                    amount,
                    from_id,
                    to_id,
                    message,
                    timestamp,
                })
            })?
            .collect::<Result<Vec<TransactionInfo>, _>>()?;

        let (account_name, account_balance): (String, f32) = conn.query_row(
            "SELECT name, balance FROM accounts WHERE account_id = (?)",
            params![account_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;

        accounts.push(AccountInfo {
            name: account_name,
            balance: account_balance,
            transactions,
        });
    }

    Ok(UserInfo {
        user_name,
        accounts,
    })
}

async fn create_account_endpoint(
    pool: web::Data<Pool<SqliteConnectionManager>>,
    req: HttpRequest,
    account: web::Json<Account>,
) -> impl Responder {
    match create_account(pool, req, account) {
        Ok(_) => HttpResponse::Ok().body("Created account"),
        Err(e) => e.error_response(),
    }
}

fn create_account(
    pool: web::Data<Pool<SqliteConnectionManager>>,
    req: HttpRequest,
    account: web::Json<Account>,
) -> Result<(), ServerError> {
    let session_token = req
        .headers()
        .get("X-Session-Token")
        .ok_or(ServerError::User("No session token".to_string()))?
        .to_str()?;

    let csrf_token = req
        .headers()
        .get("X-CSRF-Token")
        .ok_or(ServerError::User("No CSRF token".to_string()))?
        .to_str()?;

    let conn = pool.get()?;

    let _ = conn.query_row(
        r#"SELECT 1 FROM cookies WHERE type = "csrf" AND value = (?)"#,
        params![csrf_token],
        |_| Ok(()),
    )?;

    let user_id: String = conn.query_row(
        r#"SELECT user_id FROM cookies WHERE value = (?) AND type = "session""#,
        params![session_token],
        |row| row.get(0),
    )?;

    let account_id = uuid::Uuid::new_v4().to_string();

    let _ = conn.execute(
        "INSERT INTO accounts (account_id, user_id, name)",
        params![account_id, user_id, account.name],
    )?;

    Ok(())
}

async fn shutdown(
    req: HttpRequest,
    config: web::Data<Config>,
    shutdown_tx: web::Data<broadcast::Sender<()>>,
) -> impl Responder {
    let api_key = req.headers().get("API-Key");

    if let Some(api_key_value) = api_key {
        if *api_key_value == *config.master_api_key {
            // Stop the Actix system (which shuts down the server)
            println!("Stopping server...");

            let shutdown_tx = shutdown_tx.clone();
            tokio::spawn(async move {
                sleep(Duration::from_millis(100)).await;
                let _ = shutdown_tx.send(());
            });
            return HttpResponse::Ok().body("Stopping server...");
        }
    }

    utils::respond(
        HttpResponse::Forbidden(),
        "Invalid API key",
        "Invalid credentials",
        config.app_mode.clone(),
    )
}

#[derive(Clone)]
struct Config {
    app_mode: String,
    master_api_key: String,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let conn = Connection::open("database.db").expect("Faild to connect to database");

    let _ = conn.execute("DROP TABLE IF EXISTS users; DROP TABLE IF EXISTS accounts; DROP TABLE IF EXISTS transactions; DROP TABLE IF EXISTS cookies", []);

    let _ = conn.execute(
        "CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY UNIQUE,
            name TEXT NOT NULL,
            hashed_password TEXT NOT NULL,
            salt TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )",
        [],
    );

    let _ = conn.execute(
        "CREATE TABLE IF NOT EXISTS accounts (
            account_id TEXT PRIMARY KEY UNIQUE,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            balance DECIMAL(20, 4) NOT NULL DEFAULT 0,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
        )",
        [],
    );

    let _ = conn.execute(
        "CREATE TABLE IF NOT EXISTS transactions (
            transaction_id TEXT PRIMARY KEY UNIQUE,
            sender_account_id TEXT NOT NULL,
            receiver_account_id TEXT NOT NULL,
            message TEXT,
            amount DECIMAL(20, 4) NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (sender_account_id) REFERENCES accounts(account_id) ON DELETE CASCADE,
            FOREIGN KEY (receiver_account_id) REFERENCES accounts(account_id) ON DELETE CASCADE
        )",
        [],
    );

    let _ = conn.execute(
        "CREATE TABLE IF NOT EXISTS cookies (
            cookie_id TEXT PRIMARY KEY UNIQUE,
            user_id TEXT NOT NULL,
            value TEXT NOT NULL,
            type TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
        )",
        [],
    );

    // Load environment variables from .env in development mode
    dotenv().ok();

    let app_mode = env::var("APP_MODE").unwrap_or_else(|_| "prod".to_string());
    let master_api_key = env::var("API_KEY").unwrap_or_else(|_| "prod".to_string());
    let port = "127.0.0.1:2000";

    match app_mode.to_string().as_str() {
        "dev" => println!("Dev running on port {}", port),
        "prod" => println!("Prod running on port {}", port),
        _ => (),
    }

    let (shutdown_tx, mut shutdown_rx) = broadcast::channel::<()>(1);
    let shutdown_tx_clone = shutdown_tx.clone();

    let server_config = Config {
        app_mode,
        master_api_key,
    };

    let manager = SqliteConnectionManager::file("database.db");
    let pool = Pool::new(manager).expect("Failed to connect to database");

    let server = HttpServer::new(move || {
        App::new()
            .wrap(cors_middle_ware())
            .app_data(web::Data::new(shutdown_tx_clone.clone()))
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(server_config.clone()))
            .route("/create_user", web::post().to(create_user_endpoint))
            .route("/login", web::post().to(login_endpoint))
            .route("/shutdown", web::get().to(shutdown))
            .route("/get_csrf_token", web::get().to(get_csrf_token_endpoint))
            .route("/get_user_info", web::get().to(get_user_info_endpoint))
            .route("/create_account", web::get().to(create_account_endpoint))
    })
    .bind("127.0.0.1:2000")?
    .run();

    let server_handle = tokio::spawn(server);

    tokio::spawn(async move {
        signal::ctrl_c()
            .await
            .expect("Faild to stop server with CTRL-C");
        let _ = shutdown_tx.send(());
    });

    shutdown_rx.recv().await.ok();

    println!("Server stopped.");
    server_handle.abort();

    Ok(())
}
