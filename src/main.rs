use std::{env, time::Duration};

use actix_cors::Cors;
use actix_web::{
    cookie::{Cookie, SameSite},
    web::{self},
    App, HttpRequest, HttpResponse, HttpServer, Responder,
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
use uuid::Uuid;

mod error;
mod utils;

use serde::{ser::SerializeStruct, Deserialize, Serialize};

#[derive(Debug, Deserialize)]
struct User {
    name: String,
    password: String,
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

async fn create_user(
    pool: web::Data<Pool<SqliteConnectionManager>>,
    config: web::Data<Config>,
    user: web::Json<User>,
) -> impl Responder {
    let conn = pool.get();

    match conn {
        Ok(conn) => {
            let salt = generate_salt(16);
            let hashed_password = hash_password(&user.password, salt.clone());
            match conn.execute(
                "INSERT INTO users (name, hashed_password, salt) VALUES (?, ?, ?)",
                params![user.name, hashed_password, salt],
            ) {
                Ok(_) => HttpResponse::Created().body("User created"),
                Err(err) => {
                    eprintln!("Database: insert error: {}", err);
                    utils::respond(
                        HttpResponse::InternalServerError(),
                        "Failed to create user",
                        "Failed to create user",
                        config.app_mode.clone(),
                    )
                }
            }
        }
        Err(err) => {
            eprintln!("{}", err);
            utils::respond(
                HttpResponse::InternalServerError(),
                &format!("{}", err),
                "Internal Server Error",
                config.app_mode.clone(),
            )
        }
    }
}

async fn secure_hash_eq(hash1: &str, hash2: &str) -> bool {
    tokio::time::sleep(Duration::from_millis(rng().random_range(1..200))).await;
    return *hash1 == *hash2;
}

async fn login(
    pool: web::Data<Pool<SqliteConnectionManager>>,
    config: web::Data<Config>,
    user: web::Json<User>,
    req: HttpRequest,
) -> impl Responder {
    let header_token = req
        .headers()
        .get("X-CSRF-Token")
        .and_then(|val| val.to_str().ok());

    let cookie_token = req.cookie("csrf_token").map(|c| c.value().to_string());

    if header_token.is_none()
        || cookie_token.is_none()
        || cookie_token.unwrap() != header_token.unwrap()
    {
        return utils::respond(
            HttpResponse::Forbidden(),
            "Invalid csrf cookie",
            "Invalid credentials",
            config.app_mode.clone(),
        );
    }

    let conn = pool.get();

    match conn {
        Ok(conn) => {
            let row = match conn.query_row(
                "SELECT hashed_password, salt FROM users WHERE name = ?",
                params![user.name],
                |row| {
                    let hashed_password: String = row.get(0)?;
                    let salt: String = row.get(1)?;
                    Ok((hashed_password, salt))
                },
            ) {
                Ok(row) => row,
                Err(err) => {
                    eprintln!("{}", err);

                    return utils::respond(
                        HttpResponse::InternalServerError(),
                        &format!("{}", err),
                        "Internal Server Error",
                        config.app_mode.clone(),
                    );
                }
            };

            let stored_hashed_password = row.0;
            let stored_salt = row.1;

            let computed_hash = hash_password(&user.password, stored_salt);

            if secure_hash_eq(&stored_hashed_password, &computed_hash).await {
                let session_token = Uuid::new_v4().to_string();

                let cookie = Cookie::build("session_token", session_token.clone())
                    .path("/")
                    .http_only(true)
                    .same_site(SameSite::Lax)
                    .secure(true)
                    .finish();

                let user_id: i32 = conn
                    .query_row(
                        "SELECT user_id FROM users WHERE name = (?)",
                        params![user.name],
                        |row| row.get(0),
                    )
                    .unwrap();

                let _ = conn.execute(
                    "INSERT INTO cookies (user_id, cookie) VALUES (?, ?)",
                    params![user_id, session_token.clone()],
                );

                return HttpResponse::Ok().cookie(cookie).body("Login successful");
            } else {
                return utils::respond(
                    HttpResponse::Unauthorized(),
                    "Invalid credentials",
                    "Invalid credentials",
                    config.app_mode.clone(),
                );
            }
        }
        Err(err) => {
            eprintln!("{}", err);

            utils::respond(
                HttpResponse::InternalServerError(),
                &format!("{}", err),
                "Internal Server Error",
                config.app_mode.clone(),
            )
        }
    }
}

async fn get_csrf_token() -> impl Responder {
    let token: [u8; 32] = rng().random();
    let csrf_token = hex::encode(token);

    let csrf_cookie = Cookie::build("csrf_token", csrf_token.clone())
        .http_only(true)
        .same_site(SameSite::Strict)
        .secure(true)
        .finish();

    HttpResponse::Ok()
        .cookie(csrf_cookie)
        .json(serde_json::json!({ "csrf_token": csrf_token}))
}

async fn get_user_info(
    req: HttpRequest,
    config: web::Data<Config>,
    pool: web::Data<Pool<SqliteConnectionManager>>,
) -> impl Responder {
    match fetch_user_info(req, pool) {
        Ok(user_info) => HttpResponse::Ok().json(user_info),
        Err(e) => {
            eprintln!("{}", e);

            utils::respond(
                HttpResponse::InternalServerError(),
                &format!("{}", e),
                "Internal Server Error",
                config.app_mode.clone(),
            )
        }
    }
}

fn fetch_user_info(
    req: HttpRequest,
    pool: web::Data<Pool<SqliteConnectionManager>>,
) -> Result<UserInfo, ServerError> {
    let conn = pool.get()?;

    let cookie = req
        .cookie("session_token")
        .ok_or(ServerError::Other("No session token".to_owned()))?;

    let user_id: u32 = conn.query_row(
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

    let account_ids: Vec<u32> = stmt
        .query_map(params![user_id], |row| row.get::<_, u32>(0))?
        .filter_map(|result| result.ok())
        .collect::<Vec<u32>>();

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

    let _ = conn.execute("DROP TABLE IF EXISTS users; DROP TABLE IF EXISTS accounts; DROP TABLE IF EXISTS transactions", []);

    let _ = conn.execute(
        "CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            hashed_password TEXT NOT NULL,
            salt TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )",
        [],
    );

    let _ = conn.execute(
        "CREATE TABLE IF NOT EXISTS accounts (
            account_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            balance DECIMAL(20, 4) NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
        )",
        [],
    );

    let _ = conn.execute(
        "CREATE TABLE IF NOT EXISTS transactions (
            transaction_id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_account_id INTEGER NOT NULL,
            receiver_account_id INTEGER NOT NULL,
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
            cookie_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            value TEXT NOT NULL,
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
            .route("/create_user", web::post().to(create_user))
            .route("/login", web::post().to(login))
            .route("/shutdown", web::get().to(shutdown))
            .route("/get_csrf_token", web::get().to(get_csrf_token))
            .route("/get_user_info", web::get().to(get_user_info))
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
