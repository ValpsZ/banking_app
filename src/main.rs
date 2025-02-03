use std::env;

use actix_web::{rt::System, web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use dotenv::dotenv;
use rusqlite::Connection;

mod utils;

async fn create_user(app_mode: web::Data<String>) -> impl Responder {
    let conn = Connection::open("database.db");

    match conn {
        Ok(conn) => HttpResponse::Ok().json("a"),
        Err(_) => utils::server_error("Error while connecting to database", app_mode),
    }
}

async fn get_user(app_mode: web::Data<String>) -> impl Responder {
    let conn: Result<Connection, rusqlite::Error> = Connection::open("database.db");
    //let conn: Result<Connection, rusqlite::Error> = Err(rusqlite::Error::ExecuteReturnedResults);

    match conn {
        Ok(conn) => HttpResponse::Ok().json("a"),
        Err(_) => utils::server_error("Error while connecting to database", app_mode),
    }
}

async fn shutdown(
    req: HttpRequest,
    app_mode: web::Data<String>,
    master_api_key: web::Data<String>,
) -> impl Responder {
    let api_key = req.headers().get("API-Key");

    if let Some(api_key_value) = api_key {
        if *api_key_value == ***master_api_key {
            // Stop the Actix system (which shuts down the server)
            System::current().stop();
            return HttpResponse::Ok().body("Server shutting down.");
        }
    }

    utils::forbidden("Invalid API key", app_mode)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    /*
    let conn = Connection::open("database.db")?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            hashed_password TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )",
        [],
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS accounts (
            account_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            balance DECIMAL(15, 2),
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
        )",
        [],
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS transactions (
            transaction_id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_account_id INTEGER NOT NULL,
            receiver_account_id INTEGER NOT NULL,
            message TEXT,
            amount DECIMAL(15, 2) NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (sender_account_id) REFERENCES accounts(sender_account_id) ON DELETE CASCADE,
            FOREIGN KEY (receiver_account_id) REFERENCES accounts(receiver_account_id) ON DELETE CASCADE
        )",
        [],
    )?;
    */

    // Load environment variables from .env in development mode
    dotenv().ok();

    let app_mode = env::var("APP_MODE").unwrap_or_else(|_| "prod".to_string());
    let master_api_key = env::var("API_KEY").unwrap_or_else(|_| "prod".to_string());
    let system = System::new();
    let port = "127.0.0.1:2000";

    match app_mode.to_string().as_str() {
        "dev" => println!("Dev running on port {}", port),
        "prod" => println!("Prod running on port {}", port),
        _ => (),
    }

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(app_mode.clone())) // Pass app_mode as shared data
            .app_data(web::Data::new(master_api_key.clone())) // Pass app_mode as shared data
            .route("/create_user", web::post().to(create_user))
            .route("/get_user", web::get().to(get_user))
            .route("/shutdown", web::get().to(shutdown))
    })
    .bind("127.0.0.1:2000")?
    .run()
    .await?;
    println!("Done");

    Ok(())
}
