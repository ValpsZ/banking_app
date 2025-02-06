use actix_web::{error::ResponseError, HttpResponse};
use rusqlite::Error as RusqliteError;
use std::{
    env::{self, VarError},
    fmt,
};
use uuid::Error as UuidError;

use crate::utils;

#[derive(Debug)]
pub enum ServerError {
    EnvError(VarError),
    DatabaseError(RusqliteError),
    UuidError(UuidError),
    PoolError(r2d2::Error),
    TimeError(chrono::ParseError),
    Other(String),
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServerError::EnvError(e) => write!(f, "Environment variable error: {}", e),
            ServerError::DatabaseError(e) => write!(f, "Database error: {}", e),
            ServerError::UuidError(e) => write!(f, "UUID error: {}", e),
            ServerError::PoolError(e) => write!(f, "Pool error: {}", e),
            ServerError::TimeError(e) => write!(f, "Time error: {}", e),
            ServerError::Other(e) => write!(f, "Other error: {}", e),
        }
    }
}

impl std::error::Error for ServerError {}

impl From<VarError> for ServerError {
    fn from(err: VarError) -> Self {
        ServerError::EnvError(err)
    }
}

impl From<RusqliteError> for ServerError {
    fn from(err: RusqliteError) -> Self {
        ServerError::DatabaseError(err)
    }
}

impl From<UuidError> for ServerError {
    fn from(err: UuidError) -> Self {
        ServerError::UuidError(err)
    }
}

impl From<r2d2::Error> for ServerError {
    fn from(err: r2d2::Error) -> Self {
        ServerError::PoolError(err)
    }
}

impl From<chrono::ParseError> for ServerError {
    fn from(err: chrono::ParseError) -> Self {
        ServerError::TimeError(err)
    }
}

impl ResponseError for ServerError {
    fn error_response(&self) -> actix_web::HttpResponse {
        let app_mode = env::var("APP_MODE").unwrap_or("prod".to_owned());
        utils::respond(
            HttpResponse::InternalServerError(),
            &format!("{}", self),
            "Internal Server Error",
            app_mode,
        )
    }
}
