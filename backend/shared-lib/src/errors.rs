use actix_web::{HttpResponse, ResponseError};
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

#[derive(Error, Debug, Serialize, Deserialize)]
pub enum AppError {
    #[error("Authentication failed: {0}")]
    AuthError(String),

    #[error("Permission denied")]
    PermissionDenied,

    #[error("Validation failed: {0}")]
    ValidationError(String),

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Redis error: {0}")]
    RedisError(String),

    #[error("Scan engine error: {0}")]
    ScanEngineError(String),

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("Resource not found: {0}")]
    NotFound(String),

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Internal server error")]
    InternalError,

    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),

    #[error("Bad gateway: {0}")]
    BadGateway(String),

    #[error("Request timeout")]
    RequestTimeout,

    #[error("Unsupported media type")]
    UnsupportedMediaType,
}

impl AppError {
    pub fn status_code(&self) -> u16 {
        match self {
            AppError::AuthError(_) => 401,
            AppError::PermissionDenied => 403,
            AppError::ValidationError(_) => 400,
            AppError::DatabaseError(_) => 500,
            AppError::RedisError(_) => 500,
            AppError::ScanEngineError(_) => 500,
            AppError::RateLimitExceeded => 429,
            AppError::NotFound(_) => 404,
            AppError::Conflict(_) => 409,
            AppError::InternalError => 500,
            AppError::InvalidRequest(_) => 400,
            AppError::ServiceUnavailable(_) => 503,
            AppError::BadGateway(_) => 502,
            AppError::RequestTimeout => 408,
            AppError::UnsupportedMediaType => 415,
        }
    }
}

impl ResponseError for AppError {
    fn status_code(&self) -> actix_web::http::StatusCode {
        actix_web::http::StatusCode::from_u16(self.status_code()).unwrap_or(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR)
    }

    fn error_response(&self) -> HttpResponse {
        let error_response = ErrorResponse::from_error(self);
        HttpResponse::build(actix_web::http::StatusCode::from_u16(self.status_code()).unwrap_or(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR))
            .content_type("application/json")
            .json(error_response)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
    pub code: u16,
    pub timestamp: String,
}

impl ErrorResponse {
    pub fn from_error(e: &AppError) -> Self {
        ErrorResponse {
            error: e.to_string(),
            message: match e {
                AppError::AuthError(msg) => msg.clone(),
                AppError::ValidationError(msg) => msg.clone(),
                AppError::NotFound(msg) => msg.clone(),
                AppError::Conflict(msg) => msg.clone(),
                AppError::InvalidRequest(msg) => msg.clone(),
                AppError::ServiceUnavailable(msg) => msg.clone(),
                AppError::BadGateway(msg) => msg.clone(),
                AppError::DatabaseError(_) => "Database error occurred".to_string(),
                AppError::RedisError(_) => "Cache service error occurred".to_string(),
                AppError::ScanEngineError(_) => "Scan engine error occurred".to_string(),
                _ => "An error occurred".to_string(),
            },
            code: e.status_code(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }
}

impl fmt::Display for ErrorResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {} (code: {})", self.timestamp, self.error, self.code)
    }
}
