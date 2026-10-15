//! Единая точка маппинга ошибок в HTTP-ответы. THREAT_MODEL.md §3: в тело
//! ответа уходит только категория ошибки, никогда — внутренние детали
//! (пути на диске, содержимое `FormatError::detail` и т.п.).

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use cove_core::error::ErrorCategory;
use serde::Serialize;

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

pub enum ApiError {
    Core(cove_core::CoveError),
    Unauthorized,
    Forbidden,
    RateLimited,
    BadRequest(String),
    /// Внутренняя ошибка сервера, не связанная с `CoveError` (например,
    /// поток session-актора неожиданно завершился). Сообщение всегда
    /// generic — никаких деталей наружу.
    Internal(&'static str),
}

impl From<cove_core::CoveError> for ApiError {
    fn from(e: cove_core::CoveError) -> Self {
        ApiError::Core(e)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, msg) = match &self {
            ApiError::Core(e) => {
                let status = match e.category() {
                    ErrorCategory::AuthFailed => StatusCode::UNAUTHORIZED,
                    ErrorCategory::PermissionDenied => StatusCode::FORBIDDEN,
                    ErrorCategory::NotFound => StatusCode::NOT_FOUND,
                    ErrorCategory::AlreadyExists => StatusCode::CONFLICT,
                    ErrorCategory::Conflict => StatusCode::CONFLICT,
                    _ => StatusCode::INTERNAL_SERVER_ERROR,
                };
                (status, e.category().to_string())
            }
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized".to_string()),
            ApiError::Forbidden => (StatusCode::FORBIDDEN, "csrf_check_failed".to_string()),
            ApiError::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "rate_limited".to_string()),
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, m.clone()),
            ApiError::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, m.to_string()),
        };
        (status, Json(ErrorBody { error: msg })).into_response()
    }
}
