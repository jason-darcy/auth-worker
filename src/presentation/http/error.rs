use axum::{http::StatusCode, response::IntoResponse, Json};
use serde::Serialize;

use super::response::ApiResponse;

pub type ApiResult<T> = std::result::Result<T, ApiError>;

#[derive(Debug, Serialize)]
pub enum ApiError {
    BadRequest(String),
    Unauthorized(String),
    NotFound(String),
    Conflict(String),
    InternalServerError(String),
}

impl ApiError {
    pub fn status(&self) -> u16 {
        match self {
            ApiError::BadRequest(_) => 400,
            ApiError::Unauthorized(_) => 401,
            ApiError::NotFound(_) => 404,
            ApiError::Conflict(_) => 409,
            ApiError::InternalServerError(_) => 500,
        }
    }

    pub fn message(&self) -> &str {
        match self {
            ApiError::BadRequest(m)
            | ApiError::Unauthorized(m)
            | ApiError::NotFound(m)
            | ApiError::Conflict(m)
            | ApiError::InternalServerError(m) => m,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let status =
            StatusCode::from_u16(self.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let body: ApiResponse<(), Vec<String>, Vec<String>> = ApiResponse::err(
            self.status(),
            (),
            vec![self.message().to_owned()],
            Vec::new(),
        );
        (status, Json(body)).into_response()
    }
}
