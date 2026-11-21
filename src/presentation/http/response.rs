use axum::{http::StatusCode, response::IntoResponse, Json};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct ApiResponse<E, M, R> {
    pub errors: E,
    pub messages: M,
    pub results: R,
    pub success: bool,
    #[serde(skip)]
    pub status: u16,
}

impl<E, M, R> ApiResponse<E, M, R> {
    pub fn ok(status: u16, messages: M, results: R, errors: E) -> Self {
        ApiResponse {
            errors,
            messages,
            results,
            success: true,
            status,
        }
    }

    pub fn err(status: u16, messages: M, results: R, errors: E) -> Self {
        ApiResponse {
            errors,
            messages,
            results,
            success: false,
            status,
        }
    }
}

impl<E, M, R> IntoResponse for ApiResponse<E, M, R>
where
    E: Serialize,
    M: Serialize,
    R: Serialize,
{
    fn into_response(self) -> axum::response::Response {
        let status = StatusCode::from_u16(self.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        (status, Json(self)).into_response()
    }
}
