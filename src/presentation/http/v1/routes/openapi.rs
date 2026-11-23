use axum::{routing::get, Router};

use crate::presentation::{http::v1::handlers::openapi::openapi_handler, state::AppState};

/// `GET /openapi.json` — the API contract, served by the worker itself.
pub fn openapi_router() -> Router<AppState> {
    Router::new().route("/openapi.json", get(openapi_handler))
}
