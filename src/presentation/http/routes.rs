use axum::{extract::DefaultBodyLimit, Router};

use crate::presentation::{
    http::{
        error::ApiError,
        v1::routes::{health::health_router, signin::signin_router, signup::signup_router},
    },
    middlewares::cors::cors_layer,
    state::AppState,
};

/// Auth payloads are a few hundred bytes; anything larger is a client bug or an
/// attempt to make the worker buffer memory.
pub const MAX_BODY_BYTES: usize = 64 * 1024;

pub fn create_routers(state: AppState) -> Router<()> {
    let v1_routes = Router::new()
        .merge(health_router())
        .merge(signup_router())
        .merge(signin_router());

    // Unknown paths and wrong methods keep the documented response envelope
    // instead of axum's empty-bodied defaults.
    let app = Router::new()
        .nest("/api/v1", v1_routes)
        .with_state(state.clone())
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES));

    // CORS is opt-in: without `CORS_ORIGINS` no layer is added at all, so the
    // service stays same-origin only and OPTIONS is not intercepted.
    match cors_layer(&state) {
        Some(cors) => app.layer(cors),
        None => app,
    }
}

async fn not_found() -> ApiError {
    ApiError::NotFound("route not found".to_owned())
}

async fn method_not_allowed() -> ApiError {
    ApiError::MethodNotAllowed("method not allowed".to_owned())
}
