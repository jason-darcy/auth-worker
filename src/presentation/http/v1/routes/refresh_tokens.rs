use axum::{routing::post, Router};

use crate::presentation::{
    http::v1::handlers::refresh_tokens::refresh_tokens_handler, state::AppState,
};

/// `POST /refresh` — exchanges a refresh token for a new token pair.
pub fn refresh_tokens_router() -> Router<AppState> {
    Router::new().route("/refresh", post(refresh_tokens_handler))
}
