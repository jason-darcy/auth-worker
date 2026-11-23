use axum::{routing::post, Router};

use crate::presentation::{
    http::v1::handlers::forgot_password::forgot_password_handler, state::AppState,
};

/// `POST /forgot-password` — emails a password reset link.
pub fn forgot_password_router() -> Router<AppState> {
    Router::new().route("/forgot-password", post(forgot_password_handler))
}
