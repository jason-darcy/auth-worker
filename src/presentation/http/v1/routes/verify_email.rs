use axum::{routing::get, Router};

use crate::presentation::{
    http::v1::handlers::verify_email::verify_email_handler, state::AppState,
};

/// `GET /verify-email?token=...` — the link embedded in the signup email.
pub fn verify_email_router() -> Router<AppState> {
    Router::new().route("/verify-email", get(verify_email_handler))
}
