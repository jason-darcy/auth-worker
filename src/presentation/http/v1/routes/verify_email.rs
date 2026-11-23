use axum::{routing::get, Router};

use crate::presentation::{
    http::v1::handlers::verify_email::{verify_email_form_handler, verify_email_handler},
    state::AppState,
};

/// `GET /verify-email?token=...` renders the confirmation page (scanners must
/// not consume the token); `POST /verify-email` performs the verification.
pub fn verify_email_router() -> Router<AppState> {
    Router::new().route(
        "/verify-email",
        get(verify_email_form_handler).post(verify_email_handler),
    )
}
