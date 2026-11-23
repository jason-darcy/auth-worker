use axum::{routing::get, Router};

use crate::presentation::{
    http::v1::handlers::reset_password::{reset_password_form_handler, reset_password_handler},
    state::AppState,
};

/// `GET /reset-password?token=...` renders the form the email links to;
/// `POST /reset-password` performs the reset.
pub fn reset_password_router() -> Router<AppState> {
    Router::new().route(
        "/reset-password",
        get(reset_password_form_handler).post(reset_password_handler),
    )
}
