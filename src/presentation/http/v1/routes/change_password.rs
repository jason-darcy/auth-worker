use axum::{routing::post, Router};

use crate::presentation::{
    http::v1::handlers::change_password::change_password_handler, state::AppState,
};

/// `POST /change-password` — replaces the password of the authenticated account.
pub fn change_password_router() -> Router<AppState> {
    Router::new().route("/change-password", post(change_password_handler))
}
