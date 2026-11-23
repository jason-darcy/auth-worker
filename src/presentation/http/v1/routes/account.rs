use axum::{routing::get, Router};

use crate::presentation::{http::v1::handlers::account::get_account_handler, state::AppState};

/// `GET /account/{account_id}` — protected by the access token.
pub fn account_router() -> Router<AppState> {
    Router::new().route("/account/{account_id}", get(get_account_handler))
}
