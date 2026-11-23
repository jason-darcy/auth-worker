use axum::{routing::get, Router};

use crate::presentation::{
    http::v1::handlers::{
        account::{get_account_handler, me_handler},
        delete_account::delete_account_handler,
    },
    state::AppState,
};

/// `GET /account/me`, `DELETE /account/me` and `GET /account/{account_id}` — all
/// protected by the access token. The static `me` segment is matched before the
/// id parameter.
pub fn account_router() -> Router<AppState> {
    Router::new()
        .route(
            "/account/me",
            get(me_handler).delete(delete_account_handler),
        )
        .route("/account/{account_id}", get(get_account_handler))
}
