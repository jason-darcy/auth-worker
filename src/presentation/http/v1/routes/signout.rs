use axum::{routing::post, Router};

use crate::presentation::{
    http::v1::handlers::signout::{signout_all_handler, signout_handler},
    state::AppState,
};

/// `POST /signout` — revokes the refresh token in the body. Public on purpose:
/// the refresh token is the credential, and the call is idempotent.
pub fn signout_router() -> Router<AppState> {
    Router::new().route("/signout", post(signout_handler))
}

/// `POST /signout-all` — revokes every session of the caller and invalidates
/// outstanding access tokens.
pub fn signout_all_router() -> Router<AppState> {
    Router::new().route("/signout-all", post(signout_all_handler))
}
