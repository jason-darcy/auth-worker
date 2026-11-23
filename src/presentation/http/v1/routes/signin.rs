use axum::{routing::post, Router};

use crate::presentation::{http::v1::handlers::signin::signin_handler, state::AppState};

pub fn signin_router() -> Router<AppState> {
    Router::new().route("/signin", post(signin_handler))
}
