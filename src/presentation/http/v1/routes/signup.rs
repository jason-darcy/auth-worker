use axum::{routing::post, Router};

use crate::presentation::{http::v1::handlers::signup::signup_handler, state::AppState};

pub fn signup_router() -> Router<AppState> {
    Router::new().route("/signup", post(signup_handler))
}
