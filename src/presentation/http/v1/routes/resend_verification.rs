use axum::{routing::post, Router};

use crate::presentation::{
    http::v1::handlers::resend_verification::resend_verification_handler, state::AppState,
};

/// `POST /resend-verification` — emails a new verification link.
pub fn resend_verification_router() -> Router<AppState> {
    Router::new().route("/resend-verification", post(resend_verification_handler))
}
