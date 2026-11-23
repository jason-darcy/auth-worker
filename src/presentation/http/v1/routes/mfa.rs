use axum::{routing::post, Router};

use crate::presentation::{
    http::v1::handlers::mfa::{
        mfa_confirm_handler, mfa_disable_handler, mfa_recovery_codes_handler, mfa_setup_handler,
        mfa_status_handler, mfa_verify_handler,
    },
    state::AppState,
};

/// `GET /mfa`, `POST /mfa/totp/setup`, `POST /mfa/totp/confirm`,
/// `POST /mfa/disable` and `POST /mfa/recovery-codes` — all protected by the
/// access token.
pub fn mfa_router() -> Router<AppState> {
    Router::new()
        .route("/mfa", axum::routing::get(mfa_status_handler))
        .route("/mfa/totp/setup", post(mfa_setup_handler))
        .route("/mfa/totp/confirm", post(mfa_confirm_handler))
        .route("/mfa/disable", post(mfa_disable_handler))
        .route("/mfa/recovery-codes", post(mfa_recovery_codes_handler))
}

/// `POST /mfa/verify` — the second step of a sign-in, so it cannot require an
/// access token.
pub fn mfa_verify_router() -> Router<AppState> {
    Router::new().route("/mfa/verify", post(mfa_verify_handler))
}
