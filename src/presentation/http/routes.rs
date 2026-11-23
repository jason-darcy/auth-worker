use axum::{middleware, Router};

use crate::presentation::{
    http::v1::routes::{
        account::account_router, forgot_password::forgot_password_router, health::health_router,
        refresh_tokens::refresh_tokens_router, reset_password::reset_password_router,
        signin::signin_router, signup::signup_router, verify_email::verify_email_router,
    },
    middlewares::{auth::require_auth, rate_limit::rate_limit},
    state::AppState,
};

pub fn create_routers(state: AppState) -> Router<()> {
    // Only the auth endpoints are rate limited: health checks must stay
    // available even when a client exhausts its quota.
    let auth_routes = Router::new()
        .merge(signup_router())
        .merge(signin_router())
        .merge(refresh_tokens_router())
        .merge(forgot_password_router())
        .merge(reset_password_router())
        .merge(verify_email_router())
        .layer(middleware::from_fn_with_state(state.clone(), rate_limit));

    // Protected resources: require `Authorization: Bearer <access_token>`.
    let protected_routes = Router::new()
        .merge(account_router())
        .layer(middleware::from_fn_with_state(state.clone(), require_auth));

    let v1_routes = Router::new()
        .merge(health_router())
        .merge(auth_routes)
        .merge(protected_routes);
    Router::new().nest("/api/v1", v1_routes).with_state(state)
}
