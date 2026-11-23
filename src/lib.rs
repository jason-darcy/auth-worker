use tower_service::Service;
use worker::*;

use crate::{
    application::use_cases::cleanup::CleanupUseCase,
    logging::{log_error, log_info},
    presentation::{http::routes::create_routers, state::AppState},
};

pub mod application;
pub mod domain;
pub mod infrastructure;
mod logging;
pub mod presentation;

#[cfg(test)]
mod testing;

#[event(fetch)]
async fn fetch(
    req: HttpRequest,
    env: Env,
    _ctx: Context,
) -> Result<axum::http::Response<axum::body::Body>> {
    let state = AppState::new(env);
    let mut routers = create_routers(state);
    Ok(routers.call(req).await?)
}

/// Cron handler: reclaims the space taken by expired tokens.
///
/// Expiry is already enforced when a token is used, so this only keeps the
/// tables from growing forever. It never fails: a scheduled run that cannot
/// reach D1 logs and returns, and the next run retries.
#[event(scheduled)]
async fn scheduled(_event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
    let state = AppState::new(env);
    let repositories = (
        state.verification_token_repository(),
        state.password_reset_token_repository(),
        state.refresh_token_repository(),
        state.mfa_repository(),
    );
    let (
        Ok(verification_token_repository),
        Ok(password_reset_token_repository),
        Ok(refresh_token_repository),
        Ok(mfa_repository),
    ) = repositories
    else {
        log_error!("cleanup: d1 bindings unavailable, skipping this run");
        return;
    };

    let result = CleanupUseCase::new(
        verification_token_repository,
        password_reset_token_repository,
        refresh_token_repository,
        mfa_repository,
    )
    .execute()
    .await;
    log_info!("cleanup: finished, {} rows removed", result.total());
}
