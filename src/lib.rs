use tower_service::Service;
use worker::*;

use crate::presentation::{http::routes::create_routers, state::AppState};

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
