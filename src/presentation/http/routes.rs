use axum::Router;

use crate::presentation::{http::v1::routes::health::health_router, state::AppState};

pub fn create_routers(state: AppState) -> Router<()> {
    let v1_routes = Router::new().merge(health_router());
    Router::new().nest("/api/v1", v1_routes).with_state(state)
}
