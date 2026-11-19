use std::sync::Arc;

use worker::Env;

#[derive(Debug, Clone)]
pub struct AppState {
    pub env: Arc<Env>,
}

impl AppState {
    pub fn new(env: Env) -> Self {
        AppState { env: Arc::new(env) }
    }
}
