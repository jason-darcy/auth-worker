use std::sync::Arc;

use worker::Env;

use crate::{
    domain::{
        repositories::account::AccountRepository, services::hash_password::HashPasswordService,
    },
    infrastructure::{
        d1::account_repository::D1AccountRepository,
        services::hash_password::Argon2HashPasswordService,
    },
};

pub const D1_BINDING: &str = "DB";
pub const CORS_ORIGINS_VAR: &str = "CORS_ORIGINS";

#[derive(Debug, Clone)]
pub struct AppState {
    pub env: Arc<Env>,
}

impl AppState {
    pub fn new(env: Env) -> Self {
        AppState { env: Arc::new(env) }
    }

    /// Builds the account repository backed by the D1 binding.
    pub fn account_repository(&self) -> Result<Arc<dyn AccountRepository>, worker::Error> {
        let d1 = self.env.d1(D1_BINDING)?;
        Ok(Arc::new(D1AccountRepository::new(d1)))
    }

    /// Builds the password hasher (Argon2id with the default parameters).
    pub fn hash_password_service(&self) -> Arc<dyn HashPasswordService> {
        Arc::new(Argon2HashPasswordService::new())
    }
}
