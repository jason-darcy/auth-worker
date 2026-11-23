use std::sync::Arc;

use axum::http::{HeaderMap, Uri};
use worker::Env;

use crate::{
    domain::{
        repositories::{
            account::AccountRepository, password_reset_token::PasswordResetTokenRepository,
            refresh_token::RefreshTokenRepository, verification_token::VerificationTokenRepository,
        },
        services::{
            email::EmailService, hash_password::HashPasswordService, token::TokenService,
            verification_token::VerificationTokenService,
        },
    },
    infrastructure::{
        d1::{
            account_repository::D1AccountRepository,
            password_reset_token_repository::D1PasswordResetTokenRepository,
            refresh_token_repository::D1RefreshTokenRepository,
            verification_token_repository::D1VerificationTokenRepository,
        },
        email::EmailClient,
        services::{
            email::TransactionalMailer, hash_password::Argon2HashPasswordService,
            token::JwtTokenService, verification_token::RandomVerificationTokenService,
        },
    },
    logging::log_error,
    presentation::utils::request::resolve_app_base_url,
};

pub const D1_BINDING: &str = "auth-worker";
pub const PASSWORD_PEPPER_SECRET: &str = "PASSWORD_PEPPER";
pub const EMAIL_BINDING: &str = "EMAIL";
pub const EMAIL_FROM_VAR: &str = "EMAIL_FROM";
pub const DOMAIN_VAR: &str = "DOMAIN";
pub const RATE_LIMITER_BINDING: &str = "RATE_LIMITER";
pub const JWT_SECRET_SECRET: &str = "JWT_SECRET";

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

    /// Builds the verification token repository backed by the D1 binding.
    pub fn verification_token_repository(
        &self,
    ) -> Result<Arc<dyn VerificationTokenRepository>, worker::Error> {
        let d1 = self.env.d1(D1_BINDING)?;
        Ok(Arc::new(D1VerificationTokenRepository::new(d1)))
    }

    /// Builds the password hasher, peppering with `PASSWORD_PEPPER` when the
    /// secret is configured.
    pub fn hash_password_service(&self) -> Arc<dyn HashPasswordService> {
        let pepper = match self.env.secret(PASSWORD_PEPPER_SECRET) {
            Ok(secret) => secret.to_string(),
            Err(err) => {
                log_error!(
                    "failed to read {PASSWORD_PEPPER_SECRET}, hashing with empty pepper: {err}"
                );
                String::new()
            }
        };
        Arc::new(Argon2HashPasswordService::new(&pepper))
    }

    pub fn verification_token_service(&self) -> Arc<dyn VerificationTokenService> {
        Arc::new(RandomVerificationTokenService::new())
    }

    /// Builds the transactional email service from the `EMAIL` binding,
    /// `EMAIL_FROM` and `DOMAIN` (see [`resolve_app_base_url`] for the
    /// local-request override).
    pub fn email_service(
        &self,
        uri: &Uri,
        headers: &HeaderMap,
    ) -> Result<Arc<dyn EmailService>, worker::Error> {
        let client = EmailClient::new(self.env.send_email(EMAIL_BINDING)?);
        let from = self.var_or(EMAIL_FROM_VAR, "");
        let base_url = resolve_app_base_url(&self.var_or(DOMAIN_VAR, ""), uri, headers);
        Ok(Arc::new(TransactionalMailer::from_config(
            client, &from, &base_url,
        )?))
    }

    /// Builds the password reset token repository backed by the D1 binding.
    pub fn password_reset_token_repository(
        &self,
    ) -> Result<Arc<dyn PasswordResetTokenRepository>, worker::Error> {
        let d1 = self.env.d1(D1_BINDING)?;
        Ok(Arc::new(D1PasswordResetTokenRepository::new(d1)))
    }

    /// Builds the refresh token repository backed by the D1 binding.
    pub fn refresh_token_repository(
        &self,
    ) -> Result<Arc<dyn RefreshTokenRepository>, worker::Error> {
        let d1 = self.env.d1(D1_BINDING)?;
        Ok(Arc::new(D1RefreshTokenRepository::new(d1)))
    }

    /// Builds the JWT service signing access tokens with `JWT_SECRET`.
    pub fn token_service(&self) -> Arc<dyn TokenService> {
        let secret = match self.env.secret(JWT_SECRET_SECRET) {
            Ok(secret) => secret.to_string(),
            Err(err) => {
                log_error!(
                    "failed to read {JWT_SECRET_SECRET}, signing access tokens with an empty secret: {err}"
                );
                String::new()
            }
        };
        Arc::new(JwtTokenService::new(&secret))
    }

    /// Cloudflare native rate limiter binding.
    pub fn rate_limiter(&self) -> Result<worker::RateLimiter, worker::Error> {
        self.env.rate_limiter(RATE_LIMITER_BINDING)
    }

    fn var_or(&self, name: &str, fallback: &str) -> String {
        match self.env.var(name) {
            Ok(value) => value.to_string(),
            Err(err) => {
                log_error!("failed to read {name}, falling back to {fallback:?}: {err}");
                fallback.to_owned()
            }
        }
    }
}
