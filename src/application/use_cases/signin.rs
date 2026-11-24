use std::sync::Arc;

use jiff::Timestamp;
use serde::Serialize;
use snafu::{ResultExt, Snafu};
use uuid::Uuid;

use crate::domain::{
    account::normalize_email, repositories::account::AccountRepository,
    services::hash_password::HashPasswordService,
};

pub struct SignInCommand {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct SignInResult {
    pub id: Uuid,
    pub name: String,
    pub email: String,
    pub created_at: Timestamp,
}

#[derive(Debug, Snafu)]
pub enum SignInError {
    /// Returned both for unknown emails and wrong passwords so the API does
    /// not leak which accounts exist.
    #[snafu(display("invalid email or password"))]
    InvalidCredentials,
    #[snafu(display("failed to find account by email"))]
    FindAccount { source: worker::Error },
    #[snafu(display("failed to verify password"))]
    VerifyPassword {
        source: argon2::password_hash::Error,
    },
}

pub struct SignInUseCase {
    pub account_repository: Arc<dyn AccountRepository>,
    pub hash_password_service: Arc<dyn HashPasswordService>,
}

impl SignInUseCase {
    pub fn new(
        account_repository: Arc<dyn AccountRepository>,
        hash_password_service: Arc<dyn HashPasswordService>,
    ) -> Self {
        SignInUseCase {
            account_repository,
            hash_password_service,
        }
    }

    pub async fn execute(&self, command: SignInCommand) -> Result<SignInResult, SignInError> {
        // Accounts are stored with canonical (lowercase) emails.
        let email = normalize_email(&command.email);
        let account = self
            .account_repository
            .find_account_by_email(&email)
            .await
            .context(FindAccountSnafu)?;
        let Some(account) = account else {
            // Burn the same Argon2 work as a real verification, otherwise the
            // response time reveals whether the email is registered.
            self.hash_password_service.verify_dummy(&command.password);
            return Err(SignInError::InvalidCredentials);
        };

        let password_matches = self
            .hash_password_service
            .verify(&command.password, account.password_hash())
            .context(VerifyPasswordSnafu)?;
        if !password_matches {
            return Err(SignInError::InvalidCredentials);
        }

        Ok(SignInResult {
            id: account.id(),
            name: account.name().to_owned(),
            email: account.email().to_owned(),
            created_at: account.created_at(),
        })
    }
}
