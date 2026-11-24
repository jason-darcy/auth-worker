use std::sync::Arc;

use jiff::Timestamp;
use serde::Serialize;
use snafu::{ensure, ResultExt, Snafu};
use uuid::Uuid;

use crate::domain::{
    account::{normalize_email, Account},
    repositories::account::AccountRepository,
    services::hash_password::HashPasswordService,
};

pub struct SignUpCommand {
    pub name: String,
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct SignUpResult {
    pub id: Uuid,
    pub name: String,
    pub email: String,
    pub created_at: Timestamp,
}

#[derive(Debug, Snafu)]
pub enum SignUpError {
    #[snafu(display("email already exists"))]
    EmailAlreadyExists,
    #[snafu(display("failed to find account by email"))]
    FindAccount { source: worker::Error },
    #[snafu(display("failed to hash password"))]
    HashPassword {
        source: argon2::password_hash::Error,
    },
    #[snafu(display("failed to create account"))]
    CreateAccount { source: worker::Error },
}

pub struct SignUpUseCase {
    pub account_repository: Arc<dyn AccountRepository>,
    pub hash_password_service: Arc<dyn HashPasswordService>,
}

impl SignUpUseCase {
    pub fn new(
        account_repository: Arc<dyn AccountRepository>,
        hash_password_service: Arc<dyn HashPasswordService>,
    ) -> Self {
        SignUpUseCase {
            account_repository,
            hash_password_service,
        }
    }

    pub async fn execute(&self, command: SignUpCommand) -> Result<SignUpResult, SignUpError> {
        // Look up and store the canonical form, so `Ada@Example.com` and
        // `ada@example.com` cannot become two accounts.
        let email = normalize_email(&command.email);
        let existing_account = self
            .account_repository
            .find_account_by_email(&email)
            .await
            .context(FindAccountSnafu)?;
        ensure!(existing_account.is_none(), EmailAlreadyExistsSnafu);

        let password_hash = self
            .hash_password_service
            .hash(&command.password)
            .context(HashPasswordSnafu)?;
        let mut account = Account::new(&command.name, &email, &password_hash);
        // There is no email verification flow, so the account is usable as soon
        // as it exists.
        account.mark_verified();
        let result = SignUpResult {
            id: account.id(),
            name: account.name().to_owned(),
            email: account.email().to_owned(),
            created_at: account.created_at(),
        };
        match self.account_repository.create_account(account).await {
            Ok(()) => Ok(result),
            Err(worker::Error::D1(err)) if err.cause().contains("UNIQUE constraint failed") => {
                Err(SignUpError::EmailAlreadyExists)
            }
            Err(source) => Err(SignUpError::CreateAccount { source }),
        }
    }
}
