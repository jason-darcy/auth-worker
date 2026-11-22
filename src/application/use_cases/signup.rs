use std::sync::Arc;

use jiff::Timestamp;
use serde::Serialize;
use snafu::{ensure, ResultExt, Snafu};
use uuid::Uuid;
use worker::{console_error, console_log, console_warn};

use crate::domain::{
    repositories::user::UserRepository, services::hash_password::HashPasswordService, user::User,
};

pub struct SignUpCommand {
    pub name: String,
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct SignupResult {
    pub id: Uuid,
    pub name: String,
    pub email: String,
    pub created_at: Timestamp,
}

#[derive(Debug, Snafu)]
pub enum SignupError {
    #[snafu(display("email already exists"))]
    EmailAlreadyExists,
    #[snafu(display("failed to find user by email"))]
    FindUser { source: worker::Error },
    #[snafu(display("failed to hash password"))]
    HashPassword {
        source: argon2::password_hash::Error,
    },
    #[snafu(display("failed to create user"))]
    CreateUser { source: worker::Error },
}

pub struct SignupUseCase {
    pub user_repository: Arc<dyn UserRepository>,
    pub hash_password_service: Arc<dyn HashPasswordService>,
}

impl SignupUseCase {
    pub fn new(
        user_repository: Arc<dyn UserRepository>,
        hash_password_service: Arc<dyn HashPasswordService>,
    ) -> Self {
        SignupUseCase {
            user_repository,
            hash_password_service,
        }
    }

    pub async fn execute(&self, command: SignUpCommand) -> Result<SignupResult, SignupError> {
        let existing_user = self
            .user_repository
            .find_user_by_email(&command.email)
            .await
            .inspect_err(|err| {
                console_error!(
                    "signup: find_user_by_email failed for {}: {err}",
                    command.email
                );
            })
            .context(FindUserSnafu)?;
        if existing_user.is_some() {
            console_warn!("signup: email already exists: {}", command.email);
        }
        ensure!(existing_user.is_none(), EmailAlreadyExistsSnafu);

        let password_hash = self
            .hash_password_service
            .hash(&command.password)
            .inspect_err(|err| {
                console_error!("signup: hash password failed for {}: {err}", command.email);
            })
            .context(HashPasswordSnafu)?;
        let user = User::new(&command.name, &command.email, &password_hash);
        let result = SignupResult {
            id: user.id(),
            name: user.name().to_owned(),
            email: user.email().to_owned(),
            created_at: user.created_at(),
        };
        match self.user_repository.create_user(user).await {
            Ok(()) => {
                console_log!("signup: created user {} ({})", result.id, result.email);
                Ok(result)
            }
            Err(worker::Error::D1(err)) if err.cause().contains("UNIQUE constraint failed") => {
                console_warn!("signup: email already exists: {}", command.email);
                Err(SignupError::EmailAlreadyExists)
            }
            Err(source) => Err(SignupError::CreateUser { source }),
        }
    }
}
