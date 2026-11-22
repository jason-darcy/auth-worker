use std::sync::Arc;

use axum::{extract::State, Json};
use serde::Deserialize;
use snafu::{ensure, Snafu};
use worker::{console_error, console_log, console_warn};

use crate::{
    application::use_cases::signup::{SignUpCommand, SignupError, SignupResult, SignupUseCase},
    infrastructure::{
        d1::user_repository::D1UserRepository, services::hash_password::Argon2HashPasswordService,
    },
    presentation::{
        http::{
            error::{
                ApiError::{self, BadRequest},
                ApiResult,
            },
            response::ApiResponse,
        },
        state::AppState,
    },
};

#[derive(Debug, Deserialize)]
pub struct SignUpPayload {
    pub name: String,
    pub email: String,
    pub password: String,
    pub confirm_password: String,
}

#[derive(Debug, Snafu)]
pub enum SignupValidationError {
    #[snafu(display("name can't be empty"))]
    NameEmpty,
    #[snafu(display("name should be less than 20 characters"))]
    NameTooLong,
    #[snafu(display("email is invalid"))]
    EmailInvalid,
    #[snafu(display("password should be at least 8 characters"))]
    PasswordTooShort,
    #[snafu(display("password should be at most 20 characters"))]
    PasswordTooLong,
    #[snafu(display("passwords do not match"))]
    PasswordMismatch,
}

impl From<SignupValidationError> for ApiError {
    fn from(err: SignupValidationError) -> Self {
        BadRequest(err.to_string())
    }
}

impl From<SignupError> for ApiError {
    fn from(err: SignupError) -> Self {
        match err {
            SignupError::EmailAlreadyExists => ApiError::Conflict(err.to_string()),
            SignupError::FindUser { .. }
            | SignupError::HashPassword { .. }
            | SignupError::CreateUser { .. } => {
                ApiError::InternalServerError("internal server error".to_owned())
            }
        }
    }
}

fn validate_signup_payload(payload: &SignUpPayload) -> Result<(), SignupValidationError> {
    ensure!(!payload.name.trim().is_empty(), NameEmptySnafu);
    ensure!(payload.name.trim().len() < 20, NameTooLongSnafu);
    let email = payload.email.trim();
    let (local, domain) = match email.split_once('@') {
        Some(parts) => parts,
        None => return Err(SignupValidationError::EmailInvalid),
    };
    ensure!(
        !local.is_empty()
            && domain.contains('.')
            && !domain.starts_with('.')
            && !domain.ends_with('.'),
        EmailInvalidSnafu
    );
    ensure!(payload.password.len() >= 8, PasswordTooShortSnafu);
    ensure!(payload.password.len() <= 20, PasswordTooLongSnafu);
    ensure!(
        payload.password == payload.confirm_password,
        PasswordMismatchSnafu
    );
    Ok(())
}

impl TryFrom<SignUpPayload> for SignUpCommand {
    type Error = SignupValidationError;

    fn try_from(payload: SignUpPayload) -> Result<Self, Self::Error> {
        validate_signup_payload(&payload)?;

        Ok(SignUpCommand {
            name: payload.name.trim().to_owned(),
            email: payload.email.trim().to_owned(),
            password: payload.password,
        })
    }
}

#[worker::send]
pub async fn signup_handler(
    State(state): State<AppState>,
    Json(payload): Json<SignUpPayload>,
) -> ApiResult<ApiResponse<Vec<String>, Vec<String>, SignupResult>> {
    let command = SignUpCommand::try_from(payload).map_err(|err| {
        console_warn!("signup: invalid payload: {err}");
        ApiError::from(err)
    })?;
    let d1 = state.env.d1("auth-worker").map_err(|err| {
        console_error!("signup: d1 binding `auth-worker` unavailable: {err}");
        ApiError::InternalServerError("database binding is unavailable".to_owned())
    })?;
    let secret = match state.env.secret("PASSWORD_PEPPER") {
        Ok(secret) => secret.to_string(),
        Err(err) => {
            console_error!(
                "signup: failed to read PASSWORD_PEPPER, hashing with empty pepper: {err}"
            );
            String::new()
        }
    };
    let user_repository = Arc::new(D1UserRepository::new(d1));
    let hash_password_service = Arc::new(Argon2HashPasswordService::new(&secret));
    let case = SignupUseCase::new(user_repository, hash_password_service);
    let result = match case.execute(command).await {
        Ok(result) => result,
        Err(err) => {
            console_error!("signup: failed: {err}");
            return Err(ApiError::from(err));
        }
    };
    console_log!("signup: success, user id {}", result.id);
    Ok(ApiResponse::ok(
        200,
        Vec::new(),
        vec!["signup successful".to_owned()],
        result,
    ))
}
