use axum::extract::State;
use serde::Deserialize;
use snafu::{ensure, Snafu};

use crate::{
    application::use_cases::signin::{SignInCommand, SignInError, SignInResult, SignInUseCase},
    presentation::{
        http::{
            error::{
                ApiError::{self, BadRequest},
                ApiResult,
            },
            response::ApiResponse,
        },
        state::AppState,
        utils::{extract::ApiJson, validation::is_valid_email},
    },
};

#[derive(Debug, Deserialize)]
pub struct SignInPayload {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Snafu)]
pub enum SignInValidationError {
    #[snafu(display("email is invalid"))]
    EmailInvalid,
    #[snafu(display("password can't be empty"))]
    PasswordEmpty,
}

impl From<SignInValidationError> for ApiError {
    fn from(err: SignInValidationError) -> Self {
        BadRequest(err.to_string())
    }
}

impl From<SignInError> for ApiError {
    fn from(err: SignInError) -> Self {
        match err {
            SignInError::InvalidCredentials => ApiError::Unauthorized(err.to_string()),
            SignInError::FindAccount { .. } | SignInError::VerifyPassword { .. } => {
                ApiError::InternalServerError("internal server error".to_owned())
            }
        }
    }
}

fn validate_signin_payload(payload: &SignInPayload) -> Result<(), SignInValidationError> {
    ensure!(is_valid_email(payload.email.trim()), EmailInvalidSnafu);
    ensure!(!payload.password.is_empty(), PasswordEmptySnafu);
    Ok(())
}

impl TryFrom<SignInPayload> for SignInCommand {
    type Error = SignInValidationError;

    fn try_from(payload: SignInPayload) -> Result<Self, Self::Error> {
        validate_signin_payload(&payload)?;

        Ok(SignInCommand {
            email: payload.email.trim().to_owned(),
            password: payload.password,
        })
    }
}

#[worker::send]
pub async fn signin_handler(
    State(state): State<AppState>,
    ApiJson(payload): ApiJson<SignInPayload>,
) -> ApiResult<ApiResponse<Vec<String>, Vec<String>, SignInResult>> {
    let command = SignInCommand::try_from(payload).map_err(ApiError::from)?;
    let account_repository = state
        .account_repository()
        .map_err(|_| ApiError::InternalServerError("database binding is unavailable".to_owned()))?;
    let hash_password_service = state.hash_password_service();
    let case = SignInUseCase::new(account_repository, hash_password_service);
    let result = match case.execute(command).await {
        Ok(result) => result,
        Err(err) => {
            return Err(ApiError::from(err));
        }
    };

    Ok(ApiResponse::ok(
        200,
        Vec::new(),
        vec!["signin successful".to_owned()],
        result,
    ))
}
