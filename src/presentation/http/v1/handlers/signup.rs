use axum::extract::State;
use serde::Deserialize;
use snafu::{ensure, Snafu};

use crate::{
    application::use_cases::signup::{SignUpCommand, SignUpError, SignUpResult, SignUpUseCase},
    presentation::{
        http::{
            error::{
                ApiError::{self, BadRequest},
                ApiResult,
            },
            response::ApiResponse,
        },
        state::AppState,
        utils::extract::ApiJson,
    },
};

use crate::presentation::utils::validation::{is_valid_email, PASSWORD_MAX_LEN, PASSWORD_MIN_LEN};

#[derive(Debug, Deserialize)]
pub struct SignUpPayload {
    pub name: String,
    pub email: String,
    pub password: String,
    pub confirm_password: String,
}

#[derive(Debug, Snafu)]
pub enum SignUpValidationError {
    #[snafu(display("name can't be empty"))]
    NameEmpty,
    #[snafu(display("name should be less than 20 characters"))]
    NameTooLong,
    #[snafu(display("email is invalid"))]
    EmailInvalid,
    #[snafu(display("password should be at least 8 characters"))]
    PasswordTooShort,
    #[snafu(display("password should be at most 64 characters"))]
    PasswordTooLong,
    #[snafu(display("passwords do not match"))]
    PasswordMismatch,
}

impl From<SignUpValidationError> for ApiError {
    fn from(err: SignUpValidationError) -> Self {
        BadRequest(err.to_string())
    }
}

impl From<SignUpError> for ApiError {
    fn from(err: SignUpError) -> Self {
        match err {
            SignUpError::EmailAlreadyExists => ApiError::Conflict(err.to_string()),
            SignUpError::FindAccount { .. }
            | SignUpError::HashPassword { .. }
            | SignUpError::CreateAccount { .. } => {
                ApiError::InternalServerError("internal server error".to_owned())
            }
        }
    }
}

fn validate_signup_payload(payload: &SignUpPayload) -> Result<(), SignUpValidationError> {
    ensure!(!payload.name.trim().is_empty(), NameEmptySnafu);
    ensure!(payload.name.trim().len() < 20, NameTooLongSnafu);
    ensure!(is_valid_email(payload.email.trim()), EmailInvalidSnafu);
    ensure!(
        payload.password.len() >= PASSWORD_MIN_LEN,
        PasswordTooShortSnafu
    );
    ensure!(
        payload.password.len() <= PASSWORD_MAX_LEN,
        PasswordTooLongSnafu
    );
    ensure!(
        payload.password == payload.confirm_password,
        PasswordMismatchSnafu
    );
    Ok(())
}

impl TryFrom<SignUpPayload> for SignUpCommand {
    type Error = SignUpValidationError;

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
    ApiJson(payload): ApiJson<SignUpPayload>,
) -> ApiResult<ApiResponse<Vec<String>, Vec<String>, SignUpResult>> {
    let command = SignUpCommand::try_from(payload).map_err(ApiError::from)?;
    let account_repository = state
        .account_repository()
        .map_err(|_| ApiError::InternalServerError("database binding is unavailable".to_owned()))?;
    let hash_password_service = state.hash_password_service();
    let case = SignUpUseCase::new(account_repository, hash_password_service);
    let result = match case.execute(command).await {
        Ok(result) => result,
        Err(err) => {
            return Err(ApiError::from(err));
        }
    };
    Ok(ApiResponse::ok(
        200,
        Vec::new(),
        vec!["signup successful".to_owned()],
        result,
    ))
}
