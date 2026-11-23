use axum::{
    extract::State,
    http::{HeaderMap, Uri},
};
use serde::Deserialize;
use snafu::{ensure, Snafu};

use crate::{
    application::use_cases::forgot_password::{
        ForgotPasswordCommand, ForgotPasswordError, ForgotPasswordUseCase,
    },
    logging::{log_error, log_warn},
    presentation::{
        http::{
            error::{
                ApiError::{self, BadRequest},
                ApiResult,
            },
            response::ApiResponse,
        },
        state::{AppState, D1_BINDING, EMAIL_BINDING},
        utils::{extract::ApiJson, validation::is_valid_email},
    },
};

/// Always returned, whether the email exists or not.
pub const FORGOT_PASSWORD_MESSAGE: &str =
    "if the email is registered, a password reset link has been sent";

#[derive(Debug, Deserialize)]
pub struct ForgotPasswordPayload {
    pub email: String,
}

#[derive(Debug, Snafu)]
pub enum ForgotPasswordValidationError {
    #[snafu(display("email is invalid"))]
    EmailInvalid,
}

impl From<ForgotPasswordValidationError> for ApiError {
    fn from(err: ForgotPasswordValidationError) -> Self {
        BadRequest(err.to_string())
    }
}

impl From<ForgotPasswordError> for ApiError {
    fn from(err: ForgotPasswordError) -> Self {
        match err {
            ForgotPasswordError::FindAccount { .. } => {
                ApiError::InternalServerError("internal server error".to_owned())
            }
        }
    }
}

impl TryFrom<ForgotPasswordPayload> for ForgotPasswordCommand {
    type Error = ForgotPasswordValidationError;

    fn try_from(payload: ForgotPasswordPayload) -> Result<Self, Self::Error> {
        let email = payload.email.trim();
        ensure!(is_valid_email(email), EmailInvalidSnafu);

        Ok(ForgotPasswordCommand {
            email: email.to_owned(),
        })
    }
}

#[worker::send]
pub async fn forgot_password_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
    ApiJson(payload): ApiJson<ForgotPasswordPayload>,
) -> ApiResult<ApiResponse<Vec<String>, Vec<String>, ()>> {
    let command = ForgotPasswordCommand::try_from(payload).map_err(|err| {
        log_warn!("forgot_password: invalid payload: {err}");
        ApiError::from(err)
    })?;
    let account_repository = state.account_repository().map_err(|err| {
        log_error!("forgot_password: d1 binding `{D1_BINDING}` unavailable: {err}");
        ApiError::InternalServerError("database binding is unavailable".to_owned())
    })?;
    let password_reset_token_repository =
        state.password_reset_token_repository().map_err(|err| {
            log_error!("forgot_password: d1 binding `{D1_BINDING}` unavailable for tokens: {err}");
            ApiError::InternalServerError("database binding is unavailable".to_owned())
        })?;
    let email_service = state.email_service(&uri, &headers).map_err(|err| {
        log_error!("forgot_password: email binding `{EMAIL_BINDING}` unavailable: {err}");
        ApiError::InternalServerError("email binding is unavailable".to_owned())
    })?;
    let case = ForgotPasswordUseCase::new(
        account_repository,
        password_reset_token_repository,
        state.verification_token_service(),
        email_service,
    );
    if let Err(err) = case.execute(command).await {
        log_error!("forgot_password: failed: {err}");
        return Err(ApiError::from(err));
    }
    Ok(ApiResponse::ok(
        200,
        Vec::new(),
        vec![FORGOT_PASSWORD_MESSAGE.to_owned()],
        (),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(email: &str) -> ForgotPasswordPayload {
        ForgotPasswordPayload {
            email: email.to_owned(),
        }
    }

    fn validation_error(payload: ForgotPasswordPayload) -> ForgotPasswordValidationError {
        match ForgotPasswordCommand::try_from(payload) {
            Ok(_) => panic!("payload should be rejected"),
            Err(err) => err,
        }
    }

    #[test]
    fn accepts_valid_email_and_trims_it() {
        let command = ForgotPasswordCommand::try_from(payload("  ada@example.com  "))
            .expect("payload should be accepted");

        assert_eq!(command.email, "ada@example.com");
    }

    #[test]
    fn rejects_invalid_emails() {
        for email in ["", "ada", "ada@", "@example.com", "ada@@example.com"] {
            assert!(matches!(
                validation_error(payload(email)),
                ForgotPasswordValidationError::EmailInvalid
            ));
        }
        assert_eq!(
            validation_error(payload("ada")).to_string(),
            "email is invalid"
        );
    }

    #[test]
    fn maps_validation_errors_to_400_bad_request() {
        let api_error = ApiError::from(ForgotPasswordValidationError::EmailInvalid);

        assert!(matches!(api_error, ApiError::BadRequest(_)));
        assert_eq!(api_error.status(), 400);
        assert_eq!(api_error.message(), "email is invalid");
    }

    #[test]
    fn hides_internal_errors_behind_500() {
        let api_error = ApiError::from(ForgotPasswordError::FindAccount {
            source: worker::Error::RustError("d1 select failed".to_owned()),
        });

        assert!(matches!(api_error, ApiError::InternalServerError(_)));
        assert_eq!(api_error.status(), 500);
        assert_eq!(api_error.message(), "internal server error");
    }
}

#[cfg(test)]
mod response_tests {
    use super::*;

    #[test]
    fn response_is_identical_for_known_and_unknown_emails() {
        let response: ApiResponse<Vec<String>, Vec<String>, ()> = ApiResponse::ok(
            200,
            Vec::new(),
            vec![FORGOT_PASSWORD_MESSAGE.to_owned()],
            (),
        );

        let json = serde_json::to_value(&response).expect("response should serialize");

        assert_eq!(json["success"], serde_json::json!(true));
        assert_eq!(
            json["messages"],
            serde_json::json!([FORGOT_PASSWORD_MESSAGE])
        );
        assert!(
            json["messages"][0]
                .as_str()
                .expect("message")
                .contains("if the email is registered"),
            "the response must not reveal whether the account exists"
        );
    }
}
