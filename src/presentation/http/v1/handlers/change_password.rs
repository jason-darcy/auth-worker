use axum::extract::{Extension, State};
use serde::Deserialize;
use snafu::{ensure, Snafu};

use crate::{
    application::use_cases::change_password::{
        ChangePasswordCommand, ChangePasswordError, ChangePasswordResult, ChangePasswordUseCase,
    },
    logging::{log_error, log_info, log_warn},
    presentation::{
        http::{
            error::{
                ApiError::{self, BadRequest},
                ApiResult,
            },
            response::ApiResponse,
        },
        middlewares::auth::AuthenticatedAccount,
        state::{AppState, D1_BINDING},
        utils::{
            extract::ApiJson,
            validation::{PASSWORD_MAX_LEN, PASSWORD_MIN_LEN},
        },
    },
};

pub const CHANGE_PASSWORD_MESSAGE: &str = "password changed, please sign in again";

#[derive(Debug, Deserialize)]
pub struct ChangePasswordPayload {
    pub current_password: String,
    pub new_password: String,
    pub confirm_password: String,
    /// Required when the account has MFA enabled.
    #[serde(default)]
    pub mfa_code: Option<String>,
}

#[derive(Debug, Snafu)]
pub enum ChangePasswordValidationError {
    #[snafu(display("current password can't be empty"))]
    CurrentPasswordEmpty,
    #[snafu(display("password should be at least 8 characters"))]
    PasswordTooShort,
    #[snafu(display("password should be at most 64 characters"))]
    PasswordTooLong,
    #[snafu(display("passwords do not match"))]
    PasswordMismatch,
}

impl From<ChangePasswordValidationError> for ApiError {
    fn from(err: ChangePasswordValidationError) -> Self {
        BadRequest(err.to_string())
    }
}

impl From<ChangePasswordError> for ApiError {
    fn from(err: ChangePasswordError) -> Self {
        match err {
            ChangePasswordError::AccountNotFound => {
                ApiError::Unauthorized("account not found".to_owned())
            }
            ChangePasswordError::InvalidCurrentPassword
            | ChangePasswordError::PasswordUnchanged => BadRequest(err.to_string()),
            ChangePasswordError::SecondFactor { source } => super::mfa::second_factor_error(source),
            ChangePasswordError::FindAccount { .. }
            | ChangePasswordError::VerifyPassword { .. }
            | ChangePasswordError::HashPassword { .. }
            | ChangePasswordError::UpdateAccount { .. } => {
                ApiError::InternalServerError("internal server error".to_owned())
            }
        }
    }
}

impl ChangePasswordPayload {
    fn into_command(
        self,
        account_id: uuid::Uuid,
    ) -> Result<ChangePasswordCommand, ChangePasswordValidationError> {
        ensure!(!self.current_password.is_empty(), CurrentPasswordEmptySnafu);
        ensure!(
            self.new_password.len() >= PASSWORD_MIN_LEN,
            PasswordTooShortSnafu
        );
        ensure!(
            self.new_password.len() <= PASSWORD_MAX_LEN,
            PasswordTooLongSnafu
        );
        ensure!(
            self.new_password == self.confirm_password,
            PasswordMismatchSnafu
        );

        Ok(ChangePasswordCommand {
            account_id,
            current_password: self.current_password,
            new_password: self.new_password,
            mfa_code: self
                .mfa_code
                .map(|code| code.trim().to_owned())
                .filter(|code| !code.is_empty()),
        })
    }
}

#[worker::send]
pub async fn change_password_handler(
    State(state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedAccount>,
    ApiJson(payload): ApiJson<ChangePasswordPayload>,
) -> ApiResult<ApiResponse<Vec<String>, Vec<String>, ChangePasswordResult>> {
    let command = payload.into_command(authenticated.id).map_err(|err| {
        log_warn!("change_password: invalid payload: {err}");
        ApiError::from(err)
    })?;
    let account_repository = state.account_repository().map_err(|err| {
        log_error!("change_password: d1 binding `{D1_BINDING}` unavailable: {err}");
        ApiError::InternalServerError("database binding is unavailable".to_owned())
    })?;
    let refresh_token_repository = state.refresh_token_repository().map_err(|err| {
        log_error!("change_password: d1 binding `{D1_BINDING}` unavailable for sessions: {err}");
        ApiError::InternalServerError("database binding is unavailable".to_owned())
    })?;
    let hash_password_service = state.hash_password_service().map_err(|err| {
        log_error!("change_password: password hashing is misconfigured: {err}");
        ApiError::InternalServerError("server is misconfigured".to_owned())
    })?;
    let case = ChangePasswordUseCase::new(
        account_repository,
        refresh_token_repository,
        hash_password_service,
        super::mfa::second_factor(&state)?,
    );
    let result = match case.execute(command).await {
        Ok(result) => result,
        Err(err) => {
            log_error!("change_password: failed: {err}");
            return Err(ApiError::from(err));
        }
    };
    log_info!("change_password: success, account id {}", result.id);
    Ok(ApiResponse::ok(
        200,
        Vec::new(),
        vec![CHANGE_PASSWORD_MESSAGE.to_owned()],
        result,
    ))
}

#[cfg(test)]
mod tests {
    use axum::response::IntoResponse;

    use super::*;

    fn payload(current: &str, new: &str, confirm: &str) -> ChangePasswordPayload {
        ChangePasswordPayload {
            current_password: current.to_owned(),
            new_password: new.to_owned(),
            confirm_password: confirm.to_owned(),
            mfa_code: None,
        }
    }

    fn command(payload: ChangePasswordPayload) -> ChangePasswordCommand {
        payload
            .into_command(uuid::Uuid::nil())
            .expect("payload should be accepted")
    }

    fn validation_error(payload: ChangePasswordPayload) -> ChangePasswordValidationError {
        match payload.into_command(uuid::Uuid::nil()) {
            Ok(_) => panic!("payload should be rejected"),
            Err(err) => err,
        }
    }

    #[test]
    fn accepts_a_valid_payload() {
        let command = command(payload("old-password", "new-password", "new-password"));

        assert_eq!(command.account_id, uuid::Uuid::nil());
        assert_eq!(command.current_password, "old-password");
        assert_eq!(command.new_password, "new-password");
    }

    #[test]
    fn keeps_password_whitespace_untouched() {
        let command = command(payload("  old  ", "  new-pass  ", "  new-pass  "));

        assert_eq!(command.current_password, "  old  ");
        assert_eq!(command.new_password, "  new-pass  ");
    }

    #[test]
    fn rejects_an_empty_current_password() {
        assert!(matches!(
            validation_error(payload("", "new-password", "new-password")),
            ChangePasswordValidationError::CurrentPasswordEmpty
        ));
    }

    #[test]
    fn enforces_password_length() {
        assert!(matches!(
            validation_error(payload("old-password", "short", "short")),
            ChangePasswordValidationError::PasswordTooShort
        ));
        let too_long = "a".repeat(PASSWORD_MAX_LEN + 1);
        assert!(matches!(
            validation_error(payload("old-password", &too_long, &too_long)),
            ChangePasswordValidationError::PasswordTooLong
        ));
    }

    #[test]
    fn rejects_mismatched_confirmation() {
        let error = validation_error(payload("old-password", "new-password", "other-password"));

        assert!(matches!(
            error,
            ChangePasswordValidationError::PasswordMismatch
        ));
        assert_eq!(error.to_string(), "passwords do not match");
    }

    #[test]
    fn maps_validation_errors_to_400_bad_request() {
        let cases = [
            (
                ChangePasswordValidationError::CurrentPasswordEmpty,
                "current password can't be empty",
            ),
            (
                ChangePasswordValidationError::PasswordTooShort,
                "password should be at least 8 characters",
            ),
            (
                ChangePasswordValidationError::PasswordTooLong,
                "password should be at most 64 characters",
            ),
            (
                ChangePasswordValidationError::PasswordMismatch,
                "passwords do not match",
            ),
        ];

        for (error, message) in cases {
            let api_error = ApiError::from(error);
            assert!(matches!(api_error, ApiError::BadRequest(_)));
            assert_eq!(api_error.status(), 400);
            assert_eq!(api_error.message(), message);
        }
    }

    #[test]
    fn maps_a_wrong_current_password_to_400() {
        let api_error = ApiError::from(ChangePasswordError::InvalidCurrentPassword);

        assert!(matches!(api_error, ApiError::BadRequest(_)));
        assert_eq!(api_error.status(), 400);
        assert_eq!(api_error.message(), "current password is incorrect");
    }

    #[test]
    fn maps_a_missing_account_to_401() {
        let api_error = ApiError::from(ChangePasswordError::AccountNotFound);

        assert!(matches!(api_error, ApiError::Unauthorized(_)));
        assert_eq!(api_error.status(), 401);
    }

    #[test]
    fn hides_internal_errors_behind_500() {
        let cases = [
            ChangePasswordError::FindAccount {
                source: worker::Error::RustError("d1 select failed".to_owned()),
            },
            ChangePasswordError::VerifyPassword {
                source: argon2::password_hash::Error::Crypto,
            },
            ChangePasswordError::HashPassword {
                source: argon2::password_hash::Error::Crypto,
            },
            ChangePasswordError::UpdateAccount {
                source: worker::Error::RustError("d1 update failed".to_owned()),
            },
        ];

        for error in cases {
            let api_error = ApiError::from(error);
            assert!(matches!(api_error, ApiError::InternalServerError(_)));
            assert_eq!(api_error.status(), 500);
            assert_eq!(api_error.message(), "internal server error");
        }
    }

    #[test]
    fn success_envelope_matches_the_api_contract() {
        let response = ApiResponse::ok(
            200,
            Vec::<String>::new(),
            vec![CHANGE_PASSWORD_MESSAGE.to_owned()],
            ChangePasswordResult {
                id: uuid::Uuid::nil(),
                email: "ada@example.com".to_owned(),
                is_verified: true,
            },
        );

        let json = serde_json::to_value(&response).expect("response should serialize");

        assert_eq!(json["success"], serde_json::json!(true));
        assert_eq!(
            json["messages"],
            serde_json::json!([CHANGE_PASSWORD_MESSAGE])
        );
        assert_eq!(json["results"]["email"], "ada@example.com");
        assert!(json["results"].get("password").is_none());
        assert!(json["results"].get("password_hash").is_none());
    }

    #[test]
    fn responses_use_the_given_status_code() {
        let ok = ApiResponse::ok(200, Vec::<String>::new(), Vec::<String>::new(), ());
        assert_eq!(ok.into_response().status(), axum::http::StatusCode::OK);
    }
}
