use axum::extract::{Extension, State};
use serde::Deserialize;
use snafu::{ensure, Snafu};

use crate::{
    application::use_cases::delete_account::{
        DeleteAccountCommand, DeleteAccountError, DeleteAccountUseCase,
    },
    logging::{log_error, log_info, log_warn},
    presentation::{
        http::{
            error::{
                ApiError::{self, BadRequest},
                ApiResult,
            },
            openapi::{EmptyResult, Envelope},
            response::ApiResponse,
        },
        middlewares::auth::AuthenticatedAccount,
        state::{AppState, D1_BINDING},
        utils::extract::ApiJson,
    },
};

pub const DELETE_ACCOUNT_MESSAGE: &str = "account deleted";

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct DeleteAccountPayload {
    pub password: String,
    /// Required when the account has MFA enabled.
    #[serde(default)]
    pub mfa_code: Option<String>,
}

#[derive(Debug, Snafu)]
pub enum DeleteAccountValidationError {
    #[snafu(display("password can't be empty"))]
    PasswordEmpty,
}

impl From<DeleteAccountValidationError> for ApiError {
    fn from(err: DeleteAccountValidationError) -> Self {
        BadRequest(err.to_string())
    }
}

impl From<DeleteAccountError> for ApiError {
    fn from(err: DeleteAccountError) -> Self {
        match err {
            DeleteAccountError::AccountNotFound => {
                ApiError::Unauthorized("account not found".to_owned())
            }
            DeleteAccountError::InvalidPassword => BadRequest(err.to_string()),
            DeleteAccountError::SecondFactor { source } => super::mfa::second_factor_error(source),
            DeleteAccountError::FindAccount { .. }
            | DeleteAccountError::VerifyPassword { .. }
            | DeleteAccountError::DeleteAccount { .. } => {
                ApiError::InternalServerError("internal server error".to_owned())
            }
        }
    }
}

impl DeleteAccountPayload {
    fn into_command(
        self,
        account_id: uuid::Uuid,
    ) -> Result<DeleteAccountCommand, DeleteAccountValidationError> {
        ensure!(!self.password.is_empty(), PasswordEmptySnafu);

        Ok(DeleteAccountCommand {
            account_id,
            password: self.password,
            mfa_code: self
                .mfa_code
                .map(|code| code.trim().to_owned())
                .filter(|code| !code.is_empty()),
        })
    }
}

/// `DELETE /account/me` — permanently deletes the caller's account. The
/// password is required so a stolen access token alone cannot destroy it.
#[utoipa::path(
    delete,
    path = "/api/v1/account/me",
    tag = "account",
    summary = "Permanently delete the caller's account",
    description = "Requires the password, plus a valid `mfa_code` when the account has MFA \
                   enabled. Every token of the account is removed by cascade.",
    request_body = DeleteAccountPayload,
    security(("bearer" = [])),
    responses(
        (status = 200, description = "Account deleted", body = Envelope<EmptyResult>),
        (status = 400, description = "Invalid payload or wrong password", body = Envelope<Vec<String>>),
        (status = 401, description = "Missing token, or a wrong MFA code", body = Envelope<Vec<String>>),
        (status = 403, description = "MFA is enabled and no code was sent", body = Envelope<Vec<String>>),
        (status = 429, description = "Rate limit exceeded", body = Envelope<Vec<String>>)
    )
)]
#[worker::send]
pub async fn delete_account_handler(
    State(state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedAccount>,
    ApiJson(payload): ApiJson<DeleteAccountPayload>,
) -> ApiResult<ApiResponse<Vec<String>, Vec<String>, ()>> {
    let command = payload.into_command(authenticated.id).map_err(|err| {
        log_warn!("delete_account: invalid payload: {err}");
        ApiError::from(err)
    })?;
    let account_repository = state.account_repository().map_err(|err| {
        log_error!("delete_account: d1 binding `{D1_BINDING}` unavailable: {err}");
        ApiError::InternalServerError("database binding is unavailable".to_owned())
    })?;
    let hash_password_service = state.hash_password_service().map_err(|err| {
        log_error!("delete_account: password hashing is misconfigured: {err}");
        ApiError::InternalServerError("server is misconfigured".to_owned())
    })?;
    let case = DeleteAccountUseCase::new(
        account_repository,
        hash_password_service,
        super::mfa::second_factor(&state)?,
    );
    if let Err(err) = case.execute(command).await {
        log_error!("delete_account: failed: {err}");
        return Err(ApiError::from(err));
    }
    log_info!("delete_account: success, account id {}", authenticated.id);
    Ok(ApiResponse::ok(
        200,
        Vec::new(),
        vec![DELETE_ACCOUNT_MESSAGE.to_owned()],
        (),
    ))
}

#[cfg(test)]
mod tests {
    use axum::response::IntoResponse;

    use super::*;

    fn payload(password: &str) -> DeleteAccountPayload {
        DeleteAccountPayload {
            password: password.to_owned(),
            mfa_code: None,
        }
    }

    #[test]
    fn accepts_a_non_empty_password() {
        let command = payload("s3cret-pass")
            .into_command(uuid::Uuid::nil())
            .expect("payload should be accepted");

        assert_eq!(command.account_id, uuid::Uuid::nil());
        assert_eq!(command.password, "s3cret-pass");
    }

    #[test]
    fn keeps_password_whitespace_untouched() {
        let command = payload("  s3cret  ")
            .into_command(uuid::Uuid::nil())
            .expect("payload should be accepted");

        assert_eq!(command.password, "  s3cret  ");
    }

    #[test]
    fn rejects_an_empty_password() {
        let error = payload("")
            .into_command(uuid::Uuid::nil())
            .expect_err("payload should be rejected");

        assert!(matches!(error, DeleteAccountValidationError::PasswordEmpty));
        assert_eq!(error.to_string(), "password can't be empty");
    }

    #[test]
    fn maps_validation_errors_to_400_bad_request() {
        let api_error = ApiError::from(DeleteAccountValidationError::PasswordEmpty);

        assert!(matches!(api_error, ApiError::BadRequest(_)));
        assert_eq!(api_error.status(), 400);
    }

    #[test]
    fn maps_a_wrong_password_to_400() {
        let api_error = ApiError::from(DeleteAccountError::InvalidPassword);

        assert!(matches!(api_error, ApiError::BadRequest(_)));
        assert_eq!(api_error.status(), 400);
        assert_eq!(api_error.message(), "password is incorrect");
    }

    #[test]
    fn maps_a_missing_account_to_401() {
        let api_error = ApiError::from(DeleteAccountError::AccountNotFound);

        assert!(matches!(api_error, ApiError::Unauthorized(_)));
        assert_eq!(api_error.status(), 401);
    }

    #[test]
    fn hides_internal_errors_behind_500() {
        let cases = [
            DeleteAccountError::FindAccount {
                source: worker::Error::RustError("d1 select failed".to_owned()),
            },
            DeleteAccountError::VerifyPassword {
                source: argon2::password_hash::Error::Crypto,
            },
            DeleteAccountError::DeleteAccount {
                source: worker::Error::RustError("d1 delete failed".to_owned()),
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
            vec![DELETE_ACCOUNT_MESSAGE.to_owned()],
            (),
        );

        let json = serde_json::to_value(&response).expect("response should serialize");

        assert_eq!(json["success"], serde_json::json!(true));
        assert_eq!(json["errors"], serde_json::json!([]));
        assert_eq!(
            json["messages"],
            serde_json::json!([DELETE_ACCOUNT_MESSAGE])
        );
        assert_eq!(json["results"], serde_json::Value::Null);
    }

    #[test]
    fn responses_use_the_given_status_code() {
        let ok = ApiResponse::ok(200, Vec::<String>::new(), Vec::<String>::new(), ());
        assert_eq!(ok.into_response().status(), axum::http::StatusCode::OK);
    }
}
