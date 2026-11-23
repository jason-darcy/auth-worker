use axum::extract::{Extension, State};
use serde::Deserialize;
use snafu::{ensure, Snafu};

use crate::{
    application::use_cases::signout::{SignOutCommand, SignOutError, SignOutUseCase},
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
        utils::{extract::ApiJson, validation::is_valid_opaque_token},
    },
};

/// Returned for both `/signout` and `/signout-all`; it never reveals whether the
/// refresh token was still valid.
pub const SIGN_OUT_MESSAGE: &str = "signed out";
pub const SIGN_OUT_ALL_MESSAGE: &str = "signed out of every device";

#[derive(Debug, Deserialize)]
pub struct SignOutPayload {
    pub refresh_token: String,
}

#[derive(Debug, Snafu)]
pub enum SignOutValidationError {
    #[snafu(display("refresh token is invalid"))]
    TokenInvalid,
}

impl From<SignOutValidationError> for ApiError {
    fn from(err: SignOutValidationError) -> Self {
        BadRequest(err.to_string())
    }
}

impl From<SignOutError> for ApiError {
    fn from(_err: SignOutError) -> Self {
        // Every variant is a storage failure; nothing about it is actionable
        // for the client.
        ApiError::InternalServerError("internal server error".to_owned())
    }
}

impl TryFrom<SignOutPayload> for SignOutCommand {
    type Error = SignOutValidationError;

    fn try_from(payload: SignOutPayload) -> Result<Self, Self::Error> {
        let refresh_token = payload.refresh_token.trim();
        ensure!(is_valid_opaque_token(refresh_token), TokenInvalidSnafu);

        Ok(SignOutCommand {
            refresh_token: refresh_token.to_owned(),
        })
    }
}

#[worker::send]
pub async fn signout_handler(
    State(state): State<AppState>,
    ApiJson(payload): ApiJson<SignOutPayload>,
) -> ApiResult<ApiResponse<Vec<String>, Vec<String>, ()>> {
    let command = SignOutCommand::try_from(payload).map_err(|err| {
        log_warn!("signout: invalid payload: {err}");
        ApiError::from(err)
    })?;
    let account_repository = state.account_repository().map_err(|err| {
        log_error!("signout: d1 binding `{D1_BINDING}` unavailable: {err}");
        ApiError::InternalServerError("database binding is unavailable".to_owned())
    })?;
    let refresh_token_repository = state.refresh_token_repository().map_err(|err| {
        log_error!("signout: d1 binding `{D1_BINDING}` unavailable for refresh tokens: {err}");
        ApiError::InternalServerError("database binding is unavailable".to_owned())
    })?;
    let token_service = state.token_service().map_err(|err| {
        log_error!("signout: token signing is misconfigured: {err}");
        ApiError::InternalServerError("server is misconfigured".to_owned())
    })?;
    let case = SignOutUseCase::new(account_repository, refresh_token_repository, token_service);
    if let Err(err) = case.execute(command).await {
        log_error!("signout: failed: {err}");
        return Err(ApiError::from(err));
    }
    log_info!("signout: success");
    Ok(ApiResponse::ok(
        200,
        Vec::new(),
        vec![SIGN_OUT_MESSAGE.to_owned()],
        (),
    ))
}

#[worker::send]
pub async fn signout_all_handler(
    State(state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedAccount>,
) -> ApiResult<ApiResponse<Vec<String>, Vec<String>, ()>> {
    let account_repository = state.account_repository().map_err(|err| {
        log_error!("signout_all: d1 binding `{D1_BINDING}` unavailable: {err}");
        ApiError::InternalServerError("database binding is unavailable".to_owned())
    })?;
    let refresh_token_repository = state.refresh_token_repository().map_err(|err| {
        log_error!("signout_all: d1 binding `{D1_BINDING}` unavailable for refresh tokens: {err}");
        ApiError::InternalServerError("database binding is unavailable".to_owned())
    })?;
    let token_service = state.token_service().map_err(|err| {
        log_error!("signout_all: token signing is misconfigured: {err}");
        ApiError::InternalServerError("server is misconfigured".to_owned())
    })?;
    let case = SignOutUseCase::new(account_repository, refresh_token_repository, token_service);
    if let Err(err) = case.execute_all(&authenticated.id.to_string()).await {
        log_error!("signout_all: failed: {err}");
        return Err(ApiError::from(err));
    }
    log_info!("signout_all: success, account id {}", authenticated.id);
    Ok(ApiResponse::ok(
        200,
        Vec::new(),
        vec![SIGN_OUT_ALL_MESSAGE.to_owned()],
        (),
    ))
}

#[cfg(test)]
mod tests {
    use axum::response::IntoResponse;

    use super::*;

    fn payload(token: &str) -> SignOutPayload {
        SignOutPayload {
            refresh_token: token.to_owned(),
        }
    }

    fn valid_token() -> String {
        "0123456789abcdef".repeat(4)
    }

    fn validation_error(payload: SignOutPayload) -> SignOutValidationError {
        match SignOutCommand::try_from(payload) {
            Ok(_) => panic!("payload should be rejected"),
            Err(err) => err,
        }
    }

    #[test]
    fn accepts_a_well_formed_token_and_trims_it() {
        let token = format!("  {}  ", valid_token());
        let command =
            SignOutCommand::try_from(payload(&token)).expect("payload should be accepted");

        assert_eq!(command.refresh_token, valid_token());
    }

    #[test]
    fn rejects_malformed_tokens() {
        for token in ["", "not-a-token", "abc", &"z".repeat(64)] {
            assert!(matches!(
                validation_error(payload(token)),
                SignOutValidationError::TokenInvalid
            ));
        }
        assert_eq!(
            validation_error(payload("abc")).to_string(),
            "refresh token is invalid"
        );
    }

    #[test]
    fn maps_validation_errors_to_400_bad_request() {
        let api_error = ApiError::from(SignOutValidationError::TokenInvalid);

        assert!(matches!(api_error, ApiError::BadRequest(_)));
        assert_eq!(api_error.status(), 400);
        assert_eq!(api_error.message(), "refresh token is invalid");
    }

    #[test]
    fn hides_storage_failures_behind_500() {
        let cases = [
            SignOutError::RevokeToken {
                source: worker::Error::RustError("d1 delete failed".to_owned()),
            },
            SignOutError::FindAccount {
                source: worker::Error::RustError("d1 select failed".to_owned()),
            },
            SignOutError::UpdateAccount {
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
    fn success_envelopes_match_the_api_contract() {
        for (message, expected) in [
            (SIGN_OUT_MESSAGE, "signed out"),
            (SIGN_OUT_ALL_MESSAGE, "signed out of every device"),
        ] {
            let response = ApiResponse::ok(200, Vec::<String>::new(), vec![message.to_owned()], ());
            let json = serde_json::to_value(&response).expect("response should serialize");

            assert_eq!(json["success"], serde_json::json!(true));
            assert_eq!(json["errors"], serde_json::json!([]));
            assert_eq!(json["messages"], serde_json::json!([expected]));
            assert_eq!(json["results"], serde_json::Value::Null);
        }
    }

    #[test]
    fn responses_use_the_given_status_code() {
        let ok = ApiResponse::ok(200, Vec::<String>::new(), Vec::<String>::new(), ());
        assert_eq!(ok.into_response().status(), axum::http::StatusCode::OK);

        let invalid = ApiError::from(SignOutValidationError::TokenInvalid).into_response();
        assert_eq!(invalid.status(), axum::http::StatusCode::BAD_REQUEST);
    }
}
