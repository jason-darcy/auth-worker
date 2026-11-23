use axum::{extract::State, http::HeaderMap};
use serde::Deserialize;
use snafu::{ensure, Snafu};

use crate::{
    application::use_cases::refresh_tokens::{
        RefreshTokensCommand, RefreshTokensError, RefreshTokensResult, RefreshTokensUseCase,
    },
    logging::{log_error, log_info, log_warn},
    presentation::{
        http::{
            error::{
                ApiError::{self, BadRequest},
                ApiResult,
            },
            openapi::Envelope,
            response::ApiResponse,
        },
        state::{AppState, D1_BINDING},
        utils::{extract::ApiJson, request::client_info, validation::is_valid_opaque_token},
    },
};

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct RefreshTokensPayload {
    pub refresh_token: String,
}

#[derive(Debug, Snafu)]
pub enum RefreshTokensValidationError {
    #[snafu(display("refresh token is invalid"))]
    TokenInvalid,
}

impl From<RefreshTokensValidationError> for ApiError {
    fn from(err: RefreshTokensValidationError) -> Self {
        BadRequest(err.to_string())
    }
}

impl From<RefreshTokensError> for ApiError {
    fn from(err: RefreshTokensError) -> Self {
        match err {
            RefreshTokensError::InvalidRefreshToken => ApiError::Unauthorized(err.to_string()),
            RefreshTokensError::EmailNotVerified => ApiError::Forbidden(err.to_string()),
            RefreshTokensError::FindToken { .. }
            | RefreshTokensError::FindAccount { .. }
            | RefreshTokensError::IssueTokens { .. }
            | RefreshTokensError::StoreRefreshToken { .. } => {
                ApiError::InternalServerError("internal server error".to_owned())
            }
        }
    }
}

impl TryFrom<RefreshTokensPayload> for RefreshTokensCommand {
    type Error = RefreshTokensValidationError;

    fn try_from(payload: RefreshTokensPayload) -> Result<Self, Self::Error> {
        let refresh_token = payload.refresh_token.trim();
        ensure!(is_valid_opaque_token(refresh_token), TokenInvalidSnafu);

        Ok(RefreshTokensCommand {
            refresh_token: refresh_token.to_owned(),
        })
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/refresh",
    tag = "session",
    summary = "Rotate a refresh token for a new token pair",
    description = "The presented token is retired. Presenting an already rotated token is treated \
                   as a replay and revokes the whole session.",
    request_body = RefreshTokensPayload,
    responses(
        (status = 200, description = "New token pair", body = Envelope<RefreshTokensResult>),
        (status = 400, description = "Invalid payload", body = Envelope<Vec<String>>),
        (status = 401, description = "Unknown, expired or replayed token", body = Envelope<Vec<String>>),
        (status = 403, description = "The email is not verified", body = Envelope<Vec<String>>),
        (status = 429, description = "Rate limit exceeded", body = Envelope<Vec<String>>)
    )
)]
#[worker::send]
pub async fn refresh_tokens_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    ApiJson(payload): ApiJson<RefreshTokensPayload>,
) -> ApiResult<ApiResponse<Vec<String>, Vec<String>, RefreshTokensResult>> {
    let command = RefreshTokensCommand::try_from(payload).map_err(|err| {
        log_warn!("refresh: invalid payload: {err}");
        ApiError::from(err)
    })?;
    let account_repository = state.account_repository().map_err(|err| {
        log_error!("refresh: d1 binding `{D1_BINDING}` unavailable: {err}");
        ApiError::InternalServerError("database binding is unavailable".to_owned())
    })?;
    let refresh_token_repository = state.refresh_token_repository().map_err(|err| {
        log_error!("refresh: d1 binding `{D1_BINDING}` unavailable for refresh tokens: {err}");
        ApiError::InternalServerError("database binding is unavailable".to_owned())
    })?;
    let token_service = state.token_service().map_err(|err| {
        log_error!("refresh: token signing is misconfigured: {err}");
        ApiError::InternalServerError("server is misconfigured".to_owned())
    })?;
    let case =
        RefreshTokensUseCase::new(account_repository, refresh_token_repository, token_service);
    let result = match case.execute(command, &client_info(&headers)).await {
        Ok(result) => result,
        Err(err) => {
            log_error!("refresh: failed: {err}");
            return Err(ApiError::from(err));
        }
    };
    log_info!("refresh: success, account id {}", result.id);
    Ok(ApiResponse::ok(
        200,
        Vec::new(),
        vec!["tokens refreshed".to_owned()],
        result,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(token: &str) -> RefreshTokensPayload {
        RefreshTokensPayload {
            refresh_token: token.to_owned(),
        }
    }

    fn valid_token() -> String {
        "0123456789abcdef".repeat(4)
    }

    fn validation_error(payload: RefreshTokensPayload) -> RefreshTokensValidationError {
        match RefreshTokensCommand::try_from(payload) {
            Ok(_) => panic!("payload should be rejected"),
            Err(err) => err,
        }
    }

    #[test]
    fn accepts_a_well_formed_token_and_trims_it() {
        let padded = format!("  {}  ", valid_token());
        let command =
            RefreshTokensCommand::try_from(payload(&padded)).expect("payload should be accepted");

        assert_eq!(command.refresh_token, valid_token());
    }

    #[test]
    fn rejects_malformed_tokens() {
        for token in ["", "not-a-token", "abc"] {
            assert!(matches!(
                validation_error(payload(token)),
                RefreshTokensValidationError::TokenInvalid
            ));
        }
        assert_eq!(
            validation_error(payload("")).to_string(),
            "refresh token is invalid"
        );
    }

    #[test]
    fn maps_validation_errors_to_400_bad_request() {
        let api_error = ApiError::from(RefreshTokensValidationError::TokenInvalid);

        assert!(matches!(api_error, ApiError::BadRequest(_)));
        assert_eq!(api_error.status(), 400);
    }

    #[test]
    fn maps_invalid_token_to_401_unauthorized() {
        let api_error = ApiError::from(RefreshTokensError::InvalidRefreshToken);

        assert!(matches!(api_error, ApiError::Unauthorized(_)));
        assert_eq!(api_error.status(), 401);
        assert_eq!(api_error.message(), "refresh token is invalid or expired");
    }

    #[test]
    fn maps_unverified_email_to_403_forbidden() {
        let api_error = ApiError::from(RefreshTokensError::EmailNotVerified);

        assert!(matches!(api_error, ApiError::Forbidden(_)));
        assert_eq!(api_error.status(), 403);
        assert_eq!(api_error.message(), "email is not verified");
    }

    #[test]
    fn hides_internal_errors_behind_500() {
        let cases = [
            RefreshTokensError::FindToken {
                source: worker::Error::RustError("d1 select failed".to_owned()),
            },
            RefreshTokensError::FindAccount {
                source: worker::Error::RustError("d1 select failed".to_owned()),
            },
            RefreshTokensError::IssueTokens {
                source: worker::Error::RustError("signing failed".to_owned()),
            },
            RefreshTokensError::StoreRefreshToken {
                source: worker::Error::RustError("d1 insert failed".to_owned()),
            },
        ];

        for error in cases {
            let api_error = ApiError::from(error);
            assert!(matches!(api_error, ApiError::InternalServerError(_)));
            assert_eq!(api_error.status(), 500);
            assert_eq!(api_error.message(), "internal server error");
        }
    }
}

#[cfg(test)]
mod response_tests {
    use crate::domain::services::token::IssuedTokens;

    use super::*;

    fn result() -> RefreshTokensResult {
        let created_at: jiff::Timestamp = "2026-01-02T03:04:05Z".parse().expect("timestamp");
        RefreshTokensResult {
            id: uuid::Uuid::nil(),
            email: "ada@example.com".to_owned(),
            tokens: IssuedTokens {
                token_type: "Bearer".to_owned(),
                access_token: "new.access.token".to_owned(),
                refresh_token: "new-refresh-token".to_owned(),
                access_token_expires_at: created_at,
                refresh_token_expires_at: created_at,
            },
        }
    }

    #[test]
    fn success_envelope_flattens_the_tokens() {
        let response = ApiResponse::ok(
            200,
            Vec::<String>::new(),
            vec!["tokens refreshed".to_owned()],
            result(),
        );

        let json = serde_json::to_value(&response).expect("response should serialize");

        assert_eq!(json["success"], serde_json::json!(true));
        assert_eq!(json["messages"], serde_json::json!(["tokens refreshed"]));
        assert_eq!(json["results"]["email"], "ada@example.com");
        assert_eq!(json["results"]["token_type"], "Bearer");
        assert_eq!(json["results"]["access_token"], "new.access.token");
        assert_eq!(json["results"]["refresh_token"], "new-refresh-token");
        assert!(json["results"]["access_token_expires_at"].is_string());
        assert!(
            json["results"].get("tokens").is_none(),
            "tokens must be flattened into results"
        );
    }
}
