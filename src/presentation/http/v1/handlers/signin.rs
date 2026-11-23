use axum::{extract::State, http::HeaderMap};
use serde::Deserialize;
use snafu::{ensure, Snafu};

use crate::{
    application::use_cases::{
        session::SessionIssuer,
        signin::{SignInCommand, SignInError, SignInOutcome, SignInUseCase},
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
        state::{AppState, D1_BINDING},
        utils::{extract::ApiJson, request::client_info},
    },
};

use crate::presentation::utils::validation::is_valid_email;

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
            SignInError::EmailNotVerified => ApiError::Forbidden(err.to_string()),
            SignInError::FindAccount { .. }
            | SignInError::VerifyPassword { .. }
            | SignInError::FindMfaCredential { .. }
            | SignInError::CreateChallenge { .. }
            | SignInError::IssueSession { .. } => {
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
    headers: HeaderMap,
    ApiJson(payload): ApiJson<SignInPayload>,
) -> ApiResult<ApiResponse<Vec<String>, Vec<String>, SignInOutcome>> {
    let command = SignInCommand::try_from(payload).map_err(|err| {
        log_warn!("signin: invalid payload: {err}");
        ApiError::from(err)
    })?;
    let account_repository = state.account_repository().map_err(|err| {
        log_error!("signin: d1 binding `{D1_BINDING}` unavailable: {err}");
        ApiError::InternalServerError("database binding is unavailable".to_owned())
    })?;
    let hash_password_service = state.hash_password_service().map_err(|err| {
        log_error!("signin: password hashing is misconfigured: {err}");
        ApiError::InternalServerError("server is misconfigured".to_owned())
    })?;
    let refresh_token_repository = state.refresh_token_repository().map_err(|err| {
        log_error!("signin: d1 binding `{D1_BINDING}` unavailable for refresh tokens: {err}");
        ApiError::InternalServerError("database binding is unavailable".to_owned())
    })?;
    let token_service = state.token_service().map_err(|err| {
        log_error!("signin: token signing is misconfigured: {err}");
        ApiError::InternalServerError("server is misconfigured".to_owned())
    })?;
    let mfa_repository = state.mfa_repository().map_err(|err| {
        log_error!("signin: mfa storage is misconfigured: {err}");
        ApiError::InternalServerError("server is misconfigured".to_owned())
    })?;
    let case = SignInUseCase::new(
        account_repository,
        hash_password_service,
        mfa_repository,
        state.opaque_token_service(),
        SessionIssuer::new(refresh_token_repository, token_service),
    );
    let outcome = match case.execute(command, &client_info(&headers)).await {
        Ok(outcome) => outcome,
        Err(err) => {
            log_error!("signin: failed: {err}");
            return Err(ApiError::from(err));
        }
    };

    let message = match &outcome {
        SignInOutcome::SignedIn(result) => {
            log_info!("signin: success, account id {}", result.id);
            "signin successful"
        }
        SignInOutcome::MfaRequired(_) => "second factor required",
    };
    Ok(ApiResponse::ok(
        200,
        Vec::new(),
        vec![message.to_owned()],
        outcome,
    ))
}

#[cfg(test)]
mod tests {
    use crate::application::use_cases::signin::SignInResult;

    use super::*;

    fn payload(email: &str, password: &str) -> SignInPayload {
        SignInPayload {
            email: email.to_owned(),
            password: password.to_owned(),
        }
    }

    fn validation_error(payload: SignInPayload) -> SignInValidationError {
        match SignInCommand::try_from(payload) {
            Ok(_) => panic!("payload should be rejected"),
            Err(err) => err,
        }
    }

    #[test]
    fn accepts_valid_payload_and_trims_email() {
        let command = SignInCommand::try_from(payload("  ada@example.com  ", "s3cret-pass"))
            .expect("payload should be accepted");

        assert_eq!(command.email, "ada@example.com");
        assert_eq!(command.password, "s3cret-pass");
    }

    #[test]
    fn keeps_password_whitespace_untouched() {
        let command = SignInCommand::try_from(payload("ada@example.com", "  s3cret  "))
            .expect("payload should be accepted");

        assert_eq!(command.password, "  s3cret  ");
    }

    #[test]
    fn rejects_invalid_emails() {
        for email in [
            "",
            "ada",
            "ada@",
            "@example.com",
            "ada@localhost",
            "ada@@example.com",
        ] {
            assert!(
                matches!(
                    validation_error(payload(email, "s3cret-pass")),
                    SignInValidationError::EmailInvalid
                ),
                "email `{email}` should be rejected"
            );
        }
        assert_eq!(
            validation_error(payload("ada", "s3cret-pass")).to_string(),
            "email is invalid"
        );
    }

    #[test]
    fn rejects_empty_password() {
        assert!(matches!(
            validation_error(payload("ada@example.com", "")),
            SignInValidationError::PasswordEmpty
        ));
        assert_eq!(
            validation_error(payload("ada@example.com", "")).to_string(),
            "password can't be empty"
        );
    }

    #[test]
    fn maps_validation_errors_to_400_bad_request() {
        let cases = [
            (SignInValidationError::EmailInvalid, "email is invalid"),
            (
                SignInValidationError::PasswordEmpty,
                "password can't be empty",
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
    fn maps_invalid_credentials_to_401_unauthorized() {
        let api_error = ApiError::from(SignInError::InvalidCredentials);

        assert!(matches!(api_error, ApiError::Unauthorized(_)));
        assert_eq!(api_error.status(), 401);
        assert_eq!(api_error.message(), "invalid email or password");
    }

    #[test]
    fn maps_unverified_email_to_403_forbidden() {
        let api_error = ApiError::from(SignInError::EmailNotVerified);

        assert!(matches!(api_error, ApiError::Forbidden(_)));
        assert_eq!(api_error.status(), 403);
        assert_eq!(api_error.message(), "email is not verified");
    }

    #[test]
    fn hides_internal_signin_errors_behind_500() {
        let cases = [
            SignInError::FindAccount {
                source: worker::Error::RustError("d1 select failed".to_owned()),
            },
            SignInError::VerifyPassword {
                source: argon2::password_hash::Error::Crypto,
            },
            SignInError::IssueSession {
                source: worker::Error::RustError("signing failed".to_owned()),
            },
            SignInError::FindMfaCredential {
                source: worker::Error::RustError("d1 select failed".to_owned()),
            },
            SignInError::CreateChallenge {
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
    use axum::response::IntoResponse;

    use crate::application::use_cases::signin::SignInResult;

    use super::*;

    fn created_at() -> jiff::Timestamp {
        "2026-01-02T03:04:05Z".parse().expect("valid timestamp")
    }

    fn expires_at(offset_secs: i64) -> jiff::Timestamp {
        created_at()
            .saturating_add(std::time::Duration::from_secs(offset_secs as u64))
            .expect("timestamp")
    }

    fn sign_in_result() -> SignInResult {
        SignInResult {
            id: uuid::Uuid::nil(),
            name: "Ada Lovelace".to_owned(),
            email: "ada@example.com".to_owned(),
            created_at: created_at(),
            tokens: crate::domain::services::token::IssuedTokens {
                token_type: "Bearer".to_owned(),
                access_token: "access.jwt.token".to_owned(),
                refresh_token: "refresh-token".to_owned(),
                access_token_expires_at: expires_at(900),
                refresh_token_expires_at: expires_at(86_400),
            },
        }
    }

    #[test]
    fn success_envelope_matches_api_contract() {
        let response = ApiResponse::ok(
            200,
            Vec::<String>::new(),
            vec!["signin successful".to_owned()],
            sign_in_result(),
        );

        let json = serde_json::to_value(&response).expect("response should serialize");

        assert_eq!(json["success"], serde_json::json!(true));
        assert_eq!(json["errors"], serde_json::json!([]));
        assert_eq!(json["messages"], serde_json::json!(["signin successful"]));
        assert_eq!(
            json["results"]["id"],
            "00000000-0000-0000-0000-000000000000"
        );
        assert_eq!(json["results"]["name"], "Ada Lovelace");
        assert_eq!(json["results"]["email"], "ada@example.com");
        assert_eq!(json["results"]["created_at"], "2026-01-02T03:04:05Z");
        assert_eq!(json["results"]["token_type"], "Bearer");
        assert_eq!(json["results"]["access_token"], "access.jwt.token");
        assert_eq!(json["results"]["refresh_token"], "refresh-token");
        assert!(
            json["results"]["access_token_expires_at"].is_string(),
            "token expiry must be returned so clients can refresh in time"
        );
        assert!(json["results"]["refresh_token_expires_at"].is_string());
        assert!(
            json.get("status").is_none(),
            "the internal status field must not leak into the body"
        );
        assert!(
            json["results"].get("password_hash").is_none(),
            "password hash must never be returned"
        );
    }

    #[test]
    fn success_response_uses_the_given_status_code() {
        let response = ApiResponse::ok(
            200,
            Vec::<String>::new(),
            Vec::<String>::new(),
            sign_in_result(),
        );

        assert_eq!(
            response.into_response().status(),
            axum::http::StatusCode::OK
        );
    }

    #[test]
    fn invalid_credentials_response_uses_401() {
        let response = ApiError::from(SignInError::InvalidCredentials).into_response();

        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn unverified_email_response_uses_403() {
        let response = ApiError::from(SignInError::EmailNotVerified).into_response();

        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
    }
}
