use axum::{
    extract::State,
    http::{HeaderMap, Uri},
};
use serde::Deserialize;
use snafu::{ensure, Snafu};

use crate::{
    application::use_cases::resend_verification::{
        ResendVerificationCommand, ResendVerificationError, ResendVerificationUseCase,
    },
    logging::{log_error, log_warn},
    presentation::{
        http::{
            error::{
                ApiError::{self, BadRequest},
                ApiResult,
            },
            openapi::{EmptyResult, Envelope},
            response::ApiResponse,
        },
        state::{AppState, D1_BINDING, EMAIL_BINDING},
        utils::{extract::ApiJson, validation::is_valid_email},
    },
};

/// Always returned, whether the email exists, is already verified or unknown.
pub const RESEND_VERIFICATION_MESSAGE: &str =
    "if the email is registered and unverified, a new verification link has been sent";

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct ResendVerificationPayload {
    pub email: String,
}

#[derive(Debug, Snafu)]
pub enum ResendVerificationValidationError {
    #[snafu(display("email is invalid"))]
    EmailInvalid,
}

impl From<ResendVerificationValidationError> for ApiError {
    fn from(err: ResendVerificationValidationError) -> Self {
        BadRequest(err.to_string())
    }
}

impl From<ResendVerificationError> for ApiError {
    fn from(_err: ResendVerificationError) -> Self {
        // The only variant is a storage failure, which is not actionable for
        // the client and must not reveal anything about the account.
        ApiError::InternalServerError("internal server error".to_owned())
    }
}

impl TryFrom<ResendVerificationPayload> for ResendVerificationCommand {
    type Error = ResendVerificationValidationError;

    fn try_from(payload: ResendVerificationPayload) -> Result<Self, Self::Error> {
        let email = payload.email.trim();
        ensure!(is_valid_email(email), EmailInvalidSnafu);

        Ok(ResendVerificationCommand {
            email: email.to_owned(),
        })
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/resend-verification",
    tag = "email",
    summary = "Email a new verification link",
    description = "The response is identical for unknown and already verified emails. At most \
                   one email per account per minute.",
    request_body = ResendVerificationPayload,
    responses(
        (status = 200, description = "Link sent when the account exists and is unverified", body = Envelope<EmptyResult>),
        (status = 400, description = "Invalid payload", body = Envelope<Vec<String>>),
        (status = 429, description = "Rate limit exceeded", body = Envelope<Vec<String>>)
    )
)]
#[worker::send]
pub async fn resend_verification_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
    ApiJson(payload): ApiJson<ResendVerificationPayload>,
) -> ApiResult<ApiResponse<Vec<String>, Vec<String>, ()>> {
    let command = ResendVerificationCommand::try_from(payload).map_err(|err| {
        log_warn!("resend_verification: invalid payload: {err}");
        ApiError::from(err)
    })?;
    let account_repository = state.account_repository().map_err(|err| {
        log_error!("resend_verification: d1 binding `{D1_BINDING}` unavailable: {err}");
        ApiError::InternalServerError("database binding is unavailable".to_owned())
    })?;
    let verification_token_repository = state.verification_token_repository().map_err(|err| {
        log_error!("resend_verification: d1 binding `{D1_BINDING}` unavailable for tokens: {err}");
        ApiError::InternalServerError("database binding is unavailable".to_owned())
    })?;
    let email_service = state.email_service(&uri, &headers).map_err(|err| {
        log_error!("resend_verification: email binding `{EMAIL_BINDING}` unavailable: {err}");
        ApiError::InternalServerError("email binding is unavailable".to_owned())
    })?;
    let case = ResendVerificationUseCase::new(
        account_repository,
        verification_token_repository,
        state.verification_token_service(),
        email_service,
    );
    if let Err(err) = case.execute(command).await {
        log_error!("resend_verification: failed: {err}");
        return Err(ApiError::from(err));
    }
    Ok(ApiResponse::ok(
        200,
        Vec::new(),
        vec![RESEND_VERIFICATION_MESSAGE.to_owned()],
        (),
    ))
}

#[cfg(test)]
mod tests {
    use axum::response::IntoResponse;

    use super::*;

    fn payload(email: &str) -> ResendVerificationPayload {
        ResendVerificationPayload {
            email: email.to_owned(),
        }
    }

    fn validation_error(payload: ResendVerificationPayload) -> ResendVerificationValidationError {
        match ResendVerificationCommand::try_from(payload) {
            Ok(_) => panic!("payload should be rejected"),
            Err(err) => err,
        }
    }

    #[test]
    fn accepts_valid_emails_and_trims_them() {
        let command = ResendVerificationCommand::try_from(payload("  ada@example.com  "))
            .expect("payload should be accepted");

        assert_eq!(command.email, "ada@example.com");
    }

    #[test]
    fn rejects_invalid_emails() {
        for email in ["", "ada", "ada@", "@example.com", "ada@localhost"] {
            assert!(matches!(
                validation_error(payload(email)),
                ResendVerificationValidationError::EmailInvalid
            ));
        }
        assert_eq!(
            validation_error(payload("ada")).to_string(),
            "email is invalid"
        );
    }

    #[test]
    fn maps_validation_errors_to_400_bad_request() {
        let api_error = ApiError::from(ResendVerificationValidationError::EmailInvalid);

        assert!(matches!(api_error, ApiError::BadRequest(_)));
        assert_eq!(api_error.status(), 400);
        assert_eq!(api_error.message(), "email is invalid");
    }

    #[test]
    fn hides_storage_failures_behind_500() {
        let api_error = ApiError::from(ResendVerificationError::FindAccount {
            source: worker::Error::RustError("d1 select failed".to_owned()),
        });

        assert!(matches!(api_error, ApiError::InternalServerError(_)));
        assert_eq!(api_error.status(), 500);
        assert_eq!(api_error.message(), "internal server error");
    }

    #[test]
    fn success_envelope_matches_the_api_contract() {
        let response = ApiResponse::ok(
            200,
            Vec::<String>::new(),
            vec![RESEND_VERIFICATION_MESSAGE.to_owned()],
            (),
        );

        let json = serde_json::to_value(&response).expect("response should serialize");

        assert_eq!(json["success"], serde_json::json!(true));
        assert_eq!(json["errors"], serde_json::json!([]));
        assert_eq!(
            json["messages"],
            serde_json::json!([RESEND_VERIFICATION_MESSAGE])
        );
        assert!(
            !json["messages"]
                .as_array()
                .expect("messages")
                .iter()
                .any(|message| message.as_str().unwrap_or_default().contains("registered,")),
            "the message must not state whether the account exists"
        );
    }

    #[test]
    fn responses_use_the_given_status_code() {
        let ok = ApiResponse::ok(200, Vec::<String>::new(), Vec::<String>::new(), ());
        assert_eq!(ok.into_response().status(), axum::http::StatusCode::OK);
    }
}
