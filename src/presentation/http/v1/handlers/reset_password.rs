use axum::{extract::State, response::Response};
use serde::Deserialize;
use snafu::{ensure, Snafu};

use crate::{
    application::use_cases::reset_password::{
        ResetPasswordCommand, ResetPasswordError, ResetPasswordResult, ResetPasswordUseCase,
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
        utils::{
            extract::{ApiJson, ApiQuery},
            html::{document, html_page},
            validation::{is_valid_opaque_token, PASSWORD_MAX_LEN, PASSWORD_MIN_LEN},
        },
    },
};

pub const RESET_PASSWORD_FORM_PATH: &str = "/api/v1/reset-password";

#[derive(Debug, Deserialize)]
pub struct ResetPasswordPayload {
    pub token: String,
    pub password: String,
    pub confirm_password: String,
}

#[derive(Debug, Deserialize)]
pub struct ResetPasswordQuery {
    pub token: Option<String>,
}

#[derive(Debug, Snafu)]
pub enum ResetPasswordValidationError {
    #[snafu(display("password reset token is invalid"))]
    TokenInvalid,
    #[snafu(display("password should be at least 8 characters"))]
    PasswordTooShort,
    #[snafu(display("password should be at most 64 characters"))]
    PasswordTooLong,
    #[snafu(display("passwords do not match"))]
    PasswordMismatch,
}

impl From<ResetPasswordValidationError> for ApiError {
    fn from(err: ResetPasswordValidationError) -> Self {
        BadRequest(err.to_string())
    }
}

impl From<ResetPasswordError> for ApiError {
    fn from(err: ResetPasswordError) -> Self {
        match err {
            ResetPasswordError::InvalidToken => BadRequest(err.to_string()),
            ResetPasswordError::FindToken { .. }
            | ResetPasswordError::FindAccount { .. }
            | ResetPasswordError::HashPassword { .. }
            | ResetPasswordError::UpdateAccount { .. } => {
                ApiError::InternalServerError("internal server error".to_owned())
            }
        }
    }
}

impl TryFrom<ResetPasswordPayload> for ResetPasswordCommand {
    type Error = ResetPasswordValidationError;

    fn try_from(payload: ResetPasswordPayload) -> Result<Self, Self::Error> {
        let token = payload.token.trim();
        ensure!(is_valid_opaque_token(token), TokenInvalidSnafu);
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

        Ok(ResetPasswordCommand {
            token: token.to_owned(),
            password: payload.password,
        })
    }
}

/// `POST /reset-password` — the API used by clients (and by the form page).
#[worker::send]
pub async fn reset_password_handler(
    State(state): State<AppState>,
    ApiJson(payload): ApiJson<ResetPasswordPayload>,
) -> ApiResult<ApiResponse<Vec<String>, Vec<String>, ResetPasswordResult>> {
    let command = ResetPasswordCommand::try_from(payload).map_err(|err| {
        log_warn!("reset_password: invalid payload: {err}");
        ApiError::from(err)
    })?;
    let account_repository = state.account_repository().map_err(|err| {
        log_error!("reset_password: d1 binding `{D1_BINDING}` unavailable: {err}");
        ApiError::InternalServerError("database binding is unavailable".to_owned())
    })?;
    let password_reset_token_repository =
        state.password_reset_token_repository().map_err(|err| {
            log_error!("reset_password: d1 binding `{D1_BINDING}` unavailable for tokens: {err}");
            ApiError::InternalServerError("database binding is unavailable".to_owned())
        })?;
    let refresh_token_repository = state.refresh_token_repository().map_err(|err| {
        log_error!("reset_password: d1 binding `{D1_BINDING}` unavailable for sessions: {err}");
        ApiError::InternalServerError("database binding is unavailable".to_owned())
    })?;
    let hash_password_service = state.hash_password_service().map_err(|err| {
        log_error!("reset_password: password hashing is misconfigured: {err}");
        ApiError::InternalServerError("server is misconfigured".to_owned())
    })?;
    let case = ResetPasswordUseCase::new(
        account_repository,
        password_reset_token_repository,
        refresh_token_repository,
        hash_password_service,
        state.verification_token_service(),
    );
    let result = match case.execute(command).await {
        Ok(result) => result,
        Err(err) => {
            log_error!("reset_password: failed: {err}");
            return Err(ApiError::from(err));
        }
    };
    log_info!("reset_password: success, account id {}", result.id);
    Ok(ApiResponse::ok(
        200,
        Vec::new(),
        vec!["password has been reset".to_owned()],
        result,
    ))
}

/// `GET /reset-password?token=...` — the page the emailed link opens.
///
/// It is a tiny form that posts JSON to the API, so the flow works without a
/// separate frontend. Replace it with your own page when you have one.
#[worker::send]
pub async fn reset_password_form_handler(
    ApiQuery(query): ApiQuery<ResetPasswordQuery>,
) -> Response {
    let token = query.token.unwrap_or_default();
    html_page(render_form(token.trim()))
}

/// Renders the reset form. Only well-formed tokens are embedded, so nothing
/// user supplied can be reflected into the page.
pub fn render_form(token: &str) -> String {
    let token_is_valid = is_valid_opaque_token(token);
    let body = if token_is_valid {
        format!(
            r#"<p>Choose a new password for your account.</p>
<form id="reset">
  <label>New password <input type="password" id="password" minlength="8" maxlength="64" required></label>
  <label>Confirm password <input type="password" id="confirm_password" minlength="8" maxlength="64" required></label>
  <button type="submit">Reset password</button>
</form>
<p id="status" role="status"></p>
<script>
const token = "{token}";
document.getElementById("reset").addEventListener("submit", async (event) => {{
  event.preventDefault();
  const status = document.getElementById("status");
  const response = await fetch("{path}", {{
    method: "POST",
    headers: {{ "content-type": "application/json" }},
    body: JSON.stringify({{
      token,
      password: document.getElementById("password").value,
      confirm_password: document.getElementById("confirm_password").value,
    }}),
  }});
  const body = await response.json();
  status.textContent = response.ok
    ? "Your password has been reset. You can sign in again."
    : (body.messages || []).join(" ");
}});
</script>"#,
            token = token,
            path = RESET_PASSWORD_FORM_PATH
        )
    } else {
        "<p>This password reset link is invalid or expired. Please request a new one.</p>"
            .to_owned()
    };

    document("Reset password", &body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(token: &str, password: &str, confirm_password: &str) -> ResetPasswordPayload {
        ResetPasswordPayload {
            token: token.to_owned(),
            password: password.to_owned(),
            confirm_password: confirm_password.to_owned(),
        }
    }

    fn valid_token() -> String {
        "0123456789abcdef".repeat(4)
    }

    fn validation_error(payload: ResetPasswordPayload) -> ResetPasswordValidationError {
        match ResetPasswordCommand::try_from(payload) {
            Ok(_) => panic!("payload should be rejected"),
            Err(err) => err,
        }
    }

    #[test]
    fn accepts_valid_payload_and_trims_the_token() {
        let token = format!("  {}  ", valid_token());
        let command = ResetPasswordCommand::try_from(payload(&token, "new-s3cret", "new-s3cret"))
            .expect("payload should be accepted");

        assert_eq!(command.token, valid_token());
        assert_eq!(command.password, "new-s3cret");
    }

    #[test]
    fn rejects_malformed_tokens() {
        for token in ["", "not-a-token", "abc"] {
            assert!(matches!(
                validation_error(payload(token, "new-s3cret", "new-s3cret")),
                ResetPasswordValidationError::TokenInvalid
            ));
        }
    }

    #[test]
    fn enforces_password_length() {
        assert!(matches!(
            validation_error(payload(&valid_token(), "short", "short")),
            ResetPasswordValidationError::PasswordTooShort
        ));
        let too_long = "a".repeat(PASSWORD_MAX_LEN + 1);
        assert!(matches!(
            validation_error(payload(&valid_token(), &too_long, &too_long)),
            ResetPasswordValidationError::PasswordTooLong
        ));
        let at_max = "a".repeat(PASSWORD_MAX_LEN);
        assert!(ResetPasswordCommand::try_from(payload(&valid_token(), &at_max, &at_max)).is_ok());
    }

    #[test]
    fn rejects_mismatched_confirmation() {
        let error = validation_error(payload(&valid_token(), "new-s3cret", "new-s3cret2"));

        assert!(matches!(
            error,
            ResetPasswordValidationError::PasswordMismatch
        ));
        assert_eq!(error.to_string(), "passwords do not match");
    }

    #[test]
    fn maps_validation_errors_to_400_bad_request() {
        let cases = [
            (
                ResetPasswordValidationError::TokenInvalid,
                "password reset token is invalid",
            ),
            (
                ResetPasswordValidationError::PasswordTooShort,
                "password should be at least 8 characters",
            ),
            (
                ResetPasswordValidationError::PasswordTooLong,
                "password should be at most 64 characters",
            ),
            (
                ResetPasswordValidationError::PasswordMismatch,
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
    fn maps_invalid_token_to_400_bad_request() {
        let api_error = ApiError::from(ResetPasswordError::InvalidToken);

        assert!(matches!(api_error, ApiError::BadRequest(_)));
        assert_eq!(api_error.status(), 400);
        assert_eq!(
            api_error.message(),
            "password reset token is invalid or expired"
        );
    }

    #[test]
    fn hides_internal_errors_behind_500() {
        let cases = [
            ResetPasswordError::FindToken {
                source: worker::Error::RustError("d1 select failed".to_owned()),
            },
            ResetPasswordError::FindAccount {
                source: worker::Error::RustError("d1 select failed".to_owned()),
            },
            ResetPasswordError::HashPassword {
                source: argon2::password_hash::Error::Crypto,
            },
            ResetPasswordError::UpdateAccount {
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
    fn form_page_embeds_valid_tokens() {
        let token = valid_token();
        let html = render_form(&token);

        assert!(html.contains(&token));
        assert!(html.contains(RESET_PASSWORD_FORM_PATH));
        assert!(html.contains("type=\"password\""));
    }

    #[test]
    fn form_page_does_not_reflect_invalid_tokens() {
        for token in ["", "<script>alert(1)</script>", "abc"] {
            let html = render_form(token);

            assert!(!html.contains("<script>alert(1)</script>"));
            assert!(html.contains("invalid or expired"));
            assert!(!html.contains("Confirm password"));
        }
    }
}

#[cfg(test)]
mod response_tests {
    use super::*;

    #[test]
    fn success_envelope_matches_api_contract() {
        let response = ApiResponse::ok(
            200,
            Vec::<String>::new(),
            vec!["password has been reset".to_owned()],
            ResetPasswordResult {
                id: uuid::Uuid::nil(),
                email: "ada@example.com".to_owned(),
                is_verified: true,
            },
        );

        let json = serde_json::to_value(&response).expect("response should serialize");

        assert_eq!(json["success"], serde_json::json!(true));
        assert_eq!(
            json["messages"],
            serde_json::json!(["password has been reset"])
        );
        assert_eq!(json["results"]["email"], "ada@example.com");
        assert_eq!(json["results"]["is_verified"], serde_json::json!(true));
        assert!(json["results"].get("password_hash").is_none());
        assert!(json["results"].get("password").is_none());
    }
}
