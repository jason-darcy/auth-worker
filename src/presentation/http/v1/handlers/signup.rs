use axum::{
    extract::State,
    http::{HeaderMap, Uri},
    Json,
};
use serde::Deserialize;
use snafu::{ensure, Snafu};

use crate::{
    application::use_cases::signup::{SignUpCommand, SignUpError, SignUpResult, SignUpUseCase},
    logging::{log_error, log_info, log_warn},
    presentation::{
        http::{
            error::{
                ApiError::{self, BadRequest},
                ApiResult,
            },
            response::ApiResponse,
        },
        state::{AppState, D1_BINDING, EMAIL_BINDING},
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
    #[snafu(display("password should be at most 20 characters"))]
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
    headers: HeaderMap,
    uri: Uri,
    Json(payload): Json<SignUpPayload>,
) -> ApiResult<ApiResponse<Vec<String>, Vec<String>, SignUpResult>> {
    let command = SignUpCommand::try_from(payload).map_err(|err| {
        log_warn!("signup: invalid payload: {err}");
        ApiError::from(err)
    })?;
    let account_repository = state.account_repository().map_err(|err| {
        log_error!("signup: d1 binding `{D1_BINDING}` unavailable: {err}");
        ApiError::InternalServerError("database binding is unavailable".to_owned())
    })?;
    let hash_password_service = state.hash_password_service();
    let verification_token_repository = state.verification_token_repository().map_err(|err| {
        log_error!("signup: d1 binding `{D1_BINDING}` unavailable for verification tokens: {err}");
        ApiError::InternalServerError("database binding is unavailable".to_owned())
    })?;
    let verification_token_service = state.verification_token_service();
    let email_service = state.email_service(&uri, &headers).map_err(|err| {
        log_error!("signup: email binding `{EMAIL_BINDING}` unavailable: {err}");
        ApiError::InternalServerError("email binding is unavailable".to_owned())
    })?;
    let case = SignUpUseCase::new(
        account_repository,
        hash_password_service,
        verification_token_repository,
        verification_token_service,
        email_service,
    );
    let result = match case.execute(command).await {
        Ok(result) => result,
        Err(err) => {
            log_error!("signup: failed: {err}");
            return Err(ApiError::from(err));
        }
    };
    log_info!("signup: success, account id {}", result.id);
    Ok(ApiResponse::ok(
        200,
        Vec::new(),
        vec!["signup successful".to_owned()],
        result,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(name: &str, email: &str, password: &str, confirm_password: &str) -> SignUpPayload {
        SignUpPayload {
            name: name.to_owned(),
            email: email.to_owned(),
            password: password.to_owned(),
            confirm_password: confirm_password.to_owned(),
        }
    }

    fn validation_error(payload: SignUpPayload) -> SignUpValidationError {
        match SignUpCommand::try_from(payload) {
            Ok(_) => panic!("payload should be rejected"),
            Err(err) => err,
        }
    }

    #[test]
    fn accepts_valid_payload_and_trims_name_and_email() {
        let command = SignUpCommand::try_from(payload(
            "  Ada Lovelace  ",
            "  ada@example.com  ",
            "s3cret-pass",
            "s3cret-pass",
        ))
        .expect("payload should be accepted");

        assert_eq!(command.name, "Ada Lovelace");
        assert_eq!(command.email, "ada@example.com");
        assert_eq!(command.password, "s3cret-pass");
    }

    #[test]
    fn keeps_password_whitespace_untouched() {
        let command = SignUpCommand::try_from(payload(
            "Ada",
            "ada@example.com",
            "  s3cret  ",
            "  s3cret  ",
        ))
        .expect("payload should be accepted");

        assert_eq!(command.password, "  s3cret  ");
    }

    #[test]
    fn rejects_empty_or_blank_name() {
        assert!(matches!(
            validation_error(payload("", "ada@example.com", "s3cret-pass", "s3cret-pass")),
            SignUpValidationError::NameEmpty
        ));
        assert!(matches!(
            validation_error(payload(
                "   ",
                "ada@example.com",
                "s3cret-pass",
                "s3cret-pass"
            )),
            SignUpValidationError::NameEmpty
        ));
        assert_eq!(
            validation_error(payload("", "ada@example.com", "s3cret-pass", "s3cret-pass"))
                .to_string(),
            "name can't be empty"
        );
    }

    #[test]
    fn accepts_name_shorter_than_20_chars() {
        let name = "a".repeat(19);
        assert!(SignUpCommand::try_from(payload(
            &name,
            "ada@example.com",
            "s3cret-pass",
            "s3cret-pass"
        ))
        .is_ok());
    }

    #[test]
    fn rejects_name_of_20_chars_or_more() {
        let name = "a".repeat(20);
        assert!(matches!(
            validation_error(payload(
                &name,
                "ada@example.com",
                "s3cret-pass",
                "s3cret-pass"
            )),
            SignUpValidationError::NameTooLong
        ));
        assert_eq!(
            validation_error(payload(
                &name,
                "ada@example.com",
                "s3cret-pass",
                "s3cret-pass"
            ))
            .to_string(),
            "name should be less than 20 characters"
        );
    }

    #[test]
    fn rejects_invalid_emails() {
        for email in [
            "",
            "ada",
            "ada@",
            "@example.com",
            "ada@localhost",
            "ada@.com",
            "ada@example.",
            "ada@@example.com",
        ] {
            assert!(
                matches!(
                    validation_error(payload("Ada", email, "s3cret-pass", "s3cret-pass")),
                    SignUpValidationError::EmailInvalid
                ),
                "email `{email}` should be rejected"
            );
        }
        assert_eq!(
            validation_error(payload("Ada", "ada", "s3cret-pass", "s3cret-pass")).to_string(),
            "email is invalid"
        );
    }

    #[test]
    fn accepts_multi_label_domains() {
        assert!(SignUpCommand::try_from(payload(
            "Ada",
            "ada@mail.example.co.uk",
            "s3cret-pass",
            "s3cret-pass"
        ))
        .is_ok());
    }

    #[test]
    fn rejects_password_shorter_than_8_chars() {
        let password = "a".repeat(7);
        assert!(matches!(
            validation_error(payload("Ada", "ada@example.com", &password, &password)),
            SignUpValidationError::PasswordTooShort
        ));
        assert_eq!(
            validation_error(payload("Ada", "ada@example.com", &password, &password)).to_string(),
            "password should be at least 8 characters"
        );
    }

    #[test]
    fn accepts_password_between_8_and_20_chars() {
        for length in [8, 12, 20] {
            let password = "a".repeat(length);
            assert!(
                SignUpCommand::try_from(payload("Ada", "ada@example.com", &password, &password))
                    .is_ok(),
                "password of length {length} should be accepted"
            );
        }
    }

    #[test]
    fn rejects_password_longer_than_20_chars() {
        let password = "a".repeat(21);
        assert!(matches!(
            validation_error(payload("Ada", "ada@example.com", &password, &password)),
            SignUpValidationError::PasswordTooLong
        ));
        assert_eq!(
            validation_error(payload("Ada", "ada@example.com", &password, &password)).to_string(),
            "password should be at most 20 characters"
        );
    }

    #[test]
    fn rejects_mismatched_password_confirmation() {
        assert!(matches!(
            validation_error(payload(
                "Ada",
                "ada@example.com",
                "s3cret-pass",
                "s3cret-pass2"
            )),
            SignUpValidationError::PasswordMismatch
        ));
        assert_eq!(
            validation_error(payload(
                "Ada",
                "ada@example.com",
                "s3cret-pass",
                "s3cret-pass2"
            ))
            .to_string(),
            "passwords do not match"
        );
    }

    #[test]
    fn reports_first_failing_rule() {
        // 空 name 优先于其它非法字段被报出
        let error = validation_error(payload("", "ada", "short", "other"));
        assert!(matches!(error, SignUpValidationError::NameEmpty));
    }

    #[test]
    fn maps_validation_errors_to_400_bad_request() {
        let cases = [
            (SignUpValidationError::NameEmpty, "name can't be empty"),
            (
                SignUpValidationError::NameTooLong,
                "name should be less than 20 characters",
            ),
            (SignUpValidationError::EmailInvalid, "email is invalid"),
            (
                SignUpValidationError::PasswordTooShort,
                "password should be at least 8 characters",
            ),
            (
                SignUpValidationError::PasswordTooLong,
                "password should be at most 20 characters",
            ),
            (
                SignUpValidationError::PasswordMismatch,
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
    fn maps_duplicate_email_to_409_conflict() {
        let api_error = ApiError::from(SignUpError::EmailAlreadyExists);

        assert!(matches!(api_error, ApiError::Conflict(_)));
        assert_eq!(api_error.status(), 409);
        assert_eq!(api_error.message(), "email already exists");
    }

    #[test]
    fn hides_internal_signup_errors_behind_500() {
        let cases = [
            SignUpError::FindAccount {
                source: worker::Error::RustError("d1 select failed".to_owned()),
            },
            SignUpError::HashPassword {
                source: argon2::password_hash::Error::Crypto,
            },
            SignUpError::CreateAccount {
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

    use super::*;

    fn created_at() -> jiff::Timestamp {
        "2026-01-02T03:04:05Z".parse().expect("valid timestamp")
    }

    fn sign_up_result() -> SignUpResult {
        SignUpResult {
            id: uuid::Uuid::nil(),
            name: "Ada Lovelace".to_owned(),
            email: "ada@example.com".to_owned(),
            created_at: created_at(),
        }
    }

    #[test]
    fn success_envelope_matches_api_contract() {
        let response = ApiResponse::ok(
            200,
            Vec::<String>::new(),
            vec!["signup successful".to_owned()],
            sign_up_result(),
        );

        let json = serde_json::to_value(&response).expect("response should serialize");

        assert_eq!(json["success"], serde_json::json!(true));
        assert_eq!(json["errors"], serde_json::json!([]));
        assert_eq!(json["messages"], serde_json::json!(["signup successful"]));
        assert_eq!(
            json["results"]["id"],
            "00000000-0000-0000-0000-000000000000"
        );
        assert_eq!(json["results"]["name"], "Ada Lovelace");
        assert_eq!(json["results"]["email"], "ada@example.com");
        // `SignUpResult` serializes `jiff::Timestamp` as an RFC 3339 string.
        assert_eq!(json["results"]["created_at"], "2026-01-02T03:04:05Z");
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
            sign_up_result(),
        );

        assert_eq!(
            response.into_response().status(),
            axum::http::StatusCode::OK
        );
    }

    #[test]
    fn error_envelope_matches_api_contract() {
        let error = ApiError::from(SignUpError::EmailAlreadyExists);
        let body: ApiResponse<(), Vec<String>, Vec<String>> = ApiResponse::err(
            error.status(),
            (),
            vec![error.message().to_owned()],
            Vec::new(),
        );

        let json = serde_json::to_value(&body).expect("response should serialize");

        assert_eq!(json["success"], serde_json::json!(false));
        assert_eq!(
            json["messages"],
            serde_json::json!(["email already exists"])
        );
        assert!(json["results"].is_null() || json["results"] == serde_json::json!([]));
    }

    #[test]
    fn error_response_uses_the_error_status_code() {
        let conflict = ApiError::from(SignUpError::EmailAlreadyExists).into_response();
        assert_eq!(conflict.status(), axum::http::StatusCode::CONFLICT);

        let invalid = ApiError::from(SignUpValidationError::EmailInvalid).into_response();
        assert_eq!(invalid.status(), axum::http::StatusCode::BAD_REQUEST);
    }
}
