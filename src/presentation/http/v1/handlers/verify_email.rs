use axum::{extract::Query, extract::State};
use serde::Deserialize;
use snafu::{ensure, Snafu};

use crate::{
    application::use_cases::verify_email::{
        VerifyEmailCommand, VerifyEmailError, VerifyEmailResult, VerifyEmailUseCase,
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
        utils::validation::is_valid_opaque_token,
    },
};

#[derive(Debug, Deserialize)]
pub struct VerifyEmailQuery {
    pub token: Option<String>,
}

#[derive(Debug, Snafu)]
pub enum VerifyEmailValidationError {
    #[snafu(display("verification token is invalid"))]
    TokenInvalid,
}

impl From<VerifyEmailValidationError> for ApiError {
    fn from(err: VerifyEmailValidationError) -> Self {
        BadRequest(err.to_string())
    }
}

impl From<VerifyEmailError> for ApiError {
    fn from(err: VerifyEmailError) -> Self {
        match err {
            VerifyEmailError::InvalidToken => ApiError::BadRequest(err.to_string()),
            VerifyEmailError::FindToken { .. }
            | VerifyEmailError::FindAccount { .. }
            | VerifyEmailError::VerifyAccount { .. } => {
                ApiError::InternalServerError("internal server error".to_owned())
            }
        }
    }
}

impl TryFrom<VerifyEmailQuery> for VerifyEmailCommand {
    type Error = VerifyEmailValidationError;

    fn try_from(query: VerifyEmailQuery) -> Result<Self, Self::Error> {
        let token = query.token.unwrap_or_default();
        let token = token.trim();
        ensure!(is_valid_opaque_token(token), TokenInvalidSnafu);

        Ok(VerifyEmailCommand {
            token: token.to_owned(),
        })
    }
}

#[worker::send]
pub async fn verify_email_handler(
    State(state): State<AppState>,
    Query(query): Query<VerifyEmailQuery>,
) -> ApiResult<ApiResponse<Vec<String>, Vec<String>, VerifyEmailResult>> {
    let command = VerifyEmailCommand::try_from(query).map_err(|err| {
        log_warn!("verify_email: invalid token format: {err}");
        ApiError::from(err)
    })?;
    let account_repository = state.account_repository().map_err(|err| {
        log_error!("verify_email: d1 binding `{D1_BINDING}` unavailable: {err}");
        ApiError::InternalServerError("database binding is unavailable".to_owned())
    })?;
    let verification_token_repository = state.verification_token_repository().map_err(|err| {
        log_error!("verify_email: d1 binding `{D1_BINDING}` unavailable for tokens: {err}");
        ApiError::InternalServerError("database binding is unavailable".to_owned())
    })?;
    let verification_token_service = state.verification_token_service();
    let case = VerifyEmailUseCase::new(
        account_repository,
        verification_token_repository,
        verification_token_service,
    );
    let result = match case.execute(command).await {
        Ok(result) => result,
        Err(err) => {
            log_error!("verify_email: failed: {err}");
            return Err(ApiError::from(err));
        }
    };
    log_info!("verify_email: success, account id {}", result.id);
    Ok(ApiResponse::ok(
        200,
        Vec::new(),
        vec!["email verified".to_owned()],
        result,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(token: Option<&str>) -> VerifyEmailQuery {
        VerifyEmailQuery {
            token: token.map(str::to_owned),
        }
    }

    fn validation_error(query: VerifyEmailQuery) -> VerifyEmailValidationError {
        match VerifyEmailCommand::try_from(query) {
            Ok(_) => panic!("query should be rejected"),
            Err(err) => err,
        }
    }

    fn valid_token() -> String {
        "0123456789abcdef".repeat(4)
    }

    #[test]
    fn accepts_a_well_formed_token() {
        let command = VerifyEmailCommand::try_from(query(Some(&valid_token())))
            .expect("query should be accepted");

        assert_eq!(command.token, valid_token());
    }

    #[test]
    fn trims_the_token() {
        let padded = format!("  {}  ", valid_token());
        let command =
            VerifyEmailCommand::try_from(query(Some(&padded))).expect("query should be accepted");

        assert_eq!(command.token, valid_token());
    }

    #[test]
    fn rejects_missing_or_malformed_tokens() {
        for token in [None, Some(""), Some("not-a-token"), Some("abc")] {
            assert!(matches!(
                validation_error(query(token)),
                VerifyEmailValidationError::TokenInvalid
            ));
        }
        assert_eq!(
            validation_error(query(None)).to_string(),
            "verification token is invalid"
        );
    }

    #[test]
    fn maps_validation_errors_to_400_bad_request() {
        let api_error = ApiError::from(VerifyEmailValidationError::TokenInvalid);

        assert!(matches!(api_error, ApiError::BadRequest(_)));
        assert_eq!(api_error.status(), 400);
        assert_eq!(api_error.message(), "verification token is invalid");
    }

    #[test]
    fn maps_invalid_token_to_400_bad_request() {
        let api_error = ApiError::from(VerifyEmailError::InvalidToken);

        assert!(matches!(api_error, ApiError::BadRequest(_)));
        assert_eq!(api_error.status(), 400);
        assert_eq!(
            api_error.message(),
            "verification token is invalid or expired"
        );
    }

    #[test]
    fn hides_internal_errors_behind_500() {
        let cases = [
            VerifyEmailError::FindToken {
                source: worker::Error::RustError("d1 select failed".to_owned()),
            },
            VerifyEmailError::FindAccount {
                source: worker::Error::RustError("d1 select failed".to_owned()),
            },
            VerifyEmailError::VerifyAccount {
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
}

#[cfg(test)]
mod response_tests {
    use axum::response::IntoResponse;

    use super::*;

    #[test]
    fn success_envelope_matches_api_contract() {
        let response = ApiResponse::ok(
            200,
            Vec::<String>::new(),
            vec!["email verified".to_owned()],
            VerifyEmailResult {
                id: uuid::Uuid::nil(),
                email: "ada@example.com".to_owned(),
                is_verified: true,
            },
        );

        let json = serde_json::to_value(&response).expect("response should serialize");

        assert_eq!(json["success"], serde_json::json!(true));
        assert_eq!(json["errors"], serde_json::json!([]));
        assert_eq!(json["messages"], serde_json::json!(["email verified"]));
        assert_eq!(
            json["results"]["id"],
            "00000000-0000-0000-0000-000000000000"
        );
        assert_eq!(json["results"]["email"], "ada@example.com");
        assert_eq!(json["results"]["is_verified"], serde_json::json!(true));
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
            VerifyEmailResult {
                id: uuid::Uuid::nil(),
                email: "ada@example.com".to_owned(),
                is_verified: true,
            },
        );

        assert_eq!(
            response.into_response().status(),
            axum::http::StatusCode::OK
        );
    }
}
