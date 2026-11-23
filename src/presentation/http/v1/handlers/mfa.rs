use axum::extract::{Extension, State};
use serde::Deserialize;
use snafu::{ensure, Snafu};

use crate::{
    application::use_cases::{
        mfa::{
            MfaConfirmResult, MfaConfirmUseCase, MfaDisableCommand, MfaDisableUseCase, MfaError,
            MfaRecoveryCodesCommand, MfaRecoveryCodesUseCase, MfaSetupResult, MfaSetupUseCase,
            MfaStatusResult, MfaStatusUseCase, MfaVerifyCommand, MfaVerifyUseCase,
        },
        second_factor::{SecondFactorError, SecondFactorVerifier},
        session::SessionIssuer,
        signin::SignInResult,
    },
    domain::mfa::RECOVERY_CODE_LEN,
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
        state::{AppState, D1_BINDING, DOMAIN_VAR},
        utils::{extract::ApiJson, request::client_info, validation::is_valid_opaque_token},
    },
};

pub const MFA_DISABLED_MESSAGE: &str = "multi-factor authentication disabled";
pub const MFA_VERIFY_MESSAGE: &str = "signin successful";
/// Used when no domain is configured, so the authenticator app still shows
/// something meaningful.
pub const DEFAULT_ISSUER: &str = "auth-worker";

impl From<MfaError> for ApiError {
    fn from(err: MfaError) -> Self {
        match err {
            MfaError::AlreadyEnabled => ApiError::Conflict(err.to_string()),
            MfaError::NotEnabled | MfaError::NotStarted | MfaError::InvalidPassword => {
                BadRequest(err.to_string())
            }
            MfaError::InvalidCode | MfaError::InvalidChallenge | MfaError::AccountNotFound => {
                ApiError::Unauthorized(err.to_string())
            }
            MfaError::FindAccount { .. }
            | MfaError::VerifyPassword { .. }
            | MfaError::FindCredential { .. }
            | MfaError::SaveCredential { .. }
            | MfaError::DeleteCredential { .. }
            | MfaError::StoreRecoveryCodes { .. }
            | MfaError::ConsumeRecoveryCode { .. }
            | MfaError::CountRecoveryCodes { .. }
            | MfaError::CreateChallenge { .. }
            | MfaError::FindChallenge { .. }
            | MfaError::RecordAttempt { .. }
            | MfaError::DeleteChallenge { .. }
            | MfaError::GenerateSecret { .. }
            | MfaError::VerifyCode { .. }
            | MfaError::GenerateRecoveryCodes { .. }
            | MfaError::IssueSession { .. } => {
                ApiError::InternalServerError("internal server error".to_owned())
            }
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct MfaCodePayload {
    pub code: String,
}

#[derive(Debug, Snafu)]
pub enum MfaValidationError {
    #[snafu(display("the verification code is invalid"))]
    CodeInvalid,
    #[snafu(display("password can't be empty"))]
    PasswordEmpty,
    #[snafu(display("the sign-in challenge is invalid"))]
    ChallengeInvalid,
}

impl From<MfaValidationError> for ApiError {
    fn from(err: MfaValidationError) -> Self {
        BadRequest(err.to_string())
    }
}

#[derive(Debug, Deserialize)]
pub struct MfaPasswordCodePayload {
    pub password: String,
    pub code: String,
}

#[derive(Debug, Deserialize)]
pub struct MfaVerifyPayload {
    pub challenge_token: String,
    pub code: String,
}

/// A code is either 6 digits (TOTP) or a recovery code of exactly
/// [`RECOVERY_CODE_LEN`] symbols, typed with or without separators. Anything
/// else is a typo and does not deserve a database round trip.
pub fn validate_code(code: &str) -> Result<String, MfaValidationError> {
    let code = code.trim();
    let is_totp = code.len() == 6 && code.bytes().all(|byte| byte.is_ascii_digit());
    let normalized: String = code
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    let is_recovery = normalized.len() == RECOVERY_CODE_LEN;
    ensure!(is_totp || is_recovery, CodeInvalidSnafu);
    Ok(code.to_owned())
}

impl MfaPasswordCodePayload {
    fn into_command(self, account_id: uuid::Uuid) -> Result<MfaDisableCommand, MfaValidationError> {
        ensure!(!self.password.is_empty(), PasswordEmptySnafu);
        Ok(MfaDisableCommand {
            account_id,
            password: self.password,
            code: validate_code(&self.code)?,
        })
    }
}

impl MfaVerifyPayload {
    fn into_command(self) -> Result<MfaVerifyCommand, MfaValidationError> {
        let challenge_token = self.challenge_token.trim();
        ensure!(
            is_valid_opaque_token(challenge_token),
            ChallengeInvalidSnafu
        );
        Ok(MfaVerifyCommand {
            challenge_token: challenge_token.to_owned(),
            code: validate_code(&self.code)?,
        })
    }
}

fn mfa_repository(
    state: &AppState,
) -> ApiResult<std::sync::Arc<dyn crate::domain::repositories::mfa::MfaRepository>> {
    state.mfa_repository().map_err(|err| {
        log_error!("mfa: storage is misconfigured: {err}");
        ApiError::InternalServerError("server is misconfigured".to_owned())
    })
}

/// Maps a failed step-up check.
///
/// A missing code is a 403 ("you must prove the second factor"), a wrong one is
/// a 401; both tell the client to restart the sensitive operation.
pub fn second_factor_error(error: SecondFactorError) -> ApiError {
    match error {
        SecondFactorError::CodeRequired => ApiError::Forbidden(error.to_string()),
        SecondFactorError::InvalidCode => ApiError::Unauthorized(error.to_string()),
        SecondFactorError::FindCredential { .. }
        | SecondFactorError::VerifyCode { .. }
        | SecondFactorError::SaveCredential { .. }
        | SecondFactorError::ConsumeRecoveryCode { .. } => {
            ApiError::InternalServerError("internal server error".to_owned())
        }
    }
}

/// Builds the shared second-factor verifier.
pub fn second_factor(state: &AppState) -> ApiResult<SecondFactorVerifier> {
    Ok(SecondFactorVerifier::new(
        mfa_repository(state)?,
        state.totp_service(),
        state.recovery_code_service(),
    ))
}

fn refresh_token_repository(
    state: &AppState,
) -> ApiResult<std::sync::Arc<dyn crate::domain::repositories::refresh_token::RefreshTokenRepository>>
{
    state.refresh_token_repository().map_err(|err| {
        log_error!("mfa: d1 binding `{D1_BINDING}` unavailable: {err}");
        ApiError::InternalServerError("database binding is unavailable".to_owned())
    })
}

fn issuer(state: &AppState) -> String {
    state
        .env
        .var(DOMAIN_VAR)
        .map(|value| value.to_string())
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DEFAULT_ISSUER.to_owned())
}

/// `GET /mfa` — whether MFA is enabled and how many recovery codes are left.
#[worker::send]
pub async fn mfa_status_handler(
    State(state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedAccount>,
) -> ApiResult<ApiResponse<Vec<String>, Vec<String>, MfaStatusResult>> {
    let case = MfaStatusUseCase::new(mfa_repository(&state)?);
    let result = case
        .execute(&authenticated.id.to_string())
        .await
        .map_err(|err| {
            log_error!("mfa status: failed: {err}");
            ApiError::from(err)
        })?;

    Ok(ApiResponse::ok(200, Vec::new(), Vec::new(), result))
}

/// `POST /mfa/totp/setup` — starts an enrolment and returns the secret.
#[worker::send]
pub async fn mfa_setup_handler(
    State(state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedAccount>,
) -> ApiResult<ApiResponse<Vec<String>, Vec<String>, MfaSetupResult>> {
    let case = MfaSetupUseCase::new(
        mfa_repository(&state)?,
        state.totp_service(),
        &issuer(&state),
    );
    let result = case
        .execute(&authenticated.id.to_string(), &authenticated.email)
        .await
        .map_err(|err| {
            log_error!("mfa setup: failed: {err}");
            ApiError::from(err)
        })?;

    Ok(ApiResponse::ok(
        200,
        Vec::new(),
        vec!["scan the secret with your authenticator app, then confirm a code".to_owned()],
        result,
    ))
}

/// `POST /mfa/totp/confirm` — activates the enrolment, returns recovery codes.
#[worker::send]
pub async fn mfa_confirm_handler(
    State(state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedAccount>,
    ApiJson(payload): ApiJson<MfaCodePayload>,
) -> ApiResult<ApiResponse<Vec<String>, Vec<String>, MfaConfirmResult>> {
    let code = validate_code(&payload.code).map_err(|err| {
        log_warn!("mfa confirm: invalid payload: {err}");
        ApiError::from(err)
    })?;
    let case = MfaConfirmUseCase::new(
        mfa_repository(&state)?,
        state.totp_service(),
        state.recovery_code_service(),
    );
    let result = case
        .execute(&authenticated.id.to_string(), &code)
        .await
        .map_err(|err| {
            log_error!("mfa confirm: failed: {err}");
            ApiError::from(err)
        })?;

    Ok(ApiResponse::ok(
        200,
        Vec::new(),
        vec!["multi-factor authentication enabled, store the recovery codes".to_owned()],
        result,
    ))
}

/// `POST /mfa/disable` — requires the password and a valid second factor.
#[worker::send]
pub async fn mfa_disable_handler(
    State(state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedAccount>,
    ApiJson(payload): ApiJson<MfaPasswordCodePayload>,
) -> ApiResult<ApiResponse<Vec<String>, Vec<String>, ()>> {
    let command = payload.into_command(authenticated.id).map_err(|err| {
        log_warn!("mfa disable: invalid payload: {err}");
        ApiError::from(err)
    })?;
    let account_repository = state.account_repository().map_err(|err| {
        log_error!("mfa disable: d1 binding `{D1_BINDING}` unavailable: {err}");
        ApiError::InternalServerError("database binding is unavailable".to_owned())
    })?;
    let hash_password_service = state.hash_password_service().map_err(|err| {
        log_error!("mfa disable: password hashing is misconfigured: {err}");
        ApiError::InternalServerError("server is misconfigured".to_owned())
    })?;
    let case = MfaDisableUseCase {
        mfa_repository: mfa_repository(&state)?,
        account_repository,
        hash_password_service,
        second_factor: second_factor(&state)?,
    };
    case.execute(command).await.map_err(|err| {
        log_error!("mfa disable: failed: {err}");
        ApiError::from(err)
    })?;

    log_info!("mfa disable: account {} disabled mfa", authenticated.id);
    Ok(ApiResponse::ok(
        200,
        Vec::new(),
        vec![MFA_DISABLED_MESSAGE.to_owned()],
        (),
    ))
}

/// `POST /mfa/recovery-codes` — reissues the recovery codes.
#[worker::send]
pub async fn mfa_recovery_codes_handler(
    State(state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedAccount>,
    ApiJson(payload): ApiJson<MfaPasswordCodePayload>,
) -> ApiResult<ApiResponse<Vec<String>, Vec<String>, MfaConfirmResult>> {
    let command = MfaRecoveryCodesCommand {
        account_id: authenticated.id,
        password: payload.password,
        code: validate_code(&payload.code).map_err(|err| {
            log_warn!("mfa recovery codes: invalid payload: {err}");
            ApiError::from(err)
        })?,
    };
    if command.password.is_empty() {
        return Err(ApiError::BadRequest("password can't be empty".to_owned()));
    }

    let account_repository = state.account_repository().map_err(|err| {
        log_error!("mfa recovery codes: d1 binding `{D1_BINDING}` unavailable: {err}");
        ApiError::InternalServerError("database binding is unavailable".to_owned())
    })?;
    let hash_password_service = state.hash_password_service().map_err(|err| {
        log_error!("mfa recovery codes: password hashing is misconfigured: {err}");
        ApiError::InternalServerError("server is misconfigured".to_owned())
    })?;
    let case = MfaRecoveryCodesUseCase {
        account_repository,
        hash_password_service,
        second_factor: second_factor(&state)?,
        recovery_code_service: state.recovery_code_service(),
    };
    let result = case.execute(command).await.map_err(|err| {
        log_error!("mfa recovery codes: failed: {err}");
        ApiError::from(err)
    })?;

    log_info!(
        "mfa recovery codes: reissued for account {}",
        authenticated.id
    );
    Ok(ApiResponse::ok(
        200,
        Vec::new(),
        vec!["recovery codes reissued, store them now".to_owned()],
        result,
    ))
}

/// `POST /mfa/verify` — exchanges the sign-in challenge and a code for tokens.
#[worker::send]
pub async fn mfa_verify_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    ApiJson(payload): ApiJson<MfaVerifyPayload>,
) -> ApiResult<ApiResponse<Vec<String>, Vec<String>, SignInResult>> {
    let command = payload.into_command().map_err(|err| {
        log_warn!("mfa verify: invalid payload: {err}");
        ApiError::from(err)
    })?;
    let account_repository = state.account_repository().map_err(|err| {
        log_error!("mfa verify: d1 binding `{D1_BINDING}` unavailable: {err}");
        ApiError::InternalServerError("database binding is unavailable".to_owned())
    })?;
    let token_service = state.token_service().map_err(|err| {
        log_error!("mfa verify: token signing is misconfigured: {err}");
        ApiError::InternalServerError("server is misconfigured".to_owned())
    })?;
    let case = MfaVerifyUseCase {
        mfa_repository: mfa_repository(&state)?,
        account_repository,
        session_issuer: SessionIssuer::new(refresh_token_repository(&state)?, token_service),
        second_factor: second_factor(&state)?,
        opaque_token_service: state.opaque_token_service(),
    };
    let result = case
        .execute(command, &client_info(&headers))
        .await
        .map_err(|err| {
            log_error!("mfa verify: failed: {err}");
            ApiError::from(err)
        })?;

    Ok(ApiResponse::ok(
        200,
        Vec::new(),
        vec![MFA_VERIFY_MESSAGE.to_owned()],
        result,
    ))
}

#[cfg(test)]
mod tests {
    use axum::response::IntoResponse;

    use super::*;

    fn disable_payload(password: &str, code: &str) -> MfaPasswordCodePayload {
        MfaPasswordCodePayload {
            password: password.to_owned(),
            code: code.to_owned(),
        }
    }

    fn verify_payload(challenge: &str, code: &str) -> MfaVerifyPayload {
        MfaVerifyPayload {
            challenge_token: challenge.to_owned(),
            code: code.to_owned(),
        }
    }

    fn valid_token() -> String {
        "0123456789abcdef".repeat(4)
    }

    #[test]
    fn accepts_totp_and_recovery_codes() {
        assert_eq!(validate_code(" 123456 ").expect("totp"), "123456");
        assert_eq!(validate_code("ABCDEFGHJK").expect("recovery"), "ABCDEFGHJK");
        assert_eq!(
            validate_code("abcd-efgh-jk").expect("recovery"),
            "abcd-efgh-jk"
        );
        assert_eq!(
            validate_code("ABCD EFGH JK").expect("recovery"),
            "ABCD EFGH JK"
        );
    }

    #[test]
    fn rejects_obviously_wrong_codes() {
        for code in ["", "12345", "1234567", "abcdef", "!!!!!!", "  "] {
            assert!(
                validate_code(code).is_err(),
                "{code:?} must be rejected before hitting the database"
            );
        }
    }

    #[test]
    fn maps_validation_errors_to_400() {
        let api_error = ApiError::from(MfaValidationError::CodeInvalid);
        assert!(matches!(api_error, ApiError::BadRequest(_)));
        assert_eq!(api_error.status(), 400);
        assert_eq!(api_error.message(), "the verification code is invalid");

        let api_error = ApiError::from(MfaValidationError::PasswordEmpty);
        assert_eq!(api_error.status(), 400);
    }

    #[test]
    fn builds_disable_commands() {
        let command = disable_payload("s3cret", "123456")
            .into_command(uuid::Uuid::nil())
            .expect("payload");

        assert_eq!(command.account_id, uuid::Uuid::nil());
        assert_eq!(command.password, "s3cret");
        assert_eq!(command.code, "123456");
    }

    #[test]
    fn rejects_an_empty_password_on_disable() {
        let error = disable_payload("", "123456")
            .into_command(uuid::Uuid::nil())
            .expect_err("payload must be rejected");

        assert!(matches!(error, MfaValidationError::PasswordEmpty));
    }

    #[test]
    fn builds_verify_commands() {
        let token = valid_token();
        let command = verify_payload(&format!("  {token}  "), "123456")
            .into_command()
            .expect("payload");

        assert_eq!(command.challenge_token, token);
        assert_eq!(command.code, "123456");
    }

    #[test]
    fn rejects_malformed_challenge_tokens() {
        for challenge in ["", "abc", &"z".repeat(64)] {
            let error = verify_payload(challenge, "123456")
                .into_command()
                .expect_err("payload must be rejected");
            assert!(matches!(error, MfaValidationError::ChallengeInvalid));
        }
    }

    #[test]
    fn maps_domain_errors_to_status_codes() {
        let cases = [
            (MfaError::AlreadyEnabled, 409),
            (MfaError::NotEnabled, 400),
            (MfaError::NotStarted, 400),
            (MfaError::InvalidPassword, 400),
            (MfaError::InvalidCode, 401),
            (MfaError::InvalidChallenge, 401),
            (MfaError::AccountNotFound, 401),
        ];

        for (error, status) in cases {
            assert_eq!(ApiError::from(error).status(), status);
        }
    }

    #[test]
    fn hides_storage_failures_behind_500() {
        let api_error = ApiError::from(MfaError::FindCredential {
            source: worker::Error::RustError("d1 select failed".to_owned()),
        });

        assert!(matches!(api_error, ApiError::InternalServerError(_)));
        assert_eq!(api_error.status(), 500);
        assert_eq!(api_error.message(), "internal server error");
    }

    #[test]
    fn error_responses_use_the_mapped_status() {
        let conflict = ApiError::from(MfaError::AlreadyEnabled).into_response();
        assert_eq!(conflict.status(), axum::http::StatusCode::CONFLICT);

        let unauthorized = ApiError::from(MfaError::InvalidCode).into_response();
        assert_eq!(unauthorized.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn success_envelopes_match_the_api_contract() {
        let response = ApiResponse::ok(
            200,
            Vec::<String>::new(),
            Vec::<String>::new(),
            MfaSetupResult {
                secret: "JBSWY3DPEHPK3PXP".to_owned(),
                otpauth_uri: "otpauth://totp/auth-worker:ada@example.com?secret=JBSWY3DPEHPK3PXP"
                    .to_owned(),
            },
        );

        let json = serde_json::to_value(&response).expect("response should serialize");

        assert_eq!(json["success"], serde_json::json!(true));
        assert_eq!(json["results"]["secret"], "JBSWY3DPEHPK3PXP");
        assert!(json["results"]["otpauth_uri"]
            .as_str()
            .expect("uri")
            .starts_with("otpauth://totp/"));
    }
}
