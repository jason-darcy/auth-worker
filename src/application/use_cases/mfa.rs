use std::sync::Arc;

use jiff::Timestamp;
use serde::Serialize;
use snafu::{ensure, ResultExt, Snafu};
use uuid::Uuid;

use crate::{
    application::use_cases::{
        second_factor::{SecondFactorError, SecondFactorVerifier},
        session::SessionIssuer,
        signin::SignInResult,
    },
    domain::{
        client::ClientInfo,
        mfa::{TotpCredential, MFA_CHALLENGE_MAX_ATTEMPTS, RECOVERY_CODE_COUNT},
        repositories::{account::AccountRepository, mfa::MfaRepository},
        services::{
            hash_password::HashPasswordService, opaque_token::OpaqueTokenService,
            recovery_code::RecoveryCodeService, totp::TotpService,
        },
    },
    logging::{log_error, log_info, log_warn},
};

#[derive(Debug, Snafu)]
pub enum MfaError {
    #[snafu(display("multi-factor authentication is already enabled"))]
    AlreadyEnabled,
    #[snafu(display("multi-factor authentication is not enabled"))]
    NotEnabled,
    #[snafu(display("multi-factor authentication setup was not started"))]
    NotStarted,
    #[snafu(display("the verification code is invalid"))]
    InvalidCode,
    #[snafu(display("the sign-in challenge is invalid or expired"))]
    InvalidChallenge,
    #[snafu(display("password is incorrect"))]
    InvalidPassword,
    #[snafu(display("account not found"))]
    AccountNotFound,
    #[snafu(display("failed to find account"))]
    FindAccount { source: worker::Error },
    #[snafu(display("failed to verify password"))]
    VerifyPassword {
        source: argon2::password_hash::Error,
    },
    #[snafu(display("failed to find the mfa credential"))]
    FindCredential { source: worker::Error },
    #[snafu(display("failed to save the mfa credential"))]
    SaveCredential { source: worker::Error },
    #[snafu(display("failed to remove the mfa credential"))]
    DeleteCredential { source: worker::Error },
    #[snafu(display("failed to store the recovery codes"))]
    StoreRecoveryCodes { source: worker::Error },
    #[snafu(display("failed to check the recovery code"))]
    ConsumeRecoveryCode { source: worker::Error },
    #[snafu(display("failed to count the recovery codes"))]
    CountRecoveryCodes { source: worker::Error },
    #[snafu(display("failed to create the sign-in challenge"))]
    CreateChallenge { source: worker::Error },
    #[snafu(display("failed to find the sign-in challenge"))]
    FindChallenge { source: worker::Error },
    #[snafu(display("failed to record a challenge attempt"))]
    RecordAttempt { source: worker::Error },
    #[snafu(display("failed to delete the sign-in challenge"))]
    DeleteChallenge { source: worker::Error },
    #[snafu(display("failed to generate a secret"))]
    GenerateSecret { source: worker::Error },
    #[snafu(display("failed to verify the code"))]
    VerifyCode { source: worker::Error },
    #[snafu(display("failed to generate recovery codes"))]
    GenerateRecoveryCodes { source: worker::Error },
    #[snafu(display("failed to issue a session"))]
    IssueSession { source: worker::Error },
}

impl From<SecondFactorError> for MfaError {
    fn from(err: SecondFactorError) -> Self {
        match err {
            SecondFactorError::CodeRequired | SecondFactorError::InvalidCode => {
                MfaError::InvalidCode
            }
            SecondFactorError::FindCredential { source } => MfaError::FindCredential { source },
            SecondFactorError::VerifyCode { source } => MfaError::VerifyCode { source },
            SecondFactorError::SaveCredential { source } => MfaError::SaveCredential { source },
            SecondFactorError::ConsumeRecoveryCode { source } => {
                MfaError::ConsumeRecoveryCode { source }
            }
        }
    }
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct MfaStatusResult {
    pub enabled: bool,
    pub recovery_codes_remaining: u32,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct MfaSetupResult {
    /// Base32 secret, for manual entry when the QR code cannot be scanned.
    pub secret: String,
    /// `otpauth://` URI to render as a QR code.
    pub otpauth_uri: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct MfaConfirmResult {
    /// Plaintext codes. Shown exactly once; only hashes are stored.
    pub recovery_codes: Vec<String>,
}

pub struct MfaStatusUseCase {
    pub mfa_repository: Arc<dyn MfaRepository>,
}

impl MfaStatusUseCase {
    pub fn new(mfa_repository: Arc<dyn MfaRepository>) -> Self {
        MfaStatusUseCase { mfa_repository }
    }

    pub async fn execute(&self, account_id: &str) -> Result<MfaStatusResult, MfaError> {
        let credential = self.credential(account_id).await?;
        let enabled = credential
            .as_ref()
            .is_some_and(TotpCredential::is_confirmed);
        let recovery_codes_remaining = if enabled {
            self.mfa_repository
                .count_recovery_codes(account_id)
                .await
                .inspect_err(|err| {
                    log_error!("mfa: count_recovery_codes failed for {account_id}: {err}");
                })
                .context(CountRecoveryCodesSnafu)?
        } else {
            0
        };

        Ok(MfaStatusResult {
            enabled,
            recovery_codes_remaining,
        })
    }

    async fn credential(&self, account_id: &str) -> Result<Option<TotpCredential>, MfaError> {
        self.mfa_repository
            .find_credential(account_id)
            .await
            .inspect_err(|err| {
                log_error!("mfa: find_credential failed for {account_id}: {err}");
            })
            .context(FindCredentialSnafu)
    }
}

pub struct MfaSetupUseCase {
    pub mfa_repository: Arc<dyn MfaRepository>,
    pub totp_service: Arc<dyn TotpService>,
    /// Shown in the authenticator app, e.g. `auth-worker` or the public domain.
    pub issuer: String,
}

impl MfaSetupUseCase {
    pub fn new(
        mfa_repository: Arc<dyn MfaRepository>,
        totp_service: Arc<dyn TotpService>,
        issuer: &str,
    ) -> Self {
        MfaSetupUseCase {
            mfa_repository,
            totp_service,
            issuer: issuer.to_owned(),
        }
    }

    /// Starts an enrolment. Nothing is enforced until the first code is
    /// confirmed, so an abandoned setup can never lock the account out.
    pub async fn execute(
        &self,
        account_id: &str,
        account_email: &str,
    ) -> Result<MfaSetupResult, MfaError> {
        let existing = self
            .mfa_repository
            .find_credential(account_id)
            .await
            .inspect_err(|err| {
                log_error!("mfa setup: find_credential failed for {account_id}: {err}");
            })
            .context(FindCredentialSnafu)?;
        ensure!(
            !existing.as_ref().is_some_and(TotpCredential::is_confirmed),
            AlreadyEnabledSnafu
        );

        let secret = self
            .totp_service
            .generate_secret()
            .inspect_err(|err| log_error!("mfa setup: generate_secret failed: {err}"))
            .context(GenerateSecretSnafu)?;
        let credential = TotpCredential::new(account_id, &secret);
        self.mfa_repository
            .save_credential(&credential)
            .await
            .inspect_err(|err| {
                log_error!("mfa setup: save_credential failed for {account_id}: {err}");
            })
            .context(SaveCredentialSnafu)?;

        log_info!("mfa setup: enrolment started for account {account_id}");
        Ok(MfaSetupResult {
            otpauth_uri: self
                .totp_service
                .otpauth_uri(&self.issuer, account_email, &secret),
            secret,
        })
    }
}

pub struct MfaConfirmUseCase {
    pub mfa_repository: Arc<dyn MfaRepository>,
    pub totp_service: Arc<dyn TotpService>,
    pub recovery_code_service: Arc<dyn RecoveryCodeService>,
}

impl MfaConfirmUseCase {
    pub fn new(
        mfa_repository: Arc<dyn MfaRepository>,
        totp_service: Arc<dyn TotpService>,
        recovery_code_service: Arc<dyn RecoveryCodeService>,
    ) -> Self {
        MfaConfirmUseCase {
            mfa_repository,
            totp_service,
            recovery_code_service,
        }
    }

    /// Turns a pending enrolment into an active one and returns the recovery
    /// codes, which are never retrievable again.
    pub async fn execute(
        &self,
        account_id: &str,
        code: &str,
    ) -> Result<MfaConfirmResult, MfaError> {
        let mut credential = self
            .mfa_repository
            .find_credential(account_id)
            .await
            .inspect_err(|err| {
                log_error!("mfa confirm: find_credential failed for {account_id}: {err}");
            })
            .context(FindCredentialSnafu)?
            .ok_or(MfaError::NotStarted)?;
        ensure!(!credential.is_confirmed(), AlreadyEnabledSnafu);

        let now = Timestamp::now();
        let step = self
            .totp_service
            .verify(&credential.secret, code, now)
            .inspect_err(|err| log_error!("mfa confirm: verify failed: {err}"))
            .context(VerifyCodeSnafu)?
            .ok_or(MfaError::InvalidCode)?;

        credential.confirm(now, step);
        self.mfa_repository
            .save_credential(&credential)
            .await
            .inspect_err(|err| {
                log_error!("mfa confirm: save_credential failed for {account_id}: {err}");
            })
            .context(SaveCredentialSnafu)?;

        let codes = self
            .recovery_code_service
            .generate(RECOVERY_CODE_COUNT)
            .inspect_err(|err| log_error!("mfa confirm: generating recovery codes failed: {err}"))
            .context(GenerateRecoveryCodesSnafu)?;
        let hashes: Vec<String> = codes
            .iter()
            .map(|code| self.recovery_code_service.hash(code))
            .collect();
        self.mfa_repository
            .replace_recovery_codes(account_id, &hashes)
            .await
            .inspect_err(|err| {
                log_error!("mfa confirm: replace_recovery_codes failed for {account_id}: {err}");
            })
            .context(StoreRecoveryCodesSnafu)?;

        log_info!("mfa confirm: enabled for account {account_id}");
        Ok(MfaConfirmResult {
            recovery_codes: codes,
        })
    }
}

#[derive(Debug)]
pub struct MfaVerifyCommand {
    pub challenge_token: String,
    pub code: String,
}

pub struct MfaVerifyUseCase {
    pub mfa_repository: Arc<dyn MfaRepository>,
    pub account_repository: Arc<dyn AccountRepository>,
    pub session_issuer: SessionIssuer,
    pub second_factor: SecondFactorVerifier,
    pub opaque_token_service: Arc<dyn OpaqueTokenService>,
}

impl MfaVerifyUseCase {
    /// Exchanges a challenge ticket plus a second factor for a session.
    ///
    /// A wrong code counts against the ticket; once the attempts are used up the
    /// ticket is destroyed and the password has to be entered again.
    pub async fn execute(
        &self,
        command: MfaVerifyCommand,
        client: &ClientInfo,
    ) -> Result<SignInResult, MfaError> {
        let token_hash = self.opaque_token_service.hash(&command.challenge_token);
        let now = Timestamp::now();
        let challenge = self
            .mfa_repository
            .find_challenge(&token_hash)
            .await
            .inspect_err(|err| log_error!("mfa verify: find_challenge failed: {err}"))
            .context(FindChallengeSnafu)?
            .ok_or(MfaError::InvalidChallenge)?;

        if challenge.is_expired(now) || challenge.is_exhausted() {
            log_warn!(
                "mfa verify: challenge for {} is expired or exhausted",
                challenge.account_id
            );
            self.destroy_challenge(&token_hash).await;
            return Err(MfaError::InvalidChallenge);
        }

        let account = self
            .account_repository
            .find_account_by_id(&challenge.account_id)
            .await
            .inspect_err(|err| {
                log_error!(
                    "mfa verify: find_account_by_id failed for {}: {err}",
                    challenge.account_id
                );
            })
            .context(FindAccountSnafu)?;
        let Some(account) = account else {
            log_warn!(
                "mfa verify: challenge references a missing account {}",
                challenge.account_id
            );
            self.destroy_challenge(&token_hash).await;
            return Err(MfaError::InvalidChallenge);
        };
        if !account.is_verified() {
            log_warn!("mfa verify: account {} is not verified", account.id());
            return Err(MfaError::InvalidChallenge);
        }

        // Do not reveal whether the account has MFA: a missing credential looks
        // like a broken ticket.
        let mfa_enabled = self
            .second_factor
            .is_enabled(&challenge.account_id)
            .await
            .map_err(|err| {
                log_error!("mfa verify: checking the credential failed: {err}");
                MfaError::from(err)
            })?;
        if !mfa_enabled {
            log_warn!(
                "mfa verify: account {} has no active credential",
                challenge.account_id
            );
            self.destroy_challenge(&token_hash).await;
            return Err(MfaError::InvalidChallenge);
        }

        if let Err(err) = self
            .second_factor
            .verify(&challenge.account_id, &command.code)
            .await
        {
            let attempts = self
                .mfa_repository
                .record_challenge_attempt(&token_hash)
                .await
                .inspect_err(|err| log_error!("mfa verify: record_challenge_attempt failed: {err}"))
                .context(RecordAttemptSnafu)?;
            log_warn!(
                "mfa verify: rejected code for account {} (attempt {attempts}/{MFA_CHALLENGE_MAX_ATTEMPTS}): {err}",
                account.id()
            );
            if attempts >= MFA_CHALLENGE_MAX_ATTEMPTS {
                self.destroy_challenge(&token_hash).await;
            }
            return Err(MfaError::from(err));
        }

        self.destroy_challenge(&token_hash).await;
        let tokens = self
            .session_issuer
            .start(&account, client)
            .await
            .inspect_err(|err| log_error!("mfa verify: issuing a session failed: {err}"))
            .context(IssueSessionSnafu)?;

        log_info!(
            "mfa verify: second factor accepted for account {}",
            account.id()
        );
        Ok(SignInResult {
            id: account.id(),
            name: account.name().to_owned(),
            email: account.email().to_owned(),
            created_at: account.created_at(),
            tokens,
        })
    }

    /// Deleting a used or burnt ticket is best-effort: it expires anyway.
    async fn destroy_challenge(&self, token_hash: &str) {
        if let Err(err) = self.mfa_repository.delete_challenge(token_hash).await {
            log_error!("mfa verify: delete_challenge failed: {err}");
        }
    }
}

#[derive(Debug)]
pub struct MfaDisableCommand {
    pub account_id: Uuid,
    pub password: String,
    pub code: String,
}

pub struct MfaDisableUseCase {
    pub mfa_repository: Arc<dyn MfaRepository>,
    pub account_repository: Arc<dyn AccountRepository>,
    pub hash_password_service: Arc<dyn HashPasswordService>,
    pub second_factor: SecondFactorVerifier,
}

impl MfaDisableUseCase {
    /// Turns MFA off. Requires both the password and a valid second factor, so
    /// a stolen access token alone cannot weaken the account.
    pub async fn execute(&self, command: MfaDisableCommand) -> Result<(), MfaError> {
        let account_id = command.account_id.to_string();
        let account = self
            .account_repository
            .find_account_by_id(&account_id)
            .await
            .inspect_err(|err| {
                log_error!("mfa disable: find_account_by_id failed for {account_id}: {err}");
            })
            .context(FindAccountSnafu)?;
        let Some(account) = account else {
            return Err(MfaError::AccountNotFound);
        };

        let password_matches = self
            .hash_password_service
            .verify(&command.password, account.password_hash())
            .inspect_err(|err| log_error!("mfa disable: verify failed for {account_id}: {err}"))
            .context(VerifyPasswordSnafu)?;
        ensure!(password_matches, InvalidPasswordSnafu);

        if !self
            .second_factor
            .is_enabled(&account_id)
            .await
            .map_err(MfaError::from)?
        {
            return Err(MfaError::NotEnabled);
        }
        self.second_factor
            .verify(&account_id, &command.code)
            .await
            .map_err(MfaError::from)?;

        self.mfa_repository
            .delete_credential(&account_id)
            .await
            .inspect_err(|err| {
                log_error!("mfa disable: delete_credential failed for {account_id}: {err}");
            })
            .context(DeleteCredentialSnafu)?;

        log_info!("mfa disable: disabled for account {account_id}");
        Ok(())
    }
}

#[derive(Debug)]
pub struct MfaRecoveryCodesCommand {
    pub account_id: Uuid,
    pub password: String,
    pub code: String,
}

pub struct MfaRecoveryCodesUseCase {
    pub account_repository: Arc<dyn AccountRepository>,
    pub hash_password_service: Arc<dyn HashPasswordService>,
    pub second_factor: SecondFactorVerifier,
    pub recovery_code_service: Arc<dyn RecoveryCodeService>,
}

impl MfaRecoveryCodesUseCase {
    /// Replaces every recovery code with a fresh set.
    ///
    /// Requires the password and a valid second factor, exactly like disabling
    /// MFA: the codes are a recovery path, so re-issuing them must not be
    /// possible with an access token alone.
    pub async fn execute(
        &self,
        command: MfaRecoveryCodesCommand,
    ) -> Result<MfaConfirmResult, MfaError> {
        let account_id = command.account_id.to_string();
        let account = self
            .account_repository
            .find_account_by_id(&account_id)
            .await
            .inspect_err(|err| {
                log_error!("mfa recovery codes: find_account_by_id failed for {account_id}: {err}");
            })
            .context(FindAccountSnafu)?;
        let Some(account) = account else {
            return Err(MfaError::AccountNotFound);
        };

        let password_matches = self
            .hash_password_service
            .verify(&command.password, account.password_hash())
            .inspect_err(|err| {
                log_error!("mfa recovery codes: verify failed for {account_id}: {err}");
            })
            .context(VerifyPasswordSnafu)?;
        ensure!(password_matches, InvalidPasswordSnafu);

        if !self
            .second_factor
            .is_enabled(&account_id)
            .await
            .map_err(MfaError::from)?
        {
            return Err(MfaError::NotEnabled);
        }
        self.second_factor
            .verify(&account_id, &command.code)
            .await
            .map_err(MfaError::from)?;

        let codes = self
            .recovery_code_service
            .generate(RECOVERY_CODE_COUNT)
            .inspect_err(|err| log_error!("mfa recovery codes: generation failed: {err}"))
            .context(GenerateRecoveryCodesSnafu)?;
        let hashes: Vec<String> = codes
            .iter()
            .map(|code| self.recovery_code_service.hash(code))
            .collect();
        self.mfa_replace(&account_id, &hashes).await?;

        log_info!("mfa recovery codes: reissued for account {account_id}");
        Ok(MfaConfirmResult {
            recovery_codes: codes,
        })
    }

    async fn mfa_replace(&self, account_id: &str, hashes: &[String]) -> Result<(), MfaError> {
        // The verifier owns the repository; reuse it so this use case needs no
        // second handle on the same storage.
        self.second_factor
            .mfa_repository
            .replace_recovery_codes(account_id, hashes)
            .await
            .inspect_err(|err| {
                log_error!("mfa recovery codes: replace failed for {account_id}: {err}");
            })
            .context(StoreRecoveryCodesSnafu)
    }
}

#[cfg(test)]
// The use cases store their dependencies as `Arc<dyn Trait>` and the repository
// traits are `?Send`, so mocks cannot be `Sync`; `RefCell` keeps them cheap.
#[allow(clippy::arc_with_non_send_sync)]
mod tests {
    use std::{cell::RefCell, collections::HashMap, sync::Arc};

    use argon2::password_hash::Error as PasswordHashError;
    use async_trait::async_trait;

    use super::*;
    use crate::{
        domain::{
            account::Account,
            mfa::StoredMfaChallenge,
            repositories::{
                account::AccountRepository,
                refresh_token::{
                    NewRefreshToken, RefreshTokenRepository, SessionInfo, StoredRefreshToken,
                },
            },
            services::{
                opaque_token::{OpaqueToken, OpaqueTokenService},
                token::{AccessTokenClaims, TokenPair, TokenService},
            },
        },
        testing::block_on,
    };

    const SECRET: &str = "JBSWY3DPEHPK3PXP";
    const TOTP: &str = "123456";

    fn now() -> Timestamp {
        Timestamp::now()
    }

    // ---------- mocks ----------

    #[derive(Default)]
    struct MockMfaRepository {
        credential: RefCell<Option<TotpCredential>>,
        recovery: RefCell<HashMap<String, bool>>, // hash -> used
        challenges: RefCell<HashMap<String, StoredMfaChallenge>>,
    }

    impl MockMfaRepository {
        fn with_credential(credential: TotpCredential) -> Self {
            MockMfaRepository {
                credential: RefCell::new(Some(credential)),
                ..Default::default()
            }
        }

        fn with_challenge(challenge: StoredMfaChallenge) -> Self {
            let mut challenges = HashMap::new();
            challenges.insert("hash:challenge-raw".to_owned(), challenge);
            MockMfaRepository {
                challenges: RefCell::new(challenges),
                ..Default::default()
            }
        }

        fn credential(&self) -> Option<TotpCredential> {
            self.credential.borrow().clone()
        }

        fn unused_recovery_codes(&self) -> usize {
            self.recovery
                .borrow()
                .values()
                .filter(|used| !**used)
                .count()
        }
    }

    #[async_trait(?Send)]
    impl MfaRepository for MockMfaRepository {
        async fn find_credential(
            &self,
            _account_id: &str,
        ) -> Result<Option<TotpCredential>, worker::Error> {
            Ok(self.credential.borrow().clone())
        }

        async fn save_credential(&self, credential: &TotpCredential) -> Result<(), worker::Error> {
            *self.credential.borrow_mut() = Some(credential.clone());
            Ok(())
        }

        async fn delete_credential(&self, _account_id: &str) -> Result<(), worker::Error> {
            *self.credential.borrow_mut() = None;
            self.recovery.borrow_mut().clear();
            Ok(())
        }

        async fn replace_recovery_codes(
            &self,
            _account_id: &str,
            code_hashes: &[String],
        ) -> Result<(), worker::Error> {
            let mut recovery = self.recovery.borrow_mut();
            recovery.clear();
            for hash in code_hashes {
                recovery.insert(hash.clone(), false);
            }
            Ok(())
        }

        async fn consume_recovery_code(
            &self,
            _account_id: &str,
            code_hash: &str,
        ) -> Result<bool, worker::Error> {
            let mut recovery = self.recovery.borrow_mut();
            match recovery.get_mut(code_hash) {
                Some(used) if !*used => {
                    *used = true;
                    Ok(true)
                }
                _ => Ok(false),
            }
        }

        async fn count_recovery_codes(&self, _account_id: &str) -> Result<u32, worker::Error> {
            Ok(self.unused_recovery_codes() as u32)
        }

        async fn create_challenge(
            &self,
            account_id: &str,
            token_hash: &str,
            expires_at: Timestamp,
        ) -> Result<(), worker::Error> {
            self.challenges.borrow_mut().insert(
                token_hash.to_owned(),
                StoredMfaChallenge {
                    account_id: account_id.to_owned(),
                    expires_at,
                    attempts: 0,
                },
            );
            Ok(())
        }

        async fn find_challenge(
            &self,
            token_hash: &str,
        ) -> Result<Option<StoredMfaChallenge>, worker::Error> {
            Ok(self.challenges.borrow().get(token_hash).cloned())
        }

        async fn record_challenge_attempt(&self, token_hash: &str) -> Result<u32, worker::Error> {
            let mut challenges = self.challenges.borrow_mut();
            match challenges.get_mut(token_hash) {
                Some(challenge) => {
                    challenge.attempts += 1;
                    Ok(challenge.attempts)
                }
                None => Ok(0),
            }
        }

        async fn delete_challenge(&self, token_hash: &str) -> Result<(), worker::Error> {
            self.challenges.borrow_mut().remove(token_hash);
            Ok(())
        }

        async fn delete_expired_challenges(&self, _now: Timestamp) -> Result<u32, worker::Error> {
            Ok(0)
        }
    }

    #[derive(Default)]
    struct MockTotpService {
        /// Codes that are currently valid, with the step they belong to.
        valid: RefCell<Vec<(String, i64)>>,
    }

    impl MockTotpService {
        fn accepting(code: &str, step: i64) -> Self {
            MockTotpService {
                valid: RefCell::new(vec![(code.to_owned(), step)]),
            }
        }
    }

    impl TotpService for MockTotpService {
        fn generate_secret(&self) -> Result<String, worker::Error> {
            Ok(SECRET.to_owned())
        }

        fn otpauth_uri(&self, issuer: &str, account: &str, secret: &str) -> String {
            format!("otpauth://totp/{issuer}:{account}?secret={secret}")
        }

        fn verify(
            &self,
            _secret: &str,
            code: &str,
            _now: Timestamp,
        ) -> Result<Option<i64>, worker::Error> {
            Ok(self
                .valid
                .borrow()
                .iter()
                .find(|(candidate, _)| candidate == code)
                .map(|(_, step)| *step))
        }
    }

    #[derive(Default)]
    struct MockRecoveryCodeService;

    impl RecoveryCodeService for MockRecoveryCodeService {
        fn generate(&self, count: usize) -> Result<Vec<String>, worker::Error> {
            Ok((0..count).map(|index| format!("CODE{index:06}")).collect())
        }

        fn normalize(&self, code: &str) -> String {
            code.chars()
                .filter(|c| c.is_ascii_alphanumeric())
                .map(|c| c.to_ascii_uppercase())
                .collect()
        }

        fn hash(&self, code: &str) -> String {
            format!("hash:{}", self.normalize(code))
        }
    }

    #[derive(Default)]
    struct MockOpaqueTokenService;

    impl OpaqueTokenService for MockOpaqueTokenService {
        fn generate(&self) -> Result<OpaqueToken, worker::Error> {
            Ok(OpaqueToken {
                raw: "challenge-raw".to_owned(),
                hash: "hash:challenge-raw".to_owned(),
            })
        }

        fn hash(&self, token: &str) -> String {
            format!("hash:{token}")
        }
    }

    #[derive(Default)]
    struct MockAccountRepository {
        account: Option<Account>,
    }

    impl MockAccountRepository {
        fn with_account(account: Account) -> Self {
            MockAccountRepository {
                account: Some(account),
            }
        }
    }

    #[async_trait(?Send)]
    impl AccountRepository for MockAccountRepository {
        async fn create_account(&self, _account: Account) -> Result<(), worker::Error> {
            Ok(())
        }

        async fn find_account_by_id(&self, id: &str) -> Result<Option<Account>, worker::Error> {
            Ok(self
                .account
                .clone()
                .filter(|account| account.id().to_string() == id))
        }

        async fn find_account_by_name(
            &self,
            _name: &str,
        ) -> Result<Option<Account>, worker::Error> {
            Ok(None)
        }

        async fn find_account_by_email(
            &self,
            _email: &str,
        ) -> Result<Option<Account>, worker::Error> {
            Ok(None)
        }

        async fn update_account(&self, _account: &Account) -> Result<(), worker::Error> {
            Ok(())
        }

        async fn delete_account(&self, _id: &str) -> Result<(), worker::Error> {
            Ok(())
        }
    }

    struct MockHashPasswordService {
        matches: bool,
    }

    impl HashPasswordService for MockHashPasswordService {
        fn hash(&self, password: &str) -> Result<String, PasswordHashError> {
            Ok(format!("hashed:{password}"))
        }

        fn verify(&self, _password: &str, _hash: &str) -> Result<bool, PasswordHashError> {
            Ok(self.matches)
        }

        fn verify_dummy(&self, _password: &str) {}
    }

    #[derive(Default)]
    struct MockRefreshTokenRepository {
        stored: RefCell<Vec<NewRefreshToken>>,
    }

    #[async_trait(?Send)]
    impl RefreshTokenRepository for MockRefreshTokenRepository {
        async fn create_token(&self, token: NewRefreshToken) -> Result<(), worker::Error> {
            self.stored.borrow_mut().push(token);
            Ok(())
        }

        async fn find_token(
            &self,
            _token_hash: &str,
        ) -> Result<Option<StoredRefreshToken>, worker::Error> {
            Ok(None)
        }

        async fn rotate_token(
            &self,
            _old_token_hash: &str,
            _next: NewRefreshToken,
        ) -> Result<(), worker::Error> {
            Ok(())
        }

        async fn delete_session(
            &self,
            _account_id: &str,
            _family_id: &str,
        ) -> Result<bool, worker::Error> {
            Ok(false)
        }

        async fn delete_tokens_for_account(&self, _account_id: &str) -> Result<(), worker::Error> {
            Ok(())
        }

        async fn list_sessions(
            &self,
            _account_id: &str,
        ) -> Result<Vec<SessionInfo>, worker::Error> {
            Ok(Vec::new())
        }

        async fn delete_expired(&self, _now: Timestamp) -> Result<u32, worker::Error> {
            Ok(0)
        }
    }

    #[derive(Default)]
    struct MockTokenService;

    impl TokenService for MockTokenService {
        fn issue_pair(
            &self,
            account_id: &str,
            _email: &str,
            _token_version: u32,
            _session_id: &str,
        ) -> Result<TokenPair, worker::Error> {
            Ok(TokenPair {
                access_token: format!("access-for-{account_id}"),
                refresh_token: "refresh-token".to_owned(),
                access_expires_at: now(),
                refresh_expires_at: now()
                    .saturating_add(std::time::Duration::from_secs(86_400))
                    .expect("timestamp"),
            })
        }

        fn decode_access_token(&self, _token: &str) -> Result<AccessTokenClaims, worker::Error> {
            Err(worker::Error::RustError("not used".to_owned()))
        }

        fn hash_refresh_token(&self, token: &str) -> String {
            format!("hash:{token}")
        }
    }

    // ---------- fixtures ----------

    fn account() -> Account {
        let mut account = Account::new("Ada Lovelace", "ada@example.com", "hashed:s3cret");
        account.mark_verified();
        account
    }

    fn confirmed(account: &Account, last_used_step: Option<i64>) -> TotpCredential {
        TotpCredential {
            account_id: account.id().to_string(),
            secret: SECRET.to_owned(),
            confirmed_at: Some(now()),
            last_used_step,
        }
    }

    fn pending(account: &Account) -> TotpCredential {
        TotpCredential::new(&account.id().to_string(), SECRET)
    }

    struct Fixture {
        mfa: Arc<MockMfaRepository>,
        accounts: Arc<MockAccountRepository>,
        refresh_tokens: Arc<MockRefreshTokenRepository>,
        totp: Arc<MockTotpService>,
    }

    impl Fixture {
        fn new(mfa: MockMfaRepository, accounts: MockAccountRepository) -> Self {
            Fixture {
                mfa: Arc::new(mfa),
                accounts: Arc::new(accounts),
                refresh_tokens: Arc::new(MockRefreshTokenRepository::default()),
                totp: Arc::new(MockTotpService::accepting(TOTP, 1)),
            }
        }

        fn second_factor(&self) -> SecondFactorVerifier {
            SecondFactorVerifier::new(
                self.mfa.clone(),
                self.totp.clone(),
                Arc::new(MockRecoveryCodeService),
            )
        }

        fn issuer(&self) -> SessionIssuer {
            SessionIssuer::new(self.refresh_tokens.clone(), Arc::new(MockTokenService))
        }

        fn status(&self) -> MfaStatusUseCase {
            MfaStatusUseCase::new(self.mfa.clone())
        }

        fn setup(&self) -> MfaSetupUseCase {
            MfaSetupUseCase::new(self.mfa.clone(), self.totp.clone(), "auth-worker")
        }

        fn confirm(&self) -> MfaConfirmUseCase {
            MfaConfirmUseCase::new(
                self.mfa.clone(),
                self.totp.clone(),
                Arc::new(MockRecoveryCodeService),
            )
        }

        fn verify(&self) -> MfaVerifyUseCase {
            MfaVerifyUseCase {
                mfa_repository: self.mfa.clone(),
                account_repository: self.accounts.clone(),
                session_issuer: self.issuer(),
                second_factor: self.second_factor(),
                opaque_token_service: Arc::new(MockOpaqueTokenService),
            }
        }

        fn recovery_codes(&self, password_matches: bool) -> MfaRecoveryCodesUseCase {
            MfaRecoveryCodesUseCase {
                account_repository: self.accounts.clone(),
                hash_password_service: Arc::new(MockHashPasswordService {
                    matches: password_matches,
                }),
                second_factor: self.second_factor(),
                recovery_code_service: Arc::new(MockRecoveryCodeService),
            }
        }

        fn disable(&self, password_matches: bool) -> MfaDisableUseCase {
            MfaDisableUseCase {
                mfa_repository: self.mfa.clone(),
                account_repository: self.accounts.clone(),
                hash_password_service: Arc::new(MockHashPasswordService {
                    matches: password_matches,
                }),
                second_factor: self.second_factor(),
            }
        }
    }

    fn verify_command(code: &str) -> MfaVerifyCommand {
        MfaVerifyCommand {
            challenge_token: "challenge-raw".to_owned(),
            code: code.to_owned(),
        }
    }

    fn challenge(account: &Account) -> StoredMfaChallenge {
        StoredMfaChallenge {
            account_id: account.id().to_string(),
            expires_at: now()
                .saturating_add(std::time::Duration::from_secs(300))
                .expect("timestamp"),
            attempts: 0,
        }
    }

    // ---------- status ----------

    #[test]
    fn status_reports_a_disabled_account() {
        let account = account();
        let fixture = Fixture::new(
            MockMfaRepository::default(),
            MockAccountRepository::with_account(account.clone()),
        );

        let result = block_on(fixture.status().execute(&account.id().to_string())).expect("status");

        assert!(!result.enabled);
        assert_eq!(result.recovery_codes_remaining, 0);
    }

    #[test]
    fn status_reports_an_enabled_account() {
        let account = account();
        let fixture = Fixture::new(
            MockMfaRepository::with_credential(confirmed(&account, None)),
            MockAccountRepository::with_account(account.clone()),
        );
        block_on(
            fixture
                .mfa
                .replace_recovery_codes(&account.id().to_string(), &["a".to_owned()]),
        )
        .expect("seed");

        let result = block_on(fixture.status().execute(&account.id().to_string())).expect("status");

        assert!(result.enabled);
        assert_eq!(result.recovery_codes_remaining, 1);
    }

    // ---------- setup ----------

    #[test]
    fn setup_creates_a_pending_credential() {
        let account = account();
        let fixture = Fixture::new(
            MockMfaRepository::default(),
            MockAccountRepository::with_account(account.clone()),
        );

        let result = block_on(
            fixture
                .setup()
                .execute(&account.id().to_string(), account.email()),
        )
        .expect("setup");

        assert_eq!(result.secret, SECRET);
        assert!(result
            .otpauth_uri
            .starts_with("otpauth://totp/auth-worker:ada@example.com?secret="));
        let credential = fixture.mfa.credential().expect("credential");
        assert!(
            !credential.is_confirmed(),
            "setup alone must not enable MFA"
        );
    }

    #[test]
    fn setup_refuses_to_replace_an_active_credential() {
        let account = account();
        let fixture = Fixture::new(
            MockMfaRepository::with_credential(confirmed(&account, None)),
            MockAccountRepository::with_account(account.clone()),
        );

        let error = block_on(
            fixture
                .setup()
                .execute(&account.id().to_string(), account.email()),
        )
        .expect_err("setup must be refused");

        assert!(matches!(error, MfaError::AlreadyEnabled));
    }

    #[test]
    fn setup_can_restart_an_abandoned_enrolment() {
        let account = account();
        let fixture = Fixture::new(
            MockMfaRepository::with_credential(pending(&account)),
            MockAccountRepository::with_account(account.clone()),
        );

        assert!(block_on(
            fixture
                .setup()
                .execute(&account.id().to_string(), account.email())
        )
        .is_ok());
    }

    // ---------- confirm ----------

    #[test]
    fn confirm_activates_the_credential_and_returns_recovery_codes() {
        let account = account();
        let fixture = Fixture::new(
            MockMfaRepository::with_credential(pending(&account)),
            MockAccountRepository::with_account(account.clone()),
        );

        let result =
            block_on(fixture.confirm().execute(&account.id().to_string(), TOTP)).expect("confirm");

        assert_eq!(result.recovery_codes.len(), RECOVERY_CODE_COUNT);
        let credential = fixture.mfa.credential().expect("credential");
        assert!(credential.is_confirmed());
        assert_eq!(credential.last_used_step, Some(1));
        assert_eq!(
            fixture.mfa.unused_recovery_codes(),
            RECOVERY_CODE_COUNT,
            "every recovery code must be stored unused"
        );
    }

    #[test]
    fn confirm_rejects_a_wrong_code() {
        let account = account();
        let fixture = Fixture::new(
            MockMfaRepository::with_credential(pending(&account)),
            MockAccountRepository::with_account(account.clone()),
        );

        let error = block_on(
            fixture
                .confirm()
                .execute(&account.id().to_string(), "000000"),
        )
        .expect_err("wrong code must fail");

        assert!(matches!(error, MfaError::InvalidCode));
        assert!(!fixture.mfa.credential().expect("credential").is_confirmed());
        assert_eq!(fixture.mfa.unused_recovery_codes(), 0);
    }

    #[test]
    fn confirm_requires_a_started_enrolment() {
        let account = account();
        let fixture = Fixture::new(
            MockMfaRepository::default(),
            MockAccountRepository::with_account(account.clone()),
        );

        let error = block_on(fixture.confirm().execute(&account.id().to_string(), TOTP))
            .expect_err("nothing to confirm");

        assert!(matches!(error, MfaError::NotStarted));
    }

    #[test]
    fn confirm_refuses_an_already_active_credential() {
        let account = account();
        let fixture = Fixture::new(
            MockMfaRepository::with_credential(confirmed(&account, None)),
            MockAccountRepository::with_account(account.clone()),
        );

        let error = block_on(fixture.confirm().execute(&account.id().to_string(), TOTP))
            .expect_err("already enabled");

        assert!(matches!(error, MfaError::AlreadyEnabled));
    }

    // ---------- verify ----------

    #[test]
    fn verify_issues_a_session_for_a_valid_totp_code() {
        let account = account();
        let fixture = Fixture::new(
            MockMfaRepository::with_challenge(challenge(&account)),
            MockAccountRepository::with_account(account.clone()),
        );
        *fixture.mfa.credential.borrow_mut() = Some(confirmed(&account, None));

        let result = block_on(
            fixture
                .verify()
                .execute(verify_command(TOTP), &ClientInfo::default()),
        )
        .expect("verify");

        assert_eq!(result.id, account.id());
        assert_eq!(
            result.tokens.access_token,
            format!("access-for-{}", account.id())
        );
        assert_eq!(fixture.refresh_tokens.stored.borrow().len(), 1);
        assert!(
            fixture.mfa.challenges.borrow().is_empty(),
            "the ticket must be consumed"
        );
        assert_eq!(
            fixture.mfa.credential().expect("credential").last_used_step,
            Some(1),
            "the accepted step must be remembered"
        );
    }

    #[test]
    fn verify_rejects_a_replayed_totp_code() {
        let account = account();
        let fixture = Fixture::new(
            MockMfaRepository::with_challenge(challenge(&account)),
            MockAccountRepository::with_account(account.clone()),
        );
        *fixture.mfa.credential.borrow_mut() = Some(confirmed(&account, Some(1)));

        let error = block_on(
            fixture
                .verify()
                .execute(verify_command(TOTP), &ClientInfo::default()),
        )
        .expect_err("a replayed code must be refused");

        assert!(matches!(error, MfaError::InvalidCode));
        assert!(fixture.refresh_tokens.stored.borrow().is_empty());
    }

    #[test]
    fn verify_accepts_and_burns_a_recovery_code() {
        let account = account();
        let fixture = Fixture::new(
            MockMfaRepository::with_challenge(challenge(&account)),
            MockAccountRepository::with_account(account.clone()),
        );
        *fixture.mfa.credential.borrow_mut() = Some(confirmed(&account, None));
        block_on(
            fixture
                .mfa
                .replace_recovery_codes(&account.id().to_string(), &["hash:ABCDEFGHJK".to_owned()]),
        )
        .expect("seed");

        let result = block_on(
            fixture
                .verify()
                .execute(verify_command("abcdefghjk"), &ClientInfo::default()),
        )
        .expect("verify");

        assert_eq!(result.id, account.id());
        assert_eq!(fixture.mfa.unused_recovery_codes(), 0);

        let error = block_on(
            fixture
                .verify()
                .execute(verify_command("ABCDEFGHJK"), &ClientInfo::default()),
        )
        .expect_err("the ticket is gone");
        assert!(matches!(error, MfaError::InvalidChallenge));
    }

    #[test]
    fn verify_rejects_an_unknown_challenge() {
        let account = account();
        let fixture = Fixture::new(
            MockMfaRepository::default(),
            MockAccountRepository::with_account(account.clone()),
        );

        let error = block_on(
            fixture
                .verify()
                .execute(verify_command(TOTP), &ClientInfo::default()),
        )
        .expect_err("unknown ticket");

        assert!(matches!(error, MfaError::InvalidChallenge));
    }

    #[test]
    fn verify_rejects_and_deletes_an_expired_challenge() {
        let account = account();
        let mut expired = challenge(&account);
        expired.expires_at = now()
            .saturating_sub(std::time::Duration::from_secs(1))
            .expect("timestamp");
        let fixture = Fixture::new(
            MockMfaRepository::with_challenge(expired),
            MockAccountRepository::with_account(account.clone()),
        );
        *fixture.mfa.credential.borrow_mut() = Some(confirmed(&account, None));

        let error = block_on(
            fixture
                .verify()
                .execute(verify_command(TOTP), &ClientInfo::default()),
        )
        .expect_err("expired ticket");

        assert!(matches!(error, MfaError::InvalidChallenge));
        assert!(fixture.mfa.challenges.borrow().is_empty());
    }

    #[test]
    fn verify_counts_wrong_codes_and_destroys_the_ticket_at_the_limit() {
        let account = account();
        let fixture = Fixture::new(
            MockMfaRepository::with_challenge(challenge(&account)),
            MockAccountRepository::with_account(account.clone()),
        );
        *fixture.mfa.credential.borrow_mut() = Some(confirmed(&account, None));

        for attempt in 1..=MFA_CHALLENGE_MAX_ATTEMPTS {
            let error = block_on(
                fixture
                    .verify()
                    .execute(verify_command("000000"), &ClientInfo::default()),
            )
            .expect_err("wrong code");
            assert!(matches!(error, MfaError::InvalidCode));

            let stored = fixture
                .mfa
                .challenges
                .borrow()
                .get("hash:challenge-raw")
                .cloned();
            if attempt < MFA_CHALLENGE_MAX_ATTEMPTS {
                assert_eq!(stored.expect("ticket").attempts, attempt);
            } else {
                assert!(stored.is_none(), "the ticket must be destroyed");
            }
        }
        assert!(fixture.refresh_tokens.stored.borrow().is_empty());
    }

    #[test]
    fn verify_rejects_a_challenge_for_an_unverified_account() {
        let account = Account::new("Ada Lovelace", "ada@example.com", "hashed:s3cret");
        let fixture = Fixture::new(
            MockMfaRepository::with_challenge(challenge(&account)),
            MockAccountRepository::with_account(account.clone()),
        );
        *fixture.mfa.credential.borrow_mut() = Some(confirmed(&account, None));

        let error = block_on(
            fixture
                .verify()
                .execute(verify_command(TOTP), &ClientInfo::default()),
        )
        .expect_err("unverified account");

        assert!(matches!(error, MfaError::InvalidChallenge));
    }

    #[test]
    fn verify_rejects_an_account_without_an_active_credential() {
        let account = account();
        let fixture = Fixture::new(
            MockMfaRepository::with_challenge(challenge(&account)),
            MockAccountRepository::with_account(account.clone()),
        );
        *fixture.mfa.credential.borrow_mut() = Some(pending(&account));

        let error = block_on(
            fixture
                .verify()
                .execute(verify_command(TOTP), &ClientInfo::default()),
        )
        .expect_err("pending credential");

        assert!(matches!(error, MfaError::InvalidChallenge));
    }

    // ---------- disable ----------

    fn disable_command(account: &Account, code: &str) -> MfaDisableCommand {
        MfaDisableCommand {
            account_id: account.id(),
            password: "s3cret".to_owned(),
            code: code.to_owned(),
        }
    }

    #[test]
    fn disable_removes_the_credential_and_the_recovery_codes() {
        let account = account();
        let fixture = Fixture::new(
            MockMfaRepository::with_credential(confirmed(&account, None)),
            MockAccountRepository::with_account(account.clone()),
        );
        block_on(
            fixture
                .mfa
                .replace_recovery_codes(&account.id().to_string(), &["hash:ABCDEFGHJK".to_owned()]),
        )
        .expect("seed");

        block_on(
            fixture
                .disable(true)
                .execute(disable_command(&account, TOTP)),
        )
        .expect("disable");

        assert!(fixture.mfa.credential().is_none());
        assert_eq!(fixture.mfa.unused_recovery_codes(), 0);
    }

    #[test]
    fn disable_requires_the_password() {
        let account = account();
        let fixture = Fixture::new(
            MockMfaRepository::with_credential(confirmed(&account, None)),
            MockAccountRepository::with_account(account.clone()),
        );

        let error = block_on(
            fixture
                .disable(false)
                .execute(disable_command(&account, TOTP)),
        )
        .expect_err("wrong password");

        assert!(matches!(error, MfaError::InvalidPassword));
        assert!(fixture.mfa.credential().is_some());
    }

    #[test]
    fn disable_requires_a_valid_second_factor() {
        let account = account();
        let fixture = Fixture::new(
            MockMfaRepository::with_credential(confirmed(&account, None)),
            MockAccountRepository::with_account(account.clone()),
        );

        let error = block_on(
            fixture
                .disable(true)
                .execute(disable_command(&account, "000000")),
        )
        .expect_err("wrong code");

        assert!(matches!(error, MfaError::InvalidCode));
        assert!(fixture.mfa.credential().is_some());
    }

    #[test]
    fn disable_requires_an_enabled_credential() {
        let account = account();
        let fixture = Fixture::new(
            MockMfaRepository::default(),
            MockAccountRepository::with_account(account.clone()),
        );

        let error = block_on(
            fixture
                .disable(true)
                .execute(disable_command(&account, TOTP)),
        )
        .expect_err("not enabled");

        assert!(matches!(error, MfaError::NotEnabled));
    }

    // ---------- recovery codes ----------

    fn recovery_command(account: &Account, code: &str) -> MfaRecoveryCodesCommand {
        MfaRecoveryCodesCommand {
            account_id: account.id(),
            password: "s3cret".to_owned(),
            code: code.to_owned(),
        }
    }

    #[test]
    fn recovery_codes_are_reissued_and_the_old_ones_dropped() {
        let account = account();
        let fixture = Fixture::new(
            MockMfaRepository::with_credential(confirmed(&account, None)),
            MockAccountRepository::with_account(account.clone()),
        );
        block_on(
            fixture
                .mfa
                .replace_recovery_codes(&account.id().to_string(), &["hash:OLDCODE001".to_owned()]),
        )
        .expect("seed");

        let result = block_on(
            fixture
                .recovery_codes(true)
                .execute(recovery_command(&account, TOTP)),
        )
        .expect("reissue");

        assert_eq!(result.recovery_codes.len(), RECOVERY_CODE_COUNT);
        assert_eq!(fixture.mfa.unused_recovery_codes(), RECOVERY_CODE_COUNT);
        assert!(
            !fixture
                .mfa
                .recovery
                .borrow()
                .contains_key("hash:OLDCODE001"),
            "the previous codes must be gone"
        );
    }

    #[test]
    fn recovery_codes_require_the_password() {
        let account = account();
        let fixture = Fixture::new(
            MockMfaRepository::with_credential(confirmed(&account, None)),
            MockAccountRepository::with_account(account.clone()),
        );

        let error = block_on(
            fixture
                .recovery_codes(false)
                .execute(recovery_command(&account, TOTP)),
        )
        .expect_err("wrong password");

        assert!(matches!(error, MfaError::InvalidPassword));
        assert_eq!(fixture.mfa.unused_recovery_codes(), 0);
    }

    #[test]
    fn recovery_codes_require_mfa_to_be_enabled() {
        let account = account();
        let fixture = Fixture::new(
            MockMfaRepository::default(),
            MockAccountRepository::with_account(account.clone()),
        );

        let error = block_on(
            fixture
                .recovery_codes(true)
                .execute(recovery_command(&account, TOTP)),
        )
        .expect_err("mfa is off");

        assert!(matches!(error, MfaError::NotEnabled));
    }

    #[test]
    fn recovery_codes_require_a_valid_second_factor() {
        let account = account();
        let fixture = Fixture::new(
            MockMfaRepository::with_credential(confirmed(&account, None)),
            MockAccountRepository::with_account(account.clone()),
        );

        let error = block_on(
            fixture
                .recovery_codes(true)
                .execute(recovery_command(&account, "000000")),
        )
        .expect_err("wrong code");

        assert!(matches!(error, MfaError::InvalidCode));
        assert_eq!(fixture.mfa.unused_recovery_codes(), 0);
    }
}
