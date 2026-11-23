use std::sync::Arc;

use jiff::Timestamp;
use snafu::{ResultExt, Snafu};

use crate::{
    domain::{
        mfa::TotpCredential,
        repositories::mfa::MfaRepository,
        services::{recovery_code::RecoveryCodeService, totp::TotpService},
    },
    logging::{log_error, log_warn},
};

#[derive(Debug, Snafu)]
pub enum SecondFactorError {
    /// The account has MFA enabled but the request carried no code.
    #[snafu(display("a verification code is required"))]
    CodeRequired,
    /// Wrong code, or a code that was already used.
    #[snafu(display("the verification code is invalid"))]
    InvalidCode,
    #[snafu(display("failed to find the mfa credential"))]
    FindCredential { source: worker::Error },
    #[snafu(display("failed to verify the code"))]
    VerifyCode { source: worker::Error },
    #[snafu(display("failed to save the mfa credential"))]
    SaveCredential { source: worker::Error },
    #[snafu(display("failed to check the recovery code"))]
    ConsumeRecoveryCode { source: worker::Error },
}

/// Verifies the second factor of an account.
///
/// One implementation for every caller — sign-in, disabling MFA, re-issuing
/// recovery codes and the step-up guards — so the TOTP replay rule and the
/// recovery code bookkeeping cannot drift between endpoints.
pub struct SecondFactorVerifier {
    pub mfa_repository: Arc<dyn MfaRepository>,
    pub totp_service: Arc<dyn TotpService>,
    pub recovery_code_service: Arc<dyn RecoveryCodeService>,
}

impl SecondFactorVerifier {
    pub fn new(
        mfa_repository: Arc<dyn MfaRepository>,
        totp_service: Arc<dyn TotpService>,
        recovery_code_service: Arc<dyn RecoveryCodeService>,
    ) -> Self {
        SecondFactorVerifier {
            mfa_repository,
            totp_service,
            recovery_code_service,
        }
    }

    /// `true` when the account finished an MFA enrolment.
    pub async fn is_enabled(&self, account_id: &str) -> Result<bool, SecondFactorError> {
        let credential = self
            .mfa_repository
            .find_credential(account_id)
            .await
            .inspect_err(|err| {
                log_error!("second factor: find_credential failed for {account_id}: {err}");
            })
            .context(FindCredentialSnafu)?;
        Ok(credential.is_some_and(|credential| credential.is_confirmed()))
    }

    /// Accepts either a TOTP code or a recovery code.
    ///
    /// A TOTP code is single use: the accepted time step is stored, so a replay
    /// inside the clock-skew window is refused. A recovery code is marked used.
    pub async fn verify(&self, account_id: &str, code: &str) -> Result<(), SecondFactorError> {
        let mut credential = self
            .mfa_repository
            .find_credential(account_id)
            .await
            .inspect_err(|err| {
                log_error!("second factor: find_credential failed for {account_id}: {err}");
            })
            .context(FindCredentialSnafu)?
            .filter(TotpCredential::is_confirmed)
            .ok_or(SecondFactorError::InvalidCode)?;

        let now = Timestamp::now();
        let step = self
            .totp_service
            .verify(&credential.secret, code, now)
            .inspect_err(|err| log_error!("second factor: totp verify failed: {err}"))
            .context(VerifyCodeSnafu)?;

        if let Some(step) = step {
            if credential.is_replayed(step) {
                log_warn!("second factor: replayed TOTP code for account {account_id}");
                return Err(SecondFactorError::InvalidCode);
            }
            credential.accept_step(step);
            self.mfa_repository
                .save_credential(&credential)
                .await
                .inspect_err(|err| {
                    log_error!("second factor: save_credential failed for {account_id}: {err}");
                })
                .context(SaveCredentialSnafu)?;
            return Ok(());
        }

        let code_hash = self.recovery_code_service.hash(code);
        let consumed = self
            .mfa_repository
            .consume_recovery_code(account_id, &code_hash)
            .await
            .inspect_err(|err| {
                log_error!("second factor: consume_recovery_code failed for {account_id}: {err}");
            })
            .context(ConsumeRecoveryCodeSnafu)?;
        if !consumed {
            log_warn!("second factor: wrong code for account {account_id}");
            return Err(SecondFactorError::InvalidCode);
        }
        log_warn!("second factor: recovery code used for account {account_id}");
        Ok(())
    }

    /// Step-up guard for sensitive operations.
    ///
    /// Accounts without MFA pass straight through; accounts with MFA must send a
    /// valid code, otherwise the request is refused instead of silently
    /// weakening the account.
    pub async fn require(
        &self,
        account_id: &str,
        code: Option<&str>,
    ) -> Result<(), SecondFactorError> {
        if !self.is_enabled(account_id).await? {
            return Ok(());
        }
        let code = code.map(str::trim).filter(|code| !code.is_empty());
        let Some(code) = code else {
            log_warn!("second factor: step-up without a code for account {account_id}");
            return Err(SecondFactorError::CodeRequired);
        };
        self.verify(account_id, code).await
    }
}

#[cfg(test)]
// The verifier stores its dependencies as `Arc<dyn Trait>` and the repository
// trait is `?Send`, so mocks cannot be `Sync`; `RefCell` keeps them cheap.
#[allow(clippy::arc_with_non_send_sync)]
mod tests {
    use std::{cell::RefCell, collections::HashMap, sync::Arc};

    use async_trait::async_trait;

    use super::*;
    use crate::{
        domain::{mfa::StoredMfaChallenge, repositories::mfa::MfaRepository},
        testing::block_on,
    };

    const SECRET: &str = "JBSWY3DPEHPK3PXP";
    const TOTP: &str = "123456";

    #[derive(Default)]
    struct MockMfaRepository {
        credential: RefCell<Option<TotpCredential>>,
        recovery: RefCell<HashMap<String, bool>>,
        fail_find: bool,
    }

    impl MockMfaRepository {
        fn with_credential(credential: TotpCredential) -> Self {
            MockMfaRepository {
                credential: RefCell::new(Some(credential)),
                ..Default::default()
            }
        }
    }

    #[async_trait(?Send)]
    impl MfaRepository for MockMfaRepository {
        async fn find_credential(
            &self,
            _account_id: &str,
        ) -> Result<Option<TotpCredential>, worker::Error> {
            if self.fail_find {
                return Err(worker::Error::RustError("d1 select failed".to_owned()));
            }
            Ok(self.credential.borrow().clone())
        }

        async fn save_credential(&self, credential: &TotpCredential) -> Result<(), worker::Error> {
            *self.credential.borrow_mut() = Some(credential.clone());
            Ok(())
        }

        async fn delete_credential(&self, _account_id: &str) -> Result<(), worker::Error> {
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
            Ok(0)
        }

        async fn create_challenge(
            &self,
            _account_id: &str,
            _token_hash: &str,
            _expires_at: Timestamp,
        ) -> Result<(), worker::Error> {
            Ok(())
        }

        async fn find_challenge(
            &self,
            _token_hash: &str,
        ) -> Result<Option<StoredMfaChallenge>, worker::Error> {
            Ok(None)
        }

        async fn record_challenge_attempt(&self, _token_hash: &str) -> Result<u32, worker::Error> {
            Ok(0)
        }

        async fn delete_challenge(&self, _token_hash: &str) -> Result<(), worker::Error> {
            Ok(())
        }

        async fn delete_expired_challenges(&self, _now: Timestamp) -> Result<u32, worker::Error> {
            Ok(0)
        }
    }

    #[derive(Default)]
    struct MockTotpService {
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

        fn otpauth_uri(&self, _issuer: &str, _account: &str, _secret: &str) -> String {
            String::new()
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

    fn confirmed(last_used_step: Option<i64>) -> TotpCredential {
        TotpCredential {
            account_id: "account-id".to_owned(),
            secret: SECRET.to_owned(),
            confirmed_at: Some(Timestamp::now()),
            last_used_step,
        }
    }

    struct Fixture {
        mfa: Arc<MockMfaRepository>,
    }

    impl Fixture {
        fn new(mfa: MockMfaRepository) -> Self {
            Fixture { mfa: Arc::new(mfa) }
        }

        fn verifier(&self) -> SecondFactorVerifier {
            SecondFactorVerifier::new(
                self.mfa.clone(),
                Arc::new(MockTotpService::accepting(TOTP, 1)),
                Arc::new(MockRecoveryCodeService),
            )
        }
    }

    #[test]
    fn reports_whether_mfa_is_enabled() {
        let fixture = Fixture::new(MockMfaRepository::default());
        assert!(!block_on(fixture.verifier().is_enabled("account-id")).expect("enabled"));

        let fixture = Fixture::new(MockMfaRepository::with_credential(confirmed(None)));
        assert!(block_on(fixture.verifier().is_enabled("account-id")).expect("enabled"));
    }

    #[test]
    fn a_pending_credential_does_not_count_as_enabled() {
        let fixture = Fixture::new(MockMfaRepository::with_credential(TotpCredential::new(
            "account-id",
            SECRET,
        )));

        assert!(!block_on(fixture.verifier().is_enabled("account-id")).expect("enabled"));
    }

    #[test]
    fn accepts_a_totp_code_and_remembers_the_step() {
        let fixture = Fixture::new(MockMfaRepository::with_credential(confirmed(None)));

        block_on(fixture.verifier().verify("account-id", TOTP)).expect("verify");

        assert_eq!(
            fixture
                .mfa
                .credential
                .borrow()
                .as_ref()
                .expect("credential")
                .last_used_step,
            Some(1)
        );
    }

    #[test]
    fn rejects_a_replayed_totp_code() {
        let fixture = Fixture::new(MockMfaRepository::with_credential(confirmed(Some(1))));

        let error = block_on(fixture.verifier().verify("account-id", TOTP))
            .expect_err("replay must be rejected");

        assert!(matches!(error, SecondFactorError::InvalidCode));
    }

    #[test]
    fn accepts_and_burns_a_recovery_code() {
        let fixture = Fixture::new(MockMfaRepository::with_credential(confirmed(None)));
        block_on(
            fixture
                .mfa
                .replace_recovery_codes("account-id", &["hash:ABCDEFGHJK".to_owned()]),
        )
        .expect("seed");

        block_on(fixture.verifier().verify("account-id", "abcdefghjk")).expect("verify");
        let error = block_on(fixture.verifier().verify("account-id", "ABCDEFGHJK"))
            .expect_err("a used recovery code must be refused");

        assert!(matches!(error, SecondFactorError::InvalidCode));
    }

    #[test]
    fn rejects_unknown_codes() {
        let fixture = Fixture::new(MockMfaRepository::with_credential(confirmed(None)));

        let error =
            block_on(fixture.verifier().verify("account-id", "000000")).expect_err("unknown code");

        assert!(matches!(error, SecondFactorError::InvalidCode));
    }

    #[test]
    fn rejects_accounts_without_an_active_credential() {
        let fixture = Fixture::new(MockMfaRepository::default());

        let error =
            block_on(fixture.verifier().verify("account-id", TOTP)).expect_err("no credential");

        assert!(matches!(error, SecondFactorError::InvalidCode));
    }

    #[test]
    fn step_up_passes_through_when_mfa_is_off() {
        let fixture = Fixture::new(MockMfaRepository::default());

        block_on(fixture.verifier().require("account-id", None)).expect("no MFA, no code needed");
    }

    #[test]
    fn step_up_demands_a_code_when_mfa_is_on() {
        let fixture = Fixture::new(MockMfaRepository::with_credential(confirmed(None)));

        for code in [None, Some(""), Some("   ")] {
            let error = block_on(fixture.verifier().require("account-id", code))
                .expect_err("a code is required");
            assert!(matches!(error, SecondFactorError::CodeRequired));
        }
    }

    #[test]
    fn step_up_accepts_a_valid_code() {
        let fixture = Fixture::new(MockMfaRepository::with_credential(confirmed(None)));

        block_on(fixture.verifier().require("account-id", Some(TOTP))).expect("valid code");
    }

    #[test]
    fn step_up_rejects_a_wrong_code() {
        let fixture = Fixture::new(MockMfaRepository::with_credential(confirmed(None)));

        let error = block_on(fixture.verifier().require("account-id", Some("000000")))
            .expect_err("wrong code");

        assert!(matches!(error, SecondFactorError::InvalidCode));
    }

    #[test]
    fn propagates_storage_failures() {
        let fixture = Fixture::new(MockMfaRepository {
            fail_find: true,
            ..Default::default()
        });

        let error = block_on(fixture.verifier().require("account-id", Some(TOTP)))
            .expect_err("failure must surface");

        assert!(matches!(error, SecondFactorError::FindCredential { .. }));
    }
}
