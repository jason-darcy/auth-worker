//! Helpers shared by unit tests.

use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use async_trait::async_trait;

use crate::domain::{
    mfa::{StoredMfaChallenge, TotpCredential},
    repositories::mfa::MfaRepository,
    services::{recovery_code::RecoveryCodeService, totp::TotpService},
};

/// Drives a future to completion on the current thread.
///
/// The use cases only await immediately-ready futures (the repositories are
/// mocked), so a no-op waker is enough and no async runtime is needed.
pub(crate) fn block_on<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut future = pin!(future);
    loop {
        if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
            return output;
        }
    }
}

/// An account with MFA turned off, for the tests of everything else.
pub(crate) struct NoMfaRepository;

#[async_trait(?Send)]
impl MfaRepository for NoMfaRepository {
    async fn find_credential(
        &self,
        _account_id: &str,
    ) -> Result<Option<TotpCredential>, worker::Error> {
        Ok(None)
    }

    async fn save_credential(&self, _credential: &TotpCredential) -> Result<(), worker::Error> {
        Ok(())
    }

    async fn delete_credential(&self, _account_id: &str) -> Result<(), worker::Error> {
        Ok(())
    }

    async fn replace_recovery_codes(
        &self,
        _account_id: &str,
        _code_hashes: &[String],
    ) -> Result<(), worker::Error> {
        Ok(())
    }

    async fn consume_recovery_code(
        &self,
        _account_id: &str,
        _code_hash: &str,
    ) -> Result<bool, worker::Error> {
        Ok(false)
    }

    async fn count_recovery_codes(&self, _account_id: &str) -> Result<u32, worker::Error> {
        Ok(0)
    }

    async fn create_challenge(
        &self,
        _account_id: &str,
        _token_hash: &str,
        _expires_at: jiff::Timestamp,
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

    async fn delete_expired_challenges(&self, _now: jiff::Timestamp) -> Result<u32, worker::Error> {
        Ok(0)
    }
}

/// A TOTP service that never accepts anything.
pub(crate) struct UnusedTotpService;

impl TotpService for UnusedTotpService {
    fn generate_secret(&self) -> Result<String, worker::Error> {
        Ok("JBSWY3DPEHPK3PXP".to_owned())
    }

    fn otpauth_uri(&self, _issuer: &str, _account: &str, _secret: &str) -> String {
        String::new()
    }

    fn verify(
        &self,
        _secret: &str,
        _code: &str,
        _now: jiff::Timestamp,
    ) -> Result<Option<i64>, worker::Error> {
        Ok(None)
    }
}

/// A recovery code service whose codes never match.
pub(crate) struct UnusedRecoveryCodeService;

impl RecoveryCodeService for UnusedRecoveryCodeService {
    fn generate(&self, count: usize) -> Result<Vec<String>, worker::Error> {
        Ok((0..count).map(|index| format!("CODE{index:06}")).collect())
    }

    fn normalize(&self, code: &str) -> String {
        code.to_ascii_uppercase()
    }

    fn hash(&self, code: &str) -> String {
        format!("hash:{code}")
    }
}

/// A verifier for an account with MFA turned off.
pub(crate) fn no_mfa_verifier() -> crate::application::use_cases::second_factor::SecondFactorVerifier
{
    crate::application::use_cases::second_factor::SecondFactorVerifier::new(
        std::sync::Arc::new(NoMfaRepository),
        std::sync::Arc::new(UnusedTotpService),
        std::sync::Arc::new(UnusedRecoveryCodeService),
    )
}

/// The code accepted by [`AcceptingTotpService`].
pub(crate) const ACCEPTED_CODE: &str = "123456";

/// An account with a confirmed TOTP credential.
pub(crate) struct ConfirmedMfaRepository;

#[async_trait(?Send)]
impl MfaRepository for ConfirmedMfaRepository {
    async fn find_credential(
        &self,
        account_id: &str,
    ) -> Result<Option<TotpCredential>, worker::Error> {
        Ok(Some(TotpCredential {
            account_id: account_id.to_owned(),
            secret: "JBSWY3DPEHPK3PXP".to_owned(),
            confirmed_at: Some(jiff::Timestamp::now()),
            last_used_step: None,
        }))
    }

    async fn save_credential(&self, _credential: &TotpCredential) -> Result<(), worker::Error> {
        Ok(())
    }

    async fn delete_credential(&self, _account_id: &str) -> Result<(), worker::Error> {
        Ok(())
    }

    async fn replace_recovery_codes(
        &self,
        _account_id: &str,
        _code_hashes: &[String],
    ) -> Result<(), worker::Error> {
        Ok(())
    }

    async fn consume_recovery_code(
        &self,
        _account_id: &str,
        _code_hash: &str,
    ) -> Result<bool, worker::Error> {
        Ok(false)
    }

    async fn count_recovery_codes(&self, _account_id: &str) -> Result<u32, worker::Error> {
        Ok(0)
    }

    async fn create_challenge(
        &self,
        _account_id: &str,
        _token_hash: &str,
        _expires_at: jiff::Timestamp,
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

    async fn delete_expired_challenges(&self, _now: jiff::Timestamp) -> Result<u32, worker::Error> {
        Ok(0)
    }
}

/// A TOTP service that accepts exactly [`ACCEPTED_CODE`].
pub(crate) struct AcceptingTotpService;

impl TotpService for AcceptingTotpService {
    fn generate_secret(&self) -> Result<String, worker::Error> {
        Ok("JBSWY3DPEHPK3PXP".to_owned())
    }

    fn otpauth_uri(&self, _issuer: &str, _account: &str, _secret: &str) -> String {
        String::new()
    }

    fn verify(
        &self,
        _secret: &str,
        code: &str,
        _now: jiff::Timestamp,
    ) -> Result<Option<i64>, worker::Error> {
        Ok((code.trim() == ACCEPTED_CODE).then_some(1))
    }
}

/// A verifier for an account with MFA turned on.
pub(crate) fn mfa_verifier() -> crate::application::use_cases::second_factor::SecondFactorVerifier {
    crate::application::use_cases::second_factor::SecondFactorVerifier::new(
        std::sync::Arc::new(ConfirmedMfaRepository),
        std::sync::Arc::new(AcceptingTotpService),
        std::sync::Arc::new(UnusedRecoveryCodeService),
    )
}
