use std::sync::Arc;

use jiff::Timestamp;
use serde::Serialize;

use crate::{
    domain::repositories::{
        mfa::MfaRepository, password_reset_token::PasswordResetTokenRepository,
        refresh_token::RefreshTokenRepository, verification_token::VerificationTokenRepository,
    },
    logging::{log_error, log_info},
};

/// What one cleanup run removed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CleanupResult {
    pub verification_tokens: u32,
    pub password_reset_tokens: u32,
    pub refresh_tokens: u32,
    pub mfa_challenges: u32,
}

impl CleanupResult {
    pub fn total(&self) -> u32 {
        self.verification_tokens
            + self.password_reset_tokens
            + self.refresh_tokens
            + self.mfa_challenges
    }
}

/// Deletes expired tokens.
///
/// Expiry is checked on every use anyway, so this only reclaims space. Each
/// table is cleaned independently: one failure must not stop the others, and a
/// scheduled run never reports an error, it only logs.
pub struct CleanupUseCase {
    pub verification_token_repository: Arc<dyn VerificationTokenRepository>,
    pub password_reset_token_repository: Arc<dyn PasswordResetTokenRepository>,
    pub refresh_token_repository: Arc<dyn RefreshTokenRepository>,
    pub mfa_repository: Arc<dyn MfaRepository>,
}

impl CleanupUseCase {
    pub fn new(
        verification_token_repository: Arc<dyn VerificationTokenRepository>,
        password_reset_token_repository: Arc<dyn PasswordResetTokenRepository>,
        refresh_token_repository: Arc<dyn RefreshTokenRepository>,
        mfa_repository: Arc<dyn MfaRepository>,
    ) -> Self {
        CleanupUseCase {
            verification_token_repository,
            password_reset_token_repository,
            refresh_token_repository,
            mfa_repository,
        }
    }

    pub async fn execute(&self) -> CleanupResult {
        let now = Timestamp::now();
        let mut result = CleanupResult::default();

        match self.verification_token_repository.delete_expired(now).await {
            Ok(deleted) => result.verification_tokens = deleted,
            Err(err) => log_error!("cleanup: deleting verification tokens failed: {err}"),
        }
        match self
            .password_reset_token_repository
            .delete_expired(now)
            .await
        {
            Ok(deleted) => result.password_reset_tokens = deleted,
            Err(err) => log_error!("cleanup: deleting password reset tokens failed: {err}"),
        }
        match self.refresh_token_repository.delete_expired(now).await {
            Ok(deleted) => result.refresh_tokens = deleted,
            Err(err) => log_error!("cleanup: deleting refresh tokens failed: {err}"),
        }
        match self.mfa_repository.delete_expired_challenges(now).await {
            Ok(deleted) => result.mfa_challenges = deleted,
            Err(err) => log_error!("cleanup: deleting mfa challenges failed: {err}"),
        }

        log_info!(
            "cleanup: removed {} verification, {} reset, {} refresh tokens and {} mfa challenges",
            result.verification_tokens,
            result.password_reset_tokens,
            result.refresh_tokens,
            result.mfa_challenges
        );
        result
    }
}

#[cfg(test)]
// The use case stores its dependencies as `Arc<dyn Trait>` and the repository
// trait is `?Send`, so mocks cannot be `Sync`; `RefCell` keeps them cheap.
#[allow(clippy::arc_with_non_send_sync)]
mod tests {
    use std::{cell::RefCell, sync::Arc};

    use async_trait::async_trait;

    use super::*;
    use crate::{
        domain::repositories::{
            password_reset_token::StoredPasswordResetToken,
            refresh_token::{NewRefreshToken, SessionInfo, StoredRefreshToken},
            verification_token::StoredVerificationToken,
        },
        testing::block_on,
    };

    #[derive(Default)]
    struct MockVerificationTokenRepository {
        deleted: u32,
        fail: bool,
        calls: RefCell<Vec<i64>>,
    }

    #[async_trait(?Send)]
    impl VerificationTokenRepository for MockVerificationTokenRepository {
        async fn create_token(
            &self,
            _account_id: &str,
            _token_hash: &str,
            _expires_at: Timestamp,
        ) -> Result<(), worker::Error> {
            Ok(())
        }

        async fn find_token(
            &self,
            _token_hash: &str,
        ) -> Result<Option<StoredVerificationToken>, worker::Error> {
            Ok(None)
        }

        async fn delete_token(&self, _token_hash: &str) -> Result<(), worker::Error> {
            Ok(())
        }

        async fn delete_tokens_for_account(&self, _account_id: &str) -> Result<(), worker::Error> {
            Ok(())
        }

        async fn seconds_since_last_token(
            &self,
            _account_id: &str,
        ) -> Result<Option<i64>, worker::Error> {
            Ok(None)
        }

        async fn delete_expired(&self, now: Timestamp) -> Result<u32, worker::Error> {
            self.calls.borrow_mut().push(now.as_second());
            if self.fail {
                return Err(worker::Error::RustError("d1 delete failed".to_owned()));
            }
            Ok(self.deleted)
        }
    }

    #[derive(Default)]
    struct MockPasswordResetTokenRepository {
        deleted: u32,
        fail: bool,
    }

    #[async_trait(?Send)]
    impl PasswordResetTokenRepository for MockPasswordResetTokenRepository {
        async fn create_token(
            &self,
            _account_id: &str,
            _token_hash: &str,
            _expires_at: Timestamp,
        ) -> Result<(), worker::Error> {
            Ok(())
        }

        async fn delete_tokens_for_account(&self, _account_id: &str) -> Result<(), worker::Error> {
            Ok(())
        }

        async fn find_token(
            &self,
            _token_hash: &str,
        ) -> Result<Option<StoredPasswordResetToken>, worker::Error> {
            Ok(None)
        }

        async fn delete_token(&self, _token_hash: &str) -> Result<(), worker::Error> {
            Ok(())
        }

        async fn seconds_since_last_token(
            &self,
            _account_id: &str,
        ) -> Result<Option<i64>, worker::Error> {
            Ok(None)
        }

        async fn delete_expired(&self, _now: Timestamp) -> Result<u32, worker::Error> {
            if self.fail {
                return Err(worker::Error::RustError("d1 delete failed".to_owned()));
            }
            Ok(self.deleted)
        }
    }

    #[derive(Default)]
    struct MockRefreshTokenRepository {
        deleted: u32,
        fail: bool,
    }

    #[async_trait(?Send)]
    impl RefreshTokenRepository for MockRefreshTokenRepository {
        async fn create_token(&self, _token: NewRefreshToken) -> Result<(), worker::Error> {
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
            if self.fail {
                return Err(worker::Error::RustError("d1 delete failed".to_owned()));
            }
            Ok(self.deleted)
        }
    }

    #[derive(Default)]
    struct MockMfaRepository {
        deleted: u32,
        fail: bool,
    }

    #[async_trait(?Send)]
    impl MfaRepository for MockMfaRepository {
        async fn find_credential(
            &self,
            _account_id: &str,
        ) -> Result<Option<crate::domain::mfa::TotpCredential>, worker::Error> {
            Ok(None)
        }

        async fn save_credential(
            &self,
            _credential: &crate::domain::mfa::TotpCredential,
        ) -> Result<(), worker::Error> {
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
            _expires_at: Timestamp,
        ) -> Result<(), worker::Error> {
            Ok(())
        }

        async fn find_challenge(
            &self,
            _token_hash: &str,
        ) -> Result<Option<crate::domain::mfa::StoredMfaChallenge>, worker::Error> {
            Ok(None)
        }

        async fn record_challenge_attempt(&self, _token_hash: &str) -> Result<u32, worker::Error> {
            Ok(0)
        }

        async fn delete_challenge(&self, _token_hash: &str) -> Result<(), worker::Error> {
            Ok(())
        }

        async fn delete_expired_challenges(&self, _now: Timestamp) -> Result<u32, worker::Error> {
            if self.fail {
                return Err(worker::Error::RustError("d1 delete failed".to_owned()));
            }
            Ok(self.deleted)
        }
    }

    struct Fixture {
        verification: Arc<MockVerificationTokenRepository>,
        password_reset: Arc<MockPasswordResetTokenRepository>,
        refresh: Arc<MockRefreshTokenRepository>,
        mfa: Arc<MockMfaRepository>,
    }

    impl Fixture {
        fn new() -> Self {
            Fixture {
                verification: Arc::new(MockVerificationTokenRepository {
                    deleted: 3,
                    ..Default::default()
                }),
                password_reset: Arc::new(MockPasswordResetTokenRepository {
                    deleted: 2,
                    ..Default::default()
                }),
                refresh: Arc::new(MockRefreshTokenRepository {
                    deleted: 1,
                    ..Default::default()
                }),
                mfa: Arc::new(MockMfaRepository {
                    deleted: 4,
                    ..Default::default()
                }),
            }
        }

        fn use_case(&self) -> CleanupUseCase {
            CleanupUseCase::new(
                self.verification.clone(),
                self.password_reset.clone(),
                self.refresh.clone(),
                self.mfa.clone(),
            )
        }
    }

    #[test]
    fn deletes_every_expired_table() {
        let fixture = Fixture::new();

        let result = block_on(fixture.use_case().execute());

        assert_eq!(
            result,
            CleanupResult {
                verification_tokens: 3,
                password_reset_tokens: 2,
                refresh_tokens: 1,
                mfa_challenges: 4,
            }
        );
        assert_eq!(result.total(), 10);
        assert_eq!(fixture.verification.calls.borrow().len(), 1);
    }

    #[test]
    fn keeps_going_when_one_table_fails() {
        let fixture = Fixture {
            verification: Arc::new(MockVerificationTokenRepository {
                fail: true,
                ..Default::default()
            }),
            ..Fixture::new()
        };

        let result = block_on(fixture.use_case().execute());

        assert_eq!(result.verification_tokens, 0);
        assert_eq!(
            result.password_reset_tokens, 2,
            "a failed table must not stop the others"
        );
        assert_eq!(result.refresh_tokens, 1);
    }

    #[test]
    fn reports_zero_when_everything_is_empty() {
        let fixture = Fixture {
            verification: Arc::new(MockVerificationTokenRepository::default()),
            password_reset: Arc::new(MockPasswordResetTokenRepository::default()),
            refresh: Arc::new(MockRefreshTokenRepository::default()),
            mfa: Arc::new(MockMfaRepository::default()),
        };

        assert_eq!(block_on(fixture.use_case().execute()).total(), 0);
    }
}
