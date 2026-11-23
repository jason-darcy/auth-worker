use std::sync::Arc;

use jiff::Timestamp;
use serde::Serialize;
use snafu::{ResultExt, Snafu};
use uuid::Uuid;

use crate::{
    domain::{
        repositories::{
            account::AccountRepository, password_reset_token::PasswordResetTokenRepository,
            refresh_token::RefreshTokenRepository,
        },
        services::{
            hash_password::HashPasswordService, verification_token::VerificationTokenService,
        },
    },
    logging::{log_error, log_info, log_warn},
};

pub struct ResetPasswordCommand {
    pub token: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct ResetPasswordResult {
    pub id: Uuid,
    pub email: String,
    pub is_verified: bool,
}

#[derive(Debug, Snafu)]
pub enum ResetPasswordError {
    /// Unknown, expired or orphaned token. All of them look the same on
    /// purpose, so the endpoint cannot be used to probe accounts.
    #[snafu(display("password reset token is invalid or expired"))]
    InvalidToken,
    #[snafu(display("failed to find password reset token"))]
    FindToken { source: worker::Error },
    #[snafu(display("failed to find account"))]
    FindAccount { source: worker::Error },
    #[snafu(display("failed to hash password"))]
    HashPassword {
        source: argon2::password_hash::Error,
    },
    #[snafu(display("failed to update account"))]
    UpdateAccount { source: worker::Error },
}

pub struct ResetPasswordUseCase {
    pub account_repository: Arc<dyn AccountRepository>,
    pub password_reset_token_repository: Arc<dyn PasswordResetTokenRepository>,
    pub refresh_token_repository: Arc<dyn RefreshTokenRepository>,
    pub hash_password_service: Arc<dyn HashPasswordService>,
    pub token_service: Arc<dyn VerificationTokenService>,
}

impl ResetPasswordUseCase {
    pub fn new(
        account_repository: Arc<dyn AccountRepository>,
        password_reset_token_repository: Arc<dyn PasswordResetTokenRepository>,
        refresh_token_repository: Arc<dyn RefreshTokenRepository>,
        hash_password_service: Arc<dyn HashPasswordService>,
        token_service: Arc<dyn VerificationTokenService>,
    ) -> Self {
        ResetPasswordUseCase {
            account_repository,
            password_reset_token_repository,
            refresh_token_repository,
            hash_password_service,
            token_service,
        }
    }

    pub async fn execute(
        &self,
        command: ResetPasswordCommand,
    ) -> Result<ResetPasswordResult, ResetPasswordError> {
        let token_hash = self.token_service.hash(&command.token);
        let stored = self
            .password_reset_token_repository
            .find_token(&token_hash)
            .await
            .inspect_err(|err| log_error!("reset_password: find_token failed: {err}"))
            .context(FindTokenSnafu)?;
        let Some(stored) = stored else {
            log_warn!("reset_password: unknown token");
            return Err(ResetPasswordError::InvalidToken);
        };
        if stored.expires_at <= Timestamp::now() {
            log_warn!(
                "reset_password: expired token for account {}",
                stored.account_id
            );
            self.delete_token(&token_hash).await;
            return Err(ResetPasswordError::InvalidToken);
        }
        let account = self
            .account_repository
            .find_account_by_id(&stored.account_id)
            .await
            .inspect_err(|err| {
                log_error!(
                    "reset_password: find_account_by_id failed for {}: {err}",
                    stored.account_id
                );
            })
            .context(FindAccountSnafu)?;
        let Some(mut account) = account else {
            log_warn!(
                "reset_password: token references a missing account {}",
                stored.account_id
            );
            self.delete_token(&token_hash).await;
            return Err(ResetPasswordError::InvalidToken);
        };

        let password_hash = self
            .hash_password_service
            .hash(&command.password)
            .inspect_err(|err| {
                log_error!(
                    "reset_password: hash password failed for {}: {err}",
                    account.id()
                );
            })
            .context(HashPasswordSnafu)?;
        account.change_password(&password_hash);
        // Invalidates every access token issued before the reset.
        account.bump_token_version();
        // Receiving the email proves control of the mailbox, so a successful
        // reset also verifies the address.
        account.mark_verified();
        self.account_repository
            .update_account(&account)
            .await
            .inspect_err(|err| {
                log_error!(
                    "reset_password: update_account failed for {}: {err}",
                    account.id()
                );
            })
            .context(UpdateAccountSnafu)?;

        self.delete_token(&token_hash).await;
        self.revoke_sessions(&stored.account_id).await;

        log_info!(
            "reset_password: password changed for account {}",
            account.id()
        );
        Ok(ResetPasswordResult {
            id: account.id(),
            email: account.email().to_owned(),
            is_verified: account.is_verified(),
        })
    }

    /// Token cleanup and session revocation are best-effort: the password is
    /// already changed, so failing the request would only confuse the user.
    async fn delete_token(&self, token_hash: &str) {
        if let Err(err) = self
            .password_reset_token_repository
            .delete_token(token_hash)
            .await
        {
            log_error!("reset_password: delete_token failed: {err}");
        }
    }

    async fn revoke_sessions(&self, account_id: &str) {
        if let Err(err) = self
            .refresh_token_repository
            .delete_tokens_for_account(account_id)
            .await
        {
            log_error!("reset_password: revoke refresh tokens failed for {account_id}: {err}");
        }
    }
}

#[cfg(test)]
// The use case stores its dependencies as `Arc<dyn Trait>` and the repository
// trait is `?Send`, so mocks cannot be `Sync`; `RefCell` keeps them cheap.
#[allow(clippy::arc_with_non_send_sync)]
mod tests {
    use std::{cell::RefCell, sync::Arc};

    use argon2::password_hash::Error as PasswordHashError;
    use async_trait::async_trait;

    use super::*;
    use crate::{
        domain::{
            account::Account,
            repositories::{
                account::AccountRepository,
                password_reset_token::{PasswordResetTokenRepository, StoredPasswordResetToken},
                refresh_token::{RefreshTokenRepository, StoredRefreshToken},
            },
            services::{
                hash_password::HashPasswordService,
                verification_token::{VerificationToken, VerificationTokenService},
            },
        },
        testing::block_on,
    };

    const RAW_TOKEN: &str = "raw-reset-token";

    #[derive(Default)]
    struct MockAccountRepository {
        existing: Option<Account>,
        fail_find: bool,
        fail_update: bool,
        updated: RefCell<Vec<Account>>,
    }

    impl MockAccountRepository {
        fn with_account(account: &Account) -> Self {
            MockAccountRepository {
                existing: Some(account.clone()),
                ..Default::default()
            }
        }

        fn updated_accounts(&self) -> Vec<Account> {
            self.updated.borrow().clone()
        }
    }

    #[async_trait(?Send)]
    impl AccountRepository for MockAccountRepository {
        async fn create_account(&self, _account: Account) -> Result<(), worker::Error> {
            Ok(())
        }

        async fn find_account_by_id(&self, id: &str) -> Result<Option<Account>, worker::Error> {
            if self.fail_find {
                return Err(worker::Error::RustError("d1 select failed".to_owned()));
            }
            Ok(self
                .existing
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

        async fn update_account(&self, account: &Account) -> Result<(), worker::Error> {
            if self.fail_update {
                return Err(worker::Error::RustError("d1 update failed".to_owned()));
            }
            self.updated.borrow_mut().push(account.clone());
            Ok(())
        }

        async fn delete_account(&self, _id: &str) -> Result<(), worker::Error> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct MockPasswordResetTokenRepository {
        stored: Option<StoredPasswordResetToken>,
        fail_find: bool,
        fail_delete: bool,
        deleted: RefCell<Vec<String>>,
    }

    impl MockPasswordResetTokenRepository {
        fn with_token(account: &Account, expires_in_secs: i64) -> Self {
            let expires_at = if expires_in_secs >= 0 {
                Timestamp::now()
                    .saturating_add(std::time::Duration::from_secs(expires_in_secs as u64))
                    .expect("timestamp")
            } else {
                Timestamp::now()
                    .saturating_sub(std::time::Duration::from_secs(-expires_in_secs as u64))
                    .expect("timestamp")
            };
            MockPasswordResetTokenRepository {
                stored: Some(StoredPasswordResetToken {
                    account_id: account.id().to_string(),
                    expires_at,
                }),
                ..Default::default()
            }
        }

        fn deleted_tokens(&self) -> Vec<String> {
            self.deleted.borrow().clone()
        }
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
            token_hash: &str,
        ) -> Result<Option<StoredPasswordResetToken>, worker::Error> {
            if self.fail_find {
                return Err(worker::Error::RustError("d1 select failed".to_owned()));
            }
            assert_eq!(token_hash, format!("hash:{RAW_TOKEN}"));
            Ok(self.stored.clone())
        }

        async fn delete_token(&self, token_hash: &str) -> Result<(), worker::Error> {
            if self.fail_delete {
                return Err(worker::Error::RustError("d1 delete failed".to_owned()));
            }
            self.deleted.borrow_mut().push(token_hash.to_owned());
            Ok(())
        }
    }

    #[derive(Default)]
    struct MockRefreshTokenRepository {
        fail_revoke: bool,
        revoked: RefCell<Vec<String>>,
    }

    impl MockRefreshTokenRepository {
        fn revoked_accounts(&self) -> Vec<String> {
            self.revoked.borrow().clone()
        }
    }

    #[async_trait(?Send)]
    impl RefreshTokenRepository for MockRefreshTokenRepository {
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
        ) -> Result<Option<StoredRefreshToken>, worker::Error> {
            Ok(None)
        }

        async fn delete_token(&self, _token_hash: &str) -> Result<(), worker::Error> {
            Ok(())
        }

        async fn delete_tokens_for_account(&self, account_id: &str) -> Result<(), worker::Error> {
            if self.fail_revoke {
                return Err(worker::Error::RustError("d1 delete failed".to_owned()));
            }
            self.revoked.borrow_mut().push(account_id.to_owned());
            Ok(())
        }
    }

    struct MockHashPasswordService {
        fail: bool,
        hashed: RefCell<Vec<String>>,
    }

    impl MockHashPasswordService {
        fn new() -> Self {
            MockHashPasswordService {
                fail: false,
                hashed: RefCell::new(Vec::new()),
            }
        }

        fn failing() -> Self {
            MockHashPasswordService {
                fail: true,
                hashed: RefCell::new(Vec::new()),
            }
        }

        fn hashed_passwords(&self) -> Vec<String> {
            self.hashed.borrow().clone()
        }
    }

    impl HashPasswordService for MockHashPasswordService {
        fn hash(&self, password: &str) -> Result<String, PasswordHashError> {
            self.hashed.borrow_mut().push(password.to_owned());
            if self.fail {
                return Err(PasswordHashError::Crypto);
            }
            Ok(format!("hashed:{password}"))
        }

        fn verify(&self, _password: &str, _password_hash: &str) -> Result<bool, PasswordHashError> {
            Ok(false)
        }
    }

    struct MockVerificationTokenService;

    impl VerificationTokenService for MockVerificationTokenService {
        fn generate(&self) -> Result<VerificationToken, worker::Error> {
            Ok(VerificationToken {
                raw: RAW_TOKEN.to_owned(),
                hash: format!("hash:{RAW_TOKEN}"),
            })
        }

        fn hash(&self, token: &str) -> String {
            format!("hash:{token}")
        }
    }

    fn account() -> Account {
        Account::new("Ada Lovelace", "ada@example.com", "hashed:old-password")
    }

    struct Fixture {
        accounts: Arc<MockAccountRepository>,
        reset_tokens: Arc<MockPasswordResetTokenRepository>,
        refresh_tokens: Arc<MockRefreshTokenRepository>,
        hasher: Arc<MockHashPasswordService>,
    }

    impl Fixture {
        fn new(
            accounts: MockAccountRepository,
            reset_tokens: MockPasswordResetTokenRepository,
        ) -> Self {
            Fixture {
                accounts: Arc::new(accounts),
                reset_tokens: Arc::new(reset_tokens),
                refresh_tokens: Arc::new(MockRefreshTokenRepository::default()),
                hasher: Arc::new(MockHashPasswordService::new()),
            }
        }

        fn use_case(&self) -> ResetPasswordUseCase {
            ResetPasswordUseCase::new(
                self.accounts.clone(),
                self.reset_tokens.clone(),
                self.refresh_tokens.clone(),
                self.hasher.clone(),
                Arc::new(MockVerificationTokenService),
            )
        }
    }

    fn command() -> ResetPasswordCommand {
        ResetPasswordCommand {
            token: RAW_TOKEN.to_owned(),
            password: "new-s3cret".to_owned(),
        }
    }

    #[test]
    fn resets_the_password_verifies_the_account_and_revokes_sessions() {
        let account = account();
        let fixture = Fixture::new(
            MockAccountRepository::with_account(&account),
            MockPasswordResetTokenRepository::with_token(&account, 600),
        );

        let result = block_on(fixture.use_case().execute(command())).expect("reset should work");

        assert_eq!(result.id, account.id());
        assert_eq!(result.email, "ada@example.com");
        assert!(result.is_verified);
        assert_eq!(
            fixture.hasher.hashed_passwords(),
            vec!["new-s3cret".to_owned()]
        );

        let updated = fixture.accounts.updated_accounts();
        assert_eq!(updated.len(), 1);
        assert_eq!(updated[0].password_hash(), "hashed:new-s3cret");
        assert!(updated[0].is_verified());
        assert_eq!(
            updated[0].token_version(),
            1,
            "access tokens issued before the reset must be invalidated"
        );

        assert_eq!(
            fixture.reset_tokens.deleted_tokens(),
            vec![format!("hash:{RAW_TOKEN}")],
            "the used token must not be replayable"
        );
        assert_eq!(
            fixture.refresh_tokens.revoked_accounts(),
            vec![account.id().to_string()],
            "existing sessions must be revoked"
        );
    }

    #[test]
    fn rejects_unknown_token() {
        let account = account();
        let fixture = Fixture::new(
            MockAccountRepository::with_account(&account),
            MockPasswordResetTokenRepository::default(),
        );

        let error =
            block_on(fixture.use_case().execute(command())).expect_err("unknown token must fail");

        assert!(matches!(error, ResetPasswordError::InvalidToken));
        assert_eq!(
            error.to_string(),
            "password reset token is invalid or expired"
        );
        assert!(fixture.hasher.hashed_passwords().is_empty());
        assert!(fixture.accounts.updated_accounts().is_empty());
        assert!(fixture.refresh_tokens.revoked_accounts().is_empty());
    }

    #[test]
    fn rejects_expired_token_and_cleans_it_up() {
        let account = account();
        let fixture = Fixture::new(
            MockAccountRepository::with_account(&account),
            MockPasswordResetTokenRepository::with_token(&account, -60),
        );

        let error =
            block_on(fixture.use_case().execute(command())).expect_err("expired token must fail");

        assert!(matches!(error, ResetPasswordError::InvalidToken));
        assert!(fixture.hasher.hashed_passwords().is_empty());
        assert_eq!(
            fixture.reset_tokens.deleted_tokens(),
            vec![format!("hash:{RAW_TOKEN}")]
        );
    }

    #[test]
    fn rejects_token_for_a_missing_account() {
        let account = account();
        let fixture = Fixture::new(
            MockAccountRepository::default(),
            MockPasswordResetTokenRepository::with_token(&account, 600),
        );

        let error =
            block_on(fixture.use_case().execute(command())).expect_err("orphaned token must fail");

        assert!(matches!(error, ResetPasswordError::InvalidToken));
        assert!(fixture.accounts.updated_accounts().is_empty());
    }

    #[test]
    fn propagates_hash_failure_and_keeps_the_token() {
        let account = account();
        let fixture = Fixture {
            hasher: Arc::new(MockHashPasswordService::failing()),
            ..Fixture::new(
                MockAccountRepository::with_account(&account),
                MockPasswordResetTokenRepository::with_token(&account, 600),
            )
        };

        let error = block_on(fixture.use_case().execute(command()))
            .expect_err("hashing failure must surface");

        assert!(matches!(error, ResetPasswordError::HashPassword { .. }));
        assert!(fixture.accounts.updated_accounts().is_empty());
        assert!(
            fixture.reset_tokens.deleted_tokens().is_empty(),
            "the token must survive so the user can retry"
        );
    }

    #[test]
    fn propagates_update_failure_and_keeps_the_token() {
        let account = account();
        let fixture = Fixture::new(
            MockAccountRepository {
                fail_update: true,
                ..MockAccountRepository::with_account(&account)
            },
            MockPasswordResetTokenRepository::with_token(&account, 600),
        );

        let error = block_on(fixture.use_case().execute(command()))
            .expect_err("update failure must surface");

        assert!(matches!(error, ResetPasswordError::UpdateAccount { .. }));
        assert!(fixture.reset_tokens.deleted_tokens().is_empty());
        assert!(fixture.refresh_tokens.revoked_accounts().is_empty());
    }

    #[test]
    fn propagates_find_token_failure() {
        let account = account();
        let fixture = Fixture::new(
            MockAccountRepository::with_account(&account),
            MockPasswordResetTokenRepository {
                fail_find: true,
                ..Default::default()
            },
        );

        let error = block_on(fixture.use_case().execute(command()))
            .expect_err("lookup failure must surface");

        assert!(matches!(error, ResetPasswordError::FindToken { .. }));
    }

    #[test]
    fn succeeds_even_when_revoking_sessions_fails() {
        let account = account();
        let fixture = Fixture {
            refresh_tokens: Arc::new(MockRefreshTokenRepository {
                fail_revoke: true,
                ..Default::default()
            }),
            ..Fixture::new(
                MockAccountRepository::with_account(&account),
                MockPasswordResetTokenRepository::with_token(&account, 600),
            )
        };

        let result = block_on(fixture.use_case().execute(command()));

        assert!(
            result.is_ok(),
            "revocation failures must not fail the reset"
        );
        assert_eq!(fixture.accounts.updated_accounts().len(), 1);
    }
}
