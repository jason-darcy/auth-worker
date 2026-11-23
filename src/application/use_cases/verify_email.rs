use std::sync::Arc;

use jiff::Timestamp;
use serde::Serialize;
use snafu::{ResultExt, Snafu};
use uuid::Uuid;

use crate::{
    domain::{
        repositories::{
            account::AccountRepository, verification_token::VerificationTokenRepository,
        },
        services::verification_token::VerificationTokenService,
    },
    logging::{log_error, log_info, log_warn},
};

pub struct VerifyEmailCommand {
    pub token: String,
}

#[derive(Debug, Serialize)]
pub struct VerifyEmailResult {
    pub id: Uuid,
    pub email: String,
    pub is_verified: bool,
}

#[derive(Debug, Snafu)]
pub enum VerifyEmailError {
    /// Unknown, expired or orphaned token. All of them look the same on
    /// purpose, so the endpoint cannot be used to probe accounts.
    #[snafu(display("verification token is invalid or expired"))]
    InvalidToken,
    #[snafu(display("failed to find verification token"))]
    FindToken { source: worker::Error },
    #[snafu(display("failed to find account"))]
    FindAccount { source: worker::Error },
    #[snafu(display("failed to verify account"))]
    VerifyAccount { source: worker::Error },
}

pub struct VerifyEmailUseCase {
    pub account_repository: Arc<dyn AccountRepository>,
    pub verification_token_repository: Arc<dyn VerificationTokenRepository>,
    pub verification_token_service: Arc<dyn VerificationTokenService>,
}

impl VerifyEmailUseCase {
    pub fn new(
        account_repository: Arc<dyn AccountRepository>,
        verification_token_repository: Arc<dyn VerificationTokenRepository>,
        verification_token_service: Arc<dyn VerificationTokenService>,
    ) -> Self {
        VerifyEmailUseCase {
            account_repository,
            verification_token_repository,
            verification_token_service,
        }
    }

    pub async fn execute(
        &self,
        command: VerifyEmailCommand,
    ) -> Result<VerifyEmailResult, VerifyEmailError> {
        let token_hash = self.verification_token_service.hash(&command.token);
        let stored = self
            .verification_token_repository
            .find_token(&token_hash)
            .await
            .inspect_err(|err| log_error!("verify_email: find_token failed: {err}"))
            .context(FindTokenSnafu)?;
        let Some(stored) = stored else {
            log_warn!("verify_email: unknown token");
            return Err(VerifyEmailError::InvalidToken);
        };
        if stored.expires_at <= Timestamp::now() {
            log_warn!(
                "verify_email: expired token for account {}",
                stored.account_id
            );
            self.delete_token(&token_hash).await;
            return Err(VerifyEmailError::InvalidToken);
        }
        let account = self
            .account_repository
            .find_account_by_id(&stored.account_id)
            .await
            .inspect_err(|err| {
                log_error!(
                    "verify_email: find_account_by_id failed for {}: {err}",
                    stored.account_id
                );
            })
            .context(FindAccountSnafu)?;
        let Some(mut account) = account else {
            log_warn!(
                "verify_email: token references a missing account {}",
                stored.account_id
            );
            self.delete_token(&token_hash).await;
            return Err(VerifyEmailError::InvalidToken);
        };

        if account.is_verified() {
            log_info!(
                "verify_email: account {} was already verified",
                account.id()
            );
        } else {
            account.mark_verified();
            self.account_repository
                .update_account(&account)
                .await
                .inspect_err(|err| {
                    log_error!(
                        "verify_email: update_account failed for {}: {err}",
                        account.id()
                    );
                })
                .context(VerifyAccountSnafu)?;
            log_info!("verify_email: account {} verified", account.id());
        }

        self.delete_token(&token_hash).await;
        Ok(VerifyEmailResult {
            id: account.id(),
            email: account.email().to_owned(),
            is_verified: account.is_verified(),
        })
    }

    /// Token cleanup is best-effort: a leftover token can only re-verify an
    /// already verified account, so it must not fail the request.
    async fn delete_token(&self, token_hash: &str) {
        if let Err(err) = self
            .verification_token_repository
            .delete_token(token_hash)
            .await
        {
            log_error!("verify_email: delete_token failed: {err}");
        }
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
        domain::{
            account::Account,
            repositories::{
                account::AccountRepository, verification_token::StoredVerificationToken,
            },
            services::verification_token::{VerificationToken, VerificationTokenService},
        },
        testing::block_on,
    };

    const RAW_TOKEN: &str = "raw-token";

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
    struct MockVerificationTokenRepository {
        stored: Option<StoredVerificationToken>,
        fail_find: bool,
        fail_delete: bool,
        deleted: RefCell<Vec<String>>,
    }

    impl MockVerificationTokenRepository {
        fn with_token(account: &Account, expires_in_secs: i64) -> Self {
            MockVerificationTokenRepository {
                stored: Some(stored_token(account, expires_in_secs)),
                ..Default::default()
            }
        }

        fn deleted_tokens(&self) -> Vec<String> {
            self.deleted.borrow().clone()
        }
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
            token_hash: &str,
        ) -> Result<Option<StoredVerificationToken>, worker::Error> {
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
        Account::new("Ada Lovelace", "ada@example.com", "hashed:s3cret-pass")
    }

    fn stored_token(account: &Account, expires_in_secs: i64) -> StoredVerificationToken {
        let expires_at = if expires_in_secs >= 0 {
            Timestamp::now()
                .saturating_add(std::time::Duration::from_secs(expires_in_secs as u64))
                .expect("timestamp")
        } else {
            Timestamp::now()
                .saturating_sub(std::time::Duration::from_secs(-expires_in_secs as u64))
                .expect("timestamp")
        };
        StoredVerificationToken {
            account_id: account.id().to_string(),
            expires_at,
        }
    }

    struct Fixture {
        accounts: Arc<MockAccountRepository>,
        tokens: Arc<MockVerificationTokenRepository>,
    }

    impl Fixture {
        fn new(accounts: MockAccountRepository, tokens: MockVerificationTokenRepository) -> Self {
            Fixture {
                accounts: Arc::new(accounts),
                tokens: Arc::new(tokens),
            }
        }

        fn use_case(&self) -> VerifyEmailUseCase {
            VerifyEmailUseCase::new(
                self.accounts.clone(),
                self.tokens.clone(),
                Arc::new(MockVerificationTokenService),
            )
        }
    }

    fn command() -> VerifyEmailCommand {
        VerifyEmailCommand {
            token: RAW_TOKEN.to_owned(),
        }
    }

    #[test]
    fn verifies_account_and_deletes_the_token() {
        let account = account();
        let fixture = Fixture::new(
            MockAccountRepository::with_account(&account),
            MockVerificationTokenRepository::with_token(&account, 3600),
        );

        let result = block_on(fixture.use_case().execute(command())).expect("token is valid");

        assert!(result.is_verified);
        assert_eq!(result.email, "ada@example.com");
        assert_eq!(result.id, account.id());

        let updated = fixture.accounts.updated_accounts();
        assert_eq!(updated.len(), 1);
        assert!(updated[0].is_verified());
        assert_eq!(
            fixture.tokens.deleted_tokens(),
            vec![format!("hash:{RAW_TOKEN}")]
        );
    }

    #[test]
    fn rejects_unknown_token() {
        let account = account();
        let fixture = Fixture::new(
            MockAccountRepository::with_account(&account),
            MockVerificationTokenRepository::default(),
        );

        let error = block_on(fixture.use_case().execute(command()))
            .expect_err("unknown token must be rejected");

        assert!(matches!(error, VerifyEmailError::InvalidToken));
        assert_eq!(
            error.to_string(),
            "verification token is invalid or expired"
        );
        assert!(fixture.accounts.updated_accounts().is_empty());
        assert!(fixture.tokens.deleted_tokens().is_empty());
    }

    #[test]
    fn rejects_expired_token_and_cleans_it_up() {
        let account = account();
        let fixture = Fixture::new(
            MockAccountRepository::with_account(&account),
            MockVerificationTokenRepository::with_token(&account, -60),
        );

        let error = block_on(fixture.use_case().execute(command()))
            .expect_err("expired token must be rejected");

        assert!(matches!(error, VerifyEmailError::InvalidToken));
        assert!(fixture.accounts.updated_accounts().is_empty());
        assert_eq!(
            fixture.tokens.deleted_tokens(),
            vec![format!("hash:{RAW_TOKEN}")]
        );
    }

    #[test]
    fn rejects_token_for_a_missing_account() {
        let account = account();
        let fixture = Fixture::new(
            MockAccountRepository::default(),
            MockVerificationTokenRepository::with_token(&account, 3600),
        );

        let error = block_on(fixture.use_case().execute(command()))
            .expect_err("orphaned token must be rejected");

        assert!(matches!(error, VerifyEmailError::InvalidToken));
        assert!(fixture.accounts.updated_accounts().is_empty());
    }

    #[test]
    fn is_idempotent_for_an_already_verified_account() {
        let mut account = account();
        account.mark_verified();
        let fixture = Fixture::new(
            MockAccountRepository::with_account(&account),
            MockVerificationTokenRepository::with_token(&account, 3600),
        );

        let result = block_on(fixture.use_case().execute(command())).expect("token is valid");

        assert!(result.is_verified);
        assert!(
            fixture.accounts.updated_accounts().is_empty(),
            "an already verified account must not be written again"
        );
        assert_eq!(fixture.tokens.deleted_tokens().len(), 1);
    }

    #[test]
    fn succeeds_even_when_token_cleanup_fails() {
        let account = account();
        let fixture = Fixture::new(
            MockAccountRepository::with_account(&account),
            MockVerificationTokenRepository {
                fail_delete: true,
                ..MockVerificationTokenRepository::with_token(&account, 3600)
            },
        );

        let result = block_on(fixture.use_case().execute(command()));

        assert!(
            result.is_ok(),
            "cleanup failures must not fail verification"
        );
        assert_eq!(fixture.accounts.updated_accounts().len(), 1);
    }

    #[test]
    fn propagates_find_token_failure() {
        let account = account();
        let fixture = Fixture::new(
            MockAccountRepository::with_account(&account),
            MockVerificationTokenRepository {
                fail_find: true,
                ..Default::default()
            },
        );

        let error = block_on(fixture.use_case().execute(command()))
            .expect_err("lookup failure must surface");

        assert!(matches!(error, VerifyEmailError::FindToken { .. }));
    }

    #[test]
    fn propagates_find_account_failure() {
        let account = account();
        let fixture = Fixture::new(
            MockAccountRepository {
                fail_find: true,
                ..MockAccountRepository::with_account(&account)
            },
            MockVerificationTokenRepository::with_token(&account, 3600),
        );

        let error = block_on(fixture.use_case().execute(command()))
            .expect_err("lookup failure must surface");

        assert!(matches!(error, VerifyEmailError::FindAccount { .. }));
    }

    #[test]
    fn propagates_update_failure_and_keeps_the_token() {
        let account = account();
        let fixture = Fixture::new(
            MockAccountRepository {
                fail_update: true,
                ..MockAccountRepository::with_account(&account)
            },
            MockVerificationTokenRepository::with_token(&account, 3600),
        );

        let error = block_on(fixture.use_case().execute(command()))
            .expect_err("update failure must surface");

        assert!(matches!(error, VerifyEmailError::VerifyAccount { .. }));
        assert!(
            fixture.tokens.deleted_tokens().is_empty(),
            "the token must survive a failed update so it can be retried"
        );
    }
}
