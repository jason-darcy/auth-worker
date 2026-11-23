use std::sync::Arc;

use jiff::Timestamp;
use serde::Serialize;
use snafu::{ResultExt, Snafu};
use uuid::Uuid;

use crate::{
    domain::{
        repositories::{account::AccountRepository, refresh_token::RefreshTokenRepository},
        services::token::{IssuedTokens, TokenService},
    },
    logging::{log_error, log_info, log_warn},
};

pub struct RefreshTokensCommand {
    pub refresh_token: String,
}

#[derive(Debug, Serialize)]
pub struct RefreshTokensResult {
    pub id: Uuid,
    pub email: String,
    #[serde(flatten)]
    pub tokens: IssuedTokens,
}

#[derive(Debug, Snafu)]
pub enum RefreshTokensError {
    /// Unknown, expired or revoked token. They all look the same on purpose.
    #[snafu(display("refresh token is invalid or expired"))]
    InvalidRefreshToken,
    #[snafu(display("email is not verified"))]
    EmailNotVerified,
    #[snafu(display("failed to find refresh token"))]
    FindToken { source: worker::Error },
    #[snafu(display("failed to find account"))]
    FindAccount { source: worker::Error },
    #[snafu(display("failed to issue tokens"))]
    IssueTokens { source: worker::Error },
    #[snafu(display("failed to store refresh token"))]
    StoreRefreshToken { source: worker::Error },
}

pub struct RefreshTokensUseCase {
    pub account_repository: Arc<dyn AccountRepository>,
    pub refresh_token_repository: Arc<dyn RefreshTokenRepository>,
    pub token_service: Arc<dyn TokenService>,
}

impl RefreshTokensUseCase {
    pub fn new(
        account_repository: Arc<dyn AccountRepository>,
        refresh_token_repository: Arc<dyn RefreshTokenRepository>,
        token_service: Arc<dyn TokenService>,
    ) -> Self {
        RefreshTokensUseCase {
            account_repository,
            refresh_token_repository,
            token_service,
        }
    }

    /// Rotates the refresh token: a new pair is issued and the presented token
    /// is revoked, so a stolen refresh token is only usable once.
    pub async fn execute(
        &self,
        command: RefreshTokensCommand,
    ) -> Result<RefreshTokensResult, RefreshTokensError> {
        let token_hash = self
            .token_service
            .hash_refresh_token(&command.refresh_token);
        let stored = self
            .refresh_token_repository
            .find_token(&token_hash)
            .await
            .inspect_err(|err| log_error!("refresh: find_token failed: {err}"))
            .context(FindTokenSnafu)?;
        let Some(stored) = stored else {
            log_warn!("refresh: unknown refresh token");
            return Err(RefreshTokensError::InvalidRefreshToken);
        };
        if stored.expires_at <= Timestamp::now() {
            log_warn!(
                "refresh: expired refresh token for account {}",
                stored.account_id
            );
            self.delete_token(&token_hash).await;
            return Err(RefreshTokensError::InvalidRefreshToken);
        }
        let account = self
            .account_repository
            .find_account_by_id(&stored.account_id)
            .await
            .inspect_err(|err| {
                log_error!(
                    "refresh: find_account_by_id failed for {}: {err}",
                    stored.account_id
                );
            })
            .context(FindAccountSnafu)?;
        let Some(account) = account else {
            log_warn!(
                "refresh: token references a missing account {}",
                stored.account_id
            );
            self.delete_token(&token_hash).await;
            return Err(RefreshTokensError::InvalidRefreshToken);
        };
        if !account.is_verified() {
            log_warn!("refresh: account {} is not verified", account.id());
            return Err(RefreshTokensError::EmailNotVerified);
        }

        let account_id = account.id().to_string();
        let pair = self
            .token_service
            .issue_pair(&account_id, account.email(), account.token_version())
            .inspect_err(|err| {
                log_error!("refresh: issue tokens failed for {account_id}: {err}");
            })
            .context(IssueTokensSnafu)?;
        let new_token_hash = self.token_service.hash_refresh_token(&pair.refresh_token);
        // Store the new token before revoking the old one: a failed insert must
        // not leave the client without a usable refresh token.
        self.refresh_token_repository
            .create_token(&account_id, &new_token_hash, pair.refresh_expires_at)
            .await
            .inspect_err(|err| {
                log_error!("refresh: store refresh token failed for {account_id}: {err}");
            })
            .context(StoreRefreshTokenSnafu)?;
        self.delete_token(&token_hash).await;

        log_info!("refresh: rotated tokens for account {account_id}");
        Ok(RefreshTokensResult {
            id: account.id(),
            email: account.email().to_owned(),
            tokens: pair.into(),
        })
    }

    /// Revocation is best-effort: the presented token was already replaced, and
    /// it can only be used until it expires.
    async fn delete_token(&self, token_hash: &str) {
        if let Err(err) = self.refresh_token_repository.delete_token(token_hash).await {
            log_error!("refresh: delete_token failed: {err}");
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
            repositories::{account::AccountRepository, refresh_token::StoredRefreshToken},
            services::token::{AccessTokenClaims, TokenPair},
        },
        testing::block_on,
    };

    const RAW_TOKEN: &str = "raw-refresh-token";

    #[derive(Default)]
    struct MockAccountRepository {
        existing: Option<Account>,
        fail_find: bool,
    }

    impl MockAccountRepository {
        fn with_account(account: &Account) -> Self {
            MockAccountRepository {
                existing: Some(account.clone()),
                ..Default::default()
            }
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

        async fn update_account(&self, _account: &Account) -> Result<(), worker::Error> {
            Ok(())
        }

        async fn delete_account(&self, _id: &str) -> Result<(), worker::Error> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct MockRefreshTokenRepository {
        stored: Option<StoredRefreshToken>,
        fail_find: bool,
        fail_create: bool,
        fail_delete: bool,
        created: RefCell<Vec<(String, String, Timestamp)>>,
        deleted: RefCell<Vec<String>>,
    }

    impl MockRefreshTokenRepository {
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
            MockRefreshTokenRepository {
                stored: Some(StoredRefreshToken {
                    account_id: account.id().to_string(),
                    expires_at,
                }),
                ..Default::default()
            }
        }

        fn created_tokens(&self) -> Vec<(String, String, Timestamp)> {
            self.created.borrow().clone()
        }

        fn deleted_tokens(&self) -> Vec<String> {
            self.deleted.borrow().clone()
        }
    }

    #[async_trait(?Send)]
    impl RefreshTokenRepository for MockRefreshTokenRepository {
        async fn create_token(
            &self,
            account_id: &str,
            token_hash: &str,
            expires_at: Timestamp,
        ) -> Result<(), worker::Error> {
            if self.fail_create {
                return Err(worker::Error::RustError("d1 insert failed".to_owned()));
            }
            self.created.borrow_mut().push((
                account_id.to_owned(),
                token_hash.to_owned(),
                expires_at,
            ));
            Ok(())
        }

        async fn find_token(
            &self,
            token_hash: &str,
        ) -> Result<Option<StoredRefreshToken>, worker::Error> {
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

        async fn delete_tokens_for_account(&self, _account_id: &str) -> Result<(), worker::Error> {
            Ok(())
        }
    }

    struct MockTokenService {
        fail: bool,
        issued: RefCell<Vec<(String, String, u32)>>,
    }

    impl MockTokenService {
        fn new() -> Self {
            MockTokenService {
                fail: false,
                issued: RefCell::new(Vec::new()),
            }
        }

        fn failing() -> Self {
            MockTokenService {
                fail: true,
                ..Self::new()
            }
        }

        fn issued_for(&self) -> Vec<(String, String, u32)> {
            self.issued.borrow().clone()
        }
    }

    impl TokenService for MockTokenService {
        fn issue_pair(
            &self,
            account_id: &str,
            email: &str,
            token_version: u32,
        ) -> Result<TokenPair, worker::Error> {
            if self.fail {
                return Err(worker::Error::RustError("signing failed".to_owned()));
            }
            self.issued
                .borrow_mut()
                .push((account_id.to_owned(), email.to_owned(), token_version));
            Ok(TokenPair {
                access_token: format!("access-for-{account_id}"),
                refresh_token: "rotated-refresh-token".to_owned(),
                access_expires_at: Timestamp::now()
                    .saturating_add(std::time::Duration::from_secs(900))
                    .expect("timestamp"),
                refresh_expires_at: Timestamp::now()
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

    fn account() -> Account {
        let mut account = Account::new("Ada Lovelace", "ada@example.com", "hashed:s3cret-pass");
        account.mark_verified();
        account
    }

    struct Fixture {
        accounts: Arc<MockAccountRepository>,
        refresh_tokens: Arc<MockRefreshTokenRepository>,
        tokens: Arc<MockTokenService>,
    }

    impl Fixture {
        fn new(
            accounts: MockAccountRepository,
            refresh_tokens: MockRefreshTokenRepository,
        ) -> Self {
            Fixture {
                accounts: Arc::new(accounts),
                refresh_tokens: Arc::new(refresh_tokens),
                tokens: Arc::new(MockTokenService::new()),
            }
        }

        fn use_case(&self) -> RefreshTokensUseCase {
            RefreshTokensUseCase::new(
                self.accounts.clone(),
                self.refresh_tokens.clone(),
                self.tokens.clone(),
            )
        }
    }

    fn command() -> RefreshTokensCommand {
        RefreshTokensCommand {
            refresh_token: RAW_TOKEN.to_owned(),
        }
    }

    #[test]
    fn rotates_the_refresh_token_and_issues_a_new_pair() {
        let account = account();
        let fixture = Fixture::new(
            MockAccountRepository::with_account(&account),
            MockRefreshTokenRepository::with_token(&account, 3600),
        );

        let result = block_on(fixture.use_case().execute(command())).expect("refresh should work");

        assert_eq!(result.id, account.id());
        assert_eq!(result.email, "ada@example.com");
        assert_eq!(result.tokens.token_type, "Bearer");
        assert_eq!(
            result.tokens.access_token,
            format!("access-for-{}", account.id())
        );
        assert_eq!(result.tokens.refresh_token, "rotated-refresh-token");

        assert_eq!(
            fixture.refresh_tokens.created_tokens()[0].0,
            account.id().to_string()
        );
        assert_eq!(
            fixture.refresh_tokens.created_tokens()[0].1,
            "hash:rotated-refresh-token"
        );
        assert_eq!(
            fixture.refresh_tokens.deleted_tokens(),
            vec![format!("hash:{RAW_TOKEN}")],
            "the presented refresh token must be revoked"
        );
    }

    #[test]
    fn rejects_unknown_refresh_token() {
        let fixture = Fixture::new(
            MockAccountRepository::with_account(&account()),
            MockRefreshTokenRepository::default(),
        );

        let error =
            block_on(fixture.use_case().execute(command())).expect_err("unknown token must fail");

        assert!(matches!(error, RefreshTokensError::InvalidRefreshToken));
        assert_eq!(error.to_string(), "refresh token is invalid or expired");
        assert!(fixture.refresh_tokens.created_tokens().is_empty());
    }

    #[test]
    fn rejects_expired_refresh_token_and_revokes_it() {
        let account = account();
        let fixture = Fixture::new(
            MockAccountRepository::with_account(&account),
            MockRefreshTokenRepository::with_token(&account, -60),
        );

        let error =
            block_on(fixture.use_case().execute(command())).expect_err("expired token must fail");

        assert!(matches!(error, RefreshTokensError::InvalidRefreshToken));
        assert!(fixture.refresh_tokens.created_tokens().is_empty());
        assert_eq!(
            fixture.refresh_tokens.deleted_tokens(),
            vec![format!("hash:{RAW_TOKEN}")]
        );
    }

    #[test]
    fn rejects_token_for_a_missing_account() {
        let account = account();
        let fixture = Fixture::new(
            MockAccountRepository::default(),
            MockRefreshTokenRepository::with_token(&account, 3600),
        );

        let error =
            block_on(fixture.use_case().execute(command())).expect_err("orphaned token must fail");

        assert!(matches!(error, RefreshTokensError::InvalidRefreshToken));
        assert!(fixture.refresh_tokens.created_tokens().is_empty());
    }

    #[test]
    fn rejects_unverified_account() {
        let account = Account::new("Ada Lovelace", "ada@example.com", "hashed:s3cret-pass");
        let fixture = Fixture::new(
            MockAccountRepository::with_account(&account),
            MockRefreshTokenRepository::with_token(&account, 3600),
        );

        let error =
            block_on(fixture.use_case().execute(command())).expect_err("unverified must fail");

        assert!(matches!(error, RefreshTokensError::EmailNotVerified));
        assert!(fixture.tokens.issued_for().is_empty());
        assert!(fixture.refresh_tokens.created_tokens().is_empty());
    }

    #[test]
    fn propagates_find_token_failure() {
        let account = account();
        let fixture = Fixture::new(
            MockAccountRepository::with_account(&account),
            MockRefreshTokenRepository {
                fail_find: true,
                ..Default::default()
            },
        );

        let error = block_on(fixture.use_case().execute(command()))
            .expect_err("lookup failure must surface");

        assert!(matches!(error, RefreshTokensError::FindToken { .. }));
    }

    #[test]
    fn propagates_find_account_failure() {
        let account = account();
        let fixture = Fixture::new(
            MockAccountRepository {
                fail_find: true,
                ..MockAccountRepository::with_account(&account)
            },
            MockRefreshTokenRepository::with_token(&account, 3600),
        );

        let error = block_on(fixture.use_case().execute(command()))
            .expect_err("lookup failure must surface");

        assert!(matches!(error, RefreshTokensError::FindAccount { .. }));
    }

    #[test]
    fn propagates_token_issuance_failure_and_keeps_the_old_token() {
        let account = account();
        let fixture = Fixture {
            tokens: Arc::new(MockTokenService::failing()),
            ..Fixture::new(
                MockAccountRepository::with_account(&account),
                MockRefreshTokenRepository::with_token(&account, 3600),
            )
        };

        let error = block_on(fixture.use_case().execute(command()))
            .expect_err("issuance failure must surface");

        assert!(matches!(error, RefreshTokensError::IssueTokens { .. }));
        assert!(
            fixture.refresh_tokens.deleted_tokens().is_empty(),
            "the presented token must stay valid when issuance fails"
        );
    }

    #[test]
    fn propagates_storage_failure_and_keeps_the_old_token() {
        let account = account();
        let fixture = Fixture::new(
            MockAccountRepository::with_account(&account),
            MockRefreshTokenRepository {
                fail_create: true,
                ..MockRefreshTokenRepository::with_token(&account, 3600)
            },
        );

        let error = block_on(fixture.use_case().execute(command()))
            .expect_err("storage failure must surface");

        assert!(matches!(
            error,
            RefreshTokensError::StoreRefreshToken { .. }
        ));
        assert!(
            fixture.refresh_tokens.deleted_tokens().is_empty(),
            "the presented token must stay valid when the new one cannot be stored"
        );
    }

    #[test]
    fn succeeds_even_when_revoking_the_old_token_fails() {
        let account = account();
        let fixture = Fixture::new(
            MockAccountRepository::with_account(&account),
            MockRefreshTokenRepository {
                fail_delete: true,
                ..MockRefreshTokenRepository::with_token(&account, 3600)
            },
        );

        let result = block_on(fixture.use_case().execute(command()));

        assert!(
            result.is_ok(),
            "revocation failures must not fail the refresh"
        );
        assert_eq!(fixture.refresh_tokens.created_tokens().len(), 1);
    }
}
