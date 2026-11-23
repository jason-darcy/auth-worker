use std::sync::Arc;

use jiff::Timestamp;
use serde::Serialize;
use snafu::{ResultExt, Snafu};
use uuid::Uuid;

use crate::{
    domain::{
        client::ClientInfo,
        repositories::{
            account::AccountRepository,
            refresh_token::{NewRefreshToken, RefreshTokenRepository},
        },
        services::token::{IssuedTokens, TokenService},
    },
    logging::{log_error, log_info, log_warn},
};

pub struct RefreshTokensCommand {
    pub refresh_token: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
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
    /// is retired, so a stolen refresh token is only usable once.
    ///
    /// Presenting an already rotated token means somebody replayed it, so the
    /// whole session (token family) is revoked instead of only rejecting the
    /// request.
    pub async fn execute(
        &self,
        command: RefreshTokensCommand,
        client: &ClientInfo,
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
        if let Some(rotated_at) = stored.rotated_at {
            log_warn!(
                "refresh: replayed refresh token of account {} (session {}), revoking the session; rotated at {rotated_at}",
                stored.account_id,
                stored.family_id
            );
            self.revoke_session(&stored.account_id, &stored.family_id)
                .await;
            return Err(RefreshTokensError::InvalidRefreshToken);
        }
        if stored.expires_at <= Timestamp::now() {
            log_warn!(
                "refresh: expired refresh token for account {}",
                stored.account_id
            );
            self.revoke_session(&stored.account_id, &stored.family_id)
                .await;
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
            self.revoke_session(&stored.account_id, &stored.family_id)
                .await;
            return Err(RefreshTokensError::InvalidRefreshToken);
        };
        if !account.is_verified() {
            log_warn!("refresh: account {} is not verified", account.id());
            return Err(RefreshTokensError::EmailNotVerified);
        }

        let account_id = account.id().to_string();
        let pair = self
            .token_service
            .issue_pair(
                &account_id,
                account.email(),
                account.token_version(),
                &stored.family_id,
            )
            .inspect_err(|err| {
                log_error!("refresh: issue tokens failed for {account_id}: {err}");
            })
            .context(IssueTokensSnafu)?;
        let new_token_hash = self.token_service.hash_refresh_token(&pair.refresh_token);
        // The rotation keeps the old row (marked as rotated) so a replay is
        // detectable, and stores the successor in the same transaction.
        self.refresh_token_repository
            .rotate_token(
                &token_hash,
                NewRefreshToken {
                    account_id: account_id.clone(),
                    token_hash: new_token_hash,
                    family_id: stored.family_id,
                    expires_at: pair.refresh_expires_at,
                    user_agent: client.user_agent.clone(),
                    ip: client.ip.clone(),
                },
            )
            .await
            .inspect_err(|err| {
                log_error!("refresh: rotate_token failed for {account_id}: {err}");
            })
            .context(StoreRefreshTokenSnafu)?;

        log_info!("refresh: rotated tokens for account {account_id}");
        Ok(RefreshTokensResult {
            id: account.id(),
            email: account.email().to_owned(),
            tokens: pair.into(),
        })
    }

    /// Revocation is best-effort: the presented token is already unusable, and
    /// failing the request differently would leak that a replay was detected.
    async fn revoke_session(&self, account_id: &str, session_id: &str) {
        if let Err(err) = self
            .refresh_token_repository
            .delete_session(account_id, session_id)
            .await
        {
            log_error!("refresh: revoking session {session_id} failed: {err}");
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
                account::AccountRepository,
                refresh_token::{NewRefreshToken, SessionInfo, StoredRefreshToken},
            },
            services::token::{AccessTokenClaims, TokenPair},
        },
        testing::block_on,
    };

    const RAW_TOKEN: &str = "raw-refresh-token";
    const FAMILY_ID: &str = "session-id";

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
        fail_rotate: bool,
        fail_delete: bool,
        rotated: RefCell<Vec<NewRefreshToken>>,
        deleted_sessions: RefCell<Vec<(String, String)>>,
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
                    family_id: FAMILY_ID.to_owned(),
                    expires_at,
                    rotated_at: None,
                }),
                ..Default::default()
            }
        }

        fn created_tokens(&self) -> Vec<NewRefreshToken> {
            self.rotated.borrow().clone()
        }

        fn deleted_sessions(&self) -> Vec<(String, String)> {
            self.deleted_sessions.borrow().clone()
        }
    }

    #[async_trait(?Send)]
    impl RefreshTokenRepository for MockRefreshTokenRepository {
        async fn create_token(&self, _token: NewRefreshToken) -> Result<(), worker::Error> {
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

        async fn rotate_token(
            &self,
            old_token_hash: &str,
            next: NewRefreshToken,
        ) -> Result<(), worker::Error> {
            if self.fail_rotate {
                return Err(worker::Error::RustError("d1 insert failed".to_owned()));
            }
            assert_eq!(old_token_hash, format!("hash:{RAW_TOKEN}"));
            self.rotated.borrow_mut().push(next);
            Ok(())
        }

        async fn delete_session(
            &self,
            account_id: &str,
            family_id: &str,
        ) -> Result<bool, worker::Error> {
            if self.fail_delete {
                return Err(worker::Error::RustError("d1 delete failed".to_owned()));
            }
            self.deleted_sessions
                .borrow_mut()
                .push((account_id.to_owned(), family_id.to_owned()));
            Ok(true)
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
            _session_id: &str,
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

        let result = block_on(
            fixture
                .use_case()
                .execute(command(), &ClientInfo::default()),
        )
        .expect("refresh should work");

        assert_eq!(result.id, account.id());
        assert_eq!(result.email, "ada@example.com");
        assert_eq!(result.tokens.token_type, "Bearer");
        assert_eq!(
            result.tokens.access_token,
            format!("access-for-{}", account.id())
        );
        assert_eq!(result.tokens.refresh_token, "rotated-refresh-token");

        let created = fixture.refresh_tokens.created_tokens();
        assert_eq!(created.len(), 1);
        assert_eq!(created[0].account_id, account.id().to_string());
        assert_eq!(created[0].token_hash, "hash:rotated-refresh-token");
        assert_eq!(
            created[0].family_id, FAMILY_ID,
            "rotation must stay in the same session"
        );
        assert!(
            fixture.refresh_tokens.deleted_sessions().is_empty(),
            "a successful rotation must not revoke the session"
        );
    }

    #[test]
    fn rejects_unknown_refresh_token() {
        let fixture = Fixture::new(
            MockAccountRepository::with_account(&account()),
            MockRefreshTokenRepository::default(),
        );

        let error = block_on(
            fixture
                .use_case()
                .execute(command(), &ClientInfo::default()),
        )
        .expect_err("unknown token must fail");

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

        let error = block_on(
            fixture
                .use_case()
                .execute(command(), &ClientInfo::default()),
        )
        .expect_err("expired token must fail");

        assert!(matches!(error, RefreshTokensError::InvalidRefreshToken));
        assert!(fixture.refresh_tokens.created_tokens().is_empty());
        assert_eq!(
            fixture.refresh_tokens.deleted_sessions(),
            vec![(account.id().to_string(), FAMILY_ID.to_owned())],
            "an expired session must be revoked"
        );
    }

    #[test]
    fn rejects_token_for_a_missing_account() {
        let account = account();
        let fixture = Fixture::new(
            MockAccountRepository::default(),
            MockRefreshTokenRepository::with_token(&account, 3600),
        );

        let error = block_on(
            fixture
                .use_case()
                .execute(command(), &ClientInfo::default()),
        )
        .expect_err("orphaned token must fail");

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

        let error = block_on(
            fixture
                .use_case()
                .execute(command(), &ClientInfo::default()),
        )
        .expect_err("unverified must fail");

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

        let error = block_on(
            fixture
                .use_case()
                .execute(command(), &ClientInfo::default()),
        )
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

        let error = block_on(
            fixture
                .use_case()
                .execute(command(), &ClientInfo::default()),
        )
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

        let error = block_on(
            fixture
                .use_case()
                .execute(command(), &ClientInfo::default()),
        )
        .expect_err("issuance failure must surface");

        assert!(matches!(error, RefreshTokensError::IssueTokens { .. }));
        assert!(
            fixture.refresh_tokens.created_tokens().is_empty(),
            "the presented token must stay valid when issuance fails"
        );
    }

    #[test]
    fn propagates_storage_failure_and_keeps_the_old_token() {
        let account = account();
        let fixture = Fixture::new(
            MockAccountRepository::with_account(&account),
            MockRefreshTokenRepository {
                fail_rotate: true,
                ..MockRefreshTokenRepository::with_token(&account, 3600)
            },
        );

        let error = block_on(
            fixture
                .use_case()
                .execute(command(), &ClientInfo::default()),
        )
        .expect_err("storage failure must surface");

        assert!(matches!(
            error,
            RefreshTokensError::StoreRefreshToken { .. }
        ));
        assert!(
            fixture.refresh_tokens.created_tokens().is_empty(),
            "the presented token must stay valid when the new one cannot be stored"
        );
    }

    #[test]
    fn rejects_a_replayed_token_and_revokes_the_whole_session() {
        let account = account();
        let mut replayed = MockRefreshTokenRepository::with_token(&account, 3600);
        replayed.stored.as_mut().expect("stored").rotated_at = Some(Timestamp::now());
        let fixture = Fixture::new(MockAccountRepository::with_account(&account), replayed);

        let error = block_on(
            fixture
                .use_case()
                .execute(command(), &ClientInfo::default()),
        )
        .expect_err("a replayed token must be rejected");

        assert!(matches!(error, RefreshTokensError::InvalidRefreshToken));
        assert!(
            fixture.refresh_tokens.created_tokens().is_empty(),
            "a replay must not mint new tokens"
        );
        assert_eq!(
            fixture.refresh_tokens.deleted_sessions(),
            vec![(account.id().to_string(), FAMILY_ID.to_owned())],
            "a replay must revoke every token of the session"
        );
        assert!(fixture.tokens.issued_for().is_empty());
    }

    #[test]
    fn succeeds_even_when_revoking_a_broken_session_fails() {
        let account = account();
        let mut expired = MockRefreshTokenRepository::with_token(&account, -60);
        expired.fail_delete = true;
        let fixture = Fixture::new(MockAccountRepository::with_account(&account), expired);

        let error = block_on(
            fixture
                .use_case()
                .execute(command(), &ClientInfo::default()),
        )
        .expect_err("expired token must fail");

        assert!(
            matches!(error, RefreshTokensError::InvalidRefreshToken),
            "a failed revocation must not change the response"
        );
    }
}
