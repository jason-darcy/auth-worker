use std::sync::Arc;

use snafu::{ResultExt, Snafu};

use crate::{
    domain::{
        repositories::{account::AccountRepository, refresh_token::RefreshTokenRepository},
        services::token::TokenService,
    },
    logging::{log_error, log_info, log_warn},
};

pub struct SignOutCommand {
    pub refresh_token: String,
}

#[derive(Debug, Snafu)]
pub enum SignOutError {
    #[snafu(display("failed to revoke refresh token"))]
    RevokeToken { source: worker::Error },
    #[snafu(display("failed to find account"))]
    FindAccount { source: worker::Error },
    #[snafu(display("failed to update account"))]
    UpdateAccount { source: worker::Error },
}

pub struct SignOutUseCase {
    pub account_repository: Arc<dyn AccountRepository>,
    pub refresh_token_repository: Arc<dyn RefreshTokenRepository>,
    pub token_service: Arc<dyn TokenService>,
}

impl SignOutUseCase {
    pub fn new(
        account_repository: Arc<dyn AccountRepository>,
        refresh_token_repository: Arc<dyn RefreshTokenRepository>,
        token_service: Arc<dyn TokenService>,
    ) -> Self {
        SignOutUseCase {
            account_repository,
            refresh_token_repository,
            token_service,
        }
    }

    /// Revokes the session the presented refresh token belongs to.
    ///
    /// Signing out is idempotent and must not reveal anything: an unknown or
    /// already rotated token is not an error, so the endpoint cannot be used to
    /// probe which tokens exist.
    pub async fn execute(&self, command: SignOutCommand) -> Result<(), SignOutError> {
        let token_hash = self
            .token_service
            .hash_refresh_token(&command.refresh_token);
        let stored = self
            .refresh_token_repository
            .find_token(&token_hash)
            .await
            .inspect_err(|err| log_error!("signout: find_token failed: {err}"))
            .context(RevokeTokenSnafu)?;
        let Some(stored) = stored else {
            log_info!("signout: unknown refresh token, nothing to revoke");
            return Ok(());
        };
        self.refresh_token_repository
            .delete_session(&stored.account_id, &stored.family_id)
            .await
            .inspect_err(|err| log_error!("signout: delete_session failed: {err}"))
            .context(RevokeTokenSnafu)?;
        log_info!("signout: session {} revoked", stored.family_id);
        Ok(())
    }

    /// Revokes every session of an account.
    ///
    /// The refresh tokens are deleted first: if the follow-up account update
    /// fails, no client can still mint tokens, and only access tokens issued
    /// before the request stay valid until they expire.
    pub async fn execute_all(&self, account_id: &str) -> Result<(), SignOutError> {
        self.refresh_token_repository
            .delete_tokens_for_account(account_id)
            .await
            .inspect_err(|err| {
                log_error!("signout_all: revoking tokens failed for {account_id}: {err}");
            })
            .context(RevokeTokenSnafu)?;

        let account = self
            .account_repository
            .find_account_by_id(account_id)
            .await
            .inspect_err(|err| {
                log_error!("signout_all: find_account_by_id failed for {account_id}: {err}");
            })
            .context(FindAccountSnafu)?;
        let Some(mut account) = account else {
            // The account is gone, so there is nothing left to invalidate.
            log_warn!("signout_all: account {account_id} no longer exists");
            return Ok(());
        };

        // Invalidates every access token issued so far.
        account.bump_token_version();
        self.account_repository
            .update_account(&account)
            .await
            .inspect_err(|err| {
                log_error!("signout_all: update_account failed for {account_id}: {err}");
            })
            .context(UpdateAccountSnafu)?;

        log_info!("signout_all: revoked every session of {account_id}");
        Ok(())
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
                refresh_token::{
                    NewRefreshToken, RefreshTokenRepository, SessionInfo, StoredRefreshToken,
                },
            },
            services::token::{AccessTokenClaims, TokenPair},
        },
        testing::block_on,
    };

    const RAW_TOKEN: &str = "raw-refresh-token";

    #[derive(Default)]
    struct MockAccountRepository {
        existing: Option<Account>,
        updates: RefCell<Vec<Account>>,
        fail_update: bool,
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
            self.updates.borrow_mut().push(account.clone());
            Ok(())
        }

        async fn delete_account(&self, _id: &str) -> Result<(), worker::Error> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct MockRefreshTokenRepository {
        /// Token rows the repository still knows about.
        stored: Option<StoredRefreshToken>,
        deleted: RefCell<Vec<(String, String)>>,
        deleted_for_account: RefCell<Vec<String>>,
        fail_delete: bool,
    }

    impl MockRefreshTokenRepository {
        fn with_token(account: &Account, family_id: &str) -> Self {
            MockRefreshTokenRepository {
                stored: Some(StoredRefreshToken {
                    account_id: account.id().to_string(),
                    family_id: family_id.to_owned(),
                    expires_at: jiff::Timestamp::now()
                        .saturating_add(std::time::Duration::from_secs(3600))
                        .expect("timestamp"),
                    rotated_at: None,
                }),
                ..Default::default()
            }
        }
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
            Ok(self.stored.clone())
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
            account_id: &str,
            family_id: &str,
        ) -> Result<bool, worker::Error> {
            if self.fail_delete {
                return Err(worker::Error::RustError("d1 delete failed".to_owned()));
            }
            self.deleted
                .borrow_mut()
                .push((account_id.to_owned(), family_id.to_owned()));
            Ok(true)
        }

        async fn list_sessions(
            &self,
            _account_id: &str,
        ) -> Result<Vec<SessionInfo>, worker::Error> {
            Ok(Vec::new())
        }

        async fn delete_tokens_for_account(&self, account_id: &str) -> Result<(), worker::Error> {
            if self.fail_delete {
                return Err(worker::Error::RustError("d1 delete failed".to_owned()));
            }
            self.deleted_for_account
                .borrow_mut()
                .push(account_id.to_owned());
            Ok(())
        }

        async fn delete_expired(&self, _now: jiff::Timestamp) -> Result<u32, worker::Error> {
            Ok(0)
        }
    }

    #[derive(Debug)]
    struct MockTokenService;

    impl TokenService for MockTokenService {
        fn issue_pair(
            &self,
            _account_id: &str,
            _email: &str,
            _token_version: u32,
            _session_id: &str,
        ) -> Result<TokenPair, worker::Error> {
            unimplemented!("signout never issues tokens")
        }

        fn decode_access_token(&self, _token: &str) -> Result<AccessTokenClaims, worker::Error> {
            unimplemented!("signout never decodes tokens")
        }

        fn hash_refresh_token(&self, token: &str) -> String {
            format!("hashed:{token}")
        }
    }

    #[test]
    fn revokes_the_session_of_the_presented_refresh_token() {
        let account = Account::new("Ada Lovelace", "ada@example.com", "hashed");
        let accounts = Arc::new(MockAccountRepository::default());
        let refresh_tokens = Arc::new(MockRefreshTokenRepository::with_token(
            &account,
            "session-a",
        ));

        let use_case =
            SignOutUseCase::new(accounts, refresh_tokens.clone(), Arc::new(MockTokenService));

        block_on(use_case.execute(SignOutCommand {
            refresh_token: RAW_TOKEN.to_owned(),
        }))
        .expect("signout should succeed");

        assert_eq!(
            *refresh_tokens.deleted.borrow(),
            vec![(account.id().to_string(), "session-a".to_owned())],
            "signing out must end the whole session, not just one token"
        );
    }

    #[test]
    fn unknown_tokens_are_not_an_error() {
        let accounts = MockAccountRepository::default();
        let refresh_tokens = MockRefreshTokenRepository::default();

        let use_case = SignOutUseCase::new(
            Arc::new(accounts),
            Arc::new(refresh_tokens),
            Arc::new(MockTokenService),
        );

        assert!(
            block_on(use_case.execute(SignOutCommand {
                refresh_token: RAW_TOKEN.to_owned(),
            }))
            .is_ok(),
            "signout must be idempotent"
        );
    }

    #[test]
    fn surfaces_storage_failures() {
        let account = Account::new("Ada Lovelace", "ada@example.com", "hashed");
        let accounts = MockAccountRepository::default();
        let refresh_tokens = MockRefreshTokenRepository {
            fail_delete: true,
            ..MockRefreshTokenRepository::with_token(&account, "session-a")
        };

        let use_case = SignOutUseCase::new(
            Arc::new(accounts),
            Arc::new(refresh_tokens),
            Arc::new(MockTokenService),
        );

        let error = block_on(use_case.execute(SignOutCommand {
            refresh_token: RAW_TOKEN.to_owned(),
        }))
        .expect_err("failure should surface");

        assert!(matches!(error, SignOutError::RevokeToken { .. }));
    }

    #[test]
    fn signs_out_every_session_and_bumps_the_token_version() {
        let account = Account::new("Ada Lovelace", "ada@example.com", "hashed");
        let account_id = account.id().to_string();
        let accounts = Arc::new(MockAccountRepository::with_account(&account));
        let refresh_tokens = Arc::new(MockRefreshTokenRepository::default());

        let use_case = SignOutUseCase::new(
            accounts.clone(),
            refresh_tokens.clone(),
            Arc::new(MockTokenService),
        );

        block_on(use_case.execute_all(&account_id)).expect("signout all should succeed");

        assert_eq!(
            *refresh_tokens.deleted_for_account.borrow(),
            vec![account_id.clone()]
        );
        let updated = accounts.updates.borrow();
        assert_eq!(updated.len(), 1);
        assert_eq!(updated[0].token_version(), 1);
    }

    #[test]
    fn signs_out_all_is_a_noop_for_a_missing_account() {
        let accounts = Arc::new(MockAccountRepository::default());
        let refresh_tokens = Arc::new(MockRefreshTokenRepository::default());

        let use_case =
            SignOutUseCase::new(accounts, refresh_tokens.clone(), Arc::new(MockTokenService));

        block_on(use_case.execute_all(&uuid::Uuid::nil().to_string()))
            .expect("signout all should succeed");

        assert_eq!(refresh_tokens.deleted_for_account.borrow().len(), 1);
    }

    #[test]
    fn signs_out_all_stops_when_tokens_cannot_be_revoked() {
        let account = Account::new("Ada Lovelace", "ada@example.com", "hashed");
        let accounts = Arc::new(MockAccountRepository::with_account(&account));
        let refresh_tokens = Arc::new(MockRefreshTokenRepository {
            fail_delete: true,
            ..Default::default()
        });

        let use_case =
            SignOutUseCase::new(accounts.clone(), refresh_tokens, Arc::new(MockTokenService));

        let error = block_on(use_case.execute_all(&account.id().to_string()))
            .expect_err("failure should surface");

        assert!(matches!(error, SignOutError::RevokeToken { .. }));
        assert!(
            accounts.updates.borrow().is_empty(),
            "the account must not be updated when revocation failed"
        );
    }

    #[test]
    fn signs_out_all_surfaces_account_update_failures() {
        let account = Account::new("Ada Lovelace", "ada@example.com", "hashed");
        let accounts = Arc::new(MockAccountRepository {
            fail_update: true,
            ..MockAccountRepository::with_account(&account)
        });
        let refresh_tokens = Arc::new(MockRefreshTokenRepository::default());

        let use_case = SignOutUseCase::new(accounts, refresh_tokens, Arc::new(MockTokenService));

        let error = block_on(use_case.execute_all(&account.id().to_string()))
            .expect_err("failure should surface");

        assert!(matches!(error, SignOutError::UpdateAccount { .. }));
    }
}
