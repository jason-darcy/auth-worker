use std::sync::Arc;

use serde::Serialize;
use snafu::{ensure, ResultExt, Snafu};
use uuid::Uuid;

use crate::{
    application::use_cases::second_factor::{SecondFactorError, SecondFactorVerifier},
    domain::{
        repositories::{account::AccountRepository, refresh_token::RefreshTokenRepository},
        services::hash_password::HashPasswordService,
    },
    logging::{log_error, log_info, log_warn},
};

#[derive(Debug)]
pub struct ChangePasswordCommand {
    pub account_id: Uuid,
    pub current_password: String,
    pub new_password: String,
    /// Required when the account has MFA enabled.
    pub mfa_code: Option<String>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ChangePasswordResult {
    pub id: Uuid,
    pub email: String,
    pub is_verified: bool,
}

#[derive(Debug, Snafu)]
pub enum ChangePasswordError {
    #[snafu(display("account not found"))]
    AccountNotFound,
    #[snafu(display("current password is incorrect"))]
    InvalidCurrentPassword,
    #[snafu(display("the new password must differ from the current one"))]
    PasswordUnchanged,
    #[snafu(display("failed to find account"))]
    FindAccount { source: worker::Error },
    #[snafu(display("failed to verify password"))]
    VerifyPassword {
        source: argon2::password_hash::Error,
    },
    #[snafu(display("failed to hash password"))]
    HashPassword {
        source: argon2::password_hash::Error,
    },
    #[snafu(display("failed to update account"))]
    UpdateAccount { source: worker::Error },
    #[snafu(display("second factor check failed"))]
    SecondFactor { source: SecondFactorError },
}

pub struct ChangePasswordUseCase {
    pub account_repository: Arc<dyn AccountRepository>,
    pub refresh_token_repository: Arc<dyn RefreshTokenRepository>,
    pub hash_password_service: Arc<dyn HashPasswordService>,
    pub second_factor: SecondFactorVerifier,
}

impl ChangePasswordUseCase {
    pub fn new(
        account_repository: Arc<dyn AccountRepository>,
        refresh_token_repository: Arc<dyn RefreshTokenRepository>,
        hash_password_service: Arc<dyn HashPasswordService>,
        second_factor: SecondFactorVerifier,
    ) -> Self {
        ChangePasswordUseCase {
            account_repository,
            refresh_token_repository,
            hash_password_service,
            second_factor,
        }
    }

    /// Replaces the password of an already authenticated account.
    ///
    /// The current password is required: an access token alone must not be
    /// enough to take over the account. A successful change bumps the token
    /// version and revokes every refresh token, so all sessions — including the
    /// caller's — have to sign in again.
    pub async fn execute(
        &self,
        command: ChangePasswordCommand,
    ) -> Result<ChangePasswordResult, ChangePasswordError> {
        let account_id = command.account_id.to_string();
        let account = self
            .account_repository
            .find_account_by_id(&account_id)
            .await
            .inspect_err(|err| {
                log_error!("change_password: find_account_by_id failed for {account_id}: {err}");
            })
            .context(FindAccountSnafu)?;
        let Some(mut account) = account else {
            log_warn!("change_password: account {account_id} no longer exists");
            return Err(ChangePasswordError::AccountNotFound);
        };

        let current_matches = self
            .hash_password_service
            .verify(&command.current_password, account.password_hash())
            .inspect_err(|err| {
                log_error!("change_password: verify failed for {account_id}: {err}");
            })
            .context(VerifyPasswordSnafu)?;
        ensure!(current_matches, InvalidCurrentPasswordSnafu);
        // Step-up: with MFA enabled, the password alone must not be enough to
        // take the account over from a stolen access token.
        self.second_factor
            .require(&account_id, command.mfa_code.as_deref())
            .await
            .inspect_err(|err| {
                log_warn!("change_password: second factor rejected for {account_id}: {err}");
            })
            .context(SecondFactorSnafu)?;
        ensure!(
            command.new_password != command.current_password,
            PasswordUnchangedSnafu
        );

        let password_hash = self
            .hash_password_service
            .hash(&command.new_password)
            .inspect_err(|err| {
                log_error!("change_password: hash failed for {account_id}: {err}");
            })
            .context(HashPasswordSnafu)?;
        account.change_password(&password_hash);
        // Invalidates every access token issued before the change.
        account.bump_token_version();
        self.account_repository
            .update_account(&account)
            .await
            .inspect_err(|err| {
                log_error!("change_password: update_account failed for {account_id}: {err}");
            })
            .context(UpdateAccountSnafu)?;

        self.revoke_sessions(&account_id).await;

        log_info!("change_password: password changed for account {account_id}");
        Ok(ChangePasswordResult {
            id: account.id(),
            email: account.email().to_owned(),
            is_verified: account.is_verified(),
        })
    }

    /// Revocation is best-effort: the password is already changed and the token
    /// version bumped, so failing the request would only confuse the user.
    async fn revoke_sessions(&self, account_id: &str) {
        if let Err(err) = self
            .refresh_token_repository
            .delete_tokens_for_account(account_id)
            .await
        {
            log_error!("change_password: revoking sessions failed for {account_id}: {err}");
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
            repositories::refresh_token::{NewRefreshToken, SessionInfo, StoredRefreshToken},
        },
        testing::block_on,
    };

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
        revoked: RefCell<Vec<String>>,
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

        async fn list_sessions(
            &self,
            _account_id: &str,
        ) -> Result<Vec<SessionInfo>, worker::Error> {
            Ok(Vec::new())
        }

        async fn delete_tokens_for_account(&self, account_id: &str) -> Result<(), worker::Error> {
            if self.fail {
                return Err(worker::Error::RustError("d1 delete failed".to_owned()));
            }
            self.revoked.borrow_mut().push(account_id.to_owned());
            Ok(())
        }

        async fn delete_expired(&self, _now: jiff::Timestamp) -> Result<u32, worker::Error> {
            Ok(0)
        }
    }

    struct MockHashPasswordService {
        current_matches: bool,
        fail_verify: bool,
    }

    impl MockHashPasswordService {
        fn matching() -> Self {
            MockHashPasswordService {
                current_matches: true,
                fail_verify: false,
            }
        }

        fn not_matching() -> Self {
            MockHashPasswordService {
                current_matches: false,
                ..Self::matching()
            }
        }
    }

    impl HashPasswordService for MockHashPasswordService {
        fn hash(&self, password: &str) -> Result<String, PasswordHashError> {
            Ok(format!("hashed:{password}"))
        }

        fn verify(&self, _password: &str, _password_hash: &str) -> Result<bool, PasswordHashError> {
            if self.fail_verify {
                return Err(PasswordHashError::Crypto);
            }
            Ok(self.current_matches)
        }

        fn verify_dummy(&self, _password: &str) {}
    }

    struct Fixture {
        accounts: Arc<MockAccountRepository>,
        refresh_tokens: Arc<MockRefreshTokenRepository>,
        hasher: Arc<MockHashPasswordService>,
        mfa_enabled: bool,
    }

    impl Fixture {
        fn new(accounts: MockAccountRepository) -> Self {
            Fixture {
                accounts: Arc::new(accounts),
                refresh_tokens: Arc::new(MockRefreshTokenRepository::default()),
                hasher: Arc::new(MockHashPasswordService::matching()),
                mfa_enabled: false,
            }
        }

        fn with_mfa(accounts: MockAccountRepository) -> Self {
            Fixture {
                mfa_enabled: true,
                ..Self::new(accounts)
            }
        }

        fn second_factor(&self) -> SecondFactorVerifier {
            if self.mfa_enabled {
                crate::testing::mfa_verifier()
            } else {
                crate::testing::no_mfa_verifier()
            }
        }

        fn use_case(&self) -> ChangePasswordUseCase {
            ChangePasswordUseCase::new(
                self.accounts.clone(),
                self.refresh_tokens.clone(),
                self.hasher.clone(),
                self.second_factor(),
            )
        }
    }

    fn account() -> Account {
        Account::new("Ada Lovelace", "ada@example.com", "hashed:old-password")
    }

    fn command(account: &Account) -> ChangePasswordCommand {
        ChangePasswordCommand {
            account_id: account.id(),
            current_password: "old-password".to_owned(),
            new_password: "new-password".to_owned(),
            mfa_code: None,
        }
    }

    #[test]
    fn replaces_the_password_and_bumps_the_token_version() {
        let account = account();
        let fixture = Fixture::new(MockAccountRepository::with_account(&account));

        let result =
            block_on(fixture.use_case().execute(command(&account))).expect("change should succeed");

        assert_eq!(result.email, "ada@example.com");
        let updates = fixture.accounts.updates.borrow();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].password_hash(), "hashed:new-password");
        assert_eq!(updates[0].token_version(), 1);
    }

    #[test]
    fn revokes_every_session() {
        let account = account();
        let fixture = Fixture::new(MockAccountRepository::with_account(&account));

        block_on(fixture.use_case().execute(command(&account))).expect("change should succeed");

        assert_eq!(
            *fixture.refresh_tokens.revoked.borrow(),
            vec![account.id().to_string()]
        );
    }

    #[test]
    fn rejects_a_wrong_current_password() {
        let account = account();
        let fixture = Fixture {
            hasher: Arc::new(MockHashPasswordService::not_matching()),
            ..Fixture::new(MockAccountRepository::with_account(&account))
        };

        let error = block_on(fixture.use_case().execute(command(&account)))
            .expect_err("wrong password must fail");

        assert!(matches!(error, ChangePasswordError::InvalidCurrentPassword));
        assert!(fixture.accounts.updates.borrow().is_empty());
        assert!(fixture.refresh_tokens.revoked.borrow().is_empty());
    }

    #[test]
    fn rejects_reusing_the_current_password() {
        let account = account();
        let fixture = Fixture::new(MockAccountRepository::with_account(&account));
        let mut command = command(&account);
        command.new_password = "old-password".to_owned();

        let error =
            block_on(fixture.use_case().execute(command)).expect_err("reuse must be rejected");

        assert!(matches!(error, ChangePasswordError::PasswordUnchanged));
        assert!(fixture.accounts.updates.borrow().is_empty());
    }

    #[test]
    fn demands_a_code_when_mfa_is_enabled() {
        let account = account();
        let fixture = Fixture::with_mfa(MockAccountRepository::with_account(&account));

        let error = block_on(fixture.use_case().execute(command(&account)))
            .expect_err("a step-up code is required");

        assert!(matches!(
            error,
            ChangePasswordError::SecondFactor {
                source: SecondFactorError::CodeRequired
            }
        ));
        assert!(fixture.accounts.updates.borrow().is_empty());
        assert!(fixture.refresh_tokens.revoked.borrow().is_empty());
    }

    #[test]
    fn accepts_a_valid_step_up_code() {
        let account = account();
        let fixture = Fixture::with_mfa(MockAccountRepository::with_account(&account));
        let mut command = command(&account);
        command.mfa_code = Some(crate::testing::ACCEPTED_CODE.to_owned());

        block_on(fixture.use_case().execute(command)).expect("change should succeed");

        assert_eq!(fixture.accounts.updates.borrow().len(), 1);
    }

    #[test]
    fn rejects_a_wrong_step_up_code() {
        let account = account();
        let fixture = Fixture::with_mfa(MockAccountRepository::with_account(&account));
        let mut command = command(&account);
        command.mfa_code = Some("000000".to_owned());

        let error =
            block_on(fixture.use_case().execute(command)).expect_err("wrong code must fail");

        assert!(matches!(
            error,
            ChangePasswordError::SecondFactor {
                source: SecondFactorError::InvalidCode
            }
        ));
        assert!(fixture.accounts.updates.borrow().is_empty());
    }

    #[test]
    fn reports_a_missing_account() {
        let account = account();
        let fixture = Fixture::new(MockAccountRepository::default());

        let error = block_on(fixture.use_case().execute(command(&account)))
            .expect_err("missing account must fail");

        assert!(matches!(error, ChangePasswordError::AccountNotFound));
    }

    #[test]
    fn propagates_verification_failures() {
        let account = account();
        let fixture = Fixture {
            hasher: Arc::new(MockHashPasswordService {
                current_matches: true,
                fail_verify: true,
            }),
            ..Fixture::new(MockAccountRepository::with_account(&account))
        };

        let error = block_on(fixture.use_case().execute(command(&account)))
            .expect_err("verification failure must surface");

        assert!(matches!(error, ChangePasswordError::VerifyPassword { .. }));
    }

    #[test]
    fn propagates_update_failures() {
        let account = account();
        let fixture = Fixture::new(MockAccountRepository {
            fail_update: true,
            ..MockAccountRepository::with_account(&account)
        });

        let error = block_on(fixture.use_case().execute(command(&account)))
            .expect_err("update failure must surface");

        assert!(matches!(error, ChangePasswordError::UpdateAccount { .. }));
        assert!(
            fixture.refresh_tokens.revoked.borrow().is_empty(),
            "sessions must survive a failed password change"
        );
    }

    #[test]
    fn still_succeeds_when_revocation_fails() {
        let account = account();
        let fixture = Fixture {
            refresh_tokens: Arc::new(MockRefreshTokenRepository {
                fail: true,
                ..Default::default()
            }),
            ..Fixture::new(MockAccountRepository::with_account(&account))
        };

        assert!(block_on(fixture.use_case().execute(command(&account))).is_ok());
        assert_eq!(fixture.accounts.updates.borrow().len(), 1);
    }
}
