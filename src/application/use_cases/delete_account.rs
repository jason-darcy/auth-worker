use std::sync::Arc;

use snafu::{ensure, ResultExt, Snafu};
use uuid::Uuid;

use crate::{
    application::use_cases::second_factor::{SecondFactorError, SecondFactorVerifier},
    domain::{
        repositories::account::AccountRepository, services::hash_password::HashPasswordService,
    },
    logging::{log_error, log_info, log_warn},
};

#[derive(Debug)]
pub struct DeleteAccountCommand {
    pub account_id: Uuid,
    pub password: String,
    /// Required when the account has MFA enabled.
    pub mfa_code: Option<String>,
}

#[derive(Debug, Snafu)]
pub enum DeleteAccountError {
    #[snafu(display("account not found"))]
    AccountNotFound,
    #[snafu(display("password is incorrect"))]
    InvalidPassword,
    #[snafu(display("failed to find account"))]
    FindAccount { source: worker::Error },
    #[snafu(display("failed to verify password"))]
    VerifyPassword {
        source: argon2::password_hash::Error,
    },
    #[snafu(display("failed to delete account"))]
    DeleteAccount { source: worker::Error },
    #[snafu(display("second factor check failed"))]
    SecondFactor { source: SecondFactorError },
}

pub struct DeleteAccountUseCase {
    pub account_repository: Arc<dyn AccountRepository>,
    pub hash_password_service: Arc<dyn HashPasswordService>,
    pub second_factor: SecondFactorVerifier,
}

impl DeleteAccountUseCase {
    pub fn new(
        account_repository: Arc<dyn AccountRepository>,
        hash_password_service: Arc<dyn HashPasswordService>,
        second_factor: SecondFactorVerifier,
    ) -> Self {
        DeleteAccountUseCase {
            account_repository,
            hash_password_service,
            second_factor,
        }
    }

    /// Permanently deletes the account behind an access token.
    ///
    /// The password is required so a stolen access token alone cannot destroy
    /// the account. Every token row is removed by the `ON DELETE CASCADE` on the
    /// token tables.
    pub async fn execute(&self, command: DeleteAccountCommand) -> Result<(), DeleteAccountError> {
        let account_id = command.account_id.to_string();
        let account = self
            .account_repository
            .find_account_by_id(&account_id)
            .await
            .inspect_err(|err| {
                log_error!("delete_account: find_account_by_id failed for {account_id}: {err}");
            })
            .context(FindAccountSnafu)?;
        let Some(account) = account else {
            log_warn!("delete_account: account {account_id} no longer exists");
            return Err(DeleteAccountError::AccountNotFound);
        };

        let password_matches = self
            .hash_password_service
            .verify(&command.password, account.password_hash())
            .inspect_err(|err| {
                log_error!("delete_account: verify failed for {account_id}: {err}");
            })
            .context(VerifyPasswordSnafu)?;
        ensure!(password_matches, InvalidPasswordSnafu);
        // Step-up: with MFA enabled, deleting the account needs a second factor.
        self.second_factor
            .require(&account_id, command.mfa_code.as_deref())
            .await
            .inspect_err(|err| {
                log_warn!("delete_account: second factor rejected for {account_id}: {err}");
            })
            .context(SecondFactorSnafu)?;

        self.account_repository
            .delete_account(&account_id)
            .await
            .inspect_err(|err| {
                log_error!("delete_account: delete_account failed for {account_id}: {err}");
            })
            .context(DeleteAccountSnafu)?;

        log_info!("delete_account: account {account_id} deleted");
        Ok(())
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
    use crate::{domain::account::Account, testing::block_on};

    #[derive(Default)]
    struct MockAccountRepository {
        existing: Option<Account>,
        deleted: RefCell<Vec<String>>,
        fail_delete: bool,
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

        async fn update_account(&self, _account: &Account) -> Result<(), worker::Error> {
            Ok(())
        }

        async fn delete_account(&self, id: &str) -> Result<(), worker::Error> {
            if self.fail_delete {
                return Err(worker::Error::RustError("d1 delete failed".to_owned()));
            }
            self.deleted.borrow_mut().push(id.to_owned());
            Ok(())
        }
    }

    struct MockHashPasswordService {
        password_matches: bool,
        fail_verify: bool,
    }

    impl HashPasswordService for MockHashPasswordService {
        fn hash(&self, password: &str) -> Result<String, PasswordHashError> {
            Ok(format!("hashed:{password}"))
        }

        fn verify(&self, _password: &str, _password_hash: &str) -> Result<bool, PasswordHashError> {
            if self.fail_verify {
                return Err(PasswordHashError::Crypto);
            }
            Ok(self.password_matches)
        }

        fn verify_dummy(&self, _password: &str) {}
    }

    struct Fixture {
        accounts: Arc<MockAccountRepository>,
        hasher: Arc<MockHashPasswordService>,
        mfa_enabled: bool,
    }

    impl Fixture {
        fn new(accounts: MockAccountRepository) -> Self {
            Fixture {
                accounts: Arc::new(accounts),
                hasher: Arc::new(MockHashPasswordService {
                    password_matches: true,
                    fail_verify: false,
                }),
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

        fn use_case(&self) -> DeleteAccountUseCase {
            DeleteAccountUseCase::new(
                self.accounts.clone(),
                self.hasher.clone(),
                self.second_factor(),
            )
        }
    }

    fn account() -> Account {
        Account::new("Ada Lovelace", "ada@example.com", "hashed:s3cret-pass")
    }

    fn command(account: &Account) -> DeleteAccountCommand {
        DeleteAccountCommand {
            account_id: account.id(),
            password: "s3cret-pass".to_owned(),
            mfa_code: None,
        }
    }

    #[test]
    fn deletes_the_account_when_the_password_matches() {
        let account = account();
        let fixture = Fixture::new(MockAccountRepository::with_account(&account));

        block_on(fixture.use_case().execute(command(&account))).expect("delete should succeed");

        assert_eq!(
            *fixture.accounts.deleted.borrow(),
            vec![account.id().to_string()]
        );
    }

    #[test]
    fn rejects_a_wrong_password() {
        let account = account();
        let fixture = Fixture {
            hasher: Arc::new(MockHashPasswordService {
                password_matches: false,
                fail_verify: false,
            }),
            ..Fixture::new(MockAccountRepository::with_account(&account))
        };

        let error = block_on(fixture.use_case().execute(command(&account)))
            .expect_err("wrong password must fail");

        assert!(matches!(error, DeleteAccountError::InvalidPassword));
        assert!(fixture.accounts.deleted.borrow().is_empty());
    }

    #[test]
    fn demands_a_code_when_mfa_is_enabled() {
        let account = account();
        let fixture = Fixture::with_mfa(MockAccountRepository::with_account(&account));

        let error = block_on(fixture.use_case().execute(command(&account)))
            .expect_err("a step-up code is required");

        assert!(matches!(
            error,
            DeleteAccountError::SecondFactor {
                source: SecondFactorError::CodeRequired
            }
        ));
        assert!(fixture.accounts.deleted.borrow().is_empty());
    }

    #[test]
    fn accepts_a_valid_step_up_code() {
        let account = account();
        let fixture = Fixture::with_mfa(MockAccountRepository::with_account(&account));
        let mut command = command(&account);
        command.mfa_code = Some(crate::testing::ACCEPTED_CODE.to_owned());

        block_on(fixture.use_case().execute(command)).expect("delete should succeed");

        assert_eq!(
            *fixture.accounts.deleted.borrow(),
            vec![account.id().to_string()]
        );
    }

    #[test]
    fn reports_a_missing_account() {
        let account = account();
        let fixture = Fixture::new(MockAccountRepository::default());

        let error = block_on(fixture.use_case().execute(command(&account)))
            .expect_err("missing account must fail");

        assert!(matches!(error, DeleteAccountError::AccountNotFound));
    }

    #[test]
    fn propagates_verification_failures() {
        let account = account();
        let fixture = Fixture {
            hasher: Arc::new(MockHashPasswordService {
                password_matches: true,
                fail_verify: true,
            }),
            ..Fixture::new(MockAccountRepository::with_account(&account))
        };

        let error = block_on(fixture.use_case().execute(command(&account)))
            .expect_err("verification failure must surface");

        assert!(matches!(error, DeleteAccountError::VerifyPassword { .. }));
    }

    #[test]
    fn propagates_delete_failures() {
        let account = account();
        let fixture = Fixture::new(MockAccountRepository {
            fail_delete: true,
            ..MockAccountRepository::with_account(&account)
        });

        let error = block_on(fixture.use_case().execute(command(&account)))
            .expect_err("delete failure must surface");

        assert!(matches!(error, DeleteAccountError::DeleteAccount { .. }));
    }
}
