use std::sync::Arc;

use snafu::{ResultExt, Snafu};

use crate::{
    application::use_cases::verification_email::VerificationEmailSender,
    domain::{
        account::normalize_email,
        repositories::{
            account::AccountRepository, verification_token::VerificationTokenRepository,
        },
        services::{email::EmailService, verification_token::VerificationTokenService},
    },
    logging::{log_error, log_info},
};

pub struct ResendVerificationCommand {
    pub email: String,
}

#[derive(Debug, Snafu)]
pub enum ResendVerificationError {
    #[snafu(display("failed to find account by email"))]
    FindAccount { source: worker::Error },
}

pub struct ResendVerificationUseCase {
    pub account_repository: Arc<dyn AccountRepository>,
    pub verification_token_repository: Arc<dyn VerificationTokenRepository>,
    pub verification_token_service: Arc<dyn VerificationTokenService>,
    pub email_service: Arc<dyn EmailService>,
}

impl ResendVerificationUseCase {
    pub fn new(
        account_repository: Arc<dyn AccountRepository>,
        verification_token_repository: Arc<dyn VerificationTokenRepository>,
        verification_token_service: Arc<dyn VerificationTokenService>,
        email_service: Arc<dyn EmailService>,
    ) -> Self {
        ResendVerificationUseCase {
            account_repository,
            verification_token_repository,
            verification_token_service,
            email_service,
        }
    }

    /// Emails a fresh verification link when the account exists and still needs
    /// one.
    ///
    /// Unknown and already verified emails are not errors: the endpoint must not
    /// reveal which addresses are registered, so the response is identical in
    /// every case. Token storage and delivery are best-effort, like at signup.
    pub async fn execute(
        &self,
        command: ResendVerificationCommand,
    ) -> Result<(), ResendVerificationError> {
        let email = normalize_email(&command.email);
        let account = self
            .account_repository
            .find_account_by_email(&email)
            .await
            .inspect_err(|err| log_error!("resend_verification: lookup failed for {email}: {err}"))
            .context(FindAccountSnafu)?;
        let Some(account) = account else {
            log_info!("resend_verification: no account for {email}");
            return Ok(());
        };
        if account.is_verified() {
            log_info!("resend_verification: {email} is already verified");
            return Ok(());
        }

        VerificationEmailSender::new(
            self.verification_token_repository.clone(),
            self.verification_token_service.clone(),
            self.email_service.clone(),
        )
        .send(&account.id().to_string(), account.email(), account.name())
        .await;

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
            repositories::verification_token::StoredVerificationToken,
            services::{opaque_token::OpaqueTokenService, verification_token::VerificationToken},
        },
        testing::block_on,
    };

    struct MockAccountRepository {
        existing: Option<Account>,
        fail_find: bool,
        looked_up: RefCell<Vec<String>>,
    }

    impl MockAccountRepository {
        fn with_account(account: &Account) -> Self {
            MockAccountRepository {
                existing: Some(account.clone()),
                fail_find: false,
                looked_up: RefCell::new(Vec::new()),
            }
        }

        fn empty() -> Self {
            MockAccountRepository {
                existing: None,
                fail_find: false,
                looked_up: RefCell::new(Vec::new()),
            }
        }

        fn looked_up(&self) -> Vec<String> {
            self.looked_up.borrow().clone()
        }
    }

    #[async_trait(?Send)]
    impl AccountRepository for MockAccountRepository {
        async fn create_account(&self, _account: Account) -> Result<(), worker::Error> {
            Ok(())
        }

        async fn find_account_by_id(&self, _id: &str) -> Result<Option<Account>, worker::Error> {
            Ok(None)
        }

        async fn find_account_by_name(
            &self,
            _name: &str,
        ) -> Result<Option<Account>, worker::Error> {
            Ok(None)
        }

        async fn find_account_by_email(
            &self,
            email: &str,
        ) -> Result<Option<Account>, worker::Error> {
            self.looked_up.borrow_mut().push(email.to_owned());
            if self.fail_find {
                return Err(worker::Error::RustError("d1 select failed".to_owned()));
            }
            Ok(self
                .existing
                .clone()
                .filter(|account| account.email() == email))
        }

        async fn update_account(&self, _account: &Account) -> Result<(), worker::Error> {
            Ok(())
        }

        async fn delete_account(&self, _id: &str) -> Result<(), worker::Error> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct MockVerificationTokenRepository {
        stored: RefCell<Vec<(String, String)>>,
    }

    #[async_trait(?Send)]
    impl VerificationTokenRepository for MockVerificationTokenRepository {
        async fn create_token(
            &self,
            account_id: &str,
            token_hash: &str,
            _expires_at: jiff::Timestamp,
        ) -> Result<(), worker::Error> {
            self.stored
                .borrow_mut()
                .push((account_id.to_owned(), token_hash.to_owned()));
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

        async fn delete_expired(&self, _now: jiff::Timestamp) -> Result<u32, worker::Error> {
            Ok(0)
        }
    }

    struct MockVerificationTokenService;

    impl OpaqueTokenService for MockVerificationTokenService {
        fn generate(&self) -> Result<VerificationToken, worker::Error> {
            Ok(VerificationToken {
                raw: "raw-token".to_owned(),
                hash: "hash:raw-token".to_owned(),
            })
        }

        fn hash(&self, token: &str) -> String {
            format!("hash:{token}")
        }
    }

    #[derive(Default)]
    struct MockEmailService {
        sent: RefCell<Vec<String>>,
    }

    #[async_trait(?Send)]
    impl EmailService for MockEmailService {
        async fn send_verification_email(
            &self,
            to: &str,
            _name: &str,
            _token: &str,
        ) -> Result<(), worker::Error> {
            self.sent.borrow_mut().push(to.to_owned());
            Ok(())
        }

        async fn send_password_reset_email(
            &self,
            _to: &str,
            _name: &str,
            _token: &str,
        ) -> Result<(), worker::Error> {
            unimplemented!("resend_verification never resets passwords")
        }
    }

    struct Fixture {
        accounts: Arc<MockAccountRepository>,
        tokens: Arc<MockVerificationTokenRepository>,
        email: Arc<MockEmailService>,
    }

    impl Fixture {
        fn new(accounts: MockAccountRepository) -> Self {
            Fixture {
                accounts: Arc::new(accounts),
                tokens: Arc::new(MockVerificationTokenRepository::default()),
                email: Arc::new(MockEmailService::default()),
            }
        }

        fn use_case(&self) -> ResendVerificationUseCase {
            ResendVerificationUseCase::new(
                self.accounts.clone(),
                self.tokens.clone(),
                Arc::new(MockVerificationTokenService),
                self.email.clone(),
            )
        }
    }

    fn command(email: &str) -> ResendVerificationCommand {
        ResendVerificationCommand {
            email: email.to_owned(),
        }
    }

    #[test]
    fn sends_a_new_link_for_an_unverified_account() {
        let account = Account::new("Ada Lovelace", "ada@example.com", "hashed");
        let fixture = Fixture::new(MockAccountRepository::with_account(&account));

        block_on(fixture.use_case().execute(command("ada@example.com")))
            .expect("resend should succeed");

        assert_eq!(
            *fixture.tokens.stored.borrow(),
            vec![(account.id().to_string(), "hash:raw-token".to_owned())]
        );
        assert_eq!(
            *fixture.email.sent.borrow(),
            vec!["ada@example.com".to_owned()]
        );
    }

    #[test]
    fn normalizes_the_email_before_looking_it_up() {
        let account = Account::new("Ada Lovelace", "ada@example.com", "hashed");
        let fixture = Fixture::new(MockAccountRepository::with_account(&account));

        block_on(fixture.use_case().execute(command("  Ada@Example.COM  ")))
            .expect("resend should succeed");

        assert_eq!(
            fixture.accounts.looked_up(),
            vec!["ada@example.com".to_owned()]
        );
        assert_eq!(fixture.email.sent.borrow().len(), 1);
    }

    #[test]
    fn stays_silent_for_unknown_emails() {
        let fixture = Fixture::new(MockAccountRepository::empty());

        block_on(fixture.use_case().execute(command("nobody@example.com")))
            .expect("unknown emails are not an error");

        assert!(fixture.tokens.stored.borrow().is_empty());
        assert!(fixture.email.sent.borrow().is_empty());
    }

    #[test]
    fn does_not_email_already_verified_accounts() {
        let mut account = Account::new("Ada Lovelace", "ada@example.com", "hashed");
        account.mark_verified();
        let fixture = Fixture::new(MockAccountRepository::with_account(&account));

        block_on(fixture.use_case().execute(command("ada@example.com")))
            .expect("resend should succeed");

        assert!(fixture.tokens.stored.borrow().is_empty());
        assert!(fixture.email.sent.borrow().is_empty());
    }

    #[test]
    fn propagates_lookup_failures() {
        let fixture = Fixture::new(MockAccountRepository {
            fail_find: true,
            ..MockAccountRepository::empty()
        });

        let error = block_on(fixture.use_case().execute(command("ada@example.com")))
            .expect_err("lookup failure must surface");

        assert!(matches!(error, ResendVerificationError::FindAccount { .. }));
    }
}
