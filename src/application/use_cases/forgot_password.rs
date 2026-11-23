use std::sync::Arc;

use jiff::Timestamp;
use snafu::{ResultExt, Snafu};

use crate::{
    domain::{
        account::normalize_email,
        repositories::{
            account::AccountRepository, password_reset_token::PasswordResetTokenRepository,
        },
        services::{email::EmailService, verification_token::VerificationTokenService},
    },
    logging::{log_error, log_info},
};

/// Reset links are short-lived: 30 minutes.
pub const PASSWORD_RESET_TOKEN_TTL: std::time::Duration = std::time::Duration::from_secs(30 * 60);
/// Minimum delay between two reset emails for the same account.
///
/// Stops the endpoint from being used to flood somebody's inbox; a throttled
/// request still answers exactly like a delivered one.
pub const PASSWORD_RESET_EMAIL_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(60);

pub struct ForgotPasswordCommand {
    pub email: String,
}

#[derive(Debug, Snafu)]
pub enum ForgotPasswordError {
    #[snafu(display("failed to find account by email"))]
    FindAccount { source: worker::Error },
}

pub struct ForgotPasswordUseCase {
    pub account_repository: Arc<dyn AccountRepository>,
    pub password_reset_token_repository: Arc<dyn PasswordResetTokenRepository>,
    /// One-time opaque tokens (raw value in the email, SHA-256 hash in D1).
    pub token_service: Arc<dyn VerificationTokenService>,
    pub email_service: Arc<dyn EmailService>,
}

impl ForgotPasswordUseCase {
    pub fn new(
        account_repository: Arc<dyn AccountRepository>,
        password_reset_token_repository: Arc<dyn PasswordResetTokenRepository>,
        token_service: Arc<dyn VerificationTokenService>,
        email_service: Arc<dyn EmailService>,
    ) -> Self {
        ForgotPasswordUseCase {
            account_repository,
            password_reset_token_repository,
            token_service,
            email_service,
        }
    }

    /// Sends a password reset link when the email belongs to an account.
    ///
    /// Unknown emails are not an error: the API must not reveal whether an
    /// account exists. Token storage and email delivery are best-effort (the
    /// response is identical either way), so failures are only logged.
    pub async fn execute(&self, command: ForgotPasswordCommand) -> Result<(), ForgotPasswordError> {
        let email = normalize_email(&command.email);
        let account = self
            .account_repository
            .find_account_by_email(&email)
            .await
            .inspect_err(|err| log_error!("forgot_password: find_account_by_email failed: {err}"))
            .context(FindAccountSnafu)?;
        let Some(account) = account else {
            log_info!("forgot_password: no account for {email}");
            return Ok(());
        };

        let account_id = account.id().to_string();
        if self.throttled(&account_id, &email).await {
            return Ok(());
        }

        let token = match self.token_service.generate() {
            Ok(token) => token,
            Err(err) => {
                log_error!(
                    "forgot_password: failed to generate token for {}: {err}",
                    account.id()
                );
                return Ok(());
            }
        };
        // Only the newest link may work.
        if let Err(err) = self
            .password_reset_token_repository
            .delete_tokens_for_account(&account_id)
            .await
        {
            log_error!("forgot_password: failed to revoke old tokens for {account_id}: {err}");
        }
        let expires_at = Timestamp::now()
            .saturating_add(PASSWORD_RESET_TOKEN_TTL)
            .unwrap_or(Timestamp::MAX);
        if let Err(err) = self
            .password_reset_token_repository
            .create_token(&account_id, &token.hash, expires_at)
            .await
        {
            log_error!("forgot_password: failed to store token for {account_id}: {err}");
            return Ok(());
        }
        if let Err(err) = self
            .email_service
            .send_password_reset_email(account.email(), account.name(), &token.raw)
            .await
        {
            log_error!(
                "forgot_password: failed to send email to {}: {err}",
                account.email()
            );
        }
        log_info!("forgot_password: reset link sent to {email}");
        Ok(())
    }

    /// `true` when a reset link was already sent recently. Lookup failures fail
    /// open, so a broken throttle query cannot block a legitimate reset.
    async fn throttled(&self, account_id: &str, email: &str) -> bool {
        match self
            .password_reset_token_repository
            .seconds_since_last_token(account_id)
            .await
        {
            Ok(Some(age)) if age >= 0 && (age as u64) < PASSWORD_RESET_EMAIL_COOLDOWN.as_secs() => {
                log_info!("forgot_password: throttled {email}, last link was sent {age}s ago");
                true
            }
            Ok(_) => false,
            Err(err) => {
                log_error!("forgot_password: cooldown lookup failed for {email}: {err}");
                false
            }
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
                password_reset_token::{PasswordResetTokenRepository, StoredPasswordResetToken},
            },
            services::{
                email::EmailService, opaque_token::OpaqueTokenService,
                verification_token::VerificationToken,
            },
        },
        testing::block_on,
    };

    const RAW_TOKEN: &str = "raw-reset-token";

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

        fn looked_up_emails(&self) -> Vec<String> {
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
    struct MockPasswordResetTokenRepository {
        fail_create: bool,
        fail_delete: bool,
        revoked: RefCell<Vec<String>>,
        created: RefCell<Vec<(String, String, Timestamp)>>,
        seconds_since_last_token: Option<i64>,
    }

    impl MockPasswordResetTokenRepository {
        fn revoked_accounts(&self) -> Vec<String> {
            self.revoked.borrow().clone()
        }

        fn created_tokens(&self) -> Vec<(String, String, Timestamp)> {
            self.created.borrow().clone()
        }
    }

    #[async_trait(?Send)]
    impl PasswordResetTokenRepository for MockPasswordResetTokenRepository {
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

        async fn delete_tokens_for_account(&self, account_id: &str) -> Result<(), worker::Error> {
            if self.fail_delete {
                return Err(worker::Error::RustError("d1 delete failed".to_owned()));
            }
            self.revoked.borrow_mut().push(account_id.to_owned());
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
            Ok(self.seconds_since_last_token)
        }

        async fn delete_expired(&self, _now: Timestamp) -> Result<u32, worker::Error> {
            Ok(0)
        }
    }

    struct MockVerificationTokenService {
        fail: bool,
        generated: RefCell<usize>,
    }

    impl MockVerificationTokenService {
        fn new() -> Self {
            MockVerificationTokenService {
                fail: false,
                generated: RefCell::new(0),
            }
        }

        fn failing() -> Self {
            MockVerificationTokenService {
                fail: true,
                generated: RefCell::new(0),
            }
        }

        fn generated_count(&self) -> usize {
            *self.generated.borrow()
        }
    }

    impl OpaqueTokenService for MockVerificationTokenService {
        fn generate(&self) -> Result<VerificationToken, worker::Error> {
            *self.generated.borrow_mut() += 1;
            if self.fail {
                return Err(worker::Error::RustError("rng failure".to_owned()));
            }
            Ok(VerificationToken {
                raw: RAW_TOKEN.to_owned(),
                hash: format!("hash:{RAW_TOKEN}"),
            })
        }

        fn hash(&self, token: &str) -> String {
            format!("hash:{token}")
        }
    }

    #[derive(Default)]
    struct MockEmailService {
        fail: bool,
        sent: RefCell<Vec<(String, String, String)>>,
    }

    impl MockEmailService {
        fn sent_emails(&self) -> Vec<(String, String, String)> {
            self.sent.borrow().clone()
        }
    }

    #[async_trait(?Send)]
    impl EmailService for MockEmailService {
        async fn send_verification_email(
            &self,
            _to: &str,
            _name: &str,
            _token: &str,
        ) -> Result<(), worker::Error> {
            Ok(())
        }

        async fn send_password_reset_email(
            &self,
            to: &str,
            name: &str,
            token: &str,
        ) -> Result<(), worker::Error> {
            if self.fail {
                return Err(worker::Error::RustError("email binding failed".to_owned()));
            }
            self.sent
                .borrow_mut()
                .push((to.to_owned(), name.to_owned(), token.to_owned()));
            Ok(())
        }
    }

    struct Fixture {
        accounts: Arc<MockAccountRepository>,
        reset_tokens: Arc<MockPasswordResetTokenRepository>,
        token_service: Arc<MockVerificationTokenService>,
        emails: Arc<MockEmailService>,
    }

    impl Fixture {
        fn with_account(account: &Account) -> Self {
            Fixture {
                accounts: Arc::new(MockAccountRepository::with_account(account)),
                reset_tokens: Arc::new(MockPasswordResetTokenRepository::default()),
                token_service: Arc::new(MockVerificationTokenService::new()),
                emails: Arc::new(MockEmailService::default()),
            }
        }

        fn with_email(email: &str) -> Self {
            let account = Account::new("Ada Lovelace", email, "hashed");
            Self::with_account(&account)
        }

        fn use_case(&self) -> ForgotPasswordUseCase {
            ForgotPasswordUseCase::new(
                self.accounts.clone(),
                self.reset_tokens.clone(),
                self.token_service.clone(),
                self.emails.clone(),
            )
        }
    }

    fn command(email: &str) -> ForgotPasswordCommand {
        ForgotPasswordCommand {
            email: email.to_owned(),
        }
    }

    #[test]
    fn sends_a_reset_link_for_a_known_account() {
        let fixture = Fixture::with_email("ada@example.com");

        block_on(fixture.use_case().execute(command("ada@example.com")))
            .expect("request should succeed");

        assert_eq!(fixture.token_service.generated_count(), 1);
        let revoked = fixture.reset_tokens.revoked_accounts();
        assert_eq!(revoked.len(), 1, "old reset links must be revoked");

        let created = fixture.reset_tokens.created_tokens();
        assert_eq!(created.len(), 1);
        assert_eq!(created[0].0, revoked[0]);
        assert_eq!(created[0].1, format!("hash:{RAW_TOKEN}"));
        let ttl = created[0].2.as_second() - Timestamp::now().as_second();
        assert!(
            (PASSWORD_RESET_TOKEN_TTL.as_secs() as i64 - 5
                ..=PASSWORD_RESET_TOKEN_TTL.as_secs() as i64 + 5)
                .contains(&ttl),
            "unexpected ttl: {ttl}s"
        );

        assert_eq!(
            fixture.emails.sent_emails(),
            vec![(
                "ada@example.com".to_owned(),
                "Ada Lovelace".to_owned(),
                RAW_TOKEN.to_owned(),
            )]
        );
    }

    #[test]
    fn normalizes_the_email_before_looking_it_up() {
        let fixture = Fixture::with_email("ada@example.com");

        block_on(fixture.use_case().execute(command("  ADA@Example.COM ")))
            .expect("request should succeed");

        assert_eq!(
            fixture.accounts.looked_up_emails(),
            vec!["ada@example.com".to_owned()]
        );
        assert_eq!(fixture.emails.sent_emails().len(), 1);
    }

    #[test]
    fn stays_silent_for_unknown_emails() {
        let fixture = Fixture {
            accounts: Arc::new(MockAccountRepository::empty()),
            ..Fixture::with_email("ada@example.com")
        };

        let result = block_on(fixture.use_case().execute(command("nobody@example.com")));

        assert!(result.is_ok(), "unknown emails must not be an error");
        assert_eq!(fixture.token_service.generated_count(), 0);
        assert!(fixture.reset_tokens.created_tokens().is_empty());
        assert!(fixture.emails.sent_emails().is_empty());
    }

    #[test]
    fn sends_links_for_unverified_accounts_too() {
        let fixture = Fixture::with_email("ada@example.com");

        block_on(fixture.use_case().execute(command("ada@example.com")))
            .expect("request should succeed");

        assert_eq!(fixture.emails.sent_emails().len(), 1);
    }

    #[test]
    fn succeeds_without_email_when_token_generation_fails() {
        let fixture = Fixture {
            token_service: Arc::new(MockVerificationTokenService::failing()),
            ..Fixture::with_email("ada@example.com")
        };

        let result = block_on(fixture.use_case().execute(command("ada@example.com")));

        assert!(result.is_ok());
        assert!(fixture.reset_tokens.created_tokens().is_empty());
        assert!(fixture.emails.sent_emails().is_empty());
    }

    #[test]
    fn succeeds_without_email_when_token_storage_fails() {
        let fixture = Fixture {
            reset_tokens: Arc::new(MockPasswordResetTokenRepository {
                fail_create: true,
                ..Default::default()
            }),
            ..Fixture::with_email("ada@example.com")
        };

        let result = block_on(fixture.use_case().execute(command("ada@example.com")));

        assert!(result.is_ok());
        assert!(
            fixture.emails.sent_emails().is_empty(),
            "a token that was not stored must not be emailed"
        );
    }

    #[test]
    fn succeeds_when_revoking_old_tokens_fails() {
        let fixture = Fixture {
            reset_tokens: Arc::new(MockPasswordResetTokenRepository {
                fail_delete: true,
                ..Default::default()
            }),
            ..Fixture::with_email("ada@example.com")
        };

        let result = block_on(fixture.use_case().execute(command("ada@example.com")));

        assert!(result.is_ok());
        assert_eq!(fixture.reset_tokens.created_tokens().len(), 1);
        assert_eq!(fixture.emails.sent_emails().len(), 1);
    }

    #[test]
    fn succeeds_when_the_email_cannot_be_sent() {
        let fixture = Fixture {
            emails: Arc::new(MockEmailService {
                fail: true,
                ..Default::default()
            }),
            ..Fixture::with_email("ada@example.com")
        };

        let result = block_on(fixture.use_case().execute(command("ada@example.com")));

        assert!(result.is_ok(), "email failures must not leak anything");
        assert_eq!(fixture.reset_tokens.created_tokens().len(), 1);
    }

    #[test]
    fn propagates_account_lookup_failure() {
        let fixture = Fixture {
            accounts: Arc::new(MockAccountRepository {
                fail_find: true,
                ..MockAccountRepository::empty()
            }),
            ..Fixture::with_email("ada@example.com")
        };

        let error = block_on(fixture.use_case().execute(command("ada@example.com")))
            .expect_err("infrastructure failures must surface");

        assert!(matches!(error, ForgotPasswordError::FindAccount { .. }));
        assert!(fixture.emails.sent_emails().is_empty());
    }
}
