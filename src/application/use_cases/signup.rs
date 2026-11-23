use std::sync::Arc;

use jiff::Timestamp;
use serde::Serialize;
use snafu::{ensure, ResultExt, Snafu};
use uuid::Uuid;

use crate::{
    application::use_cases::verification_email::VerificationEmailSender,
    domain::{
        account::{normalize_email, Account},
        repositories::{
            account::AccountRepository, verification_token::VerificationTokenRepository,
        },
        services::{
            email::EmailService, hash_password::HashPasswordService,
            verification_token::VerificationTokenService,
        },
    },
    logging::{log_error, log_info, log_warn},
};

/// How long the emailed verification link stays valid.
pub const VERIFICATION_TOKEN_TTL: std::time::Duration =
    std::time::Duration::from_secs(24 * 60 * 60);

pub struct SignUpCommand {
    pub name: String,
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct SignUpResult {
    pub id: Uuid,
    pub name: String,
    pub email: String,
    pub created_at: Timestamp,
}

#[derive(Debug, Snafu)]
pub enum SignUpError {
    #[snafu(display("email already exists"))]
    EmailAlreadyExists,
    #[snafu(display("failed to find account by email"))]
    FindAccount { source: worker::Error },
    #[snafu(display("failed to hash password"))]
    HashPassword {
        source: argon2::password_hash::Error,
    },
    #[snafu(display("failed to create account"))]
    CreateAccount { source: worker::Error },
}

pub struct SignUpUseCase {
    pub account_repository: Arc<dyn AccountRepository>,
    pub hash_password_service: Arc<dyn HashPasswordService>,
    pub verification_token_repository: Arc<dyn VerificationTokenRepository>,
    pub verification_token_service: Arc<dyn VerificationTokenService>,
    pub email_service: Arc<dyn EmailService>,
}

impl SignUpUseCase {
    pub fn new(
        account_repository: Arc<dyn AccountRepository>,
        hash_password_service: Arc<dyn HashPasswordService>,
        verification_token_repository: Arc<dyn VerificationTokenRepository>,
        verification_token_service: Arc<dyn VerificationTokenService>,
        email_service: Arc<dyn EmailService>,
    ) -> Self {
        SignUpUseCase {
            account_repository,
            hash_password_service,
            verification_token_repository,
            verification_token_service,
            email_service,
        }
    }

    pub async fn execute(&self, command: SignUpCommand) -> Result<SignUpResult, SignUpError> {
        // Look up and store the canonical form, so `Ada@Example.com` and
        // `ada@example.com` cannot become two accounts.
        let email = normalize_email(&command.email);
        let existing_account = self
            .account_repository
            .find_account_by_email(&email)
            .await
            .inspect_err(|err| {
                log_error!("signup: find_account_by_email failed for {email}: {err}");
            })
            .context(FindAccountSnafu)?;
        if existing_account.is_some() {
            log_warn!("signup: email already exists: {email}");
        }
        ensure!(existing_account.is_none(), EmailAlreadyExistsSnafu);
        let password_hash = self
            .hash_password_service
            .hash(&command.password)
            .inspect_err(|err| {
                log_error!("signup: hash password failed for {email}: {err}");
            })
            .context(HashPasswordSnafu)?;
        let account = Account::new(&command.name, &email, &password_hash);
        let result = SignUpResult {
            id: account.id(),
            name: account.name().to_owned(),
            email: account.email().to_owned(),
            created_at: account.created_at(),
        };
        match self.account_repository.create_account(account).await {
            Ok(()) => {
                log_info!("signup: created account {} ({})", result.id, result.email);
                self.send_verification_email(&result).await;
                Ok(result)
            }
            Err(worker::Error::D1(err)) if err.cause().contains("UNIQUE constraint failed") => {
                log_warn!("signup: email already exists: {email}");
                Err(SignUpError::EmailAlreadyExists)
            }
            Err(source) => Err(SignUpError::CreateAccount { source }),
        }
    }

    /// Sends the signup verification email.
    ///
    /// Verification is best-effort on purpose: the account is already created
    /// at this point, so a broken token store or email binding must not turn a
    /// successful signup into an error (it would also make retries fail with
    /// `email already exists`). The user can ask for another link through
    /// `POST /resend-verification`.
    async fn send_verification_email(&self, result: &SignUpResult) {
        VerificationEmailSender::new(
            self.verification_token_repository.clone(),
            self.verification_token_service.clone(),
            self.email_service.clone(),
        )
        .send(&result.id.to_string(), &result.email, &result.name)
        .await;
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
            repositories::{
                account::AccountRepository,
                verification_token::{StoredVerificationToken, VerificationTokenRepository},
            },
            services::{
                email::EmailService, hash_password::HashPasswordService,
                opaque_token::OpaqueTokenService, verification_token::VerificationToken,
            },
        },
        testing::block_on,
    };

    #[derive(Default)]
    struct MockVerificationTokenRepository {
        fail: bool,
        stored: RefCell<Vec<(String, String, Timestamp)>>,
    }

    impl MockVerificationTokenRepository {
        fn failing() -> Self {
            MockVerificationTokenRepository {
                fail: true,
                ..Default::default()
            }
        }

        fn stored_tokens(&self) -> Vec<(String, String, Timestamp)> {
            self.stored.borrow().clone()
        }
    }

    #[async_trait(?Send)]
    impl VerificationTokenRepository for MockVerificationTokenRepository {
        async fn create_token(
            &self,
            account_id: &str,
            token_hash: &str,
            expires_at: Timestamp,
        ) -> Result<(), worker::Error> {
            if self.fail {
                return Err(worker::Error::RustError("d1 insert failed".to_owned()));
            }
            self.stored.borrow_mut().push((
                account_id.to_owned(),
                token_hash.to_owned(),
                expires_at,
            ));
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

        async fn delete_expired(&self, _now: Timestamp) -> Result<u32, worker::Error> {
            Ok(0)
        }
    }

    struct MockVerificationTokenService {
        token: Result<VerificationToken, String>,
        generated: RefCell<usize>,
    }

    impl MockVerificationTokenService {
        fn returning(raw: &str) -> Self {
            MockVerificationTokenService {
                token: Ok(VerificationToken {
                    raw: raw.to_owned(),
                    hash: format!("hash:{raw}"),
                }),
                generated: RefCell::new(0),
            }
        }

        fn failing() -> Self {
            MockVerificationTokenService {
                token: Err("rng failure".to_owned()),
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
            self.token.clone().map_err(worker::Error::RustError)
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
        fn failing() -> Self {
            MockEmailService {
                fail: true,
                ..Default::default()
            }
        }

        fn sent_emails(&self) -> Vec<(String, String, String)> {
            self.sent.borrow().clone()
        }
    }

    #[async_trait(?Send)]
    impl EmailService for MockEmailService {
        async fn send_verification_email(
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

        async fn send_password_reset_email(
            &self,
            _to: &str,
            _name: &str,
            _token: &str,
        ) -> Result<(), worker::Error> {
            Ok(())
        }
    }

    struct Fixture {
        accounts: Arc<MockAccountRepository>,
        hasher: Arc<MockHashPasswordService>,
        tokens: Arc<MockVerificationTokenRepository>,
        token_service: Arc<MockVerificationTokenService>,
        emails: Arc<MockEmailService>,
    }

    impl Fixture {
        fn new() -> Self {
            Fixture {
                accounts: Arc::new(MockAccountRepository::default()),
                hasher: Arc::new(MockHashPasswordService::default()),
                tokens: Arc::new(MockVerificationTokenRepository::default()),
                token_service: Arc::new(MockVerificationTokenService::returning("raw-token")),
                emails: Arc::new(MockEmailService::default()),
            }
        }

        fn use_case(&self) -> SignUpUseCase {
            SignUpUseCase::new(
                self.accounts.clone(),
                self.hasher.clone(),
                self.tokens.clone(),
                self.token_service.clone(),
                self.emails.clone(),
            )
        }
    }

    #[derive(Default)]
    struct MockAccountRepository {
        existing: Option<Account>,
        fail_find: bool,
        fail_create: bool,
        created: RefCell<Vec<Account>>,
    }

    impl MockAccountRepository {
        fn with_existing(account: Account) -> Self {
            MockAccountRepository {
                existing: Some(account),
                ..Default::default()
            }
        }

        fn created_accounts(&self) -> Vec<Account> {
            self.created.borrow().clone()
        }
    }

    #[async_trait(?Send)]
    impl AccountRepository for MockAccountRepository {
        async fn create_account(&self, account: Account) -> Result<(), worker::Error> {
            if self.fail_create {
                return Err(worker::Error::RustError("d1 create failed".to_owned()));
            }
            self.created.borrow_mut().push(account);
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
    struct MockHashPasswordService {
        fail: bool,
        hashed: RefCell<Vec<String>>,
    }

    impl MockHashPasswordService {
        fn failing() -> Self {
            MockHashPasswordService {
                fail: true,
                ..Default::default()
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

        fn verify_dummy(&self, _password: &str) {}
    }

    fn command() -> SignUpCommand {
        SignUpCommand {
            name: "Ada Lovelace".to_owned(),
            email: "ada@example.com".to_owned(),
            password: "s3cret-pass".to_owned(),
        }
    }

    #[test]
    fn creates_account_with_hashed_password() {
        let fixture = Fixture::new();

        let result =
            block_on(fixture.use_case().execute(command())).expect("signup should succeed");

        assert_eq!(result.name, "Ada Lovelace");
        assert_eq!(result.email, "ada@example.com");
        assert_eq!(
            fixture.hasher.hashed_passwords(),
            vec!["s3cret-pass".to_owned()]
        );

        let created = fixture.accounts.created_accounts();
        assert_eq!(created.len(), 1);
        assert_eq!(created[0].id(), result.id);
        assert_eq!(created[0].name(), "Ada Lovelace");
        assert_eq!(created[0].email(), "ada@example.com");
        assert_eq!(created[0].password_hash(), "hashed:s3cret-pass");
        assert_eq!(created[0].created_at(), result.created_at);
        assert!(!created[0].is_verified(), "new accounts start unverified");
        assert!(!result.id.is_nil());
    }

    #[test]
    fn stores_verification_token_and_emails_it_after_signup() {
        let fixture = Fixture::new();
        let before = Timestamp::now();

        let result =
            block_on(fixture.use_case().execute(command())).expect("signup should succeed");

        assert_eq!(fixture.token_service.generated_count(), 1);
        let stored = fixture.tokens.stored_tokens();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].0, result.id.to_string());
        assert_eq!(stored[0].1, "hash:raw-token");
        let ttl = stored[0].2.as_second() - before.as_second();
        assert!(
            (VERIFICATION_TOKEN_TTL.as_secs() as i64 - 5
                ..=VERIFICATION_TOKEN_TTL.as_secs() as i64 + 5)
                .contains(&ttl),
            "token should expire in ~24h, got {ttl}s"
        );

        assert_eq!(
            fixture.emails.sent_emails(),
            vec![(
                "ada@example.com".to_owned(),
                "Ada Lovelace".to_owned(),
                "raw-token".to_owned(),
            )]
        );
    }

    #[test]
    fn signup_succeeds_when_verification_email_fails() {
        let fixture = Fixture {
            emails: Arc::new(MockEmailService::failing()),
            ..Fixture::new()
        };

        let result = block_on(fixture.use_case().execute(command()));

        assert!(result.is_ok(), "email failures must not fail signup");
        assert_eq!(fixture.accounts.created_accounts().len(), 1);
        assert_eq!(fixture.tokens.stored_tokens().len(), 1);
    }

    #[test]
    fn signup_succeeds_but_skips_email_when_token_storage_fails() {
        let fixture = Fixture {
            tokens: Arc::new(MockVerificationTokenRepository::failing()),
            ..Fixture::new()
        };

        let result = block_on(fixture.use_case().execute(command()));

        assert!(
            result.is_ok(),
            "token storage failures must not fail signup"
        );
        assert_eq!(fixture.accounts.created_accounts().len(), 1);
        assert!(
            fixture.emails.sent_emails().is_empty(),
            "a token that was not stored must not be emailed"
        );
    }

    #[test]
    fn signup_succeeds_without_email_when_token_generation_fails() {
        let fixture = Fixture {
            token_service: Arc::new(MockVerificationTokenService::failing()),
            ..Fixture::new()
        };

        let result = block_on(fixture.use_case().execute(command()));

        assert!(
            result.is_ok(),
            "token generation failures must not fail signup"
        );
        assert!(fixture.tokens.stored_tokens().is_empty());
        assert!(fixture.emails.sent_emails().is_empty());
    }

    #[test]
    fn normalizes_email_before_lookup_and_storage() {
        let fixture = Fixture::new();
        let command = SignUpCommand {
            name: "Ada Lovelace".to_owned(),
            email: "  Ada@Example.COM ".to_owned(),
            password: "s3cret-pass".to_owned(),
        };

        let result = block_on(fixture.use_case().execute(command)).expect("signup should succeed");

        assert_eq!(result.email, "ada@example.com");
        let created = fixture.accounts.created_accounts();
        assert_eq!(created[0].email(), "ada@example.com");
        assert_eq!(
            fixture.emails.sent_emails()[0].0,
            "ada@example.com",
            "the verification email must go to the canonical address"
        );
    }

    #[test]
    fn treats_emails_as_case_insensitive_when_checking_duplicates() {
        let existing = Account::new("Ada Lovelace", "ada@example.com", "hashed:old");
        let fixture = Fixture {
            accounts: Arc::new(MockAccountRepository::with_existing(existing)),
            ..Fixture::new()
        };
        let command = SignUpCommand {
            name: "Ada Lovelace".to_owned(),
            email: "ADA@Example.COM".to_owned(),
            password: "s3cret-pass".to_owned(),
        };

        let error =
            block_on(fixture.use_case().execute(command)).expect_err("duplicate must be rejected");

        assert!(matches!(error, SignUpError::EmailAlreadyExists));
        assert!(fixture.accounts.created_accounts().is_empty());
    }

    #[test]
    fn rejects_existing_email_without_hashing_writing_or_emailing() {
        let existing = Account::new("Ada Lovelace", "ada@example.com", "hashed:old");
        let fixture = Fixture {
            accounts: Arc::new(MockAccountRepository::with_existing(existing)),
            ..Fixture::new()
        };

        let error =
            block_on(fixture.use_case().execute(command())).expect_err("duplicate email must fail");

        assert!(matches!(error, SignUpError::EmailAlreadyExists));
        assert_eq!(error.to_string(), "email already exists");
        assert!(fixture.hasher.hashed_passwords().is_empty());
        assert!(fixture.accounts.created_accounts().is_empty());
        assert_eq!(fixture.token_service.generated_count(), 0);
        assert!(fixture.emails.sent_emails().is_empty());
    }

    #[test]
    fn propagates_find_account_failure() {
        let fixture = Fixture {
            accounts: Arc::new(MockAccountRepository {
                fail_find: true,
                ..Default::default()
            }),
            ..Fixture::new()
        };

        let error = block_on(fixture.use_case().execute(command()))
            .expect_err("lookup failure must surface");

        assert!(matches!(error, SignUpError::FindAccount { .. }));
        assert!(fixture.hasher.hashed_passwords().is_empty());
        assert!(fixture.accounts.created_accounts().is_empty());
        assert!(fixture.emails.sent_emails().is_empty());
    }

    #[test]
    fn propagates_hash_password_failure() {
        let fixture = Fixture {
            hasher: Arc::new(MockHashPasswordService::failing()),
            ..Fixture::new()
        };

        let error = block_on(fixture.use_case().execute(command()))
            .expect_err("hashing failure must surface");

        assert!(matches!(error, SignUpError::HashPassword { .. }));
        assert!(fixture.accounts.created_accounts().is_empty());
        assert!(fixture.emails.sent_emails().is_empty());
    }

    #[test]
    fn propagates_create_account_failure() {
        let fixture = Fixture {
            accounts: Arc::new(MockAccountRepository {
                fail_create: true,
                ..Default::default()
            }),
            ..Fixture::new()
        };

        let error = block_on(fixture.use_case().execute(command()))
            .expect_err("insert failure must surface");

        assert!(matches!(error, SignUpError::CreateAccount { .. }));
        assert!(fixture.accounts.created_accounts().is_empty());
        assert_eq!(fixture.token_service.generated_count(), 0);
        assert!(fixture.emails.sent_emails().is_empty());
    }
}
