use std::sync::Arc;

use jiff::Timestamp;
use serde::Serialize;
use snafu::{ensure, ResultExt, Snafu};
use uuid::Uuid;

use crate::{
    domain::{
        account::normalize_email,
        repositories::{account::AccountRepository, refresh_token::RefreshTokenRepository},
        services::{
            hash_password::HashPasswordService,
            token::{IssuedTokens, TokenService},
        },
    },
    logging::{log_error, log_info, log_warn},
};

pub struct SignInCommand {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct SignInResult {
    pub id: Uuid,
    pub name: String,
    pub email: String,
    pub created_at: Timestamp,
    #[serde(flatten)]
    pub tokens: IssuedTokens,
}

#[derive(Debug, Snafu)]
pub enum SignInError {
    /// Returned both for unknown emails and wrong passwords so the API does
    /// not leak which accounts exist.
    #[snafu(display("invalid email or password"))]
    InvalidCredentials,
    /// Only returned for correct credentials, so it cannot be used to probe
    /// which emails are registered.
    #[snafu(display("email is not verified"))]
    EmailNotVerified,
    #[snafu(display("failed to find account by email"))]
    FindAccount { source: worker::Error },
    #[snafu(display("failed to verify password"))]
    VerifyPassword {
        source: argon2::password_hash::Error,
    },
    #[snafu(display("failed to issue tokens"))]
    IssueTokens { source: worker::Error },
    #[snafu(display("failed to store refresh token"))]
    StoreRefreshToken { source: worker::Error },
}

pub struct SignInUseCase {
    pub account_repository: Arc<dyn AccountRepository>,
    pub hash_password_service: Arc<dyn HashPasswordService>,
    pub refresh_token_repository: Arc<dyn RefreshTokenRepository>,
    pub token_service: Arc<dyn TokenService>,
}

impl SignInUseCase {
    pub fn new(
        account_repository: Arc<dyn AccountRepository>,
        hash_password_service: Arc<dyn HashPasswordService>,
        refresh_token_repository: Arc<dyn RefreshTokenRepository>,
        token_service: Arc<dyn TokenService>,
    ) -> Self {
        SignInUseCase {
            account_repository,
            hash_password_service,
            refresh_token_repository,
            token_service,
        }
    }

    pub async fn execute(&self, command: SignInCommand) -> Result<SignInResult, SignInError> {
        // Accounts are stored with canonical (lowercase) emails.
        let email = normalize_email(&command.email);
        let account = self
            .account_repository
            .find_account_by_email(&email)
            .await
            .inspect_err(|err| {
                log_error!("signin: find_account_by_email failed for {email}: {err}");
            })
            .context(FindAccountSnafu)?;
        let Some(account) = account else {
            log_warn!("signin: no account for email: {email}");
            return Err(SignInError::InvalidCredentials);
        };
        let password_matches = self
            .hash_password_service
            .verify(&command.password, account.password_hash())
            .inspect_err(|err| {
                log_error!("signin: verify password failed for {email}: {err}");
            })
            .context(VerifyPasswordSnafu)?;
        ensure!(password_matches, InvalidCredentialsSnafu);
        if !account.is_verified() {
            log_warn!("signin: account is not verified: {email}");
            return Err(SignInError::EmailNotVerified);
        }
        // Only verified accounts get here, so a token pair is always issued for
        // a usable account.
        let account_id = account.id().to_string();
        let tokens = self
            .token_service
            .issue_pair(&account_id, account.email(), account.token_version())
            .inspect_err(|err| {
                log_error!("signin: issue tokens failed for {email}: {err}");
            })
            .context(IssueTokensSnafu)?;
        let refresh_token_hash = self.token_service.hash_refresh_token(&tokens.refresh_token);
        self.refresh_token_repository
            .create_token(&account_id, &refresh_token_hash, tokens.refresh_expires_at)
            .await
            .inspect_err(|err| {
                log_error!("signin: store refresh token failed for {email}: {err}");
            })
            .context(StoreRefreshTokenSnafu)?;

        let result = SignInResult {
            id: account.id(),
            name: account.name().to_owned(),
            email: account.email().to_owned(),
            created_at: account.created_at(),
            tokens: tokens.into(),
        };
        log_info!("signin: account {} signed in", result.id);
        Ok(result)
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
                refresh_token::{RefreshTokenRepository, StoredRefreshToken},
            },
            services::{
                hash_password::HashPasswordService,
                token::{AccessTokenClaims, TokenPair},
            },
        },
        testing::block_on,
    };

    #[derive(Default)]
    struct MockAccountRepository {
        existing: Option<Account>,
        fail_find: bool,
        looked_up: RefCell<Vec<String>>,
    }

    impl MockAccountRepository {
        fn with_account(account: Account) -> Self {
            MockAccountRepository {
                existing: Some(account),
                ..Default::default()
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

    struct MockHashPasswordService {
        password_matches: bool,
        fail_verify: bool,
        verified: RefCell<Vec<(String, String)>>,
    }

    impl MockHashPasswordService {
        fn matching() -> Self {
            MockHashPasswordService {
                password_matches: true,
                fail_verify: false,
                verified: RefCell::new(Vec::new()),
            }
        }

        fn not_matching() -> Self {
            MockHashPasswordService {
                password_matches: false,
                ..Self::matching()
            }
        }

        fn failing() -> Self {
            MockHashPasswordService {
                fail_verify: true,
                ..Self::matching()
            }
        }

        fn verified_pairs(&self) -> Vec<(String, String)> {
            self.verified.borrow().clone()
        }
    }

    impl HashPasswordService for MockHashPasswordService {
        fn hash(&self, _password: &str) -> Result<String, PasswordHashError> {
            Ok("hashed".to_owned())
        }

        fn verify(&self, password: &str, password_hash: &str) -> Result<bool, PasswordHashError> {
            self.verified
                .borrow_mut()
                .push((password.to_owned(), password_hash.to_owned()));
            if self.fail_verify {
                return Err(PasswordHashError::Crypto);
            }
            Ok(self.password_matches)
        }
    }

    #[derive(Default)]
    struct MockRefreshTokenRepository {
        fail: bool,
        stored: RefCell<Vec<(String, String, Timestamp)>>,
    }

    impl MockRefreshTokenRepository {
        fn failing() -> Self {
            MockRefreshTokenRepository {
                fail: true,
                ..Default::default()
            }
        }

        fn stored_tokens(&self) -> Vec<(String, String, Timestamp)> {
            self.stored.borrow().clone()
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
        ) -> Result<Option<StoredRefreshToken>, worker::Error> {
            Ok(None)
        }

        async fn delete_token(&self, _token_hash: &str) -> Result<(), worker::Error> {
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
                refresh_token: "refresh-token".to_owned(),
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

    struct Fixture {
        accounts: Arc<MockAccountRepository>,
        hasher: Arc<MockHashPasswordService>,
        refresh_tokens: Arc<MockRefreshTokenRepository>,
        tokens: Arc<MockTokenService>,
    }

    impl Fixture {
        fn new(accounts: MockAccountRepository) -> Self {
            Fixture {
                accounts: Arc::new(accounts),
                hasher: Arc::new(MockHashPasswordService::matching()),
                refresh_tokens: Arc::new(MockRefreshTokenRepository::default()),
                tokens: Arc::new(MockTokenService::new()),
            }
        }

        fn use_case(&self) -> SignInUseCase {
            SignInUseCase::new(
                self.accounts.clone(),
                self.hasher.clone(),
                self.refresh_tokens.clone(),
                self.tokens.clone(),
            )
        }
    }

    fn stored_account() -> Account {
        let mut account = Account::new("Ada Lovelace", "ada@example.com", "hashed:s3cret-pass");
        account.mark_verified();
        account
    }

    fn unverified_account() -> Account {
        Account::new("Ada Lovelace", "ada@example.com", "hashed:s3cret-pass")
    }

    fn command() -> SignInCommand {
        SignInCommand {
            email: "ada@example.com".to_owned(),
            password: "s3cret-pass".to_owned(),
        }
    }

    #[test]
    fn returns_account_when_credentials_match() {
        let account = stored_account();
        let fixture = Fixture::new(MockAccountRepository::with_account(account.clone()));

        let result =
            block_on(fixture.use_case().execute(command())).expect("signin should succeed");

        assert_eq!(result.id, account.id());
        assert_eq!(result.name, "Ada Lovelace");
        assert_eq!(result.email, "ada@example.com");
        assert_eq!(result.created_at, account.created_at());
        assert_eq!(
            fixture.accounts.looked_up_emails(),
            vec!["ada@example.com".to_owned()]
        );
        assert_eq!(
            fixture.hasher.verified_pairs(),
            vec![("s3cret-pass".to_owned(), "hashed:s3cret-pass".to_owned())]
        );
    }

    #[test]
    fn issues_a_token_pair_and_stores_the_refresh_token_hash() {
        let account = stored_account();
        let fixture = Fixture::new(MockAccountRepository::with_account(account.clone()));

        let result =
            block_on(fixture.use_case().execute(command())).expect("signin should succeed");

        assert_eq!(result.tokens.token_type, "Bearer");
        assert_eq!(
            result.tokens.access_token,
            format!("access-for-{}", account.id())
        );
        assert_eq!(result.tokens.refresh_token, "refresh-token");
        assert!(result.tokens.access_token_expires_at < result.tokens.refresh_token_expires_at);

        assert_eq!(
            fixture.tokens.issued_for(),
            vec![(
                account.id().to_string(),
                "ada@example.com".to_owned(),
                account.token_version(),
            )],
            "tokens must be issued for the authenticated account and its token version"
        );
        assert_eq!(
            fixture.refresh_tokens.stored_tokens(),
            vec![(
                account.id().to_string(),
                "hash:refresh-token".to_owned(),
                result.tokens.refresh_token_expires_at,
            )],
            "the refresh token must be stored hashed with its expiry"
        );
    }

    #[test]
    fn looks_up_accounts_case_insensitively() {
        let account = stored_account();
        let fixture = Fixture::new(MockAccountRepository::with_account(account.clone()));

        let command = SignInCommand {
            email: "  ADA@Example.COM ".to_owned(),
            password: "s3cret-pass".to_owned(),
        };
        let result = block_on(fixture.use_case().execute(command)).expect("signin should succeed");

        assert_eq!(result.id, account.id());
        assert_eq!(
            fixture.accounts.looked_up_emails(),
            vec!["ada@example.com".to_owned()]
        );
    }

    #[test]
    fn rejects_unverified_account_after_correct_password() {
        let fixture = Fixture::new(MockAccountRepository::with_account(unverified_account()));

        let error = block_on(fixture.use_case().execute(command()))
            .expect_err("unverified account must fail");

        assert!(matches!(error, SignInError::EmailNotVerified));
        assert_eq!(error.to_string(), "email is not verified");
        assert_eq!(
            fixture.hasher.verified_pairs().len(),
            1,
            "the password must be checked before revealing verification state"
        );
        assert!(
            fixture.tokens.issued_for().is_empty(),
            "no tokens may be issued for an unverified account"
        );
        assert!(fixture.refresh_tokens.stored_tokens().is_empty());
    }

    #[test]
    fn rejects_wrong_password_before_revealing_verification_state() {
        let fixture = Fixture {
            hasher: Arc::new(MockHashPasswordService::not_matching()),
            ..Fixture::new(MockAccountRepository::with_account(unverified_account()))
        };

        let error =
            block_on(fixture.use_case().execute(command())).expect_err("wrong password must fail");

        assert!(matches!(error, SignInError::InvalidCredentials));
        assert_eq!(error.to_string(), "invalid email or password");
        assert!(fixture.tokens.issued_for().is_empty());
    }

    #[test]
    fn rejects_unknown_email_without_verifying_password() {
        let fixture = Fixture::new(MockAccountRepository::default());

        let error =
            block_on(fixture.use_case().execute(command())).expect_err("unknown email must fail");

        assert!(matches!(error, SignInError::InvalidCredentials));
        assert_eq!(error.to_string(), "invalid email or password");
        assert!(fixture.hasher.verified_pairs().is_empty());
        assert!(fixture.tokens.issued_for().is_empty());
    }

    #[test]
    fn propagates_find_account_failure() {
        let fixture = Fixture::new(MockAccountRepository {
            fail_find: true,
            ..Default::default()
        });

        let error = block_on(fixture.use_case().execute(command()))
            .expect_err("lookup failure must surface");

        assert!(matches!(error, SignInError::FindAccount { .. }));
        assert!(fixture.hasher.verified_pairs().is_empty());
    }

    #[test]
    fn propagates_verify_password_failure() {
        let fixture = Fixture {
            hasher: Arc::new(MockHashPasswordService::failing()),
            ..Fixture::new(MockAccountRepository::with_account(stored_account()))
        };

        let error = block_on(fixture.use_case().execute(command()))
            .expect_err("verify failure must surface");

        assert!(matches!(error, SignInError::VerifyPassword { .. }));
        assert!(fixture.tokens.issued_for().is_empty());
    }

    #[test]
    fn propagates_token_issuance_failure() {
        let fixture = Fixture {
            tokens: Arc::new(MockTokenService::failing()),
            ..Fixture::new(MockAccountRepository::with_account(stored_account()))
        };

        let error = block_on(fixture.use_case().execute(command()))
            .expect_err("token issuance failure must surface");

        assert!(matches!(error, SignInError::IssueTokens { .. }));
        assert!(fixture.refresh_tokens.stored_tokens().is_empty());
    }

    #[test]
    fn propagates_refresh_token_storage_failure() {
        let fixture = Fixture {
            refresh_tokens: Arc::new(MockRefreshTokenRepository::failing()),
            ..Fixture::new(MockAccountRepository::with_account(stored_account()))
        };

        let error = block_on(fixture.use_case().execute(command()))
            .expect_err("refresh token storage failure must surface");

        assert!(matches!(error, SignInError::StoreRefreshToken { .. }));
    }
}
