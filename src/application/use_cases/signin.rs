use std::sync::Arc;

use jiff::Timestamp;
use serde::Serialize;
use snafu::{ResultExt, Snafu};
use uuid::Uuid;

use crate::{
    application::use_cases::session::SessionIssuer,
    domain::{
        account::{normalize_email, Account},
        client::ClientInfo,
        mfa::{TotpCredential, MFA_CHALLENGE_TTL},
        repositories::{account::AccountRepository, mfa::MfaRepository},
        services::{
            hash_password::HashPasswordService, opaque_token::OpaqueTokenService,
            token::IssuedTokens,
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

/// Returned instead of the tokens when the account has MFA enabled.
#[derive(Debug, Serialize)]
pub struct MfaChallengeResult {
    /// Always `true`; it discriminates this shape from [`SignInResult`].
    pub mfa_required: bool,
    /// Single-use ticket for `POST /mfa/verify`.
    pub challenge_token: String,
    pub challenge_expires_at: Timestamp,
}

/// Either a completed sign-in or the request for the second factor.
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum SignInOutcome {
    SignedIn(SignInResult),
    MfaRequired(MfaChallengeResult),
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
    #[snafu(display("failed to find the mfa credential"))]
    FindMfaCredential { source: worker::Error },
    #[snafu(display("failed to create the sign-in challenge"))]
    CreateChallenge { source: worker::Error },
    #[snafu(display("failed to issue a session"))]
    IssueSession { source: worker::Error },
}

pub struct SignInUseCase {
    pub account_repository: Arc<dyn AccountRepository>,
    pub hash_password_service: Arc<dyn HashPasswordService>,
    pub mfa_repository: Arc<dyn MfaRepository>,
    pub opaque_token_service: Arc<dyn OpaqueTokenService>,
    pub session_issuer: SessionIssuer,
}

impl SignInUseCase {
    pub fn new(
        account_repository: Arc<dyn AccountRepository>,
        hash_password_service: Arc<dyn HashPasswordService>,
        mfa_repository: Arc<dyn MfaRepository>,
        opaque_token_service: Arc<dyn OpaqueTokenService>,
        session_issuer: SessionIssuer,
    ) -> Self {
        SignInUseCase {
            account_repository,
            hash_password_service,
            mfa_repository,
            opaque_token_service,
            session_issuer,
        }
    }

    pub async fn execute(
        &self,
        command: SignInCommand,
        client: &ClientInfo,
    ) -> Result<SignInOutcome, SignInError> {
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
        let Some(mut account) = account else {
            log_warn!("signin: no account for email: {email}");
            // Burn the same Argon2 work as a real verification, otherwise the
            // response time reveals whether the email is registered.
            self.hash_password_service.verify_dummy(&command.password);
            return Err(SignInError::InvalidCredentials);
        };

        let now = Timestamp::now();
        if account.is_locked(now) {
            log_warn!(
                "signin: account {} is locked until {:?}",
                account.id(),
                account.locked_until()
            );
            // Same work as a real verification, so a lockout cannot be told
            // apart from a wrong password.
            self.hash_password_service.verify_dummy(&command.password);
            return Err(SignInError::InvalidCredentials);
        }

        let password_matches = self
            .hash_password_service
            .verify(&command.password, account.password_hash())
            .inspect_err(|err| {
                log_error!("signin: verify password failed for {email}: {err}");
            })
            .context(VerifyPasswordSnafu)?;
        if !password_matches {
            self.register_failed_login(&mut account, now).await;
            return Err(SignInError::InvalidCredentials);
        }
        if !account.is_verified() {
            log_warn!("signin: account is not verified: {email}");
            return Err(SignInError::EmailNotVerified);
        }

        // A successful sign-in clears the brute-force counter.
        if account.failed_login_attempts() > 0 || account.locked_until().is_some() {
            account.reset_failed_logins();
            if let Err(err) = self.account_repository.update_account(&account).await {
                log_error!("signin: clearing failed logins failed for {email}: {err}");
            }
        }

        if self.mfa_enabled(&account).await? {
            return self
                .start_challenge(&account)
                .await
                .map(SignInOutcome::MfaRequired);
        }

        let tokens = self
            .session_issuer
            .start(&account, client)
            .await
            .inspect_err(|err| {
                log_error!("signin: issuing a session failed for {email}: {err}");
            })
            .context(IssueSessionSnafu)?;

        let result = SignInResult {
            id: account.id(),
            name: account.name().to_owned(),
            email: account.email().to_owned(),
            created_at: account.created_at(),
            tokens,
        };
        log_info!("signin: account {} signed in", result.id);
        Ok(SignInOutcome::SignedIn(result))
    }

    /// `true` when the account finished an MFA enrolment.
    async fn mfa_enabled(&self, account: &Account) -> Result<bool, SignInError> {
        let account_id = account.id().to_string();
        let credential = self
            .mfa_repository
            .find_credential(&account_id)
            .await
            .inspect_err(|err| {
                log_error!("signin: find_credential failed for {account_id}: {err}");
            })
            .context(FindMfaCredentialSnafu)?;
        Ok(credential.is_some_and(|credential: TotpCredential| credential.is_confirmed()))
    }

    /// The password was correct but the second factor is still missing.
    async fn start_challenge(&self, account: &Account) -> Result<MfaChallengeResult, SignInError> {
        let account_id = account.id().to_string();
        let token = self
            .opaque_token_service
            .generate()
            .inspect_err(|err| {
                log_error!("signin: generating a challenge token failed for {account_id}: {err}");
            })
            .context(CreateChallengeSnafu)?;
        let challenge_expires_at = Timestamp::now()
            .saturating_add(MFA_CHALLENGE_TTL)
            .unwrap_or(Timestamp::MAX);
        self.mfa_repository
            .create_challenge(&account_id, &token.hash, challenge_expires_at)
            .await
            .inspect_err(|err| {
                log_error!("signin: create_challenge failed for {account_id}: {err}");
            })
            .context(CreateChallengeSnafu)?;

        log_info!("signin: second factor required for account {account_id}");
        Ok(MfaChallengeResult {
            mfa_required: true,
            challenge_token: token.raw,
            challenge_expires_at,
        })
    }

    /// Records a failed attempt. Best-effort: the caller answers the same way
    /// whether or not the counter could be persisted.
    async fn register_failed_login(&self, account: &mut Account, now: Timestamp) {
        let locked = account.register_failed_login(now);
        if locked {
            log_warn!(
                "signin: account {} locked after {} failed attempts",
                account.id(),
                crate::domain::account::MAX_FAILED_LOGIN_ATTEMPTS
            );
        }
        if let Err(err) = self.account_repository.update_account(account).await {
            log_error!(
                "signin: storing failed login attempt failed for {}: {err}",
                account.id()
            );
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
            account::{Account, MAX_FAILED_LOGIN_ATTEMPTS},
            mfa::TotpCredential,
            repositories::{
                account::AccountRepository,
                mfa::MfaRepository,
                refresh_token::{
                    NewRefreshToken, RefreshTokenRepository, SessionInfo, StoredRefreshToken,
                },
            },
            services::{
                hash_password::HashPasswordService,
                opaque_token::{OpaqueToken, OpaqueTokenService},
                token::{AccessTokenClaims, TokenPair, TokenService},
            },
        },
        testing::block_on,
    };

    #[derive(Default)]
    struct MockAccountRepository {
        existing: Option<Account>,
        fail_find: bool,
        looked_up: RefCell<Vec<String>>,
        updates: RefCell<Vec<Account>>,
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

        async fn update_account(&self, account: &Account) -> Result<(), worker::Error> {
            self.updates.borrow_mut().push(account.clone());
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
        dummy_verifications: RefCell<Vec<String>>,
    }

    impl MockHashPasswordService {
        fn matching() -> Self {
            MockHashPasswordService {
                password_matches: true,
                fail_verify: false,
                verified: RefCell::new(Vec::new()),
                dummy_verifications: RefCell::new(Vec::new()),
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

        fn dummy_verifications(&self) -> Vec<String> {
            self.dummy_verifications.borrow().clone()
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

        fn verify_dummy(&self, password: &str) {
            self.dummy_verifications
                .borrow_mut()
                .push(password.to_owned());
        }
    }

    #[derive(Default)]
    struct MockRefreshTokenRepository {
        fail: bool,
        stored: RefCell<Vec<NewRefreshToken>>,
    }

    impl MockRefreshTokenRepository {
        fn failing() -> Self {
            MockRefreshTokenRepository {
                fail: true,
                ..Default::default()
            }
        }

        fn stored_tokens(&self) -> Vec<NewRefreshToken> {
            self.stored.borrow().clone()
        }
    }

    #[async_trait(?Send)]
    impl RefreshTokenRepository for MockRefreshTokenRepository {
        async fn create_token(&self, token: NewRefreshToken) -> Result<(), worker::Error> {
            if self.fail {
                return Err(worker::Error::RustError("d1 insert failed".to_owned()));
            }
            self.stored.borrow_mut().push(token);
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

    #[derive(Default)]
    struct MockMfaRepository {
        credential: Option<TotpCredential>,
        challenges: RefCell<Vec<(String, String)>>,
        fail_find: bool,
    }

    impl MockMfaRepository {
        fn with_credential(credential: TotpCredential) -> Self {
            MockMfaRepository {
                credential: Some(credential),
                ..Default::default()
            }
        }

        fn challenges(&self) -> Vec<(String, String)> {
            self.challenges.borrow().clone()
        }
    }

    #[async_trait(?Send)]
    impl MfaRepository for MockMfaRepository {
        async fn find_credential(
            &self,
            _account_id: &str,
        ) -> Result<Option<TotpCredential>, worker::Error> {
            if self.fail_find {
                return Err(worker::Error::RustError("d1 select failed".to_owned()));
            }
            Ok(self.credential.clone())
        }

        async fn save_credential(&self, _credential: &TotpCredential) -> Result<(), worker::Error> {
            Ok(())
        }

        async fn delete_credential(&self, _account_id: &str) -> Result<(), worker::Error> {
            Ok(())
        }

        async fn replace_recovery_codes(
            &self,
            _account_id: &str,
            _code_hashes: &[String],
        ) -> Result<(), worker::Error> {
            Ok(())
        }

        async fn consume_recovery_code(
            &self,
            _account_id: &str,
            _code_hash: &str,
        ) -> Result<bool, worker::Error> {
            Ok(false)
        }

        async fn count_recovery_codes(&self, _account_id: &str) -> Result<u32, worker::Error> {
            Ok(0)
        }

        async fn create_challenge(
            &self,
            account_id: &str,
            token_hash: &str,
            _expires_at: Timestamp,
        ) -> Result<(), worker::Error> {
            self.challenges
                .borrow_mut()
                .push((account_id.to_owned(), token_hash.to_owned()));
            Ok(())
        }

        async fn find_challenge(
            &self,
            _token_hash: &str,
        ) -> Result<Option<crate::domain::mfa::StoredMfaChallenge>, worker::Error> {
            Ok(None)
        }

        async fn record_challenge_attempt(&self, _token_hash: &str) -> Result<u32, worker::Error> {
            Ok(1)
        }

        async fn delete_challenge(&self, _token_hash: &str) -> Result<(), worker::Error> {
            Ok(())
        }

        async fn delete_expired_challenges(&self, _now: Timestamp) -> Result<u32, worker::Error> {
            Ok(0)
        }
    }

    #[derive(Default)]
    struct MockOpaqueTokenService;

    impl OpaqueTokenService for MockOpaqueTokenService {
        fn generate(&self) -> Result<OpaqueToken, worker::Error> {
            Ok(OpaqueToken {
                raw: "challenge-token".to_owned(),
                hash: "hash:challenge-token".to_owned(),
            })
        }

        fn hash(&self, token: &str) -> String {
            format!("hash:{token}")
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
        mfa: Arc<MockMfaRepository>,
    }

    impl Fixture {
        fn new(accounts: MockAccountRepository) -> Self {
            Fixture {
                accounts: Arc::new(accounts),
                hasher: Arc::new(MockHashPasswordService::matching()),
                refresh_tokens: Arc::new(MockRefreshTokenRepository::default()),
                tokens: Arc::new(MockTokenService::new()),
                mfa: Arc::new(MockMfaRepository::default()),
            }
        }

        fn use_case(&self) -> SignInUseCase {
            SignInUseCase::new(
                self.accounts.clone(),
                self.hasher.clone(),
                self.mfa.clone(),
                Arc::new(MockOpaqueTokenService),
                SessionIssuer::new(self.refresh_tokens.clone(), self.tokens.clone()),
            )
        }

        fn with_mfa(accounts: MockAccountRepository, mfa: MockMfaRepository) -> Self {
            Fixture {
                mfa: Arc::new(mfa),
                ..Self::new(accounts)
            }
        }

        /// Runs a sign-in that is expected to complete without a second factor.
        fn sign_in(&self, command: SignInCommand) -> Result<SignInResult, SignInError> {
            block_on(self.use_case().execute(command, &ClientInfo::default())).map(|outcome| {
                match outcome {
                    SignInOutcome::SignedIn(result) => result,
                    SignInOutcome::MfaRequired(_) => {
                        panic!("expected a completed sign-in, got an MFA challenge")
                    }
                }
            })
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

    fn account_with_failures(attempts: u32) -> Account {
        let mut account = stored_account();
        let now = Timestamp::now();
        for _ in 0..attempts {
            account.register_failed_login(now);
        }
        account
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

        let result = fixture.sign_in(command()).expect("signin should succeed");

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

        let result = fixture.sign_in(command()).expect("signin should succeed");

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
        let stored = fixture.refresh_tokens.stored_tokens();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].account_id, account.id().to_string());
        assert_eq!(stored[0].token_hash, "hash:refresh-token");
        assert_eq!(stored[0].expires_at, result.tokens.refresh_token_expires_at);
        assert!(
            !stored[0].family_id.is_empty(),
            "a sign-in must open a session"
        );
    }

    fn confirmed_credential(account: &Account) -> TotpCredential {
        let mut credential = TotpCredential::new(&account.id().to_string(), "JBSWY3DPEHPK3PXP");
        credential.confirm(Timestamp::now(), 1);
        credential
    }

    #[test]
    fn asks_for_the_second_factor_when_mfa_is_enabled() {
        let account = stored_account();
        let fixture = Fixture::with_mfa(
            MockAccountRepository::with_account(account.clone()),
            MockMfaRepository::with_credential(confirmed_credential(&account)),
        );

        let outcome = block_on(
            fixture
                .use_case()
                .execute(command(), &ClientInfo::default()),
        )
        .expect("signin should reach the second factor");

        match outcome {
            SignInOutcome::MfaRequired(challenge) => {
                assert!(challenge.mfa_required);
                assert_eq!(challenge.challenge_token, "challenge-token");
                assert!(challenge.challenge_expires_at > Timestamp::now());
            }
            SignInOutcome::SignedIn(_) => {
                panic!("no tokens may be issued before the second factor")
            }
        }
        assert!(
            fixture.tokens.issued_for().is_empty(),
            "no access token may be issued before the second factor"
        );
        assert!(
            fixture.refresh_tokens.stored_tokens().is_empty(),
            "no session may be opened before the second factor"
        );
        assert_eq!(
            fixture.mfa.challenges(),
            vec![(account.id().to_string(), "hash:challenge-token".to_owned())]
        );
    }

    #[test]
    fn ignores_a_pending_mfa_enrolment() {
        let account = stored_account();
        let fixture = Fixture::with_mfa(
            MockAccountRepository::with_account(account.clone()),
            MockMfaRepository::with_credential(TotpCredential::new(
                &account.id().to_string(),
                "JBSWY3DPEHPK3PXP",
            )),
        );

        let result = fixture.sign_in(command()).expect("signin should succeed");

        assert_eq!(result.id, account.id());
        assert!(
            fixture.mfa.challenges().is_empty(),
            "an unfinished enrolment must not block the sign-in"
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
        let result = fixture.sign_in(command).expect("signin should succeed");

        assert_eq!(result.id, account.id());
        assert_eq!(
            fixture.accounts.looked_up_emails(),
            vec!["ada@example.com".to_owned()]
        );
    }

    #[test]
    fn rejects_unverified_account_after_correct_password() {
        let fixture = Fixture::new(MockAccountRepository::with_account(unverified_account()));

        let error = fixture
            .sign_in(command())
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
    fn counts_failed_sign_ins() {
        let fixture = Fixture {
            hasher: Arc::new(MockHashPasswordService::not_matching()),
            ..Fixture::new(MockAccountRepository::with_account(account_with_failures(
                2,
            )))
        };

        fixture
            .sign_in(command())
            .expect_err("wrong password must fail");

        let updates = fixture.accounts.updates.borrow();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].failed_login_attempts(), 3);
        assert!(updates[0].locked_until().is_none());
    }

    #[test]
    fn locks_the_account_after_repeated_failures() {
        let fixture = Fixture {
            hasher: Arc::new(MockHashPasswordService::not_matching()),
            ..Fixture::new(MockAccountRepository::with_account(account_with_failures(
                9,
            )))
        };

        let error = fixture
            .sign_in(command())
            .expect_err("wrong password must fail");

        assert!(matches!(error, SignInError::InvalidCredentials));
        let updates = fixture.accounts.updates.borrow();
        assert_eq!(updates.len(), 1);
        assert!(
            updates[0].locked_until().is_some(),
            "the tenth failure must lock the account"
        );
    }

    #[test]
    fn refuses_locked_accounts_without_checking_the_password() {
        let fixture = Fixture::new(MockAccountRepository::with_account(account_with_failures(
            MAX_FAILED_LOGIN_ATTEMPTS,
        )));

        let error = fixture
            .sign_in(command())
            .expect_err("a locked account must be refused");

        assert!(matches!(error, SignInError::InvalidCredentials));
        assert!(
            fixture.hasher.verified_pairs().is_empty(),
            "no real verification may run for a locked account"
        );
        assert_eq!(
            fixture.hasher.dummy_verifications(),
            vec!["s3cret-pass".to_owned()],
            "a lockout must still burn the same Argon2 work"
        );
        assert!(fixture.accounts.updates.borrow().is_empty());
        assert!(fixture.tokens.issued_for().is_empty());
    }

    #[test]
    fn clears_failed_sign_ins_after_a_successful_one() {
        let fixture = Fixture::new(MockAccountRepository::with_account(account_with_failures(
            3,
        )));

        fixture.sign_in(command()).expect("signin should succeed");

        let updates = fixture.accounts.updates.borrow();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].failed_login_attempts(), 0);
        assert!(updates[0].locked_until().is_none());
    }

    #[test]
    fn rejects_wrong_password_before_revealing_verification_state() {
        let fixture = Fixture {
            hasher: Arc::new(MockHashPasswordService::not_matching()),
            ..Fixture::new(MockAccountRepository::with_account(unverified_account()))
        };

        let error = fixture
            .sign_in(command())
            .expect_err("wrong password must fail");

        assert!(matches!(error, SignInError::InvalidCredentials));
        assert_eq!(error.to_string(), "invalid email or password");
        assert!(fixture.tokens.issued_for().is_empty());
    }

    #[test]
    fn rejects_unknown_email_and_still_spends_the_hashing_work() {
        let fixture = Fixture::new(MockAccountRepository::default());

        let error = fixture
            .sign_in(command())
            .expect_err("unknown email must fail");

        assert!(matches!(error, SignInError::InvalidCredentials));
        assert_eq!(error.to_string(), "invalid email or password");
        assert!(
            fixture.hasher.verified_pairs().is_empty(),
            "there is no stored hash to verify against"
        );
        assert_eq!(
            fixture.hasher.dummy_verifications(),
            vec!["s3cret-pass".to_owned()],
            "unknown emails must burn the same Argon2 work as known ones"
        );
        assert!(fixture.tokens.issued_for().is_empty());
    }

    #[test]
    fn known_emails_never_run_the_dummy_verification() {
        let fixture = Fixture::new(MockAccountRepository::with_account(stored_account()));

        fixture.sign_in(command()).expect("signin should succeed");

        assert!(fixture.hasher.dummy_verifications().is_empty());
    }

    #[test]
    fn propagates_find_account_failure() {
        let fixture = Fixture::new(MockAccountRepository {
            fail_find: true,
            ..Default::default()
        });

        let error = fixture
            .sign_in(command())
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

        let error = fixture
            .sign_in(command())
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

        let error = fixture
            .sign_in(command())
            .expect_err("token issuance failure must surface");

        assert!(matches!(error, SignInError::IssueSession { .. }));
        assert!(fixture.refresh_tokens.stored_tokens().is_empty());
    }

    #[test]
    fn propagates_refresh_token_storage_failure() {
        let fixture = Fixture {
            refresh_tokens: Arc::new(MockRefreshTokenRepository::failing()),
            ..Fixture::new(MockAccountRepository::with_account(stored_account()))
        };

        let error = fixture
            .sign_in(command())
            .expect_err("refresh token storage failure must surface");

        assert!(matches!(error, SignInError::IssueSession { .. }));
    }
}
