use std::sync::Arc;

use jiff::Timestamp;

use crate::{
    domain::{
        repositories::verification_token::VerificationTokenRepository,
        services::{email::EmailService, verification_token::VerificationTokenService},
    },
    logging::{log_error, log_info},
};

use super::signup::VERIFICATION_TOKEN_TTL;

/// Minimum delay between two verification emails for the same account.
///
/// Stops the resend endpoint from being used to flood somebody's inbox; a
/// throttled request still answers exactly like a delivered one.
pub const VERIFICATION_EMAIL_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(60);

/// Issues an email verification token and sends the link.
///
/// Shared by signup and the resend endpoint so both produce exactly the same
/// kind of link. Every failure is logged and swallowed: callers have already
/// committed their own state (an account exists), so turning a mail failure into
/// an error would only invite retries that fail differently.
pub struct VerificationEmailSender {
    pub verification_token_repository: Arc<dyn VerificationTokenRepository>,
    pub verification_token_service: Arc<dyn VerificationTokenService>,
    pub email_service: Arc<dyn EmailService>,
}

impl VerificationEmailSender {
    pub fn new(
        verification_token_repository: Arc<dyn VerificationTokenRepository>,
        verification_token_service: Arc<dyn VerificationTokenService>,
        email_service: Arc<dyn EmailService>,
    ) -> Self {
        VerificationEmailSender {
            verification_token_repository,
            verification_token_service,
            email_service,
        }
    }

    pub async fn send(&self, account_id: &str, email: &str, name: &str) {
        if self.throttled(account_id, email).await {
            return;
        }
        let token = match self.verification_token_service.generate() {
            Ok(token) => token,
            Err(err) => {
                log_error!("verification email: failed to generate a token for {email}: {err}");
                return;
            }
        };
        // Only the newest link may work.
        if let Err(err) = self
            .verification_token_repository
            .delete_tokens_for_account(account_id)
            .await
        {
            log_error!("verification email: failed to revoke old tokens of {account_id}: {err}");
        }
        let expires_at = Timestamp::now()
            .saturating_add(VERIFICATION_TOKEN_TTL)
            .unwrap_or(Timestamp::MAX);
        if let Err(err) = self
            .verification_token_repository
            .create_token(account_id, &token.hash, expires_at)
            .await
        {
            log_error!("verification email: failed to store a token for {email}: {err}");
            return;
        }
        if let Err(err) = self
            .email_service
            .send_verification_email(email, name, &token.raw)
            .await
        {
            log_error!("verification email: failed to send to {email}: {err}");
            return;
        }
        log_info!("verification email: sent to {email}");
    }

    /// `true` when a link was already sent recently. Lookup failures fail open:
    /// a broken throttle query must not block a legitimate email.
    async fn throttled(&self, account_id: &str, email: &str) -> bool {
        match self
            .verification_token_repository
            .seconds_since_last_token(account_id)
            .await
        {
            Ok(Some(age)) if age >= 0 && (age as u64) < VERIFICATION_EMAIL_COOLDOWN.as_secs() => {
                log_info!("verification email: throttled {email}, last link was sent {age}s ago");
                true
            }
            Ok(_) => false,
            Err(err) => {
                log_error!("verification email: cooldown lookup failed for {email}: {err}");
                false
            }
        }
    }
}

#[cfg(test)]
// The sender stores its dependencies as `Arc<dyn Trait>` and the repository
// trait is `?Send`, so mocks cannot be `Sync`; `RefCell` keeps them cheap.
#[allow(clippy::arc_with_non_send_sync)]
mod tests {
    use std::{cell::RefCell, sync::Arc};

    use async_trait::async_trait;

    use super::*;
    use crate::{
        domain::{
            repositories::verification_token::StoredVerificationToken,
            services::{opaque_token::OpaqueTokenService, verification_token::VerificationToken},
        },
        testing::block_on,
    };

    #[derive(Default)]
    struct MockVerificationTokenRepository {
        revoked: RefCell<Vec<String>>,
        stored: RefCell<Vec<(String, String, Timestamp)>>,
        fail: bool,
        seconds_since_last_token: Option<i64>,
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

        async fn delete_tokens_for_account(&self, account_id: &str) -> Result<(), worker::Error> {
            self.revoked.borrow_mut().push(account_id.to_owned());
            Ok(())
        }

        async fn seconds_since_last_token(
            &self,
            _account_id: &str,
        ) -> Result<Option<i64>, worker::Error> {
            Ok(self.seconds_since_last_token)
        }

        async fn delete_expired(&self, _now: jiff::Timestamp) -> Result<u32, worker::Error> {
            Ok(0)
        }
    }

    #[derive(Default)]
    struct MockVerificationTokenService {
        fail: bool,
    }

    impl OpaqueTokenService for MockVerificationTokenService {
        fn generate(&self) -> Result<VerificationToken, worker::Error> {
            if self.fail {
                return Err(worker::Error::RustError("rng failure".to_owned()));
            }
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
        sent: RefCell<Vec<(String, String, String)>>,
        fail: bool,
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
            unimplemented!("verification emails never reset passwords")
        }
    }

    struct Fixture {
        tokens: Arc<MockVerificationTokenRepository>,
        token_service: Arc<MockVerificationTokenService>,
        email: Arc<MockEmailService>,
    }

    impl Fixture {
        fn new() -> Self {
            Fixture {
                tokens: Arc::new(MockVerificationTokenRepository::default()),
                token_service: Arc::new(MockVerificationTokenService::default()),
                email: Arc::new(MockEmailService::default()),
            }
        }

        fn sender(&self) -> VerificationEmailSender {
            VerificationEmailSender::new(
                self.tokens.clone(),
                self.token_service.clone(),
                self.email.clone(),
            )
        }
    }

    #[test]
    fn stores_a_token_and_sends_the_link() {
        let fixture = Fixture::new();

        block_on(
            fixture
                .sender()
                .send("account-id", "ada@example.com", "Ada"),
        );

        assert_eq!(
            *fixture.tokens.revoked.borrow(),
            vec!["account-id".to_owned()]
        );
        let stored = fixture.tokens.stored.borrow();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].0, "account-id");
        assert_eq!(stored[0].1, "hash:raw-token");
        assert_eq!(
            *fixture.email.sent.borrow(),
            vec![(
                "ada@example.com".to_owned(),
                "Ada".to_owned(),
                "raw-token".to_owned()
            )]
        );
    }

    #[test]
    fn swallows_token_generation_failures() {
        let fixture = Fixture {
            token_service: Arc::new(MockVerificationTokenService { fail: true }),
            ..Fixture::new()
        };

        block_on(
            fixture
                .sender()
                .send("account-id", "ada@example.com", "Ada"),
        );

        assert!(fixture.tokens.stored.borrow().is_empty());
        assert!(fixture.email.sent.borrow().is_empty());
    }

    #[test]
    fn swallows_storage_failures() {
        let fixture = Fixture {
            tokens: Arc::new(MockVerificationTokenRepository {
                fail: true,
                ..Default::default()
            }),
            ..Fixture::new()
        };

        block_on(
            fixture
                .sender()
                .send("account-id", "ada@example.com", "Ada"),
        );

        assert!(
            fixture.email.sent.borrow().is_empty(),
            "no link must be sent for a token that was never stored"
        );
    }

    #[test]
    fn throttles_repeated_sends() {
        let fixture = Fixture {
            tokens: Arc::new(MockVerificationTokenRepository {
                seconds_since_last_token: Some(5),
                ..Default::default()
            }),
            ..Fixture::new()
        };

        block_on(
            fixture
                .sender()
                .send("account-id", "ada@example.com", "Ada"),
        );

        assert!(fixture.tokens.stored.borrow().is_empty());
        assert!(fixture.email.sent.borrow().is_empty());
    }

    #[test]
    fn sends_again_once_the_cooldown_elapsed() {
        let fixture = Fixture {
            tokens: Arc::new(MockVerificationTokenRepository {
                seconds_since_last_token: Some(60),
                ..Default::default()
            }),
            ..Fixture::new()
        };

        block_on(
            fixture
                .sender()
                .send("account-id", "ada@example.com", "Ada"),
        );

        assert_eq!(fixture.tokens.stored.borrow().len(), 1);
        assert_eq!(fixture.email.sent.borrow().len(), 1);
    }

    #[test]
    fn swallows_email_failures() {
        let fixture = Fixture {
            email: Arc::new(MockEmailService {
                fail: true,
                ..Default::default()
            }),
            ..Fixture::new()
        };

        block_on(
            fixture
                .sender()
                .send("account-id", "ada@example.com", "Ada"),
        );

        assert_eq!(fixture.tokens.stored.borrow().len(), 1);
    }
}
