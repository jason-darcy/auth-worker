use async_trait::async_trait;
use worker::{EmailAddress, Error};

use crate::{domain::services::email::EmailService, infrastructure::email::EmailClient};

/// Sends transactional emails (signup verification, password reset) through
/// the Cloudflare `send_email` binding.
#[derive(Debug, Clone)]
pub struct TransactionalMailer {
    pub client: EmailClient,
    pub from: EmailAddress,
    /// Public URL of the API, used to build the verification link.
    pub base_url: String,
}

impl TransactionalMailer {
    pub fn new(client: EmailClient, from: EmailAddress, base_url: &str) -> Self {
        TransactionalMailer {
            client,
            from,
            base_url: base_url.trim_end_matches('/').to_owned(),
        }
    }

    /// Builds the mailer from configuration values:
    /// `EMAIL_FROM` accepts `no-reply@example.com` or `Auth <no-reply@example.com>`.
    pub fn from_config(client: EmailClient, from: &str, base_url: &str) -> Result<Self, Error> {
        let (name, email) = parse_email_from(from)?;
        Ok(Self::new(
            client,
            EmailAddress::new(&name, &email),
            base_url,
        ))
    }

    pub fn verification_url(&self, token: &str) -> String {
        verification_url(&self.base_url, token)
    }

    fn verification_content(&self, name: &str, token: &str) -> String {
        verification_content(&self.base_url, name, token)
    }

    pub fn password_reset_url(&self, token: &str) -> String {
        password_reset_url(&self.base_url, token)
    }

    fn password_reset_content(&self, name: &str, token: &str) -> String {
        password_reset_content(&self.base_url, name, token)
    }
}

#[async_trait(?Send)]
impl EmailService for TransactionalMailer {
    async fn send_verification_email(
        &self,
        to: &str,
        name: &str,
        token: &str,
    ) -> Result<(), Error> {
        let recipient = EmailAddress::new("", to);
        self.client
            .send(
                &self.from,
                &[recipient],
                "Verify your email address",
                &self.verification_content(name, token),
            )
            .await
            .map(|_result| ())
            .map_err(Error::from)
    }

    async fn send_password_reset_email(
        &self,
        to: &str,
        name: &str,
        token: &str,
    ) -> Result<(), Error> {
        let recipient = EmailAddress::new("", to);
        self.client
            .send(
                &self.from,
                &[recipient],
                "Reset your password",
                &self.password_reset_content(name, token),
            )
            .await
            .map(|_result| ())
            .map_err(Error::from)
    }
}

pub fn verification_url(base_url: &str, token: &str) -> String {
    format!(
        "{}/api/v1/verify-email?token={token}",
        base_url.trim_end_matches('/')
    )
}

fn verification_content(base_url: &str, name: &str, token: &str) -> String {
    format!(
        "Hi {name},\n\n\
         Thanks for signing up. Please verify your email address by opening the link below:\n\n\
         {}\n\n\
         The link expires in 24 hours. If you did not create this account, you can ignore this email.\n",
        verification_url(base_url, token)
    )
}

pub fn password_reset_url(base_url: &str, token: &str) -> String {
    format!(
        "{}/api/v1/reset-password?token={token}",
        base_url.trim_end_matches('/')
    )
}

fn password_reset_content(base_url: &str, name: &str, token: &str) -> String {
    format!(
        "Hi {name},\n\n\
         We received a request to reset the password of your account.\n\
         Open the link below to choose a new password:\n\n\
         {}\n\n\
         The link expires in 30 minutes and can be used once.\n\
         If you did not ask for a password reset, you can ignore this email.\n",
        password_reset_url(base_url, token)
    )
}

/// Splits `Auth <no-reply@example.com>` into `("Auth", "no-reply@example.com")`.
fn parse_email_from(raw: &str) -> Result<(String, String), Error> {
    let raw = raw.trim();
    if let Some((name, rest)) = raw.rsplit_once('<') {
        let name = name.trim().trim_matches('"').trim();
        let email = rest.trim_end_matches('>').trim();
        if email.contains('@') {
            return Ok((name.to_owned(), email.to_owned()));
        }
    }
    if raw.contains('@') {
        return Ok((String::new(), raw.to_owned()));
    }
    Err(Error::RustError(format!(
        "invalid EMAIL_FROM address: {raw:?}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_verification_url_without_double_slash() {
        assert_eq!(
            verification_url("https://auth.example.com/", "abc123"),
            "https://auth.example.com/api/v1/verify-email?token=abc123"
        );
        assert_eq!(
            verification_url("http://localhost:8787", "abc123"),
            "http://localhost:8787/api/v1/verify-email?token=abc123"
        );
    }

    #[test]
    fn content_mentions_recipient_and_link() {
        let content = verification_content("https://auth.example.com", "Ada", "abc123");

        assert!(content.contains("Hi Ada,"));
        assert!(content.contains("https://auth.example.com/api/v1/verify-email?token=abc123"));
        assert!(content.contains("24 hours"));
    }

    #[test]
    fn builds_password_reset_url() {
        assert_eq!(
            password_reset_url("https://auth.example.com/", "abc123"),
            "https://auth.example.com/api/v1/reset-password?token=abc123"
        );
    }

    #[test]
    fn reset_content_mentions_recipient_link_and_expiry() {
        let content = password_reset_content("https://auth.example.com", "Ada", "abc123");

        assert!(content.contains("Hi Ada,"));
        assert!(content.contains("https://auth.example.com/api/v1/reset-password?token=abc123"));
        assert!(content.contains("30 minutes"));
    }

    #[test]
    fn parses_email_from_with_and_without_display_name() {
        assert_eq!(
            parse_email_from("Auth <no-reply@example.com>").expect("should parse"),
            ("Auth".to_owned(), "no-reply@example.com".to_owned())
        );
        assert_eq!(
            parse_email_from("\"Auth Team\" <no-reply@example.com>").expect("should parse"),
            ("Auth Team".to_owned(), "no-reply@example.com".to_owned())
        );
        assert_eq!(
            parse_email_from("  no-reply@example.com  ").expect("should parse"),
            (String::new(), "no-reply@example.com".to_owned())
        );
    }

    #[test]
    fn rejects_email_from_without_address() {
        let error = parse_email_from("Auth").expect_err("should be rejected");

        assert!(error.to_string().contains("invalid EMAIL_FROM"));
    }
}
