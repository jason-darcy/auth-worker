use async_trait::async_trait;

/// Sends account related transactional emails.
#[async_trait(?Send)]
pub trait EmailService {
    /// Emails the raw verification token to `to`.
    async fn send_verification_email(
        &self,
        to: &str,
        name: &str,
        token: &str,
    ) -> Result<(), worker::Error>;

    /// Emails the raw password reset token to `to`.
    async fn send_password_reset_email(
        &self,
        to: &str,
        name: &str,
        token: &str,
    ) -> Result<(), worker::Error>;
}
