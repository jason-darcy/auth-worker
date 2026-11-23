use snafu::Snafu;
use worker::{EmailAddress, EmailSendResult, SendEmail, SendEmailBuilder};

use crate::logging::log_error;

pub type EmailResult<T> = std::result::Result<T, EmailError>;

#[derive(Debug, Snafu)]
pub enum EmailError {
    #[snafu(display("email needs at least one recipient"))]
    NoRecipients,
    #[snafu(display("failed to send email to {to}"))]
    Send { to: String, source: worker::Error },
}

impl From<EmailError> for worker::Error {
    fn from(err: EmailError) -> Self {
        match err {
            EmailError::Send { source, .. } => source,
            EmailError::NoRecipients => worker::Error::RustError(err.to_string()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct EmailClient {
    pub client: SendEmail,
}

impl EmailClient {
    pub fn new(client: SendEmail) -> Self {
        EmailClient { client }
    }

    /// Sends a plain-text email.
    pub async fn send(
        &self,
        from: &EmailAddress,
        to: &[EmailAddress],
        subject: &str,
        content: &str,
    ) -> EmailResult<EmailSendResult> {
        let recipients = Self::recipients(to)?;
        let builder =
            SendEmailBuilder::builder_with_email_address_and_slice(from, &recipients, subject)
                .text(content)
                .build();
        self.deliver(builder, &recipients).await
    }

    /// Sends an HTML email.
    pub async fn send_html(
        &self,
        from: &EmailAddress,
        to: &[EmailAddress],
        subject: &str,
        html: &str,
    ) -> EmailResult<EmailSendResult> {
        let recipients = Self::recipients(to)?;
        let builder =
            SendEmailBuilder::builder_with_email_address_and_slice(from, &recipients, subject)
                .html(html)
                .build();
        self.deliver(builder, &recipients).await
    }

    /// Escape hatch for options `send`/`send_html` don't cover
    /// (cc/bcc, reply-to, attachments, headers, ...).
    pub async fn send_with(&self, builder: SendEmailBuilder) -> EmailResult<EmailSendResult> {
        self.client
            .send_with_builder(&builder)
            .await
            .map_err(worker::Error::from)
            .map_err(|source| EmailError::Send {
                to: "unknown recipients".to_owned(),
                source,
            })
    }

    async fn deliver(
        &self,
        builder: SendEmailBuilder,
        recipients: &[String],
    ) -> EmailResult<EmailSendResult> {
        self.client
            .send_with_builder(&builder)
            .await
            .map_err(worker::Error::from)
            .map_err(|source| {
                log_error!("failed to send email to {recipients:?}: {source}");
                EmailError::Send {
                    to: recipients.join(", "),
                    source,
                }
            })
    }

    /// The structured send API only accepts bare addresses for `to`, so the
    /// display names carried by `EmailAddress` are dropped here.
    fn recipients(to: &[EmailAddress]) -> EmailResult<Vec<String>> {
        if to.is_empty() {
            return Err(EmailError::NoRecipients);
        }
        Ok(to.iter().map(|address| address.email()).collect())
    }
}
