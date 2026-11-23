use async_trait::async_trait;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use worker::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredPasswordResetToken {
    pub account_id: String,
    #[serde(with = "jiff::fmt::serde::timestamp::second::required")]
    pub expires_at: Timestamp,
}

#[async_trait(?Send)]
pub trait PasswordResetTokenRepository {
    /// Stores the hash of a password reset token.
    async fn create_token(
        &self,
        account_id: &str,
        token_hash: &str,
        expires_at: Timestamp,
    ) -> Result<(), Error>;

    /// Revokes every pending reset token of an account, so only the most
    /// recently emailed link is valid.
    async fn delete_tokens_for_account(&self, account_id: &str) -> Result<(), Error>;

    /// Looks a reset token up by its hash.
    async fn find_token(&self, token_hash: &str)
        -> Result<Option<StoredPasswordResetToken>, Error>;

    /// Removes a reset token, so it cannot be replayed.
    async fn delete_token(&self, token_hash: &str) -> Result<(), Error>;
}
