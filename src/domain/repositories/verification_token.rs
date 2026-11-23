use async_trait::async_trait;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use worker::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredVerificationToken {
    pub account_id: String,
    #[serde(with = "jiff::fmt::serde::timestamp::second::required")]
    pub expires_at: Timestamp,
}

#[async_trait(?Send)]
pub trait VerificationTokenRepository {
    /// Stores the hash of a verification token for `account_id`.
    async fn create_token(
        &self,
        account_id: &str,
        token_hash: &str,
        expires_at: Timestamp,
    ) -> Result<(), Error>;

    /// Looks a token up by its hash.
    async fn find_token(&self, token_hash: &str) -> Result<Option<StoredVerificationToken>, Error>;

    /// Removes a token, so it cannot be replayed.
    async fn delete_token(&self, token_hash: &str) -> Result<(), Error>;
}
