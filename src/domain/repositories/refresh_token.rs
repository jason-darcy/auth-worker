use async_trait::async_trait;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use worker::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredRefreshToken {
    pub account_id: String,
    #[serde(with = "jiff::fmt::serde::timestamp::second::required")]
    pub expires_at: Timestamp,
}

#[async_trait(?Send)]
pub trait RefreshTokenRepository {
    /// Stores the hash of an issued refresh token.
    async fn create_token(
        &self,
        account_id: &str,
        token_hash: &str,
        expires_at: Timestamp,
    ) -> Result<(), Error>;

    /// Looks a refresh token up by its hash.
    async fn find_token(&self, token_hash: &str) -> Result<Option<StoredRefreshToken>, Error>;

    /// Removes a refresh token, so it cannot be replayed (rotation).
    async fn delete_token(&self, token_hash: &str) -> Result<(), Error>;

    /// Revokes every refresh token of an account (password reset, sign-out).
    async fn delete_tokens_for_account(&self, account_id: &str) -> Result<(), Error>;
}
