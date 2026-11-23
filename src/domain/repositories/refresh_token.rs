use async_trait::async_trait;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use worker::Error;

/// A refresh token that is about to be stored.
///
/// `family_id` groups every token produced by the same sign-in, so rotating a
/// token keeps the session and a replay can revoke it as a whole.
#[derive(Debug, Clone)]
pub struct NewRefreshToken {
    pub account_id: String,
    pub token_hash: String,
    pub family_id: String,
    pub expires_at: Timestamp,
    pub user_agent: Option<String>,
    pub ip: Option<String>,
}

/// A refresh token as stored in D1.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredRefreshToken {
    pub account_id: String,
    pub family_id: String,
    #[serde(with = "jiff::fmt::serde::timestamp::second::required")]
    pub expires_at: Timestamp,
    /// Set once the token was exchanged for a newer one.
    #[serde(default, with = "jiff::fmt::serde::timestamp::second::optional")]
    pub rotated_at: Option<Timestamp>,
}

/// One row of `GET /sessions`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    /// Refresh token family; also the session id.
    pub family_id: String,
    #[serde(with = "jiff::fmt::serde::timestamp::second::required")]
    pub created_at: Timestamp,
    #[serde(with = "jiff::fmt::serde::timestamp::second::required")]
    pub expires_at: Timestamp,
    #[serde(default, with = "jiff::fmt::serde::timestamp::second::optional")]
    pub last_used_at: Option<Timestamp>,
    #[serde(default)]
    pub user_agent: Option<String>,
    #[serde(default)]
    pub ip: Option<String>,
}

#[async_trait(?Send)]
pub trait RefreshTokenRepository {
    /// Stores the hash of an issued refresh token.
    async fn create_token(&self, token: NewRefreshToken) -> Result<(), Error>;

    /// Looks a refresh token up by its hash.
    async fn find_token(&self, token_hash: &str) -> Result<Option<StoredRefreshToken>, Error>;

    /// Marks `old_token_hash` as rotated and stores its successor.
    ///
    /// Doing both in one call keeps a replay detectable: the old row survives
    /// with `rotated_at` set instead of disappearing.
    async fn rotate_token(&self, old_token_hash: &str, next: NewRefreshToken) -> Result<(), Error>;

    /// Revokes every token of a session. Returns `false` when the session does
    /// not belong to `account_id` (or no longer exists).
    async fn delete_session(&self, account_id: &str, family_id: &str) -> Result<bool, Error>;

    /// Revokes every session of an account (password reset, sign-out everywhere).
    async fn delete_tokens_for_account(&self, account_id: &str) -> Result<(), Error>;

    /// Lists the live sessions of an account, newest first.
    async fn list_sessions(&self, account_id: &str) -> Result<Vec<SessionInfo>, Error>;

    /// Deletes every token that expired before `now`. Returns how many rows were
    /// removed.
    async fn delete_expired(&self, now: jiff::Timestamp) -> Result<u32, Error>;
}
