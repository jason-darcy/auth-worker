use async_trait::async_trait;
use jiff::Timestamp;
use worker::Error;

use crate::domain::mfa::{StoredMfaChallenge, TotpCredential};

#[async_trait(?Send)]
pub trait MfaRepository {
    /// TOTP credential of an account, if one was ever started.
    async fn find_credential(&self, account_id: &str) -> Result<Option<TotpCredential>, Error>;

    /// Creates or replaces the credential. A pending enrolment overwrites a
    /// previous pending one but never an active credential.
    async fn save_credential(&self, credential: &TotpCredential) -> Result<(), Error>;

    /// Removes the credential and every recovery code of the account.
    async fn delete_credential(&self, account_id: &str) -> Result<(), Error>;

    /// Replaces every recovery code of the account with `code_hashes`.
    async fn replace_recovery_codes(
        &self,
        account_id: &str,
        code_hashes: &[String],
    ) -> Result<(), Error>;

    /// Marks a recovery code as used. Returns `false` when it was unknown or
    /// already used.
    async fn consume_recovery_code(&self, account_id: &str, code_hash: &str)
        -> Result<bool, Error>;

    /// Recovery codes that are still usable.
    async fn count_recovery_codes(&self, account_id: &str) -> Result<u32, Error>;

    async fn create_challenge(
        &self,
        account_id: &str,
        token_hash: &str,
        expires_at: Timestamp,
    ) -> Result<(), Error>;

    async fn find_challenge(&self, token_hash: &str) -> Result<Option<StoredMfaChallenge>, Error>;

    /// Counts a wrong attempt and returns the new total.
    async fn record_challenge_attempt(&self, token_hash: &str) -> Result<u32, Error>;

    async fn delete_challenge(&self, token_hash: &str) -> Result<(), Error>;

    /// Drops expired challenges. Returns how many rows were removed.
    async fn delete_expired_challenges(&self, now: Timestamp) -> Result<u32, Error>;
}
