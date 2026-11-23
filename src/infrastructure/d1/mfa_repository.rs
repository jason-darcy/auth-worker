use async_trait::async_trait;
use jiff::Timestamp;
use serde::Deserialize;
use worker::{wasm_bindgen::JsValue, D1Database, Error};

use crate::{
    domain::{
        mfa::{StoredMfaChallenge, TotpCredential},
        repositories::mfa::MfaRepository,
    },
    infrastructure::services::secret_box::SecretBox,
    logging::log_error,
};

/// Raw row of `totp_credentials`, with the secret still encrypted.
#[derive(Deserialize)]
struct CredentialRow {
    account_id: String,
    secret: String,
    confirmed_at: Option<i64>,
    last_used_step: Option<i64>,
}

/// Row shape of `COUNT(*)`.
#[derive(Deserialize)]
struct CountRow {
    count: u32,
}

/// Row shape of the attempt counter update.
#[derive(Deserialize)]
struct AttemptsRow {
    attempts: u32,
}

#[derive(Debug)]
pub struct D1MfaRepository {
    pub d1: D1Database,
    /// Encrypts the TOTP secrets at rest.
    pub secret_box: SecretBox,
}

impl D1MfaRepository {
    pub fn new(d1: D1Database, secret_box: SecretBox) -> Self {
        D1MfaRepository { d1, secret_box }
    }
}

fn optional_seconds(value: Option<Timestamp>) -> JsValue {
    match value {
        Some(value) => JsValue::from_f64(value.as_second() as f64),
        None => JsValue::NULL,
    }
}

fn optional_step(value: Option<i64>) -> JsValue {
    match value {
        Some(value) => JsValue::from_f64(value as f64),
        None => JsValue::NULL,
    }
}

fn seconds_to_timestamp(second: i64) -> Timestamp {
    Timestamp::from_second(second).unwrap_or(Timestamp::MAX)
}

#[async_trait(?Send)]
impl MfaRepository for D1MfaRepository {
    async fn find_credential(&self, account_id: &str) -> Result<Option<TotpCredential>, Error> {
        let statement = self.d1.prepare(
            "SELECT account_id, secret, confirmed_at, last_used_step \
             FROM totp_credentials WHERE account_id = ?1",
        );
        let query = statement.bind(&[JsValue::from(account_id)])?;
        let row = query.first::<CredentialRow>(None).await.map_err(|err| {
            log_error!("find totp credential failed for {account_id}: {err}");
            err
        })?;

        let Some(row) = row else {
            return Ok(None);
        };
        let secret = self.secret_box.open(&row.secret)?;
        Ok(Some(TotpCredential {
            account_id: row.account_id,
            secret,
            confirmed_at: row.confirmed_at.map(seconds_to_timestamp),
            last_used_step: row.last_used_step,
        }))
    }

    async fn save_credential(&self, credential: &TotpCredential) -> Result<(), Error> {
        let sealed = self.secret_box.seal(&credential.secret)?;
        let statement = self.d1.prepare(
            "INSERT INTO totp_credentials (account_id, secret, confirmed_at, last_used_step, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, unixepoch(), unixepoch()) \
             ON CONFLICT(account_id) DO UPDATE SET \
                secret = excluded.secret, \
                confirmed_at = excluded.confirmed_at, \
                last_used_step = excluded.last_used_step, \
                updated_at = unixepoch()",
        );
        let query = statement.bind(&[
            JsValue::from(credential.account_id.as_str()),
            JsValue::from(sealed),
            optional_seconds(credential.confirmed_at),
            optional_step(credential.last_used_step),
        ])?;
        query.run().await.map_err(|err| {
            log_error!(
                "save totp credential failed for {}: {err}",
                credential.account_id
            );
            err
        })?;
        Ok(())
    }

    async fn delete_credential(&self, account_id: &str) -> Result<(), Error> {
        let statements = vec![
            self.d1
                .prepare("DELETE FROM totp_credentials WHERE account_id = ?1")
                .bind(&[JsValue::from(account_id)])?,
            self.d1
                .prepare("DELETE FROM recovery_codes WHERE account_id = ?1")
                .bind(&[JsValue::from(account_id)])?,
        ];
        self.d1.batch(statements).await.map_err(|err| {
            log_error!("delete totp credential failed for {account_id}: {err}");
            err
        })?;
        Ok(())
    }

    async fn replace_recovery_codes(
        &self,
        account_id: &str,
        code_hashes: &[String],
    ) -> Result<(), Error> {
        let mut statements = vec![self
            .d1
            .prepare("DELETE FROM recovery_codes WHERE account_id = ?1")
            .bind(&[JsValue::from(account_id)])?];
        for code_hash in code_hashes {
            statements.push(
                self.d1
                    .prepare("INSERT INTO recovery_codes (code_hash, account_id) VALUES (?1, ?2)")
                    .bind(&[JsValue::from(code_hash.as_str()), JsValue::from(account_id)])?,
            );
        }
        self.d1.batch(statements).await.map_err(|err| {
            log_error!("replace recovery codes failed for {account_id}: {err}");
            err
        })?;
        Ok(())
    }

    async fn consume_recovery_code(
        &self,
        account_id: &str,
        code_hash: &str,
    ) -> Result<bool, Error> {
        let statement = self.d1.prepare(
            "UPDATE recovery_codes SET used_at = unixepoch() \
             WHERE account_id = ?1 AND code_hash = ?2 AND used_at IS NULL",
        );
        let query = statement.bind(&[JsValue::from(account_id), JsValue::from(code_hash)])?;
        let result = query.run().await.map_err(|err| {
            log_error!("consume recovery code failed for {account_id}: {err}");
            err
        })?;
        Ok(result
            .meta()
            .ok()
            .flatten()
            .and_then(|meta| meta.changes)
            .unwrap_or(0)
            > 0)
    }

    async fn count_recovery_codes(&self, account_id: &str) -> Result<u32, Error> {
        let statement = self.d1.prepare(
            "SELECT COUNT(*) AS count FROM recovery_codes WHERE account_id = ?1 AND used_at IS NULL",
        );
        let query = statement.bind(&[JsValue::from(account_id)])?;
        Ok(query
            .first::<CountRow>(None)
            .await
            .map_err(|err| {
                log_error!("count recovery codes failed for {account_id}: {err}");
                err
            })?
            .map(|row| row.count)
            .unwrap_or(0))
    }

    async fn create_challenge(
        &self,
        account_id: &str,
        token_hash: &str,
        expires_at: Timestamp,
    ) -> Result<(), Error> {
        let statement = self.d1.prepare(
            "INSERT INTO mfa_challenges (token_hash, account_id, expires_at) VALUES (?1, ?2, ?3)",
        );
        let query = statement.bind(&[
            JsValue::from(token_hash),
            JsValue::from(account_id),
            JsValue::from_f64(expires_at.as_second() as f64),
        ])?;
        query.run().await.map_err(|err| {
            log_error!("create mfa challenge failed for {account_id}: {err}");
            err
        })?;
        Ok(())
    }

    async fn find_challenge(&self, token_hash: &str) -> Result<Option<StoredMfaChallenge>, Error> {
        let statement = self.d1.prepare(
            "SELECT account_id, expires_at, attempts FROM mfa_challenges WHERE token_hash = ?1",
        );
        let query = statement.bind(&[JsValue::from(token_hash)])?;
        query
            .first::<StoredMfaChallenge>(None)
            .await
            .map_err(|err| {
                log_error!("find mfa challenge failed: {err}");
                err
            })
    }

    async fn record_challenge_attempt(&self, token_hash: &str) -> Result<u32, Error> {
        let update = self
            .d1
            .prepare("UPDATE mfa_challenges SET attempts = attempts + 1 WHERE token_hash = ?1")
            .bind(&[JsValue::from(token_hash)])?;
        update.run().await.map_err(|err| {
            log_error!("recording an mfa attempt failed: {err}");
            err
        })?;

        let statement = self
            .d1
            .prepare("SELECT attempts FROM mfa_challenges WHERE token_hash = ?1");
        let query = statement.bind(&[JsValue::from(token_hash)])?;
        Ok(query
            .first::<AttemptsRow>(None)
            .await?
            .map(|row| row.attempts)
            .unwrap_or(0))
    }

    async fn delete_challenge(&self, token_hash: &str) -> Result<(), Error> {
        let statement = self
            .d1
            .prepare("DELETE FROM mfa_challenges WHERE token_hash = ?1");
        let query = statement.bind(&[JsValue::from(token_hash)])?;
        query.run().await.map_err(|err| {
            log_error!("delete mfa challenge failed: {err}");
            err
        })?;
        Ok(())
    }

    async fn delete_expired_challenges(&self, now: Timestamp) -> Result<u32, Error> {
        let statement = self
            .d1
            .prepare("DELETE FROM mfa_challenges WHERE expires_at <= ?1");
        let query = statement.bind(&[JsValue::from_f64(now.as_second() as f64)])?;
        let result = query.run().await.map_err(|err| {
            log_error!("delete expired mfa challenges failed: {err}");
            err
        })?;
        Ok(result
            .meta()
            .ok()
            .flatten()
            .and_then(|meta| meta.changes)
            .unwrap_or(0) as u32)
    }
}
