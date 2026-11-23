use async_trait::async_trait;
use jiff::Timestamp;
use worker::{wasm_bindgen::JsValue, D1Database, Error};

use crate::{
    domain::repositories::verification_token::{
        StoredVerificationToken, VerificationTokenRepository,
    },
    logging::log_error,
};

/// Row shape of the `MAX(created_at)` aggregate, which is `NULL` without rows.
#[derive(serde::Deserialize)]
struct TokenAge {
    age: Option<i64>,
}

#[derive(Debug)]
pub struct D1VerificationTokenRepository {
    pub d1: D1Database,
}

impl D1VerificationTokenRepository {
    pub fn new(d1: D1Database) -> Self {
        D1VerificationTokenRepository { d1 }
    }
}

#[async_trait(?Send)]
impl VerificationTokenRepository for D1VerificationTokenRepository {
    async fn create_token(
        &self,
        account_id: &str,
        token_hash: &str,
        expires_at: Timestamp,
    ) -> Result<(), Error> {
        let statement = self.d1.prepare(
            "INSERT INTO email_verification_tokens (token_hash, account_id, expires_at) VALUES (?1, ?2, ?3)",
        );
        let query = statement.bind(&[
            JsValue::from(token_hash),
            JsValue::from(account_id),
            JsValue::from_f64(expires_at.as_second() as f64),
        ])?;
        query.run().await.map_err(|err| {
            log_error!("create verification token failed for account {account_id}: {err}");
            err
        })?;
        Ok(())
    }

    async fn find_token(&self, token_hash: &str) -> Result<Option<StoredVerificationToken>, Error> {
        let statement = self.d1.prepare(
            "SELECT account_id, expires_at FROM email_verification_tokens WHERE token_hash = ?1",
        );
        let query = statement.bind(&[JsValue::from(token_hash)])?;
        query
            .first::<StoredVerificationToken>(None)
            .await
            .map_err(|err| {
                log_error!("find verification token failed: {err}");
                err
            })
    }

    async fn delete_token(&self, token_hash: &str) -> Result<(), Error> {
        let statement = self
            .d1
            .prepare("DELETE FROM email_verification_tokens WHERE token_hash = ?1");
        let query = statement.bind(&[JsValue::from(token_hash)])?;
        query.run().await.map_err(|err| {
            log_error!("delete verification token failed: {err}");
            err
        })?;
        Ok(())
    }

    async fn seconds_since_last_token(&self, account_id: &str) -> Result<Option<i64>, Error> {
        let statement = self.d1.prepare(
            "SELECT unixepoch() - MAX(created_at) AS age FROM email_verification_tokens WHERE account_id = ?1",
        );
        let query = statement.bind(&[JsValue::from(account_id)])?;
        Ok(query
            .first::<TokenAge>(None)
            .await
            .map_err(|err| {
                log_error!("token age lookup failed for account {account_id}: {err}");
                err
            })?
            .and_then(|row| row.age))
    }

    async fn delete_expired(&self, now: Timestamp) -> Result<u32, Error> {
        let statement = self
            .d1
            .prepare("DELETE FROM email_verification_tokens WHERE expires_at <= ?1");
        let query = statement.bind(&[JsValue::from_f64(now.as_second() as f64)])?;
        let result = query.run().await.map_err(|err| {
            log_error!("delete expired verification tokens failed: {err}");
            err
        })?;
        Ok(result
            .meta()
            .ok()
            .flatten()
            .and_then(|meta| meta.changes)
            .unwrap_or(0) as u32)
    }

    async fn delete_tokens_for_account(&self, account_id: &str) -> Result<(), Error> {
        let statement = self
            .d1
            .prepare("DELETE FROM email_verification_tokens WHERE account_id = ?1");
        let query = statement.bind(&[JsValue::from(account_id)])?;
        query.run().await.map_err(|err| {
            log_error!("delete verification tokens failed for account {account_id}: {err}");
            err
        })?;
        Ok(())
    }
}
