use async_trait::async_trait;
use jiff::Timestamp;
use worker::{wasm_bindgen::JsValue, D1Database, Error};

use crate::{
    domain::repositories::verification_token::{
        StoredVerificationToken, VerificationTokenRepository,
    },
    logging::log_error,
};

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
}
