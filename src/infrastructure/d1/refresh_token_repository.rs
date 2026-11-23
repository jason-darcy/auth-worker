use async_trait::async_trait;
use jiff::Timestamp;
use worker::{wasm_bindgen::JsValue, D1Database, Error};

use crate::{
    domain::repositories::refresh_token::{RefreshTokenRepository, StoredRefreshToken},
    logging::log_error,
};

#[derive(Debug)]
pub struct D1RefreshTokenRepository {
    pub d1: D1Database,
}

impl D1RefreshTokenRepository {
    pub fn new(d1: D1Database) -> Self {
        D1RefreshTokenRepository { d1 }
    }
}

#[async_trait(?Send)]
impl RefreshTokenRepository for D1RefreshTokenRepository {
    async fn create_token(
        &self,
        account_id: &str,
        token_hash: &str,
        expires_at: Timestamp,
    ) -> Result<(), Error> {
        let statement = self.d1.prepare(
            "INSERT INTO refresh_tokens (token_hash, account_id, expires_at) VALUES (?1, ?2, ?3)",
        );
        let query = statement.bind(&[
            JsValue::from(token_hash),
            JsValue::from(account_id),
            JsValue::from_f64(expires_at.as_second() as f64),
        ])?;
        query.run().await.map_err(|err| {
            log_error!("create refresh token failed for account {account_id}: {err}");
            err
        })?;
        Ok(())
    }

    async fn find_token(&self, token_hash: &str) -> Result<Option<StoredRefreshToken>, Error> {
        let statement = self
            .d1
            .prepare("SELECT account_id, expires_at FROM refresh_tokens WHERE token_hash = ?1");
        let query = statement.bind(&[JsValue::from(token_hash)])?;
        query
            .first::<StoredRefreshToken>(None)
            .await
            .map_err(|err| {
                log_error!("find refresh token failed: {err}");
                err
            })
    }

    async fn delete_token(&self, token_hash: &str) -> Result<(), Error> {
        let statement = self
            .d1
            .prepare("DELETE FROM refresh_tokens WHERE token_hash = ?1");
        let query = statement.bind(&[JsValue::from(token_hash)])?;
        query.run().await.map_err(|err| {
            log_error!("delete refresh token failed: {err}");
            err
        })?;
        Ok(())
    }

    async fn delete_tokens_for_account(&self, account_id: &str) -> Result<(), Error> {
        let statement = self
            .d1
            .prepare("DELETE FROM refresh_tokens WHERE account_id = ?1");
        let query = statement.bind(&[JsValue::from(account_id)])?;
        query.run().await.map_err(|err| {
            log_error!("revoke refresh tokens failed for account {account_id}: {err}");
            err
        })?;
        Ok(())
    }
}
