use async_trait::async_trait;
use jiff::Timestamp;
use worker::{wasm_bindgen::JsValue, D1Database, Error};

use crate::{
    domain::repositories::password_reset_token::{
        PasswordResetTokenRepository, StoredPasswordResetToken,
    },
    logging::log_error,
};

#[derive(Debug)]
pub struct D1PasswordResetTokenRepository {
    pub d1: D1Database,
}

impl D1PasswordResetTokenRepository {
    pub fn new(d1: D1Database) -> Self {
        D1PasswordResetTokenRepository { d1 }
    }
}

#[async_trait(?Send)]
impl PasswordResetTokenRepository for D1PasswordResetTokenRepository {
    async fn create_token(
        &self,
        account_id: &str,
        token_hash: &str,
        expires_at: Timestamp,
    ) -> Result<(), Error> {
        let statement = self.d1.prepare(
            "INSERT INTO password_reset_tokens (token_hash, account_id, expires_at) VALUES (?1, ?2, ?3)",
        );
        let query = statement.bind(&[
            JsValue::from(token_hash),
            JsValue::from(account_id),
            JsValue::from_f64(expires_at.as_second() as f64),
        ])?;
        query.run().await.map_err(|err| {
            log_error!("create password reset token failed for account {account_id}: {err}");
            err
        })?;
        Ok(())
    }

    async fn find_token(
        &self,
        token_hash: &str,
    ) -> Result<Option<StoredPasswordResetToken>, Error> {
        let statement = self.d1.prepare(
            "SELECT account_id, expires_at FROM password_reset_tokens WHERE token_hash = ?1",
        );
        let query = statement.bind(&[JsValue::from(token_hash)])?;
        query
            .first::<StoredPasswordResetToken>(None)
            .await
            .map_err(|err| {
                log_error!("find password reset token failed: {err}");
                err
            })
    }

    async fn delete_token(&self, token_hash: &str) -> Result<(), Error> {
        let statement = self
            .d1
            .prepare("DELETE FROM password_reset_tokens WHERE token_hash = ?1");
        let query = statement.bind(&[JsValue::from(token_hash)])?;
        query.run().await.map_err(|err| {
            log_error!("delete password reset token failed: {err}");
            err
        })?;
        Ok(())
    }

    async fn delete_tokens_for_account(&self, account_id: &str) -> Result<(), Error> {
        let statement = self
            .d1
            .prepare("DELETE FROM password_reset_tokens WHERE account_id = ?1");
        let query = statement.bind(&[JsValue::from(account_id)])?;
        query.run().await.map_err(|err| {
            log_error!("delete password reset tokens failed for account {account_id}: {err}");
            err
        })?;
        Ok(())
    }
}
