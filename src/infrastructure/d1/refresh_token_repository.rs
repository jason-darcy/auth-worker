use async_trait::async_trait;
use worker::{wasm_bindgen::JsValue, D1Database, Error};

use crate::{
    domain::repositories::refresh_token::{
        NewRefreshToken, RefreshTokenRepository, SessionInfo, StoredRefreshToken,
    },
    logging::log_error,
};

const COLUMNS: &str = "account_id, family_id, expires_at, rotated_at";

#[derive(Debug)]
pub struct D1RefreshTokenRepository {
    pub d1: D1Database,
}

impl D1RefreshTokenRepository {
    pub fn new(d1: D1Database) -> Self {
        D1RefreshTokenRepository { d1 }
    }

    fn insert_statement(
        &self,
        token: &NewRefreshToken,
    ) -> Result<worker::D1PreparedStatement, Error> {
        let statement = self.d1.prepare(
            "INSERT INTO refresh_tokens (token_hash, account_id, family_id, expires_at, user_agent, ip, last_used_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        );
        statement.bind(&[
            JsValue::from(token.token_hash.as_str()),
            JsValue::from(token.account_id.as_str()),
            JsValue::from(token.family_id.as_str()),
            JsValue::from_f64(token.expires_at.as_second() as f64),
            optional_string(&token.user_agent),
            optional_string(&token.ip),
            // A freshly issued token was just used.
            JsValue::from_f64(now_seconds()),
        ])
    }
}

fn now_seconds() -> f64 {
    jiff::Timestamp::now().as_second() as f64
}

fn optional_string(value: &Option<String>) -> JsValue {
    match value {
        Some(value) => JsValue::from(value.as_str()),
        None => JsValue::NULL,
    }
}

#[async_trait(?Send)]
impl RefreshTokenRepository for D1RefreshTokenRepository {
    async fn create_token(&self, token: NewRefreshToken) -> Result<(), Error> {
        let statement = self.insert_statement(&token)?;
        statement.run().await.map_err(|err| {
            log_error!(
                "create refresh token failed for account {}: {err}",
                token.account_id
            );
            err
        })?;
        Ok(())
    }

    async fn find_token(&self, token_hash: &str) -> Result<Option<StoredRefreshToken>, Error> {
        let statement = self.d1.prepare(format!(
            "SELECT {COLUMNS} FROM refresh_tokens WHERE token_hash = ?1"
        ));
        let query = statement.bind(&[JsValue::from(token_hash)])?;
        query
            .first::<StoredRefreshToken>(None)
            .await
            .map_err(|err| {
                log_error!("find refresh token failed: {err}");
                err
            })
    }

    async fn rotate_token(&self, old_token_hash: &str, next: NewRefreshToken) -> Result<(), Error> {
        let now = now_seconds();
        let mark_rotated = self
            .d1
            .prepare(
                "UPDATE refresh_tokens SET rotated_at = ?1, last_used_at = ?1 WHERE token_hash = ?2",
            )
            .bind(&[JsValue::from_f64(now), JsValue::from(old_token_hash)])?;
        let insert = self.insert_statement(&next)?;

        // Batched so the old token never disappears without its successor.
        self.d1
            .batch(vec![mark_rotated, insert])
            .await
            .map_err(|err| {
                log_error!(
                    "rotate refresh token failed for account {}: {err}",
                    next.account_id
                );
                err
            })?;
        Ok(())
    }

    async fn delete_session(&self, account_id: &str, family_id: &str) -> Result<bool, Error> {
        let statement = self
            .d1
            .prepare("DELETE FROM refresh_tokens WHERE account_id = ?1 AND family_id = ?2");
        let query = statement.bind(&[JsValue::from(account_id), JsValue::from(family_id)])?;
        let result = query.run().await.map_err(|err| {
            log_error!("delete session {family_id} failed for account {account_id}: {err}");
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

    async fn delete_expired(&self, now: jiff::Timestamp) -> Result<u32, Error> {
        // Rotated rows keep their original expiry, so a replay stays detectable
        // until the token would have expired anyway.
        let statement = self
            .d1
            .prepare("DELETE FROM refresh_tokens WHERE expires_at <= ?1");
        let query = statement.bind(&[JsValue::from_f64(now.as_second() as f64)])?;
        let result = query.run().await.map_err(|err| {
            log_error!("delete expired refresh tokens failed: {err}");
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
            .prepare("DELETE FROM refresh_tokens WHERE account_id = ?1");
        let query = statement.bind(&[JsValue::from(account_id)])?;
        query.run().await.map_err(|err| {
            log_error!("revoke refresh tokens failed for account {account_id}: {err}");
            err
        })?;
        Ok(())
    }

    async fn list_sessions(&self, account_id: &str) -> Result<Vec<SessionInfo>, Error> {
        // Only the newest (not yet rotated) token of a family is live; the
        // aggregates collapse the rest of the lineage into one session row.
        let statement = self.d1.prepare(
            "SELECT family_id, \
                    MIN(created_at) AS created_at, \
                    MAX(expires_at) AS expires_at, \
                    MAX(last_used_at) AS last_used_at, \
                    MAX(user_agent) AS user_agent, \
                    MAX(ip) AS ip \
             FROM refresh_tokens \
             WHERE account_id = ?1 AND rotated_at IS NULL AND expires_at > unixepoch() \
             GROUP BY family_id \
             ORDER BY created_at DESC",
        );
        let query = statement.bind(&[JsValue::from(account_id)])?;
        let result = query.all().await.map_err(|err| {
            log_error!("list sessions failed for account {account_id}: {err}");
            err
        })?;
        result.results::<SessionInfo>()
    }
}
