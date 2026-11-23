use async_trait::async_trait;
use worker::{wasm_bindgen::JsValue, D1Database, Error};

use crate::{
    domain::{account::Account, repositories::account::AccountRepository},
    logging::log_error,
};

const COLUMNS: &str = "id, name, email, password_hash, is_verified, token_version, \
                       failed_login_attempts, locked_until, created_at, updated_at";

#[derive(Debug)]
pub struct D1AccountRepository {
    pub d1: D1Database,
}

impl D1AccountRepository {
    pub fn new(d1: D1Database) -> Self {
        D1AccountRepository { d1 }
    }

    fn select(&self, predicate: &str) -> worker::D1PreparedStatement {
        self.d1
            .prepare(format!("SELECT {COLUMNS} FROM accounts WHERE {predicate}"))
    }
}

fn optional_seconds(value: Option<jiff::Timestamp>) -> JsValue {
    match value {
        Some(value) => JsValue::from_f64(value.as_second() as f64),
        None => JsValue::NULL,
    }
}

#[async_trait(?Send)]
impl AccountRepository for D1AccountRepository {
    async fn create_account(&self, account: Account) -> Result<(), Error> {
        let statement = self.d1.prepare(
            "INSERT INTO accounts (id, name, email, password_hash, is_verified, token_version, failed_login_attempts, locked_until, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        );
        let query = statement.bind(&[
            JsValue::from(account.id().to_string()),
            JsValue::from(account.name()),
            JsValue::from(account.email()),
            JsValue::from(account.password_hash()),
            JsValue::from_f64(if account.is_verified() { 1.0 } else { 0.0 }),
            JsValue::from_f64(account.token_version() as f64),
            JsValue::from_f64(account.failed_login_attempts() as f64),
            optional_seconds(account.locked_until()),
            JsValue::from_f64(account.created_at().as_second() as f64),
            JsValue::from_f64(account.updated_at().as_second() as f64),
        ])?;
        query.run().await.map_err(|err| {
            log_error!("create_account failed for {}: {err}", account.email());
            err
        })?;
        Ok(())
    }
    async fn find_account_by_id(&self, id: &str) -> Result<Option<Account>, Error> {
        let statement = self.select("id = ?1");
        let query = statement.bind(&[JsValue::from(id)])?;
        query.first::<Account>(None).await
    }
    async fn find_account_by_name(&self, name: &str) -> Result<Option<Account>, Error> {
        let statement = self.select("name = ?1");
        let query = statement.bind(&[JsValue::from(name)])?;
        query.first::<Account>(None).await
    }
    async fn find_account_by_email(&self, email: &str) -> Result<Option<Account>, Error> {
        let statement = self.select("email = ?1");
        let query = statement.bind(&[JsValue::from(email)])?;
        query.first::<Account>(None).await.map_err(|err| {
            log_error!("find_account_by_email failed for {email}: {err}");
            err
        })
    }
    async fn update_account(&self, account: &Account) -> Result<(), Error> {
        let statement = self.d1.prepare(
            "UPDATE accounts SET name = ?1, email = ?2, password_hash = ?3, is_verified = ?4, \
             token_version = ?5, failed_login_attempts = ?6, locked_until = ?7, updated_at = ?8 \
             WHERE id = ?9",
        );
        let query = statement.bind(&[
            JsValue::from(account.name()),
            JsValue::from(account.email()),
            JsValue::from(account.password_hash()),
            JsValue::from_f64(if account.is_verified() { 1.0 } else { 0.0 }),
            JsValue::from_f64(account.token_version() as f64),
            JsValue::from_f64(account.failed_login_attempts() as f64),
            optional_seconds(account.locked_until()),
            JsValue::from_f64(account.updated_at().as_second() as f64),
            JsValue::from(account.id().to_string()),
        ])?;
        query.run().await?;
        Ok(())
    }
    async fn delete_account(&self, id: &str) -> Result<(), Error> {
        let statement = self.d1.prepare("DELETE FROM accounts WHERE id = ?1");
        let query = statement.bind(&[JsValue::from(id)])?;
        query.run().await?;
        Ok(())
    }
}
