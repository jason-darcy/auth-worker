use async_trait::async_trait;
use worker::{wasm_bindgen::JsValue, D1Database, Error};

use crate::domain::{account::Account, repositories::account::AccountRepository};

const COLUMNS: &str = "id, name, email, password_hash, is_verified, created_at, updated_at";

#[derive(Debug)]
pub struct D1AccountRepository {
    pub d1: D1Database,
}

impl D1AccountRepository {
    pub fn new(d1: D1Database) -> Self {
        D1AccountRepository { d1 }
    }
}

#[async_trait(?Send)]
impl AccountRepository for D1AccountRepository {
    async fn create_account(&self, account: Account) -> Result<(), Error> {
        let statement = self.d1.prepare(
            "INSERT INTO accounts (id, name, email, password_hash, is_verified, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        );
        let query = statement.bind(&[
            JsValue::from(account.id().to_string()),
            JsValue::from(account.name()),
            JsValue::from(account.email()),
            JsValue::from(account.password_hash()),
            JsValue::from_f64(if account.is_verified() { 1.0 } else { 0.0 }),
            JsValue::from_f64(account.created_at().as_second() as f64),
            JsValue::from_f64(account.updated_at().as_second() as f64),
        ])?;
        query.run().await?;
        Ok(())
    }

    async fn find_account_by_email(&self, email: &str) -> Result<Option<Account>, Error> {
        let statement = self
            .d1
            .prepare(format!("SELECT {COLUMNS} FROM accounts WHERE email = ?1"));
        let query = statement.bind(&[JsValue::from(email)])?;
        query.first::<Account>(None).await
    }
}
