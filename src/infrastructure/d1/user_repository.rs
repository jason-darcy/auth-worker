use async_trait::async_trait;
use worker::{console_error, wasm_bindgen::JsValue, D1Database, Error};

use crate::domain::{repositories::user::UserRepository, user::User};

#[derive(Debug)]
pub struct D1UserRepository {
    pub d1: D1Database,
}

impl D1UserRepository {
    pub fn new(d1: D1Database) -> Self {
        D1UserRepository { d1 }
    }
}

#[async_trait(?Send)]
impl UserRepository for D1UserRepository {
    async fn create_user(&self, user: User) -> Result<(), Error> {
        let statement = self.d1.prepare(
            "INSERT INTO users (id, name, email, password_hash, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        );
        let query = statement.bind(&[
            JsValue::from(user.id().to_string()),
            JsValue::from(user.name()),
            JsValue::from(user.email()),
            JsValue::from(user.password_hash()),
            JsValue::from_f64(user.created_at().as_second() as f64),
            JsValue::from_f64(user.updated_at().as_second() as f64),
        ])?;
        query.run().await.map_err(|err| {
            console_error!("create_user failed for {}: {err}", user.email());
            err
        })?;
        Ok(())
    }
    async fn find_user_by_id(&self, id: &str) -> Result<Option<User>, Error> {
        let statement = self.d1.prepare(
            "SELECT id, name, email, password_hash, created_at, updated_at FROM users WHERE id = ?1",
        );
        let query = statement.bind(&[JsValue::from(id)])?;
        query.first::<User>(None).await
    }
    async fn find_user_by_name(&self, name: &str) -> Result<Option<User>, Error> {
        let statement = self.d1.prepare(
            "SELECT id, name, email, password_hash, created_at, updated_at FROM users WHERE name = ?1",
        );
        let query = statement.bind(&[JsValue::from(name)])?;
        query.first::<User>(None).await
    }
    async fn find_user_by_email(&self, email: &str) -> Result<Option<User>, Error> {
        let statement = self.d1.prepare(
            "SELECT id, name, email, password_hash, created_at, updated_at FROM users WHERE email = ?1",
        );
        let query = statement.bind(&[JsValue::from(email)])?;
        query.first::<User>(None).await.map_err(|err| {
            console_error!("find_user_by_email failed for {email}: {err}");
            err
        })
    }
    async fn update_user(&self, user: &User) -> Result<(), Error> {
        let statement = self.d1.prepare(
            "UPDATE users SET name = ?1, email = ?2, password_hash = ?3, updated_at = ?4 WHERE id = ?5",
        );
        let query = statement.bind(&[
            JsValue::from(user.name()),
            JsValue::from(user.email()),
            JsValue::from(user.password_hash()),
            JsValue::from_f64(user.updated_at().as_second() as f64),
            JsValue::from(user.id().to_string()),
        ])?;
        query.run().await?;
        Ok(())
    }
    async fn delete_user(&self, id: &str) -> Result<(), Error> {
        let statement = self.d1.prepare("DELETE FROM users WHERE id = ?1");
        let query = statement.bind(&[JsValue::from(id)])?;
        query.run().await?;
        Ok(())
    }
}
