use async_trait::async_trait;
use worker::{wasm_bindgen::JsValue, D1Database, Error};

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
        let statement = self.d1.prepare("");
        let query = statement.bind(&[
            JsValue::from(user.id),
            JsValue::from(user.name),
            JsValue::from(user.password_hash),
        ])?;
        let _result = query.first::<User>(None).await?;
        Ok(())
    }
    async fn find_user_by_id(&self) {}
    async fn find_user_by_name(&self) {}
    async fn find_user_by_email(&self) {}
    async fn update_user(&self) {}
    async fn delete_user(&self) {}
}
