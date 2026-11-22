use async_trait::async_trait;
use worker::Error;

use crate::domain::user::User;

#[async_trait(?Send)]
pub trait UserRepository {
    async fn create_user(&self, user: User) -> Result<(), Error>;
    async fn find_user_by_id(&self, id: &str) -> Result<Option<User>, Error>;
    async fn find_user_by_name(&self, name: &str) -> Result<Option<User>, Error>;
    async fn find_user_by_email(&self, email: &str) -> Result<Option<User>, Error>;
    async fn update_user(&self, user: &User) -> Result<(), Error>;
    async fn delete_user(&self, id: &str) -> Result<(), Error>;
}
