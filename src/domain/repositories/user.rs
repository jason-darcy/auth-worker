use async_trait::async_trait;
use worker::Error;

use crate::domain::user::User;

#[async_trait(?Send)]
pub trait UserRepository {
    async fn create_user(&self, user: User) -> Result<(), Error>;
    async fn find_user_by_id(&self);
    async fn find_user_by_name(&self);
    async fn find_user_by_email(&self);
    async fn update_user(&self);
    async fn delete_user(&self);
}
