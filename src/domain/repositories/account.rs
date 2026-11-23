use async_trait::async_trait;
use worker::Error;

use crate::domain::account::Account;

#[async_trait(?Send)]
pub trait AccountRepository {
    async fn create_account(&self, account: Account) -> Result<(), Error>;
    async fn find_account_by_id(&self, id: &str) -> Result<Option<Account>, Error>;
    async fn find_account_by_name(&self, name: &str) -> Result<Option<Account>, Error>;
    async fn find_account_by_email(&self, email: &str) -> Result<Option<Account>, Error>;
    async fn update_account(&self, account: &Account) -> Result<(), Error>;
    async fn delete_account(&self, id: &str) -> Result<(), Error>;
}
