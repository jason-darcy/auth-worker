use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    id: Uuid,
    name: String,
    email: String,
    password_hash: String,
    #[serde(with = "jiff::fmt::serde::timestamp::second::required")]
    created_at: Timestamp,
    #[serde(with = "jiff::fmt::serde::timestamp::second::required")]
    updated_at: Timestamp,
}

impl User {
    pub fn new(name: &str, email: &str, password_hash: &str) -> Self {
        User {
            id: Uuid::now_v7(),
            name: name.to_owned(),
            email: email.to_owned(),
            password_hash: password_hash.to_owned(),
            created_at: Timestamp::now(),
            updated_at: Timestamp::now(),
        }
    }
    pub fn id(&self) -> Uuid {
        self.id
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn email(&self) -> &str {
        &self.email
    }
    pub fn password_hash(&self) -> &str {
        &self.password_hash
    }
    pub fn created_at(&self) -> Timestamp {
        self.created_at
    }
    pub fn updated_at(&self) -> Timestamp {
        self.updated_at
    }
}
