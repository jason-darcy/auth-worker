use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    id: Uuid,
    name: String,
    email: String,
    password_hash: String,
    /// SQLite/D1 stores booleans as integers, so `0`/`1` must be accepted too.
    #[serde(deserialize_with = "deserialize_bool_from_integer")]
    is_verified: bool,
    #[serde(with = "jiff::fmt::serde::timestamp::second::required")]
    created_at: Timestamp,
    #[serde(with = "jiff::fmt::serde::timestamp::second::required")]
    updated_at: Timestamp,
}

/// Canonical form of an email address.
///
/// Emails are stored and looked up case-insensitively: otherwise
/// `Ada@Example.com` and `ada@example.com` would be different accounts.
pub fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

impl Account {
    pub fn new(name: &str, email: &str, password_hash: &str) -> Self {
        Account {
            id: Uuid::now_v7(),
            name: name.to_owned(),
            email: normalize_email(email),
            password_hash: password_hash.to_owned(),
            is_verified: false,
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
    pub fn is_verified(&self) -> bool {
        self.is_verified
    }
    /// Marks the account as usable.
    ///
    /// There is no email verification flow, so a freshly created account is
    /// already active; the flag is kept because the table carries it.
    pub fn mark_verified(&mut self) {
        self.is_verified = true;
        self.updated_at = Timestamp::now();
    }
    pub fn created_at(&self) -> Timestamp {
        self.created_at
    }
    pub fn updated_at(&self) -> Timestamp {
        self.updated_at
    }
}

fn deserialize_bool_from_integer<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum BoolOrInteger {
        Bool(bool),
        Integer(i64),
    }

    Ok(match BoolOrInteger::deserialize(deserializer)? {
        BoolOrInteger::Bool(value) => value,
        BoolOrInteger::Integer(value) => value != 0,
    })
}
