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
    /// Incremented on credential changes; access tokens carry the value they
    /// were issued with and are rejected once it changes.
    #[serde(default)]
    token_version: u32,
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
            token_version: 0,
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
    pub fn token_version(&self) -> u32 {
        self.token_version
    }
    /// Invalidates every access token issued so far.
    pub fn bump_token_version(&mut self) {
        self.token_version = self.token_version.saturating_add(1);
        self.updated_at = Timestamp::now();
    }
    /// Replaces the password hash after a password reset.
    pub fn change_password(&mut self, password_hash: &str) {
        self.password_hash = password_hash.to_owned();
        self.updated_at = Timestamp::now();
    }
    /// Marks the account as verified once the emailed token was confirmed.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_account_is_not_verified() {
        let account = Account::new("Ada Lovelace", "ada@example.com", "hashed");

        assert!(!account.is_verified());
        assert!(!account.id().is_nil());
    }

    #[test]
    fn token_version_starts_at_zero_and_bumps() {
        let mut account = Account::new("Ada Lovelace", "ada@example.com", "hashed");

        assert_eq!(account.token_version(), 0);
        account.bump_token_version();
        assert_eq!(account.token_version(), 1);
        account.bump_token_version();
        assert_eq!(account.token_version(), 2);
    }

    #[test]
    fn normalizes_email_on_construction() {
        let account = Account::new("Ada Lovelace", "  Ada@Example.COM  ", "hashed");

        assert_eq!(account.email(), "ada@example.com");
    }

    #[test]
    fn normalizes_emails_by_trimming_and_lowercasing() {
        assert_eq!(normalize_email("  Ada@Example.COM "), "ada@example.com");
        assert_eq!(normalize_email("ada@example.com"), "ada@example.com");
        assert_eq!(normalize_email(""), "");
    }

    #[test]
    fn deserializes_is_verified_from_integers_and_booleans() {
        let row = serde_json::json!({
            "id": "00000000-0000-0000-0000-000000000000",
            "name": "Ada Lovelace",
            "email": "ada@example.com",
            "password_hash": "hashed",
            "is_verified": 1,
            "created_at": 1767323045,
            "updated_at": 1767323045,
        });
        let account: Account = serde_json::from_value(row).expect("row should deserialize");
        assert!(account.is_verified());

        let mut row = serde_json::json!({
            "id": "00000000-0000-0000-0000-000000000000",
            "name": "Ada Lovelace",
            "email": "ada@example.com",
            "password_hash": "hashed",
            "is_verified": 0,
            "created_at": 1767323045,
            "updated_at": 1767323045,
        });
        let account: Account = serde_json::from_value(row.clone()).expect("row should deserialize");
        assert!(!account.is_verified());

        row["is_verified"] = serde_json::json!(true);
        let account: Account = serde_json::from_value(row).expect("row should deserialize");
        assert!(account.is_verified());
    }
}
