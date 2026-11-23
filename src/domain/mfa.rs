use jiff::Timestamp;
use serde::{Deserialize, Serialize};

/// How long the ticket issued after a correct password stays usable.
pub const MFA_CHALLENGE_TTL: std::time::Duration = std::time::Duration::from_secs(5 * 60);
/// Wrong second factors allowed before the ticket is destroyed.
pub const MFA_CHALLENGE_MAX_ATTEMPTS: u32 = 5;
/// Recovery codes handed out when MFA is enabled.
pub const RECOVERY_CODE_COUNT: usize = 10;
/// Symbols in a recovery code (50 bits).
pub const RECOVERY_CODE_LEN: usize = 10;

/// TOTP credential of an account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TotpCredential {
    pub account_id: String,
    /// Base32 secret. The repository encrypts it at rest.
    pub secret: String,
    /// `None` while the enrolment is still waiting for its first valid code.
    pub confirmed_at: Option<Timestamp>,
    /// Last accepted time step, used to reject replayed codes.
    pub last_used_step: Option<i64>,
}

impl TotpCredential {
    pub fn new(account_id: &str, secret: &str) -> Self {
        TotpCredential {
            account_id: account_id.to_owned(),
            secret: secret.to_owned(),
            confirmed_at: None,
            last_used_step: None,
        }
    }

    pub fn is_confirmed(&self) -> bool {
        self.confirmed_at.is_some()
    }

    /// Marks the enrolment as finished.
    pub fn confirm(&mut self, now: Timestamp, step: i64) {
        self.confirmed_at = Some(now);
        self.last_used_step = Some(step);
    }

    /// Records a successful verification, so the same code cannot be replayed.
    pub fn accept_step(&mut self, step: i64) {
        self.last_used_step = Some(step);
    }

    /// `true` when `step` was already used (a replayed code).
    pub fn is_replayed(&self, step: i64) -> bool {
        self.last_used_step.is_some_and(|last| step <= last)
    }
}

/// A pending second-factor challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredMfaChallenge {
    pub account_id: String,
    #[serde(with = "jiff::fmt::serde::timestamp::second::required")]
    pub expires_at: Timestamp,
    #[serde(default)]
    pub attempts: u32,
}

impl StoredMfaChallenge {
    pub fn is_expired(&self, now: Timestamp) -> bool {
        self.expires_at <= now
    }

    pub fn is_exhausted(&self) -> bool {
        self.attempts >= MFA_CHALLENGE_MAX_ATTEMPTS
    }
}
