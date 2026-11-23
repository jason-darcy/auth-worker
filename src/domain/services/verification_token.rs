#[derive(Debug, Clone)]
pub struct VerificationToken {
    /// Secret handed to the account owner (embedded in the email link).
    pub raw: String,
    /// Value persisted in the database; the raw token is never stored.
    pub hash: String,
}

pub trait VerificationTokenService {
    fn generate(&self) -> Result<VerificationToken, worker::Error>;

    /// Hashes a raw token, so it can be looked up in the database.
    fn hash(&self, token: &str) -> String;
}
