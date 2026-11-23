/// A freshly generated opaque token: the raw value goes to the client, only the
/// hash is persisted.
#[derive(Debug, Clone)]
pub struct OpaqueToken {
    pub raw: String,
    pub hash: String,
}

/// Generates high-entropy opaque tokens and hashes them for storage.
///
/// Used for email verification links, password reset links and MFA challenges.
pub trait OpaqueTokenService {
    fn generate(&self) -> Result<OpaqueToken, worker::Error>;

    /// Hashes a raw token, so it can be looked up in the database.
    fn hash(&self, token: &str) -> String;
}
