use argon2::password_hash::Error;

pub trait HashPasswordService {
    fn hash(&self, password: &str) -> Result<String, Error>;
    fn verify(&self, password: &str, password_hash: &str) -> Result<bool, Error>;

    /// Spends the same work as a real [`verify`](Self::verify) without needing a
    /// stored hash.
    ///
    /// Sign-in calls this when the email is unknown, so a response for a
    /// non-existent account takes as long as one for an existing account and
    /// cannot be used to enumerate users.
    fn verify_dummy(&self, password: &str);
}
