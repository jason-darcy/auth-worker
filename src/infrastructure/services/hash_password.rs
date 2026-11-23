use std::sync::OnceLock;

use argon2::password_hash::Error;
use argon2::{Algorithm, Argon2, Params, PasswordHasher, PasswordVerifier, Version};

use crate::domain::services::hash_password::HashPasswordService;

/// Throwaway hash used by [`Argon2HashPasswordService::verify_dummy`].
///
/// Computed once per worker instance with the configured pepper and parameters,
/// so the dummy verification costs exactly as much as a real one.
static DUMMY_HASH: OnceLock<String> = OnceLock::new();

/// Password fed to the dummy verification. Its value is irrelevant: the point
/// is to burn the same CPU time.
const DUMMY_PASSWORD: &str = "timing-equalisation-only";

#[derive(Debug, Clone)]
pub struct Argon2HashPasswordService {
    pub secret: String,
}

impl Argon2HashPasswordService {
    pub fn new(secret: &str) -> Self {
        Argon2HashPasswordService {
            secret: secret.to_owned(),
        }
    }
}

impl HashPasswordService for Argon2HashPasswordService {
    fn hash(&self, password: &str) -> Result<String, Error> {
        let argon2 = Argon2::new_with_secret(
            self.secret.as_bytes(),
            Algorithm::default(),
            Version::default(),
            Params::default(),
        )?;
        let hash = argon2.hash_password(password.as_bytes())?;
        Ok(hash.to_string())
    }
    fn verify(&self, password: &str, password_hash: &str) -> Result<bool, Error> {
        let argon2 = Argon2::new_with_secret(
            self.secret.as_bytes(),
            Algorithm::default(),
            Version::default(),
            Params::default(),
        )?;
        match argon2.verify_password(password.as_bytes(), password_hash) {
            Ok(()) => Ok(true),
            Err(Error::PasswordInvalid) => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn verify_dummy(&self, password: &str) {
        let dummy = DUMMY_HASH.get_or_init(|| self.hash(DUMMY_PASSWORD).unwrap_or_default());
        if dummy.is_empty() {
            return;
        }
        // The result is irrelevant: only the Argon2 work matters here.
        let _ = self.verify(password, dummy);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_only_with_the_same_pepper() {
        let service = Argon2HashPasswordService::new("pepper");
        let hash = service.hash("s3cret-pass").expect("hash should succeed");

        assert!(service.verify("s3cret-pass", &hash).expect("verify"));
        assert!(!service.verify("wrong-pass", &hash).expect("verify"));
        assert!(
            !Argon2HashPasswordService::new("another-pepper")
                .verify("s3cret-pass", &hash)
                .expect("verify"),
            "a hash must not verify under a different pepper"
        );
    }

    #[test]
    fn dummy_verification_accepts_any_password() {
        let service = Argon2HashPasswordService::new("pepper");

        // The point is that it returns at all: sign-in relies on it to burn the
        // same CPU time as a real verification.
        service.verify_dummy("anything");
        service.verify_dummy("");
    }
}
