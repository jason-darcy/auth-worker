use std::sync::OnceLock;

use argon2::password_hash::Error;
use argon2::{Argon2, PasswordHasher, PasswordVerifier};

use crate::domain::services::hash_password::HashPasswordService;

/// Throwaway hash used by [`Argon2HashPasswordService::verify_dummy`].
///
/// Computed once per worker instance with the default parameters, so the dummy
/// verification costs exactly as much as a real one.
static DUMMY_HASH: OnceLock<String> = OnceLock::new();

/// Password fed to the dummy verification. Its value is irrelevant: the point
/// is to burn the same CPU time.
const DUMMY_PASSWORD: &str = "timing-equalisation-only";

/// Argon2id with the crate's default parameters.
#[derive(Debug, Clone, Copy, Default)]
pub struct Argon2HashPasswordService;

impl Argon2HashPasswordService {
    pub fn new() -> Self {
        Argon2HashPasswordService
    }
}

impl HashPasswordService for Argon2HashPasswordService {
    fn hash(&self, password: &str) -> Result<String, Error> {
        let hash = Argon2::default().hash_password(password.as_bytes())?;
        Ok(hash.to_string())
    }

    fn verify(&self, password: &str, password_hash: &str) -> Result<bool, Error> {
        match Argon2::default().verify_password(password.as_bytes(), password_hash) {
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
