use argon2::password_hash::Error;
use argon2::{Algorithm, Argon2, Params, PasswordHasher, PasswordVerifier, Version};

use crate::domain::services::hash_password::HashPasswordService;

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
}
