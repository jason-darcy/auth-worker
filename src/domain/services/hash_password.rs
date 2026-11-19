use argon2::password_hash::Error;

pub trait HashPasswordService {
    fn hash(&self, password: &str) -> Result<String, Error>;
    fn verify(&self, password: &str, password_hash: &str) -> Result<bool, Error>;
}
