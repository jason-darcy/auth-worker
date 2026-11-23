use crate::{
    domain::services::opaque_token::{OpaqueToken, OpaqueTokenService},
    infrastructure::services::opaque_token::{random_hex, sha256_hex},
};

/// Number of random bytes in a verification token (256 bits).
const TOKEN_BYTES: usize = 32;

#[derive(Debug, Default, Clone)]
pub struct RandomVerificationTokenService;

impl RandomVerificationTokenService {
    pub fn new() -> Self {
        RandomVerificationTokenService
    }
}

impl OpaqueTokenService for RandomVerificationTokenService {
    fn generate(&self) -> Result<OpaqueToken, worker::Error> {
        let raw = random_hex(TOKEN_BYTES)?;
        let hash = self.hash(&raw);
        Ok(OpaqueToken { raw, hash })
    }

    fn hash(&self, token: &str) -> String {
        sha256_hex(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_distinct_url_safe_tokens_with_hashes() {
        let service = RandomVerificationTokenService::new();

        let first = service.generate().expect("token should be generated");
        let second = service.generate().expect("token should be generated");

        assert_ne!(first.raw, second.raw);
        assert_eq!(first.raw.len(), TOKEN_BYTES * 2);
        assert!(first.raw.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(first.hash.len(), 64);
        assert_ne!(first.hash, first.raw);
    }

    #[test]
    fn hash_is_sha256_of_the_raw_token() {
        let service = RandomVerificationTokenService::new();

        let token = service.generate().expect("token should be generated");

        assert_eq!(token.hash, service.hash(&token.raw));
        assert_eq!(token.hash, sha256_hex(&token.raw));
    }
}
