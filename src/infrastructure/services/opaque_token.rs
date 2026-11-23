use std::fmt::Write as _;

use sha2::{Digest, Sha256};

/// Generates `len` cryptographically secure random bytes, hex-encoded.
pub fn random_hex(len: usize) -> Result<String, worker::Error> {
    let mut bytes = vec![0u8; len];
    getrandom::fill(&mut bytes).map_err(|err| {
        worker::Error::RustError(format!("failed to generate random token: {err}"))
    })?;
    Ok(to_hex(&bytes))
}

/// SHA-256 of `value`, hex-encoded. Used to store opaque tokens by hash.
pub fn sha256_hex(value: &str) -> String {
    to_hex(&Sha256::digest(value.as_bytes()))
}

pub fn to_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_hex_tokens_of_the_requested_size() {
        let first = random_hex(32).expect("token should be generated");
        let second = random_hex(32).expect("token should be generated");

        assert_ne!(first, second);
        assert_eq!(first.len(), 64);
        assert!(first.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn hashes_are_stable_and_not_the_input() {
        assert_eq!(sha256_hex("abc"), sha256_hex("abc"));
        assert_ne!(sha256_hex("abc"), sha256_hex("abd"));
        assert_eq!(sha256_hex("abc").len(), 64);
        assert_ne!(sha256_hex("abc"), "abc");
    }
}
