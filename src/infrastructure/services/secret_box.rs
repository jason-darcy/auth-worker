use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::infrastructure::services::opaque_token::to_hex;

/// Domain separation for the key derived from the configured pepper.
const KEY_INFO: &[u8] = b"auth-worker/totp-secret-box/v1";
const NONCE_BYTES: usize = 12;

/// Encrypts secrets at rest (AES-256-GCM).
///
/// The key is derived from `PASSWORD_PEPPER` with HMAC-SHA256 under a dedicated
/// label, so the encryption key and the password pepper are different values
/// even though they share material.
#[derive(Clone)]
pub struct SecretBox {
    key: [u8; 32],
}

impl std::fmt::Debug for SecretBox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the key, not even redacted fragments.
        f.write_str("SecretBox(<redacted>)")
    }
}

impl SecretBox {
    pub fn derive(material: &str) -> Self {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(material.as_bytes())
            .expect("HMAC accepts keys of any length");
        mac.update(KEY_INFO);
        let digest = mac.finalize().into_bytes();
        let mut key = [0u8; 32];
        key.copy_from_slice(&digest[..32]);
        SecretBox { key }
    }

    /// Returns `hex(nonce || ciphertext || tag)`.
    pub fn seal(&self, plaintext: &str) -> Result<String, worker::Error> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.key));
        let mut nonce = [0u8; NONCE_BYTES];
        getrandom::fill(&mut nonce).map_err(|err| {
            worker::Error::RustError(format!("failed to generate a nonce: {err}"))
        })?;
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext.as_bytes())
            .map_err(|_| worker::Error::RustError("failed to encrypt the secret".to_owned()))?;

        let mut sealed = Vec::with_capacity(NONCE_BYTES + ciphertext.len());
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(&ciphertext);
        Ok(to_hex(&sealed))
    }

    pub fn open(&self, sealed: &str) -> Result<String, worker::Error> {
        let bytes = from_hex(sealed)
            .ok_or_else(|| worker::Error::RustError("stored secret is not valid hex".to_owned()))?;
        if bytes.len() <= NONCE_BYTES {
            return Err(worker::Error::RustError(
                "stored secret is too short".to_owned(),
            ));
        }
        let (nonce, ciphertext) = bytes.split_at(NONCE_BYTES);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.key));
        let plaintext = cipher
            .decrypt(Nonce::from_slice(nonce), ciphertext)
            .map_err(|_| {
                worker::Error::RustError(
                    "failed to decrypt the secret (was PASSWORD_PEPPER rotated?)".to_owned(),
                )
            })?;

        String::from_utf8(plaintext)
            .map_err(|_| worker::Error::RustError("decrypted secret is not utf-8".to_owned()))
    }
}

fn from_hex(value: &str) -> Option<Vec<u8>> {
    if value.len() % 2 != 0 {
        return None;
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks(2) {
        let high = (pair[0] as char).to_digit(16)?;
        let low = (pair[1] as char).to_digit(16)?;
        bytes.push((high * 16 + low) as u8);
    }
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "JBSWY3DPEHPK3PXP";

    fn secret_box() -> SecretBox {
        SecretBox::derive("pepper")
    }

    #[test]
    fn round_trips_a_secret() {
        let sealed = secret_box().seal(SECRET).expect("seal");

        assert_ne!(sealed, SECRET, "the stored value must not be the secret");
        assert!(!sealed.contains(SECRET));
        assert_eq!(secret_box().open(&sealed).expect("open"), SECRET);
    }

    #[test]
    fn produces_a_different_ciphertext_every_time() {
        let first = secret_box().seal(SECRET).expect("seal");
        let second = secret_box().seal(SECRET).expect("seal");

        assert_ne!(first, second, "the nonce must be random");
        assert_eq!(secret_box().open(&first).expect("open"), SECRET);
    }

    #[test]
    fn cannot_be_opened_with_another_key() {
        let sealed = secret_box().seal(SECRET).expect("seal");

        assert!(SecretBox::derive("another-pepper").open(&sealed).is_err());
    }

    #[test]
    fn rejects_tampered_ciphertexts() {
        let mut sealed = secret_box().seal(SECRET).expect("seal");
        let last = sealed.pop().expect("non-empty");
        sealed.push(if last == 'a' { 'b' } else { 'a' });

        assert!(secret_box().open(&sealed).is_err());
    }

    #[test]
    fn rejects_malformed_values() {
        for value in ["", "abc", "zz", "00"] {
            assert!(secret_box().open(value).is_err(), "{value:?} must fail");
        }
    }

    #[test]
    fn debug_output_never_leaks_the_key() {
        let rendered = format!("{:?}", secret_box());

        assert_eq!(rendered, "SecretBox(<redacted>)");
    }
}
