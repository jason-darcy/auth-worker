use std::fmt::Write as _;

use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use jiff::Timestamp;
use sha1::Sha1;

use crate::domain::services::totp::TotpService;

/// 160 bits, the size every authenticator app supports.
pub const SECRET_BYTES: usize = 20;
/// RFC 6238 default period, in seconds.
pub const STEP_SECONDS: i64 = 30;
/// Digits in a code.
pub const DIGITS: u32 = 6;
/// Accepted clock drift, in steps (±30 s).
pub const SKEW_STEPS: i64 = 1;

type HmacSha1 = Hmac<Sha1>;

/// RFC 6238 TOTP with the SHA-1 defaults every authenticator app assumes.
#[derive(Debug, Clone, Copy, Default)]
pub struct Rfc6238TotpService;

impl Rfc6238TotpService {
    pub fn new() -> Self {
        Rfc6238TotpService
    }
}

impl TotpService for Rfc6238TotpService {
    fn generate_secret(&self) -> Result<String, worker::Error> {
        let mut bytes = [0u8; SECRET_BYTES];
        getrandom::fill(&mut bytes).map_err(|err| {
            worker::Error::RustError(format!("failed to generate a secret: {err}"))
        })?;
        Ok(BASE32_NOPAD.encode(&bytes))
    }

    fn otpauth_uri(&self, issuer: &str, account: &str, secret: &str) -> String {
        let label = format!("{}:{}", escape(issuer), escape(account));
        format!(
            "otpauth://totp/{label}?secret={secret}&issuer={}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECONDS}",
            escape(issuer)
        )
    }

    fn verify(
        &self,
        secret: &str,
        code: &str,
        now: Timestamp,
    ) -> Result<Option<i64>, worker::Error> {
        let code = code.trim();
        if code.len() != DIGITS as usize || !code.bytes().all(|byte| byte.is_ascii_digit()) {
            return Ok(None);
        }
        let key = decode_secret(secret)?;
        let counter = now.as_second().div_euclid(STEP_SECONDS);

        for offset in -SKEW_STEPS..=SKEW_STEPS {
            let step = counter + offset;
            let candidate = hotp(&key, step as u64);
            if constant_time_eq(candidate.as_bytes(), code.as_bytes()) {
                return Ok(Some(step));
            }
        }
        Ok(None)
    }
}

/// RFC 4226 HOTP value for a counter.
fn hotp(key: &[u8], counter: u64) -> String {
    let mut mac = <HmacSha1 as Mac>::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();

    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let binary = ((digest[offset] as u32 & 0x7f) << 24)
        | ((digest[offset + 1] as u32) << 16)
        | ((digest[offset + 2] as u32) << 8)
        | (digest[offset + 3] as u32);
    let modulo = 10u32.pow(DIGITS);

    let mut code = String::with_capacity(DIGITS as usize);
    let _ = write!(code, "{:0width$}", binary % modulo, width = DIGITS as usize);
    code
}

fn decode_secret(secret: &str) -> Result<Vec<u8>, worker::Error> {
    let normalized = secret.trim().to_ascii_uppercase().replace(' ', "");
    BASE32_NOPAD
        .decode(normalized.as_bytes())
        .map_err(|err| worker::Error::RustError(format!("invalid TOTP secret: {err}")))
}

/// Compares without leaking the position of the first difference.
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (left, right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    difference == 0
}

/// Percent-encodes everything outside the unreserved set, so the label and the
/// issuer cannot break the URI.
fn escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                escaped.push(byte as char)
            }
            _ => {
                let _ = write!(escaped, "%{byte:02X}");
            }
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 appendix B test vector (SHA-1, 8 digits truncated to 6).
    const RFC_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    fn service() -> Rfc6238TotpService {
        Rfc6238TotpService::new()
    }

    fn at(second: i64) -> Timestamp {
        Timestamp::from_second(second).expect("timestamp")
    }

    fn code_at(secret: &str, second: i64) -> String {
        let key = decode_secret(secret).expect("secret");
        hotp(&key, (second / STEP_SECONDS) as u64)
    }

    #[test]
    fn generates_base32_secrets_of_the_expected_size() {
        let first = service().generate_secret().expect("secret");
        let second = service().generate_secret().expect("secret");

        assert_ne!(first, second);
        assert_eq!(first.len(), 32, "20 bytes encode to 32 base32 characters");
        assert!(first
            .chars()
            .all(|c| c.is_ascii_uppercase() || ('2'..='7').contains(&c)));
        assert!(decode_secret(&first).is_ok());
    }

    #[test]
    fn matches_the_rfc_6238_test_vector() {
        // 59 s is step 1; the RFC lists 94287082 for 8 digits, 287082 for 6.
        assert_eq!(code_at(RFC_SECRET, 59), "287082");
        // 1111111109 s is step 37037036; RFC value 07081804 -> 081804.
        assert_eq!(code_at(RFC_SECRET, 1_111_111_109), "081804");
    }

    #[test]
    fn accepts_the_current_code() {
        let secret = service().generate_secret().expect("secret");
        let now = at(1_767_323_045);
        let code = code_at(&secret, 1_767_323_045);

        assert_eq!(
            service().verify(&secret, &code, now).expect("verify"),
            Some(1_767_323_045 / 30)
        );
    }

    #[test]
    fn accepts_codes_within_the_skew_window() {
        let secret = service().generate_secret().expect("secret");
        let now = 1_767_323_045;

        for drift in [-STEP_SECONDS, 0, STEP_SECONDS] {
            let code = code_at(&secret, now + drift);
            assert!(
                service()
                    .verify(&secret, &code, at(now))
                    .expect("verify")
                    .is_some(),
                "a drift of {drift}s must be accepted"
            );
        }
    }

    #[test]
    fn rejects_codes_outside_the_skew_window() {
        let secret = service().generate_secret().expect("secret");
        let now = 1_767_323_045;
        let code = code_at(&secret, now + 5 * STEP_SECONDS);

        assert_eq!(
            service().verify(&secret, &code, at(now)).expect("verify"),
            None
        );
    }

    #[test]
    fn rejects_malformed_codes() {
        let secret = service().generate_secret().expect("secret");
        let now = at(1_767_323_045);

        for code in ["", "12345", "1234567", "abcdef", " 12345 "] {
            assert_eq!(
                service().verify(&secret, code, now).expect("verify"),
                None,
                "{code:?} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_a_secret_that_is_not_base32() {
        let error = service().verify("not base32!", "123456", at(0));

        assert!(error.is_err());
    }

    #[test]
    fn accepts_lowercase_and_spaced_secrets() {
        let secret = service().generate_secret().expect("secret");
        let now = at(1_767_323_045);
        let code = code_at(&secret, 1_767_323_045);
        let messy = format!(" {} ", secret.to_lowercase());

        assert!(service()
            .verify(&messy, &code, now)
            .expect("verify")
            .is_some());
    }

    #[test]
    fn builds_an_otpauth_uri() {
        let uri = service().otpauth_uri("auth-worker", "ada@example.com", "ABC234");

        assert!(uri.starts_with("otpauth://totp/auth-worker:ada%40example.com?"));
        assert!(uri.contains("secret=ABC234"));
        assert!(uri.contains("issuer=auth-worker"));
        assert!(uri.contains("algorithm=SHA1"));
        assert!(uri.contains("digits=6"));
        assert!(uri.contains("period=30"));
    }

    #[test]
    fn escapes_the_label() {
        assert_eq!(escape("a b"), "a%20b");
        assert_eq!(escape("a@b.c"), "a%40b.c");
        assert_eq!(escape("safe-._~"), "safe-._~");
    }
}
