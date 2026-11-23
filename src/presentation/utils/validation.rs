pub const PASSWORD_MIN_LEN: usize = 8;
pub const PASSWORD_MAX_LEN: usize = 20;

/// Opaque tokens (email verification, password reset, refresh) are 32 random
/// bytes hex-encoded.
pub const OPAQUE_TOKEN_LEN: usize = 64;

/// Rejects obviously malformed tokens before hitting the database.
pub fn is_valid_opaque_token(token: &str) -> bool {
    token.len() == OPAQUE_TOKEN_LEN && token.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Minimal, dependency-free email shape check shared by the auth handlers.
///
/// It only rejects obviously broken addresses (`missing @`, empty local part,
/// domain without a dot, leading/trailing dot, multiple `@`); full RFC 5322
/// validation is intentionally out of scope.
pub(crate) fn is_valid_email(email: &str) -> bool {
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && !domain.contains('@')
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_common_addresses() {
        for email in [
            "ada@example.com",
            "ada.lovelace+auth@mail.example.co.uk",
            "a@b.co",
        ] {
            assert!(is_valid_email(email), "`{email}` should be accepted");
        }
    }

    #[test]
    fn accepts_hex_tokens_of_the_expected_length() {
        assert!(is_valid_opaque_token(&"a".repeat(OPAQUE_TOKEN_LEN)));
        assert!(is_valid_opaque_token(&"0123456789abcdef".repeat(4)));
    }

    #[test]
    fn rejects_malformed_tokens() {
        assert!(!is_valid_opaque_token(""));
        assert!(!is_valid_opaque_token(&"a".repeat(63)));
        assert!(!is_valid_opaque_token(&"a".repeat(65)));
        assert!(!is_valid_opaque_token(&"z".repeat(OPAQUE_TOKEN_LEN)));
        assert!(!is_valid_opaque_token(&"g".repeat(OPAQUE_TOKEN_LEN)));
        assert!(!is_valid_opaque_token(&"A".repeat(OPAQUE_TOKEN_LEN + 1)));
    }

    #[test]
    fn rejects_broken_addresses() {
        for email in [
            "",
            "ada",
            "ada@",
            "@example.com",
            "ada@localhost",
            "ada@.com",
            "ada@example.",
            "ada@@example.com",
        ] {
            assert!(!is_valid_email(email), "`{email}` should be rejected");
        }
    }
}
