pub const PASSWORD_MIN_LEN: usize = 8;
/// Long enough for passphrases and password-manager output; the upper bound
/// only exists so a request cannot force an unbounded Argon2 input.
pub const PASSWORD_MAX_LEN: usize = 64;

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
