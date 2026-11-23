use jiff::Timestamp;

/// Time-based one-time passwords (RFC 6238).
pub trait TotpService {
    /// New base32 secret, without padding, uppercase.
    fn generate_secret(&self) -> Result<String, worker::Error>;

    /// `otpauth://totp/...` URI for authenticator apps.
    fn otpauth_uri(&self, issuer: &str, account: &str, secret: &str) -> String;

    /// Returns the matching time step when `code` is valid.
    ///
    /// The caller compares it with the last accepted step to reject replays.
    fn verify(
        &self,
        secret: &str,
        code: &str,
        now: Timestamp,
    ) -> Result<Option<i64>, worker::Error>;
}
