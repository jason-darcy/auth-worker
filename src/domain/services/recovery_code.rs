/// Human typable single-use codes handed out when MFA is enabled.
pub trait RecoveryCodeService {
    /// Generates `count` distinct codes.
    fn generate(&self, count: usize) -> Result<Vec<String>, worker::Error>;

    /// Canonical form used for hashing and lookup, so a user may type the code
    /// with spaces, dashes or lowercase letters.
    fn normalize(&self, code: &str) -> String;

    /// Value persisted for a code; the code itself is never stored.
    fn hash(&self, code: &str) -> String;
}
