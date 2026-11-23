use crate::{
    domain::mfa::RECOVERY_CODE_LEN as CODE_LEN,
    domain::services::recovery_code::RecoveryCodeService,
    infrastructure::services::opaque_token::sha256_hex,
};

/// 32 symbols without `I`, `O`, `0` and `1`, so a code cannot be misread.
const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

#[derive(Debug, Clone, Copy, Default)]
pub struct RandomRecoveryCodeService;

impl RandomRecoveryCodeService {
    pub fn new() -> Self {
        RandomRecoveryCodeService
    }
}

impl RecoveryCodeService for RandomRecoveryCodeService {
    fn generate(&self, count: usize) -> Result<Vec<String>, worker::Error> {
        let mut codes = Vec::with_capacity(count);
        while codes.len() < count {
            let code = self.random_code()?;
            if !codes.contains(&code) {
                codes.push(code);
            }
        }
        Ok(codes)
    }

    fn normalize(&self, code: &str) -> String {
        code.chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .map(|c| c.to_ascii_uppercase())
            .collect()
    }

    fn hash(&self, code: &str) -> String {
        sha256_hex(&self.normalize(code))
    }
}

impl RandomRecoveryCodeService {
    fn random_code(&self) -> Result<String, worker::Error> {
        let mut bytes = [0u8; CODE_LEN];
        getrandom::fill(&mut bytes)
            .map_err(|err| worker::Error::RustError(format!("failed to generate a code: {err}")))?;
        Ok(bytes
            .iter()
            .map(|byte| ALPHABET[*byte as usize % ALPHABET.len()] as char)
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service() -> RandomRecoveryCodeService {
        RandomRecoveryCodeService::new()
    }

    #[test]
    fn generates_distinct_codes_of_the_expected_shape() {
        let codes = service().generate(10).expect("codes");

        assert_eq!(codes.len(), 10);
        assert_eq!(codes[0].len(), CODE_LEN);
        for code in &codes {
            assert!(
                code.bytes().all(|byte| ALPHABET.contains(&byte)),
                "{code} uses a symbol outside the alphabet"
            );
        }
        let mut unique = codes.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), codes.len(), "codes must be distinct");
    }

    #[test]
    fn normalizes_case_and_separators() {
        assert_eq!(service().normalize(" abcd-efgh "), "ABCDEFGH");
        assert_eq!(service().normalize("ABCD EFGH"), "ABCDEFGH");
        assert_eq!(service().normalize("abcd"), "ABCD");
        assert_eq!(service().normalize(""), "");
    }

    #[test]
    fn hashes_the_normalized_form() {
        assert_eq!(
            service().hash("abcd-efgh"),
            service().hash("ABCDEFGH"),
            "the same code typed differently must hash identically"
        );
        assert_ne!(service().hash("ABCDEFGH"), service().hash("ABCDEFGI"));
        assert_eq!(service().hash("ABCDEFGH").len(), 64);
    }
}
