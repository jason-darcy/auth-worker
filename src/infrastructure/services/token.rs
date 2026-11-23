use std::time::Duration;

use jiff::Timestamp;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};

use crate::{
    domain::services::token::{
        AccessTokenClaims, TokenPair, TokenService, ACCESS_TOKEN_TYPE, TOKEN_AUDIENCE, TOKEN_ISSUER,
    },
    infrastructure::services::opaque_token::{random_hex, sha256_hex},
};

/// Access tokens are short-lived; clients refresh them with the refresh token.
pub const DEFAULT_ACCESS_TOKEN_TTL: Duration = Duration::from_secs(15 * 60);
/// Refresh tokens are long-lived and revocable (stored hashed in D1).
pub const DEFAULT_REFRESH_TOKEN_TTL: Duration = Duration::from_secs(30 * 24 * 60 * 60);
/// 256 bits of entropy for the opaque refresh token.
pub const REFRESH_TOKEN_BYTES: usize = 32;

/// Issues HS256 access tokens plus opaque refresh tokens.
#[derive(Debug, Clone)]
pub struct JwtTokenService {
    secret: String,
    access_ttl: Duration,
    refresh_ttl: Duration,
}

impl JwtTokenService {
    pub fn new(secret: &str) -> Self {
        Self::with_ttls(secret, DEFAULT_ACCESS_TOKEN_TTL, DEFAULT_REFRESH_TOKEN_TTL)
    }

    pub fn with_ttls(secret: &str, access_ttl: Duration, refresh_ttl: Duration) -> Self {
        JwtTokenService {
            secret: secret.to_owned(),
            access_ttl,
            refresh_ttl,
        }
    }

    fn encoding_key(&self) -> Result<EncodingKey, worker::Error> {
        EncodingKey::from_secret(self.secret.as_bytes())
            .map_err(|err| worker::Error::RustError(format!("invalid JWT secret: {err}")))
    }

    fn decoding_key(&self) -> Result<DecodingKey, worker::Error> {
        DecodingKey::from_secret(self.secret.as_bytes())
            .map_err(|err| worker::Error::RustError(format!("invalid JWT secret: {err}")))
    }
}

impl TokenService for JwtTokenService {
    fn issue_pair(
        &self,
        account_id: &str,
        email: &str,
        token_version: u32,
    ) -> Result<TokenPair, worker::Error> {
        let now = Timestamp::now();
        let access_expires_at = now
            .saturating_add(self.access_ttl)
            .unwrap_or(Timestamp::MAX);
        let refresh_expires_at = now
            .saturating_add(self.refresh_ttl)
            .unwrap_or(Timestamp::MAX);
        let claims = AccessTokenClaims {
            sub: account_id.to_owned(),
            email: email.to_owned(),
            typ: ACCESS_TOKEN_TYPE.to_owned(),
            iss: TOKEN_ISSUER.to_owned(),
            aud: TOKEN_AUDIENCE.to_owned(),
            iat: now.as_second(),
            exp: access_expires_at.as_second(),
            ver: token_version,
        };
        let access_token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &self.encoding_key()?,
        )
        .map_err(|err| worker::Error::RustError(format!("failed to sign access token: {err}")))?;
        let refresh_token = random_hex(REFRESH_TOKEN_BYTES)?;

        Ok(TokenPair {
            access_token,
            refresh_token,
            access_expires_at,
            refresh_expires_at,
        })
    }

    fn decode_access_token(&self, token: &str) -> Result<AccessTokenClaims, worker::Error> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_audience(&[TOKEN_AUDIENCE]);
        validation.set_issuer(&[TOKEN_ISSUER]);
        let claims = decode::<AccessTokenClaims>(token, &self.decoding_key()?, &validation)
            .map_err(|err| worker::Error::RustError(format!("invalid access token: {err}")))?
            .claims;
        if claims.typ != ACCESS_TOKEN_TYPE {
            return Err(worker::Error::RustError(
                "invalid access token type".to_owned(),
            ));
        }
        Ok(claims)
    }

    fn hash_refresh_token(&self, token: &str) -> String {
        sha256_hex(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "test-secret";

    fn service() -> JwtTokenService {
        JwtTokenService::new(SECRET)
    }

    #[test]
    fn issues_a_decodable_access_token() {
        let pair = service()
            .issue_pair("account-1", "ada@example.com", 3)
            .expect("tokens should be issued");

        let claims = service()
            .decode_access_token(&pair.access_token)
            .expect("access token should decode");

        assert_eq!(claims.sub, "account-1");
        assert_eq!(claims.email, "ada@example.com");
        assert_eq!(claims.typ, ACCESS_TOKEN_TYPE);
        assert_eq!(claims.iss, TOKEN_ISSUER);
        assert_eq!(claims.aud, TOKEN_AUDIENCE);
        assert_eq!(claims.ver, 3);
        assert_eq!(claims.exp, pair.access_expires_at.as_second());
        assert!(claims.exp > claims.iat);
    }

    #[test]
    fn access_token_expires_in_fifteen_minutes_by_default() {
        let before = Timestamp::now().as_second();
        let pair = service()
            .issue_pair("account-1", "ada@example.com", 0)
            .expect("tokens should be issued");

        let access_ttl = pair.access_expires_at.as_second() - before;
        assert!(
            (DEFAULT_ACCESS_TOKEN_TTL.as_secs() as i64 - 5
                ..=DEFAULT_ACCESS_TOKEN_TTL.as_secs() as i64 + 5)
                .contains(&access_ttl),
            "unexpected access token ttl: {access_ttl}s"
        );
    }

    #[test]
    fn issues_an_opaque_refresh_token_that_is_stored_hashed() {
        let pair = service()
            .issue_pair("account-1", "ada@example.com", 0)
            .expect("tokens should be issued");
        let other = service()
            .issue_pair("account-1", "ada@example.com", 0)
            .expect("tokens should be issued");

        assert_ne!(pair.refresh_token, other.refresh_token);
        assert_eq!(pair.refresh_token.len(), REFRESH_TOKEN_BYTES * 2);
        assert_ne!(pair.refresh_token, pair.access_token);
        assert_eq!(
            service().hash_refresh_token(&pair.refresh_token),
            sha256_hex(&pair.refresh_token)
        );
        assert!(
            pair.refresh_expires_at > pair.access_expires_at,
            "refresh tokens must outlive access tokens"
        );
    }

    #[test]
    fn rejects_tokens_signed_with_another_secret() {
        let pair = JwtTokenService::new("other-secret")
            .issue_pair("account-1", "ada@example.com", 0)
            .expect("tokens should be issued");

        assert!(service().decode_access_token(&pair.access_token).is_err());
    }

    #[test]
    fn rejects_expired_access_tokens() {
        let claims = AccessTokenClaims {
            sub: "account-1".to_owned(),
            email: "ada@example.com".to_owned(),
            typ: ACCESS_TOKEN_TYPE.to_owned(),
            iss: TOKEN_ISSUER.to_owned(),
            aud: TOKEN_AUDIENCE.to_owned(),
            iat: Timestamp::now().as_second() - 3600,
            exp: Timestamp::now().as_second() - 600,
            ver: 0,
        };
        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(SECRET.as_bytes()).expect("valid key"),
        )
        .expect("token should be signed");

        assert!(service().decode_access_token(&token).is_err());
    }

    #[test]
    fn rejects_tokens_with_another_type() {
        let claims = AccessTokenClaims {
            sub: "account-1".to_owned(),
            email: "ada@example.com".to_owned(),
            typ: "refresh".to_owned(),
            iss: TOKEN_ISSUER.to_owned(),
            aud: TOKEN_AUDIENCE.to_owned(),
            iat: Timestamp::now().as_second(),
            exp: Timestamp::now().as_second() + 600,
            ver: 0,
        };
        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(SECRET.as_bytes()).expect("valid key"),
        )
        .expect("token should be signed");

        let error = service()
            .decode_access_token(&token)
            .expect_err("token type must be enforced");
        assert!(error.to_string().contains("access token type"));
    }

    #[test]
    fn rejects_garbage_tokens() {
        assert!(service().decode_access_token("not-a-token").is_err());
    }
}
