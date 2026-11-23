use jiff::Timestamp;
use serde::{Deserialize, Serialize};

/// `typ` claim of access tokens. It keeps a token minted for another purpose
/// from being accepted as an access token.
pub const ACCESS_TOKEN_TYPE: &str = "access";
pub const TOKEN_ISSUER: &str = "auth-worker";
pub const TOKEN_AUDIENCE: &str = "auth-worker";
pub const BEARER_TOKEN_TYPE: &str = "Bearer";

/// Claims carried by an access token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    /// Account id.
    pub sub: String,
    pub email: String,
    /// Always [`ACCESS_TOKEN_TYPE`] for access tokens.
    pub typ: String,
    pub iss: String,
    pub aud: String,
    pub iat: i64,
    pub exp: i64,
    /// Account token version at issue time; a mismatch means the token was
    /// revoked by a credential change.
    pub ver: u32,
}

/// A freshly issued pair: a short-lived access token plus the long-lived
/// refresh token used to obtain a new pair.
#[derive(Debug, Clone)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub access_expires_at: Timestamp,
    pub refresh_expires_at: Timestamp,
}

/// The token part of a signin/refresh response.
#[derive(Debug, Clone, Serialize)]
pub struct IssuedTokens {
    /// Always `Bearer`; clients send the access token as
    /// `Authorization: Bearer <access_token>`.
    pub token_type: String,
    pub access_token: String,
    pub refresh_token: String,
    pub access_token_expires_at: Timestamp,
    pub refresh_token_expires_at: Timestamp,
}

impl From<TokenPair> for IssuedTokens {
    fn from(pair: TokenPair) -> Self {
        IssuedTokens {
            token_type: BEARER_TOKEN_TYPE.to_owned(),
            access_token: pair.access_token,
            refresh_token: pair.refresh_token,
            access_token_expires_at: pair.access_expires_at,
            refresh_token_expires_at: pair.refresh_expires_at,
        }
    }
}

pub trait TokenService {
    /// Signs an access token and generates a refresh token for the account.
    fn issue_pair(
        &self,
        account_id: &str,
        email: &str,
        token_version: u32,
    ) -> Result<TokenPair, worker::Error>;

    /// Validates an access token and returns its claims.
    fn decode_access_token(&self, token: &str) -> Result<AccessTokenClaims, worker::Error>;

    /// Value persisted for a refresh token; the raw token is never stored.
    fn hash_refresh_token(&self, token: &str) -> String;
}
