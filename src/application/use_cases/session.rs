use std::sync::Arc;

use uuid::Uuid;

use crate::domain::{
    account::Account,
    client::ClientInfo,
    repositories::refresh_token::{NewRefreshToken, RefreshTokenRepository},
    services::token::{IssuedTokens, TokenService},
};

/// Opens a session and hands out the token pair for it.
///
/// Shared by sign-in and by the second-factor endpoint, so both produce exactly
/// the same tokens and session records.
pub struct SessionIssuer {
    pub refresh_token_repository: Arc<dyn RefreshTokenRepository>,
    pub token_service: Arc<dyn TokenService>,
}

impl SessionIssuer {
    pub fn new(
        refresh_token_repository: Arc<dyn RefreshTokenRepository>,
        token_service: Arc<dyn TokenService>,
    ) -> Self {
        SessionIssuer {
            refresh_token_repository,
            token_service,
        }
    }

    pub async fn start(
        &self,
        account: &Account,
        client: &ClientInfo,
    ) -> Result<IssuedTokens, worker::Error> {
        // Every sign-in starts a new session (refresh token family).
        let session_id = Uuid::now_v7().to_string();
        let account_id = account.id().to_string();
        let pair = self.token_service.issue_pair(
            &account_id,
            account.email(),
            account.token_version(),
            &session_id,
        )?;
        let token_hash = self.token_service.hash_refresh_token(&pair.refresh_token);
        self.refresh_token_repository
            .create_token(NewRefreshToken {
                account_id,
                token_hash,
                family_id: session_id,
                expires_at: pair.refresh_expires_at,
                user_agent: client.user_agent.clone(),
                ip: client.ip.clone(),
            })
            .await?;
        Ok(pair.into())
    }
}
