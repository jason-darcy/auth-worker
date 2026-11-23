use std::sync::Arc;

use jiff::Timestamp;
use serde::Serialize;
use snafu::{ResultExt, Snafu};

use crate::{
    domain::repositories::refresh_token::RefreshTokenRepository,
    logging::{log_error, log_info},
};

/// One session as returned by `GET /sessions`.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct SessionResult {
    /// Refresh token family id; also the path segment of `DELETE /sessions/{id}`.
    pub id: String,
    #[schema(value_type = String, format = DateTime)]
    pub created_at: Timestamp,
    #[schema(value_type = String, format = DateTime)]
    pub expires_at: Timestamp,
    #[schema(value_type = Option<String>, format = DateTime)]
    pub last_used_at: Option<Timestamp>,
    pub user_agent: Option<String>,
    pub ip: Option<String>,
    /// `true` for the session that made the request.
    pub current: bool,
}

#[derive(Debug, Snafu)]
pub enum SessionsError {
    #[snafu(display("failed to list sessions"))]
    ListSessions { source: worker::Error },
    #[snafu(display("failed to revoke session"))]
    RevokeSession { source: worker::Error },
}

pub struct SessionsUseCase {
    pub refresh_token_repository: Arc<dyn RefreshTokenRepository>,
}

impl SessionsUseCase {
    pub fn new(refresh_token_repository: Arc<dyn RefreshTokenRepository>) -> Self {
        SessionsUseCase {
            refresh_token_repository,
        }
    }

    /// Lists the live sessions of an account, newest first.
    pub async fn list(
        &self,
        account_id: &str,
        current_session_id: &str,
    ) -> Result<Vec<SessionResult>, SessionsError> {
        let sessions = self
            .refresh_token_repository
            .list_sessions(account_id)
            .await
            .inspect_err(|err| log_error!("sessions: list_sessions failed for {account_id}: {err}"))
            .context(ListSessionsSnafu)?;

        Ok(sessions
            .into_iter()
            .map(|session| SessionResult {
                current: session.family_id == current_session_id,
                id: session.family_id,
                created_at: session.created_at,
                expires_at: session.expires_at,
                last_used_at: session.last_used_at,
                user_agent: session.user_agent,
                ip: session.ip,
            })
            .collect())
    }

    /// Revokes one session. Returns `false` when the session does not belong to
    /// the account, so the caller can answer 404 without leaking other users'
    /// session ids.
    pub async fn revoke(&self, account_id: &str, session_id: &str) -> Result<bool, SessionsError> {
        let revoked = self
            .refresh_token_repository
            .delete_session(account_id, session_id)
            .await
            .inspect_err(|err| {
                log_error!("sessions: delete_session failed for {account_id}: {err}");
            })
            .context(RevokeSessionSnafu)?;
        if revoked {
            log_info!("sessions: revoked session {session_id} of {account_id}");
        }
        Ok(revoked)
    }
}

#[cfg(test)]
// The use case stores its dependencies as `Arc<dyn Trait>` and the repository
// trait is `?Send`, so mocks cannot be `Sync`; `RefCell` keeps them cheap.
#[allow(clippy::arc_with_non_send_sync)]
mod tests {
    use std::{cell::RefCell, sync::Arc};

    use async_trait::async_trait;

    use super::*;
    use crate::{
        domain::repositories::refresh_token::{NewRefreshToken, SessionInfo, StoredRefreshToken},
        testing::block_on,
    };

    #[derive(Default)]
    struct MockRefreshTokenRepository {
        sessions: Vec<SessionInfo>,
        deleted: RefCell<Vec<(String, String)>>,
        fail: bool,
    }

    impl MockRefreshTokenRepository {
        fn with_sessions(sessions: Vec<SessionInfo>) -> Self {
            MockRefreshTokenRepository {
                sessions,
                ..Default::default()
            }
        }
    }

    #[async_trait(?Send)]
    impl RefreshTokenRepository for MockRefreshTokenRepository {
        async fn create_token(&self, _token: NewRefreshToken) -> Result<(), worker::Error> {
            Ok(())
        }

        async fn find_token(
            &self,
            _token_hash: &str,
        ) -> Result<Option<StoredRefreshToken>, worker::Error> {
            Ok(None)
        }

        async fn rotate_token(
            &self,
            _old_token_hash: &str,
            _next: NewRefreshToken,
        ) -> Result<(), worker::Error> {
            Ok(())
        }

        async fn delete_session(
            &self,
            account_id: &str,
            family_id: &str,
        ) -> Result<bool, worker::Error> {
            if self.fail {
                return Err(worker::Error::RustError("d1 delete failed".to_owned()));
            }
            let exists = self
                .sessions
                .iter()
                .any(|session| session.family_id == family_id);
            self.deleted
                .borrow_mut()
                .push((account_id.to_owned(), family_id.to_owned()));
            Ok(exists)
        }

        async fn delete_tokens_for_account(&self, _account_id: &str) -> Result<(), worker::Error> {
            Ok(())
        }

        async fn list_sessions(
            &self,
            _account_id: &str,
        ) -> Result<Vec<SessionInfo>, worker::Error> {
            if self.fail {
                return Err(worker::Error::RustError("d1 select failed".to_owned()));
            }
            Ok(self.sessions.clone())
        }

        async fn delete_expired(&self, _now: Timestamp) -> Result<u32, worker::Error> {
            Ok(0)
        }
    }

    fn timestamp(second: i64) -> Timestamp {
        Timestamp::from_second(second).expect("timestamp")
    }

    fn session(family_id: &str) -> SessionInfo {
        SessionInfo {
            family_id: family_id.to_owned(),
            created_at: timestamp(1_767_323_045),
            expires_at: timestamp(1_769_915_045),
            last_used_at: Some(timestamp(1_767_400_000)),
            user_agent: Some("Firefox".to_owned()),
            ip: Some("203.0.113.7".to_owned()),
        }
    }

    fn use_case(repository: MockRefreshTokenRepository) -> SessionsUseCase {
        SessionsUseCase::new(Arc::new(repository))
    }

    #[test]
    fn marks_the_callers_session_as_current() {
        let sessions = use_case(MockRefreshTokenRepository::with_sessions(vec![
            session("session-a"),
            session("session-b"),
        ]));

        let result = block_on(sessions.list("account-id", "session-b")).expect("list should work");

        assert_eq!(result.len(), 2);
        assert!(!result[0].current);
        assert!(result[1].current);
        assert_eq!(result[1].id, "session-b");
        assert_eq!(result[1].user_agent.as_deref(), Some("Firefox"));
        assert_eq!(result[1].ip.as_deref(), Some("203.0.113.7"));
    }

    #[test]
    fn marks_nothing_as_current_without_a_session_claim() {
        let sessions = use_case(MockRefreshTokenRepository::with_sessions(vec![session(
            "session-a",
        )]));

        let result = block_on(sessions.list("account-id", "")).expect("list should work");

        assert!(!result[0].current);
    }

    #[test]
    fn propagates_listing_failures() {
        let sessions = use_case(MockRefreshTokenRepository {
            fail: true,
            ..Default::default()
        });

        let error =
            block_on(sessions.list("account-id", "session-a")).expect_err("failure must surface");

        assert!(matches!(error, SessionsError::ListSessions { .. }));
    }

    #[test]
    fn revokes_a_known_session() {
        let repository = Arc::new(MockRefreshTokenRepository::with_sessions(vec![session(
            "session-a",
        )]));
        let sessions = SessionsUseCase::new(repository.clone());

        let revoked =
            block_on(sessions.revoke("account-id", "session-a")).expect("revoke should work");

        assert!(revoked);
        assert_eq!(
            *repository.deleted.borrow(),
            vec![("account-id".to_owned(), "session-a".to_owned())]
        );
    }

    #[test]
    fn reports_unknown_sessions_as_not_revoked() {
        let sessions = use_case(MockRefreshTokenRepository::default());

        let revoked =
            block_on(sessions.revoke("account-id", "session-x")).expect("revoke should work");

        assert!(!revoked);
    }

    #[test]
    fn propagates_revocation_failures() {
        let sessions = use_case(MockRefreshTokenRepository {
            fail: true,
            ..Default::default()
        });

        let error =
            block_on(sessions.revoke("account-id", "session-a")).expect_err("failure must surface");

        assert!(matches!(error, SessionsError::RevokeSession { .. }));
    }
}
