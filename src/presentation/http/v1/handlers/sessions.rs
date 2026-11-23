use axum::extract::{Extension, Path, State};

use crate::{
    application::use_cases::sessions::{SessionResult, SessionsError, SessionsUseCase},
    logging::{log_error, log_info, log_warn},
    presentation::{
        http::{
            error::{ApiError, ApiResult},
            response::ApiResponse,
        },
        middlewares::auth::AuthenticatedAccount,
        state::{AppState, D1_BINDING},
    },
};

pub const REVOKE_SESSION_MESSAGE: &str = "session revoked";

impl From<SessionsError> for ApiError {
    fn from(_err: SessionsError) -> Self {
        ApiError::InternalServerError("internal server error".to_owned())
    }
}

fn refresh_token_repository(
    state: &AppState,
) -> ApiResult<std::sync::Arc<dyn crate::domain::repositories::refresh_token::RefreshTokenRepository>>
{
    state.refresh_token_repository().map_err(|err| {
        log_error!("sessions: d1 binding `{D1_BINDING}` unavailable: {err}");
        ApiError::InternalServerError("database binding is unavailable".to_owned())
    })
}

/// `GET /sessions` — every live session of the caller, newest first.
#[worker::send]
pub async fn list_sessions_handler(
    State(state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedAccount>,
) -> ApiResult<ApiResponse<Vec<String>, Vec<String>, Vec<SessionResult>>> {
    let case = SessionsUseCase::new(refresh_token_repository(&state)?);
    let sessions = match case
        .list(&authenticated.id.to_string(), &authenticated.session_id)
        .await
    {
        Ok(sessions) => sessions,
        Err(err) => {
            log_error!("sessions: list failed: {err}");
            return Err(ApiError::from(err));
        }
    };

    Ok(ApiResponse::ok(200, Vec::new(), Vec::new(), sessions))
}

/// `DELETE /sessions/{session_id}` — revokes one session of the caller.
#[worker::send]
pub async fn revoke_session_handler(
    State(state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedAccount>,
    Path(session_id): Path<String>,
) -> ApiResult<ApiResponse<Vec<String>, Vec<String>, ()>> {
    let session_id = session_id.trim();
    if session_id.is_empty() {
        log_warn!("sessions: empty session id");
        return Err(ApiError::BadRequest("session id is invalid".to_owned()));
    }

    let case = SessionsUseCase::new(refresh_token_repository(&state)?);
    let revoked = match case.revoke(&authenticated.id.to_string(), session_id).await {
        Ok(revoked) => revoked,
        Err(err) => {
            log_error!("sessions: revoke failed: {err}");
            return Err(ApiError::from(err));
        }
    };
    if !revoked {
        log_warn!(
            "sessions: {} does not belong to account {}",
            session_id,
            authenticated.id
        );
        return Err(ApiError::NotFound("session not found".to_owned()));
    }

    log_info!(
        "sessions: account {} revoked session {session_id}",
        authenticated.id
    );
    Ok(ApiResponse::ok(
        200,
        Vec::new(),
        vec![REVOKE_SESSION_MESSAGE.to_owned()],
        (),
    ))
}

#[cfg(test)]
mod tests {
    use axum::response::IntoResponse;

    use super::*;

    #[test]
    fn hides_storage_failures_behind_500() {
        let api_error = ApiError::from(SessionsError::ListSessions {
            source: worker::Error::RustError("d1 select failed".to_owned()),
        });

        assert!(matches!(api_error, ApiError::InternalServerError(_)));
        assert_eq!(api_error.status(), 500);
        assert_eq!(api_error.message(), "internal server error");
    }

    #[test]
    fn success_envelope_matches_the_api_contract() {
        let created_at = "2026-01-02T03:04:05Z".parse().expect("timestamp");
        let response = ApiResponse::ok(
            200,
            Vec::<String>::new(),
            Vec::<String>::new(),
            vec![SessionResult {
                id: "session-a".to_owned(),
                created_at,
                expires_at: created_at,
                last_used_at: None,
                user_agent: Some("Firefox".to_owned()),
                ip: Some("203.0.113.7".to_owned()),
                current: true,
            }],
        );

        let json = serde_json::to_value(&response).expect("response should serialize");

        assert_eq!(json["success"], serde_json::json!(true));
        assert_eq!(json["results"][0]["id"], "session-a");
        assert_eq!(json["results"][0]["current"], serde_json::json!(true));
        assert_eq!(json["results"][0]["user_agent"], "Firefox");
        assert!(
            json["results"][0].get("token_hash").is_none(),
            "token hashes must never be returned"
        );
    }

    #[test]
    fn responses_use_the_given_status_code() {
        let ok = ApiResponse::ok(200, Vec::<String>::new(), Vec::<String>::new(), ());
        assert_eq!(ok.into_response().status(), axum::http::StatusCode::OK);

        let missing = ApiError::NotFound("session not found".to_owned()).into_response();
        assert_eq!(missing.status(), axum::http::StatusCode::NOT_FOUND);
    }
}
