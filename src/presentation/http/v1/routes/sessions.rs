use axum::{
    routing::{delete, get},
    Router,
};

use crate::presentation::{
    http::v1::handlers::sessions::{list_sessions_handler, revoke_session_handler},
    state::AppState,
};

/// `GET /sessions` and `DELETE /sessions/{session_id}` — both protected.
pub fn sessions_router() -> Router<AppState> {
    Router::new()
        .route("/sessions", get(list_sessions_handler))
        .route("/sessions/{session_id}", delete(revoke_session_handler))
}
