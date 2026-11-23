use axum::{
    extract::{Request, State},
    http::header::AUTHORIZATION,
    middleware::Next,
    response::{IntoResponse, Response},
};
use uuid::Uuid;

use crate::{
    logging::{log_error, log_warn},
    presentation::{
        http::error::ApiError,
        state::{AppState, D1_BINDING, JWT_SECRET_SECRET},
    },
};

pub const BEARER_PREFIX: &str = "Bearer";
const INVALID_TOKEN_MESSAGE: &str = "invalid or expired access token";

/// Identity of the caller, injected into the request extensions by
/// [`require_auth`]. Handlers read it with `Extension<AuthenticatedAccount>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedAccount {
    pub id: Uuid,
    pub email: String,
    /// Refresh token family (`sid` claim) the access token belongs to. Empty for
    /// tokens issued before sessions existed.
    pub session_id: String,
}

/// Rejects requests without a valid `Authorization: Bearer <access_token>`
/// header and injects [`AuthenticatedAccount`] for the downstream handlers.
///
/// Access tokens are signed JWTs, but they also carry the account's
/// `token_version`: the account is loaded on every request so a credential
/// change (password reset) invalidates already issued tokens immediately.
///
/// `#[worker::send]` is required because the D1 repository futures are `?Send`;
/// Workers is single-threaded, so wrapping them is sound.
#[worker::send]
pub async fn require_auth(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let Some(token) = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(bearer_token)
    else {
        log_warn!("auth: missing or malformed Authorization header");
        return ApiError::Unauthorized("missing bearer token".to_owned()).into_response();
    };

    let token_service = match state.token_service() {
        Ok(service) => service,
        Err(err) => {
            log_error!("auth: `{JWT_SECRET_SECRET}` unavailable: {err}");
            return ApiError::InternalServerError("server is misconfigured".to_owned())
                .into_response();
        }
    };
    let claims = match token_service.decode_access_token(token) {
        Ok(claims) => claims,
        Err(err) => {
            log_warn!("auth: invalid access token: {err}");
            return unauthorized();
        }
    };

    let Ok(id) = Uuid::parse_str(&claims.sub) else {
        log_error!("auth: access token has a non-uuid subject: {}", claims.sub);
        return unauthorized();
    };

    let account_repository = match state.account_repository() {
        Ok(repository) => repository,
        Err(err) => {
            log_error!("auth: d1 binding `{D1_BINDING}` unavailable: {err}");
            return ApiError::InternalServerError("database binding is unavailable".to_owned())
                .into_response();
        }
    };
    let account = match account_repository.find_account_by_id(&id.to_string()).await {
        Ok(Some(account)) => account,
        Ok(None) => {
            log_warn!("auth: access token references a missing account {id}");
            return unauthorized();
        }
        Err(err) => {
            log_error!("auth: find_account_by_id failed for {id}: {err}");
            return ApiError::InternalServerError("internal server error".to_owned())
                .into_response();
        }
    };
    if claims.ver != account.token_version() {
        log_warn!(
            "auth: stale access token for account {id} (token version {} != {})",
            claims.ver,
            account.token_version()
        );
        return unauthorized();
    }

    request.extensions_mut().insert(AuthenticatedAccount {
        id,
        email: claims.email,
        session_id: claims.sid,
    });
    next.run(request).await
}

fn unauthorized() -> Response {
    ApiError::Unauthorized(INVALID_TOKEN_MESSAGE.to_owned()).into_response()
}

/// Extracts the token from an `Authorization` header value.
pub fn bearer_token(header: &str) -> Option<&str> {
    let (scheme, token) = header.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case(BEARER_PREFIX) {
        return None;
    }
    let token = token.trim();
    (!token.is_empty()).then_some(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bearer_tokens() {
        assert_eq!(bearer_token("Bearer abc.def.ghi"), Some("abc.def.ghi"));
        assert_eq!(bearer_token("bearer abc"), Some("abc"));
        assert_eq!(bearer_token("BEARER   abc  "), Some("abc"));
    }

    #[test]
    fn rejects_other_schemes_and_empty_tokens() {
        assert_eq!(bearer_token("Basic abc"), None);
        assert_eq!(bearer_token("Bearer"), None);
        assert_eq!(bearer_token("Bearer   "), None);
        assert_eq!(bearer_token("abc"), None);
        assert_eq!(bearer_token(""), None);
    }
}
