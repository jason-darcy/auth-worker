use axum::{
    extract::{Request, State},
    http::HeaderMap,
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::{
    logging::{log_error, log_warn},
    presentation::{
        http::error::ApiError,
        state::{AppState, RATE_LIMITER_BINDING},
        utils::request::client_ip,
    },
};

pub use crate::presentation::utils::request::{CLIENT_IP_HEADER, FORWARDED_FOR_HEADER};

/// Used when no client address can be determined at all.
pub const UNKNOWN_CLIENT_KEY: &str = "unknown-client";

/// Rate limits requests per client IP through the Cloudflare rate limiting
/// binding (`RATE_LIMITER`, configured in `cloudflare.config.ts`).
///
/// The limiter fails **open**: a missing binding or a limiter error only logs
/// and lets the request through, so an infrastructure problem cannot take the
/// auth API down.
pub async fn rate_limit(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let key = client_key(request.headers());

    let limiter = match state.rate_limiter() {
        Ok(limiter) => limiter,
        Err(err) => {
            log_error!("rate limit: binding `{RATE_LIMITER_BINDING}` unavailable: {err}");
            return next.run(request).await;
        }
    };

    match limiter.limit(key.clone()).await {
        Ok(outcome) if outcome.success => next.run(request).await,
        Ok(_outcome) => {
            log_warn!("rate limit: exceeded for {key}");
            ApiError::TooManyRequests("too many requests, please try again later".to_owned())
                .into_response()
        }
        Err(err) => {
            log_error!("rate limit: limiter failed for {key}: {err}");
            next.run(request).await
        }
    }
}

/// Derives the rate limit key from the request headers.
pub fn client_key(headers: &HeaderMap) -> String {
    client_ip(headers).unwrap_or_else(|| UNKNOWN_CLIENT_KEY.to_owned())
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    #[test]
    fn prefers_cf_connecting_ip() {
        let mut headers = HeaderMap::new();
        headers.insert(CLIENT_IP_HEADER, HeaderValue::from_static("203.0.113.7"));
        headers.insert(
            FORWARDED_FOR_HEADER,
            HeaderValue::from_static("198.51.100.1, 198.51.100.2"),
        );

        assert_eq!(client_key(&headers), "203.0.113.7");
    }

    #[test]
    fn falls_back_to_first_forwarded_for_entry() {
        let mut headers = HeaderMap::new();
        headers.insert(
            FORWARDED_FOR_HEADER,
            HeaderValue::from_static("198.51.100.1, 198.51.100.2"),
        );

        assert_eq!(client_key(&headers), "198.51.100.1");
    }

    #[test]
    fn falls_back_to_unknown_client() {
        assert_eq!(client_key(&HeaderMap::new()), UNKNOWN_CLIENT_KEY);

        let mut headers = HeaderMap::new();
        headers.insert(CLIENT_IP_HEADER, HeaderValue::from_static("   "));
        assert_eq!(client_key(&headers), UNKNOWN_CLIENT_KEY);
    }
}
