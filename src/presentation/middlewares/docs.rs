use axum::{
    extract::Request,
    http::HeaderMap,
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::presentation::{http::error::ApiError, utils::request::is_local_request};

/// Whether the API documentation may be served to this request.
///
/// Only `cf dev` reaches the worker from a loopback address: Cloudflare sets
/// `cf-connecting-ip` at the edge and overwrites whatever the client sent, so a
/// deployed worker can never be tricked into treating a remote request as
/// local.
pub fn docs_visible(headers: &HeaderMap) -> bool {
    is_local_request(headers)
}

/// Serves the OpenAPI document and Swagger UI to local development only.
///
/// Everything else gets the same 404 as an unknown path, so the documentation
/// is not even discoverable in production.
pub async fn local_only(request: Request, next: Next) -> Response {
    if docs_visible(request.headers()) {
        return next.run(request).await;
    }
    ApiError::NotFound("route not found".to_owned()).into_response()
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;
    use crate::presentation::utils::request::CLIENT_IP_HEADER;

    fn headers(client_ip: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(client_ip) = client_ip {
            headers.insert(
                CLIENT_IP_HEADER,
                HeaderValue::from_str(client_ip).expect("ip"),
            );
        }
        headers
    }

    #[test]
    fn is_visible_to_loopback_clients() {
        for ip in ["127.0.0.1", "::1", "127.0.0.2"] {
            assert!(docs_visible(&headers(Some(ip))), "{ip} must be local");
        }
    }

    #[test]
    fn is_hidden_from_remote_clients() {
        for ip in ["203.0.113.7", "10.0.0.1", "192.168.1.1"] {
            assert!(!docs_visible(&headers(Some(ip))), "{ip} must not be local");
        }
    }

    #[test]
    fn is_hidden_when_the_edge_header_is_missing() {
        assert!(
            !docs_visible(&headers(None)),
            "a missing cf-connecting-ip must not be treated as local"
        );
    }

    #[test]
    fn is_hidden_for_garbage_headers() {
        assert!(!docs_visible(&headers(Some("not-an-ip"))));
        assert!(!docs_visible(&headers(Some(""))));
    }
}
