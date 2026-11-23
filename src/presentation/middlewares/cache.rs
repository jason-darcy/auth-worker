use axum::{
    extract::Request,
    http::{
        header::{HeaderValue, CACHE_CONTROL},
        HeaderMap,
    },
    middleware::Next,
    response::Response,
};

/// Header value applied to every response that is not the OpenAPI document.
pub const NO_STORE: HeaderValue = HeaderValue::from_static("no-store");
/// The API contract is safe to cache (but must be revalidated after a deploy).
pub const NO_CACHE: HeaderValue = HeaderValue::from_static("no-cache");

/// Marks API responses as uncacheable.
///
/// Auth responses carry access and refresh tokens, and the server-rendered
/// forms carry tokens in their URL; neither may be stored by a proxy or the
/// browser. The OpenAPI document is the only exception.
pub async fn no_store(request: Request, next: Next) -> Response {
    let is_openapi = request.uri().path().ends_with("/openapi.json");
    let mut response = next.run(request).await;
    set_cache_control(
        response.headers_mut(),
        if is_openapi { NO_CACHE } else { NO_STORE },
    );
    response
}

/// Applies `Cache-Control`, keeping an explicit value a handler already chose.
fn set_cache_control(headers: &mut HeaderMap, fallback: HeaderValue) {
    if !headers.contains_key(CACHE_CONTROL) {
        headers.insert(CACHE_CONTROL, fallback);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sets_cache_control_when_absent() {
        let mut headers = HeaderMap::new();

        set_cache_control(&mut headers, NO_STORE);

        assert_eq!(headers.get(CACHE_CONTROL).expect("header"), "no-store");
    }

    #[test]
    fn keeps_an_explicit_value() {
        let mut headers = HeaderMap::new();
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("private"));

        set_cache_control(&mut headers, NO_STORE);

        assert_eq!(headers.get(CACHE_CONTROL).expect("header"), "private");
    }
}
