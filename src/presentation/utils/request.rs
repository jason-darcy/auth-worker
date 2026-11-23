use axum::http::{HeaderMap, Uri};

use crate::logging::log_warn;

/// Local development server (`cf dev`).
pub const DEFAULT_APP_BASE_URL: &str = "http://localhost:8787";
pub const CLIENT_IP_HEADER: &str = "cf-connecting-ip";

/// Resolves the public base URL used to build links inside emails.
///
/// Precedence:
/// 1. local requests (loopback `cf-connecting-ip`, i.e. `cf dev`) use the local
///    server origin, so links stay local even when `DOMAIN` is configured;
/// 2. `DOMAIN` (`auth.example.com` → `https://auth.example.com`) wins everywhere
///    else, so a spoofed request can never redirect links to another site;
/// 3. without `DOMAIN`, fall back to the request origin (e.g. `*.workers.dev`);
/// 4. finally `DEFAULT_APP_BASE_URL`.
pub fn resolve_app_base_url(domain: &str, uri: &Uri, headers: &HeaderMap) -> String {
    if is_local_request(headers) {
        // `cf dev` rewrites the request host to the configured `DOMAIN`, so the
        // request origin is only usable when it is still loopback.
        return local_base_url(uri).unwrap_or_else(|| DEFAULT_APP_BASE_URL.to_owned());
    }
    if let Some(base_url) = base_url_from_domain(domain) {
        return base_url;
    }
    if let Some(base_url) = request_base_url(uri) {
        log_warn!("DOMAIN is not set, using the request origin {base_url}");
        return base_url;
    }
    log_warn!("DOMAIN is not set, falling back to {DEFAULT_APP_BASE_URL}");
    DEFAULT_APP_BASE_URL.to_owned()
}

/// Turns a configured domain into the public base URL.
///
/// Accepts a bare host (`auth.example.com`) or a full origin
/// (`https://auth.example.com/`); returns `None` when nothing is configured.
pub fn base_url_from_domain(domain: &str) -> Option<String> {
    let domain = domain.trim().trim_end_matches('/');
    if domain.is_empty() {
        return None;
    }
    if domain.starts_with("http://") || domain.starts_with("https://") {
        return Some(domain.to_owned());
    }
    Some(format!("https://{domain}"))
}

/// `true` when the request was served by the local dev server.
///
/// `cf-connecting-ip` is set by the Cloudflare edge to the client address, so a
/// loopback value only happens in local development.
pub fn is_local_request(headers: &HeaderMap) -> bool {
    headers
        .get(CLIENT_IP_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(|value| is_loopback_ip(value.trim()))
        .unwrap_or(false)
}

/// Origin of the incoming request, e.g. `http://localhost:8787`.
pub fn request_base_url(uri: &Uri) -> Option<String> {
    let authority = uri.authority()?.as_str();
    let scheme = uri
        .scheme_str()
        .filter(|scheme| *scheme == "http" || *scheme == "https")
        .unwrap_or_else(|| {
            if is_loopback_authority(authority) {
                "http"
            } else {
                "https"
            }
        });
    Some(format!("{scheme}://{authority}"))
}

/// Request origin, but only when it points at loopback (local dev).
pub fn local_base_url(uri: &Uri) -> Option<String> {
    let authority = uri.authority()?.as_str();
    is_loopback_authority(authority).then(|| request_base_url(uri))?
}

fn is_loopback_ip(value: &str) -> bool {
    match value.trim().parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => ip.is_loopback(),
        Ok(std::net::IpAddr::V6(ip)) => {
            ip.is_loopback() || ip.to_ipv4_mapped().is_some_and(|ipv4| ipv4.is_loopback())
        }
        Err(_) => false,
    }
}

fn is_loopback_authority(authority: &str) -> bool {
    let host = host_without_port(authority).to_ascii_lowercase();
    host == "localhost"
        || host.ends_with(".localhost")
        || is_loopback_ip(&host)
        || host == "0.0.0.0"
}

fn host_without_port(authority: &str) -> &str {
    if let Some(rest) = authority.strip_prefix('[') {
        // `[::1]:8787`
        return rest.split(']').next().unwrap_or(rest);
    }
    authority.split(':').next().unwrap_or(authority)
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    fn uri(value: &str) -> Uri {
        value.parse().expect("valid uri")
    }

    fn headers(client_ip: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(client_ip) = client_ip {
            headers.insert(
                CLIENT_IP_HEADER,
                HeaderValue::from_str(client_ip).expect("valid header value"),
            );
        }
        headers
    }

    #[test]
    fn local_requests_win_over_a_configured_domain() {
        // `cf dev` serves on localhost and keeps the port.
        assert_eq!(
            resolve_app_base_url(
                "auth.example.com",
                &uri("http://localhost:8787/api/v1/signup"),
                &headers(Some("::1")),
            ),
            "http://localhost:8787"
        );
    }

    #[test]
    fn local_requests_fall_back_to_the_dev_server_when_the_host_is_rewritten() {
        // `cf dev` rewrites the host to the configured domain (no port info).
        assert_eq!(
            resolve_app_base_url(
                "auth.example.com",
                &uri("http://auth.example.com/api/v1/signup"),
                &headers(Some("::1")),
            ),
            DEFAULT_APP_BASE_URL
        );
    }

    #[test]
    fn configured_domain_wins_for_non_local_requests() {
        assert_eq!(
            resolve_app_base_url(
                "auth.example.com",
                &uri("https://evil.example.net/api/v1/signup"),
                &headers(Some("203.0.113.7")),
            ),
            "https://auth.example.com"
        );
    }

    #[test]
    fn falls_back_to_the_request_origin_without_a_domain() {
        assert_eq!(
            resolve_app_base_url(
                "",
                &uri("https://auth-worker.alice.workers.dev/api/v1/signup"),
                &headers(None),
            ),
            "https://auth-worker.alice.workers.dev"
        );
    }

    #[test]
    fn falls_back_to_the_default_without_domain_and_authority() {
        assert_eq!(
            resolve_app_base_url("", &uri("/api/v1/signup"), &HeaderMap::new()),
            DEFAULT_APP_BASE_URL
        );
    }

    #[test]
    fn builds_https_base_url_from_bare_domain() {
        assert_eq!(
            base_url_from_domain("auth.example.com"),
            Some("https://auth.example.com".to_owned())
        );
        assert_eq!(
            base_url_from_domain("  auth.example.com/  "),
            Some("https://auth.example.com".to_owned())
        );
    }

    #[test]
    fn keeps_an_explicit_scheme() {
        assert_eq!(
            base_url_from_domain("http://localhost:8787"),
            Some("http://localhost:8787".to_owned())
        );
        assert_eq!(
            base_url_from_domain("https://auth.example.com/"),
            Some("https://auth.example.com".to_owned())
        );
    }

    #[test]
    fn returns_none_for_empty_domain() {
        assert_eq!(base_url_from_domain(""), None);
        assert_eq!(base_url_from_domain("   "), None);
        assert_eq!(base_url_from_domain("/"), None);
    }

    #[test]
    fn detects_local_requests_by_loopback_client_ip() {
        assert!(is_local_request(&headers(Some("::1"))));
        assert!(is_local_request(&headers(Some("127.0.0.1"))));
        assert!(is_local_request(&headers(Some("::ffff:127.0.0.1"))));
        assert!(!is_local_request(&headers(Some("203.0.113.7"))));
        assert!(!is_local_request(&headers(Some("::2"))));
        assert!(!is_local_request(&headers(Some("127.0.0.1.evil.com"))));
        assert!(!is_local_request(&HeaderMap::new()));
    }

    #[test]
    fn detects_loopback_authorities() {
        for (authority, expected) in [
            ("localhost", true),
            ("localhost:8787", true),
            ("api.localhost:8787", true),
            ("127.0.0.1:8787", true),
            ("[::1]:8787", true),
            ("0.0.0.0:8787", true),
            ("[::ffff:127.0.0.1]:8787", true),
            ("auth.example.com", false),
            ("127.0.0.1.evil.com", false),
            ("localhost.evil.com", false),
        ] {
            assert_eq!(
                is_loopback_authority(authority),
                expected,
                "authority `{authority}`"
            );
        }
    }

    #[test]
    fn local_base_url_requires_loopback() {
        assert_eq!(
            local_base_url(&uri("http://localhost:8787/x")),
            Some("http://localhost:8787".to_owned())
        );
        assert_eq!(local_base_url(&uri("https://auth.example.com/x")), None);
    }
}
