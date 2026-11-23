use std::time::Duration;

use axum::http::{
    header::{AUTHORIZATION, CONTENT_TYPE},
    HeaderValue, Method,
};
use tower_http::cors::{AllowOrigin, CorsLayer};

use crate::{
    logging::log_warn,
    presentation::state::{AppState, CORS_ORIGINS_VAR},
};

/// Value that allows every origin.
pub const WILDCARD: &str = "*";
/// How long a browser may cache a preflight response.
pub const PREFLIGHT_MAX_AGE: Duration = Duration::from_secs(600);

/// Builds the CORS layer from the `CORS_ORIGINS` variable.
///
/// CORS is opt-in: without `CORS_ORIGINS` the API stays same-origin only, which
/// is the safe default for an auth service.
pub fn cors_layer(state: &AppState) -> Option<CorsLayer> {
    // A missing variable is the normal "CORS disabled" state, so it must not
    // log on every request.
    let raw = state
        .env
        .var(CORS_ORIGINS_VAR)
        .map(|value| value.to_string())
        .unwrap_or_default();
    build_cors_layer(&raw)
}

/// Turns a comma separated `CORS_ORIGINS` value into a layer.
///
/// Returns `None` when nothing is configured, so the caller can skip the layer
/// entirely instead of adding no-op headers to every response.
pub fn build_cors_layer(raw: &str) -> Option<CorsLayer> {
    let origins = parse_origins(raw);

    let layer = CorsLayer::new()
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([AUTHORIZATION, CONTENT_TYPE])
        // The API authenticates with a bearer header, never with cookies, so
        // credentialed CORS is not needed (and `*` stays usable).
        .allow_credentials(false)
        .max_age(PREFLIGHT_MAX_AGE);

    match origins {
        Origins::None => None,
        Origins::Any => {
            log_warn!("CORS: {CORS_ORIGINS_VAR} allows every origin");
            Some(layer.allow_origin(AllowOrigin::any()))
        }
        Origins::List(origins) => Some(layer.allow_origin(AllowOrigin::list(origins))),
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Origins {
    None,
    Any,
    List(Vec<HeaderValue>),
}

fn parse_origins(raw: &str) -> Origins {
    let mut origins = Vec::new();
    let mut allow_any = false;

    for entry in raw.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        if entry == WILDCARD {
            allow_any = true;
            continue;
        }
        // `AllowOrigin::list` panics on a wildcard, so it is handled above.
        match origin_header_value(entry) {
            Some(value) => origins.push(value),
            None => log_warn!("CORS: ignoring invalid origin {entry:?} in {CORS_ORIGINS_VAR}"),
        }
    }

    if allow_any {
        Origins::Any
    } else if origins.is_empty() {
        Origins::None
    } else {
        Origins::List(origins)
    }
}

/// Validates that an entry looks like an origin (`scheme://host[:port]`) and
/// has no path, because browsers send the origin without one.
///
/// A trailing slash is tolerated and trimmed: it is the most common way to get
/// this configuration wrong.
fn origin_header_value(entry: &str) -> Option<HeaderValue> {
    let entry = entry.trim().trim_end_matches('/');
    let rest = entry
        .strip_prefix("https://")
        .or_else(|| entry.strip_prefix("http://"))?;
    if rest.is_empty() || rest.contains('/') || rest.contains('?') || rest.contains('#') {
        return None;
    }
    HeaderValue::from_str(entry).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_comma_separated_allowlist() {
        let origins = parse_origins(" https://app.example.com , https://admin.example.com ");

        assert_eq!(
            origins,
            Origins::List(vec![
                HeaderValue::from_static("https://app.example.com"),
                HeaderValue::from_static("https://admin.example.com"),
            ])
        );
    }

    #[test]
    fn accepts_localhost_origins_for_development() {
        let origins = parse_origins("http://localhost:5173");

        assert_eq!(
            origins,
            Origins::List(vec![HeaderValue::from_static("http://localhost:5173")])
        );
    }

    #[test]
    fn wildcard_wins_over_an_allowlist() {
        assert_eq!(parse_origins("https://app.example.com, *"), Origins::Any);
    }

    #[test]
    fn empty_configuration_disables_cors() {
        for raw in ["", "   ", ",", " , , "] {
            assert_eq!(parse_origins(raw), Origins::None);
            assert!(build_cors_layer(raw).is_none());
        }
    }

    #[test]
    fn trims_a_trailing_slash() {
        assert_eq!(
            parse_origins("https://app.example.com/"),
            Origins::List(vec![HeaderValue::from_static("https://app.example.com")])
        );
    }

    #[test]
    fn ignores_entries_that_are_not_origins() {
        for entry in [
            "app.example.com",
            "https://app.example.com/path",
            "ftp://app.example.com",
            "https://app.example.com?x=1",
            "https://",
            "https://app.example.com#fragment",
        ] {
            assert_eq!(parse_origins(entry), Origins::None, "{entry}");
        }
    }

    #[test]
    fn keeps_the_valid_entries_next_to_invalid_ones() {
        let origins = parse_origins("https://app.example.com,nonsense");

        assert_eq!(
            origins,
            Origins::List(vec![HeaderValue::from_static("https://app.example.com")])
        );
    }

    #[test]
    fn builds_a_layer_when_origins_are_configured() {
        assert!(build_cors_layer("https://app.example.com").is_some());
        assert!(build_cors_layer("*").is_some());
    }
}
