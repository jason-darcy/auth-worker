use std::time::Duration;

use axum::http::{
    header::{AUTHORIZATION, CONTENT_TYPE},
    HeaderValue, Method,
};
use tower_http::cors::{AllowOrigin, CorsLayer};

use crate::presentation::state::{AppState, CORS_ORIGINS_VAR};

/// Value that allows every origin.
pub const WILDCARD: &str = "*";
/// How long a browser may cache a preflight response.
pub const PREFLIGHT_MAX_AGE: Duration = Duration::from_secs(600);

/// Builds the CORS layer from the `CORS_ORIGINS` variable.
///
/// CORS is opt-in: without `CORS_ORIGINS` the API stays same-origin only, which
/// is the safe default for an auth service.
pub fn cors_layer(state: &AppState) -> Option<CorsLayer> {
    // A missing variable is the normal "CORS disabled" state.
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
        Origins::Any => Some(layer.allow_origin(AllowOrigin::any())),
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
        if let Some(value) = origin_header_value(entry) {
            origins.push(value);
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
