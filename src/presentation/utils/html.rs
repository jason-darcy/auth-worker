use axum::{
    http::header,
    response::{Html, IntoResponse, Response},
};

/// Policy for the server-rendered forms.
///
/// The pages are self-contained (inline style and script, no external
/// resources), so everything but those can be blocked.
pub const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; \
     style-src 'unsafe-inline'; \
     script-src 'unsafe-inline'; \
     connect-src 'self'; \
     form-action 'self'; \
     base-uri 'none'; \
     frame-ancestors 'none'";

/// Wraps a page with the headers every server-rendered page must carry.
///
/// Tokens travel in the URL of these pages, so they must never be cached or
/// leaked through `Referer` to a third party.
pub fn html_page(html: String) -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (header::REFERRER_POLICY, "no-referrer"),
            (header::CONTENT_SECURITY_POLICY, CONTENT_SECURITY_POLICY),
        ],
        Html(html),
    )
        .into_response()
}

/// Wraps a body in the shared document shell.
pub fn document(title: &str, body: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
</head>
<body>
<h1>{title}</h1>
{body}
</body>
</html>"#
    )
}

#[cfg(test)]
mod tests {
    use axum::response::IntoResponse;

    use super::*;

    #[test]
    fn pages_are_not_cacheable_and_cannot_be_framed() {
        let response = html_page(document("Verify email", "<p>hi</p>")).into_response();
        let headers = response.headers();

        assert_eq!(
            headers.get(header::CACHE_CONTROL).expect("cache-control"),
            "no-store"
        );
        assert_eq!(
            headers
                .get(header::X_CONTENT_TYPE_OPTIONS)
                .expect("nosniff"),
            "nosniff"
        );
        assert_eq!(
            headers
                .get(header::REFERRER_POLICY)
                .expect("referrer-policy"),
            "no-referrer"
        );
        let csp = headers
            .get(header::CONTENT_SECURITY_POLICY)
            .expect("csp")
            .to_str()
            .expect("ascii");
        assert!(csp.contains("frame-ancestors 'none'"));
        assert!(csp.contains("default-src 'none'"));
    }

    #[test]
    fn documents_have_a_title_and_the_body() {
        let html = document("Verify email", "<p>hi</p>");

        assert!(html.starts_with("<!doctype html>"));
        assert!(html.contains("<title>Verify email</title>"));
        assert!(html.contains("<p>hi</p>"));
    }
}
