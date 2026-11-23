use axum::{
    http::header,
    response::{IntoResponse, Response},
};

/// The document lives at the repository root so it can be linted and diffed
/// like any other file, and is embedded into the worker at build time.
pub const OPENAPI_JSON: &str = include_str!("../../../../../openapi.json");

/// `GET /openapi.json` — the machine readable API contract.
pub async fn openapi_handler() -> Response {
    (
        [
            (header::CONTENT_TYPE, "application/json; charset=utf-8"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        OPENAPI_JSON,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn document() -> serde_json::Value {
        serde_json::from_str(OPENAPI_JSON).expect("the embedded document must be valid JSON")
    }

    #[test]
    fn is_an_openapi_3_document() {
        let document = document();

        assert!(
            document["openapi"]
                .as_str()
                .expect("openapi version")
                .starts_with("3."),
            "the document must declare an OpenAPI 3 version"
        );
        assert_eq!(document["info"]["title"], "auth-worker API");
    }

    #[test]
    fn documents_every_route() {
        let document = document();
        let paths = document["paths"].as_object().expect("paths");

        for path in [
            "/api/v1/health",
            "/api/v1/signup",
            "/api/v1/signin",
            "/api/v1/refresh",
            "/api/v1/signout",
            "/api/v1/signout-all",
            "/api/v1/sessions",
            "/api/v1/sessions/{session_id}",
            "/api/v1/forgot-password",
            "/api/v1/reset-password",
            "/api/v1/verify-email",
            "/api/v1/resend-verification",
            "/api/v1/change-password",
            "/api/v1/account/me",
            "/api/v1/account/{account_id}",
            "/api/v1/mfa",
            "/api/v1/mfa/totp/setup",
            "/api/v1/mfa/totp/confirm",
            "/api/v1/mfa/disable",
            "/api/v1/mfa/recovery-codes",
            "/api/v1/mfa/verify",
            "/api/v1/openapi.json",
        ] {
            assert!(paths.contains_key(path), "`{path}` is not documented");
        }
    }

    #[test]
    fn documents_the_documented_methods() {
        let document = document();

        let expectations: [(&str, &[&str]); 5] = [
            ("/api/v1/account/me", &["get", "delete"]),
            ("/api/v1/reset-password", &["get", "post"]),
            ("/api/v1/verify-email", &["get", "post"]),
            ("/api/v1/sessions/{session_id}", &["delete"]),
            ("/api/v1/mfa/verify", &["post"]),
        ];

        for (path, methods) in expectations {
            for method in methods {
                assert!(
                    !document["paths"][path][method].is_null(),
                    "`{method} {path}` is not documented"
                );
            }
        }
    }

    #[test]
    fn every_operation_has_responses() {
        let document = document();
        let paths = document["paths"].as_object().expect("paths");

        for (path, operations) in paths {
            for (method, operation) in operations.as_object().expect("operations") {
                assert!(
                    !operation["responses"].is_null(),
                    "`{method} {path}` has no responses"
                );
            }
        }
    }

    #[test]
    fn protected_operations_require_the_bearer_scheme() {
        let document = document();

        for path in [
            "/api/v1/sessions",
            "/api/v1/account/me",
            "/api/v1/change-password",
            "/api/v1/mfa",
            "/api/v1/mfa/totp/setup",
            "/api/v1/mfa/totp/confirm",
            "/api/v1/mfa/disable",
            "/api/v1/mfa/recovery-codes",
        ] {
            let get_or_post = &document["paths"][path];
            let operations = get_or_post.as_object().expect("operations");
            let (_, operation) = operations.iter().next().expect("one operation");

            assert_eq!(
                operation["security"][0]["bearer"],
                serde_json::json!([]),
                "`{path}` must be documented as protected"
            );
        }
    }

    #[test]
    fn is_served_as_json() {
        let response = crate::testing::block_on(openapi_handler());

        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .expect("content-type"),
            "application/json; charset=utf-8"
        );
    }
}
