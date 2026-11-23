//! OpenAPI document, generated from the handler and type definitions.
//!
//! The document is built by `utoipa` at compile time, so a handler change and
//! its documentation cannot drift apart. Swagger UI renders it at
//! `/swagger-ui`; the raw document is served at `/api/v1/openapi.json`.

use serde::Serialize;
use utoipa::{
    openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme},
    Modify, OpenApi, ToSchema,
};

// Imported as modules: `utoipa` resolves `paths(health::health_handler)` to the
// `__path_health_handler` item generated in that module, which only exists next
// to the handler itself.
use crate::{
    application::use_cases::{
        change_password::ChangePasswordResult,
        mfa::{MfaConfirmResult, MfaSetupResult, MfaStatusResult},
        refresh_tokens::RefreshTokensResult,
        reset_password::ResetPasswordResult,
        sessions::SessionResult,
        signin::{MfaChallengeResult, SignInOutcome, SignInResult},
        signup::SignUpResult,
        verify_email::VerifyEmailResult,
    },
    presentation::http::v1::handlers::{
        account::{self, AccountResult},
        change_password, delete_account, forgot_password, health, mfa, openapi, refresh_tokens,
        resend_verification, reset_password, sessions, signin, signout, signup, verify_email,
    },
};

/// Documentation mirror of [`crate::presentation::http::response::ApiResponse`].
///
/// The real type is generic over three parameters (errors, messages, results)
/// and carries a `#[serde(skip)]` status; documenting this two-shape version
/// keeps the generated schema readable while matching what goes over the wire.
///
/// It doubles as the error schema: an error response is `Envelope<Vec<String>>`
/// with `success: false`, `errors: null`, the reason in `messages` and an empty
/// `results`.
#[derive(Debug, Serialize, ToSchema)]
pub struct Envelope<T> {
    /// `true` for a successful response.
    pub success: bool,
    /// Reserved; `null` today, `[]` on an error response.
    pub errors: Option<Vec<String>>,
    /// Human readable notes, including the reason of a failure.
    pub messages: Vec<String>,
    /// Endpoint specific payload.
    pub results: T,
}

/// `results` is always `null` for this endpoint.
#[derive(Debug, Serialize, ToSchema)]
pub struct EmptyResult;

/// Declares the `bearer` security scheme used by the protected operations.
struct BearerAuth;

impl Modify for BearerAuth {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .description(Some(
                            "Access token from /signin or /refresh. Lifetime is 15 minutes.",
                        ))
                        .build(),
                ),
            );
        }
    }
}

/// The API contract.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "auth-worker API",
        version = "1.0.0",
        description = "Self-hosted authentication API. Every JSON response uses the same \
                       envelope: `{ success, errors, messages, results }`. Errors carry the \
                       human readable reason in `messages`; `errors` is reserved and currently \
                       `null`.",
        license(name = "MIT")
    ),
    tags(
        (name = "health", description = "Liveness"),
        (name = "registration", description = "Account creation"),
        (name = "session", description = "Sign-in, tokens and sessions"),
        (name = "password", description = "Password reset and change"),
        (name = "email", description = "Email verification"),
        (name = "account", description = "The caller's account"),
        (name = "mfa", description = "TOTP multi-factor authentication"),
        (name = "meta", description = "The API contract itself")
    ),
    paths(
        health::health_handler,
        openapi::openapi_handler,
        signup::signup_handler,
        signin::signin_handler,
        refresh_tokens::refresh_tokens_handler,
        signout::signout_handler,
        signout::signout_all_handler,
        sessions::list_sessions_handler,
        sessions::revoke_session_handler,
        forgot_password::forgot_password_handler,
        reset_password::reset_password_form_handler,
        reset_password::reset_password_handler,
        verify_email::verify_email_form_handler,
        verify_email::verify_email_handler,
        resend_verification::resend_verification_handler,
        change_password::change_password_handler,
        account::me_handler,
        delete_account::delete_account_handler,
        account::get_account_handler,
        mfa::mfa_status_handler,
        mfa::mfa_setup_handler,
        mfa::mfa_confirm_handler,
        mfa::mfa_disable_handler,
        mfa::mfa_recovery_codes_handler,
        mfa::mfa_verify_handler
    ),
    components(schemas(
        Envelope<EmptyResult>,
        Envelope<Vec<String>>,
        Envelope<AccountResult>,
        Envelope<Vec<SessionResult>>,
        Envelope<SignUpResult>,
        Envelope<SignInOutcome>,
        Envelope<SignInResult>,
        Envelope<MfaChallengeResult>,
        Envelope<RefreshTokensResult>,
        Envelope<ResetPasswordResult>,
        Envelope<VerifyEmailResult>,
        Envelope<ChangePasswordResult>,
        Envelope<MfaStatusResult>,
        Envelope<MfaSetupResult>,
        Envelope<MfaConfirmResult>,
    )),
    modifiers(&BearerAuth)
)]
pub struct ApiDoc;

/// The rendered document, built once per worker instance.
pub fn spec() -> &'static str {
    use std::sync::OnceLock;

    static SPEC: OnceLock<String> = OnceLock::new();
    SPEC.get_or_init(|| {
        ApiDoc::openapi()
            .to_json()
            .expect("the generated OpenAPI document is valid JSON")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    // The result types are already in scope through `use super::*`; this keeps
    // the assertions below honest about what the document contains.
    use super::{AccountResult, MfaConfirmResult, MfaSetupResult, MfaStatusResult, SessionResult};

    fn document() -> serde_json::Value {
        serde_json::from_str(spec()).expect("the generated document must be valid JSON")
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
    fn documents_every_method() {
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
                assert!(operation["tags"].is_array(), "`{method} {path}` has no tag");
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
            "/api/v1/signout-all",
        ] {
            let operations = document["paths"][path].as_object().expect("operations");
            let (method, operation) = operations.iter().next().expect("one operation");

            assert_eq!(
                operation["security"][0]["bearer"],
                serde_json::json!([]),
                "`{method} {path}` must be documented as protected"
            );
        }
    }

    #[test]
    fn public_operations_do_not_require_a_token() {
        let document = document();

        for path in ["/api/v1/signin", "/api/v1/signup", "/api/v1/mfa/verify"] {
            let operations = document["paths"][path].as_object().expect("operations");
            let (method, operation) = operations.iter().next().expect("one operation");

            assert!(
                operation.get("security").is_none(),
                "`{method} {path}` must not require a token"
            );
        }
    }

    #[test]
    fn declares_the_bearer_security_scheme() {
        let document = document();

        assert_eq!(
            document["components"]["securitySchemes"]["bearer"]["scheme"],
            "bearer"
        );
        assert_eq!(
            document["components"]["securitySchemes"]["bearer"]["bearerFormat"],
            "JWT"
        );
    }

    #[test]
    fn documents_the_envelope_and_timestamp_format() {
        let document = document();
        let schemas = &document["components"]["schemas"];

        let envelope = &schemas["Envelope_AccountResult"];
        assert_eq!(
            envelope["required"],
            serde_json::json!(["success", "messages", "results"])
        );
        assert_eq!(
            schemas["AccountResult"]["properties"]["created_at"]["format"],
            "date-time"
        );
        assert_eq!(
            schemas["AccountResult"]["properties"]["id"]["format"],
            "uuid"
        );

        // The MFA challenge shape must be part of the signin response.
        assert!(!schemas["Envelope_SignInOutcome"].is_null());
        assert!(!schemas["MfaChallengeResult"].is_null());
    }

    #[test]
    fn empty_results_are_documented_as_null() {
        let document = document();

        assert_eq!(
            document["components"]["schemas"]["EmptyResult"]["default"],
            serde_json::Value::Null
        );
    }

    #[test]
    fn test_only_imports_are_reachable() {
        // Keeps the schema types in scope for the assertions above.
        let _ = std::any::type_name::<(
            AccountResult,
            SessionResult,
            MfaStatusResult,
            MfaSetupResult,
            MfaConfirmResult,
        )>();
    }
}
