use axum::{
    extract::{
        rejection::{JsonRejection, QueryRejection},
        FromRequest, FromRequestParts, Query, Request,
    },
    http::request::Parts,
    Json,
};
use serde::de::DeserializeOwned;

use crate::{logging::log_warn, presentation::http::error::ApiError};

/// `Json` extractor that rejects with the API error envelope.
///
/// The stock `Json` extractor answers with axum's own plain-text rejection, so
/// a malformed body would bypass `ApiResponse` and break the documented
/// contract (`success`, `errors`, `messages`, `results`).
pub struct ApiJson<T>(pub T);

impl<S, T> FromRequest<S> for ApiJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(request, state).await {
            Ok(Json(value)) => Ok(ApiJson(value)),
            Err(rejection) => Err(json_rejection_error(rejection)),
        }
    }
}

/// `Query` extractor that rejects with the API error envelope.
pub struct ApiQuery<T>(pub T);

impl<S, T> FromRequestParts<S> for ApiQuery<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match Query::<T>::from_request_parts(parts, state).await {
            Ok(Query(value)) => Ok(ApiQuery(value)),
            Err(rejection) => Err(query_rejection_error(rejection)),
        }
    }
}

/// The two failure modes a JSON body can have from the client's point of view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JsonProblem {
    /// The request was not sent as `application/json`.
    MissingContentType,
    /// The body was malformed or did not match the expected shape.
    InvalidBody,
}

fn json_problem(rejection: &JsonRejection) -> JsonProblem {
    match rejection {
        JsonRejection::MissingJsonContentType(_) => JsonProblem::MissingContentType,
        _ => JsonProblem::InvalidBody,
    }
}

fn json_problem_message(problem: JsonProblem) -> String {
    match problem {
        JsonProblem::MissingContentType => "content-type must be application/json".to_owned(),
        JsonProblem::InvalidBody => "invalid request body".to_owned(),
    }
}

fn json_rejection_error(rejection: JsonRejection) -> ApiError {
    let problem = json_problem(&rejection);
    let message = json_problem_message(problem);
    log_warn!("invalid json body: {} ({message})", rejection.body_text());
    ApiError::BadRequest(message)
}

fn query_rejection_error(rejection: QueryRejection) -> ApiError {
    let message = rejection.body_text();
    log_warn!("invalid query string: {message}");
    ApiError::BadRequest(message)
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{header, StatusCode},
        response::IntoResponse,
    };

    use super::*;
    use crate::testing::block_on;

    #[derive(Debug, serde::Deserialize)]
    struct Payload {
        email: String,
    }

    fn json_request(body: &str, content_type: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder().method("POST").uri("/");
        if let Some(content_type) = content_type {
            builder = builder.header(header::CONTENT_TYPE, content_type);
        }
        builder.body(Body::from(body.to_owned())).expect("request")
    }

    fn extract(body: &str, content_type: Option<&str>) -> Result<Payload, ApiError> {
        block_on(ApiJson::<Payload>::from_request(
            json_request(body, content_type),
            &(),
        ))
        .map(|ApiJson(payload)| payload)
    }

    #[test]
    fn accepts_a_well_formed_body() {
        let payload = extract(r#"{"email":"ada@example.com"}"#, Some("application/json"))
            .expect("body should be accepted");

        assert_eq!(payload.email, "ada@example.com");
    }

    #[test]
    fn rejects_a_missing_content_type_with_a_bad_request() {
        let error = extract(r#"{"email":"ada@example.com"}"#, None).expect_err("should reject");

        assert_eq!(error.status(), StatusCode::BAD_REQUEST.as_u16());
        assert_eq!(error.message(), "content-type must be application/json");
    }

    #[test]
    fn rejects_malformed_json_with_a_bad_request() {
        let error = extract("{not json", Some("application/json")).expect_err("should reject");

        assert_eq!(error.status(), StatusCode::BAD_REQUEST.as_u16());
        assert_eq!(error.message(), "invalid request body");
    }

    #[test]
    fn rejects_a_body_missing_a_field() {
        let error = extract("{}", Some("application/json")).expect_err("should reject");

        assert_eq!(error.status(), StatusCode::BAD_REQUEST.as_u16());
        assert_eq!(error.message(), "invalid request body");
    }

    #[test]
    fn rejections_are_rendered_with_the_api_envelope() {
        let response = extract("{", Some("application/json"))
            .expect_err("should reject")
            .into_response();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn json_problems_map_to_stable_messages() {
        assert_eq!(
            json_problem_message(JsonProblem::MissingContentType),
            "content-type must be application/json"
        );
        assert_eq!(
            json_problem_message(JsonProblem::InvalidBody),
            "invalid request body"
        );
    }
}
