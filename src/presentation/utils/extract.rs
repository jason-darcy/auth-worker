use axum::{
    extract::{
        rejection::{JsonRejection, QueryRejection},
        FromRequest, FromRequestParts, Query, Request,
    },
    http::request::Parts,
    Json,
};
use serde::de::DeserializeOwned;

use crate::presentation::http::error::ApiError;

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
    ApiError::BadRequest(message)
}

fn query_rejection_error(rejection: QueryRejection) -> ApiError {
    let message = rejection.body_text();
    ApiError::BadRequest(message)
}
