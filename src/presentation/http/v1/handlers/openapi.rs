use axum::{
    http::header,
    response::{IntoResponse, Response},
};

use crate::presentation::http::openapi::spec;

#[utoipa::path(
    get,
    path = "/api/v1/openapi.json",
    tag = "meta",
    summary = "This document",
    description = "The contract is generated from the handler and type definitions at build time.",
    responses((
        status = 200,
        description = "OpenAPI document",
        body = String,
        content_type = "application/json"
    ))
)]
#[worker::send]
pub async fn openapi_handler() -> Response {
    (
        [
            (header::CONTENT_TYPE, "application/json; charset=utf-8"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        spec(),
    )
        .into_response()
}
