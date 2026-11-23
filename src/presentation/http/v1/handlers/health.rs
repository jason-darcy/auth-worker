use crate::presentation::http::{error::ApiResult, openapi::Envelope, response::ApiResponse};

#[utoipa::path(
    get,
    path = "/api/v1/health",
    tag = "health",
    summary = "Liveness probe",
    responses((status = 200, description = "The worker answered", body = Envelope<Vec<String>>))
)]
#[worker::send]
pub async fn health_handler() -> ApiResult<ApiResponse<Vec<String>, Vec<String>, Vec<String>>> {
    Ok(ApiResponse::ok(
        200,
        Vec::new(),
        vec!["service is running".to_owned()],
        Vec::new(),
    ))
}
