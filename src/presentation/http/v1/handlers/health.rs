use crate::presentation::http::{error::ApiResult, response::ApiResponse};

#[worker::send]
pub async fn health_handler() -> ApiResult<ApiResponse<Vec<String>, Vec<String>, Vec<String>>> {
    Ok(ApiResponse::ok(
        200,
        Vec::new(),
        vec!["service is running".to_owned()],
        Vec::new(),
    ))
}
