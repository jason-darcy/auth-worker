use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct HealthView {
    pub status: &'static str,
    pub service: &'static str,
    pub version: &'static str,
    pub environment: String,
}

impl HealthView {
    pub fn new(environment: impl Into<String>) -> Self {
        HealthView {
            status: "healthy",
            service: env!("CARGO_PKG_NAME"),
            version: env!("CARGO_PKG_VERSION"),
            environment: environment.into(),
        }
    }
}
