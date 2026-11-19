use axum::extract::State;
use worker::Error;

use crate::{infrastructure::d1::user_repository::D1UserRepository, presentation::state::AppState};

pub async fn signup_handler(State(state): State<AppState>) -> Result<(), Error> {
    let d1 = state.env.d1("auth")?;
    let _user_repo = D1UserRepository::new(d1);
    Ok(())
}
