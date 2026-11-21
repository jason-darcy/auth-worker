use axum::extract::State;

use crate::presentation::state::AppState;

pub async fn signup_handler(State(state): State<AppState>) -> &'static str {
    let d1 = state.env.d1("auth-worker").unwrap();
    let _user_repo = crate::infrastructure::d1::user_repository::D1UserRepository::new(d1);
    ""
}
