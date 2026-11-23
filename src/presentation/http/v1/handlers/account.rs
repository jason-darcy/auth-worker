use axum::extract::{Extension, Path, State};
use jiff::Timestamp;
use serde::Serialize;
use snafu::Snafu;
use uuid::Uuid;

use crate::{
    logging::{log_error, log_warn},
    presentation::{
        http::{
            error::{
                ApiError::{self, BadRequest},
                ApiResult,
            },
            response::ApiResponse,
        },
        middlewares::auth::AuthenticatedAccount,
        state::{AppState, D1_BINDING},
    },
};

#[derive(Debug, Serialize)]
pub struct AccountResult {
    pub id: Uuid,
    pub name: String,
    pub email: String,
    pub is_verified: bool,
    pub created_at: Timestamp,
}

#[derive(Debug, Snafu)]
pub enum AccountAccessError {
    #[snafu(display("account id is invalid"))]
    AccountIdInvalid,
    #[snafu(display("you can only access your own account"))]
    Forbidden,
}

impl From<AccountAccessError> for ApiError {
    fn from(err: AccountAccessError) -> Self {
        match err {
            AccountAccessError::AccountIdInvalid => BadRequest(err.to_string()),
            AccountAccessError::Forbidden => ApiError::Forbidden(err.to_string()),
        }
    }
}

/// Parses the path id and makes sure the caller only reads its own account.
fn authorize(
    account_id: &str,
    authenticated: &AuthenticatedAccount,
) -> Result<Uuid, AccountAccessError> {
    let account_id = account_id.trim();
    let id = Uuid::parse_str(account_id).map_err(|_| AccountAccessError::AccountIdInvalid)?;
    if id != authenticated.id {
        return Err(AccountAccessError::Forbidden);
    }
    Ok(id)
}

/// Loads the account behind an authenticated id.
async fn load_account(state: &AppState, id: Uuid) -> ApiResult<AccountResult> {
    let account_repository = state.account_repository().map_err(|err| {
        log_error!("account: d1 binding `{D1_BINDING}` unavailable: {err}");
        ApiError::InternalServerError("database binding is unavailable".to_owned())
    })?;
    let account = account_repository
        .find_account_by_id(&id.to_string())
        .await
        .map_err(|err| {
            log_error!("account: find_account_by_id failed for {id}: {err}");
            ApiError::InternalServerError("internal server error".to_owned())
        })?
        .ok_or_else(|| {
            log_warn!("account: {id} no longer exists");
            ApiError::NotFound("account not found".to_owned())
        })?;

    Ok(AccountResult {
        id: account.id(),
        name: account.name().to_owned(),
        email: account.email().to_owned(),
        is_verified: account.is_verified(),
        created_at: account.created_at(),
    })
}

/// `GET /account/me` — the account behind the presented access token.
#[worker::send]
pub async fn me_handler(
    State(state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedAccount>,
) -> ApiResult<ApiResponse<Vec<String>, Vec<String>, AccountResult>> {
    let account = load_account(&state, authenticated.id).await?;

    Ok(ApiResponse::ok(200, Vec::new(), Vec::new(), account))
}

#[worker::send]
pub async fn get_account_handler(
    State(state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedAccount>,
    Path(account_id): Path<String>,
) -> ApiResult<ApiResponse<Vec<String>, Vec<String>, AccountResult>> {
    let account_id = authorize(&account_id, &authenticated).map_err(|err| {
        log_warn!(
            "account: rejected access to `{account_id}` by {}: {err}",
            authenticated.id
        );
        ApiError::from(err)
    })?;
    let account = load_account(&state, account_id).await?;

    Ok(ApiResponse::ok(200, Vec::new(), Vec::new(), account))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authenticated() -> AuthenticatedAccount {
        AuthenticatedAccount {
            id: Uuid::nil(),
            email: "ada@example.com".to_owned(),
            session_id: "session-id".to_owned(),
        }
    }

    fn access_error(account_id: &str, authenticated: &AuthenticatedAccount) -> AccountAccessError {
        match authorize(account_id, authenticated) {
            Ok(_) => panic!("access should be rejected"),
            Err(err) => err,
        }
    }

    #[test]
    fn allows_access_to_the_callers_own_account() {
        let id = Uuid::nil();

        assert_eq!(authorize(&id.to_string(), &authenticated()).ok(), Some(id));
        assert_eq!(
            authorize(&format!("  {id}  "), &authenticated()).ok(),
            Some(id)
        );
    }

    #[test]
    fn rejects_another_account() {
        let other = Uuid::now_v7();
        let error = access_error(&other.to_string(), &authenticated());

        assert!(matches!(error, AccountAccessError::Forbidden));
        assert_eq!(error.to_string(), "you can only access your own account");
    }

    #[test]
    fn rejects_malformed_ids() {
        for account_id in ["", "abc", "01a206d7-0f70-7064-97cd"] {
            assert!(matches!(
                access_error(account_id, &authenticated()),
                AccountAccessError::AccountIdInvalid
            ));
        }
        assert_eq!(
            access_error("abc", &authenticated()).to_string(),
            "account id is invalid"
        );
    }

    #[test]
    fn maps_access_errors() {
        let invalid = ApiError::from(AccountAccessError::AccountIdInvalid);
        assert!(matches!(invalid, ApiError::BadRequest(_)));
        assert_eq!(invalid.status(), 400);

        let forbidden = ApiError::from(AccountAccessError::Forbidden);
        assert!(matches!(forbidden, ApiError::Forbidden(_)));
        assert_eq!(forbidden.status(), 403);
        assert_eq!(forbidden.message(), "you can only access your own account");
    }
}

#[cfg(test)]
mod response_tests {
    use super::*;

    #[test]
    fn success_envelope_never_leaks_secrets() {
        let created_at: Timestamp = "2026-01-02T03:04:05Z".parse().expect("timestamp");
        let response = ApiResponse::ok(
            200,
            Vec::<String>::new(),
            Vec::<String>::new(),
            AccountResult {
                id: Uuid::nil(),
                name: "Ada Lovelace".to_owned(),
                email: "ada@example.com".to_owned(),
                is_verified: true,
                created_at,
            },
        );

        let json = serde_json::to_value(&response).expect("response should serialize");

        assert_eq!(json["success"], serde_json::json!(true));
        assert_eq!(
            json["results"]["id"],
            "00000000-0000-0000-0000-000000000000"
        );
        assert_eq!(json["results"]["name"], "Ada Lovelace");
        assert_eq!(json["results"]["email"], "ada@example.com");
        assert_eq!(json["results"]["is_verified"], serde_json::json!(true));
        assert_eq!(json["results"]["created_at"], "2026-01-02T03:04:05Z");
        assert!(
            json["results"].get("password_hash").is_none(),
            "password hash must never be returned"
        );
    }
}
