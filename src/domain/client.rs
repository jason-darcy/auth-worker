/// Best-effort metadata about the client that opened a session.
///
/// Used for the session list only, so it is never trusted for authorisation and
/// every field is optional.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientInfo {
    pub user_agent: Option<String>,
    pub ip: Option<String>,
}
