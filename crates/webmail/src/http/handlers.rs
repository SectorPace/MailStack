use std::net::SocketAddr;

use axum::extract::rejection::{JsonRejection, PathRejection, QueryRejection};
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{header, HeaderValue, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use time::OffsetDateTime;

use crate::account::Account;
use crate::auth::ThrottleDecision;
use crate::compose::{ComposeRequest, DraftRequest};
use crate::error::{WebmailError, WebmailResult};
use crate::http::auth::{client_key, peer_addr, AuthSession};
use crate::http::{assets, blocking, cookie_context, AppState};
use crate::maildir_service::{BatchRequest, FlagPatch, ListOptions, MaildirService, SortOrder};
use crate::session;
use crate::{DEFAULT_LIST_LIMIT, MAX_LIST_LIMIT, VERSION};

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserView {
    pub email: String,
    pub account: String,
    pub display_name: String,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionView {
    pub user: UserView,
    pub csrf_token: String,
    pub expires_in_seconds: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoginRequest {
    #[serde(alias = "email")]
    pub login: String,
    pub password: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FolderNameRequest {
    pub name: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MoveRequest {
    pub to: String,
    #[serde(default)]
    pub copy: Option<bool>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct MessageListQuery {
    #[serde(default)]
    pub folder: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub offset: Option<usize>,
    #[serde(default)]
    pub q: Option<String>,
    #[serde(default)]
    pub unread: Option<u8>,
    #[serde(default)]
    pub flagged: Option<u8>,
    #[serde(default)]
    pub sort: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct DetailQuery {
    #[serde(default)]
    pub images: Option<u8>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct PartQuery {
    #[serde(default)]
    pub download: Option<u8>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct SearchQuery {
    #[serde(default)]
    pub q: Option<String>,
    #[serde(default)]
    pub folder: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub offset: Option<usize>,
}

fn json_response(status: StatusCode, value: impl serde::Serialize) -> WebmailResult<Response> {
    Ok((status, Json(value)).into_response())
}

fn session_view(account: &Account, csrf: &str) -> SessionView {
    SessionView {
        user: UserView {
            email: account.email.clone(),
            account: account.account.clone(),
            display_name: account.display_name.clone(),
        },
        csrf_token: csrf.to_string(),
        expires_in_seconds: crate::SESSION_TTL_SECONDS,
    }
}

fn parse_json<T: serde::de::DeserializeOwned>(
    body: Result<Json<T>, JsonRejection>,
) -> WebmailResult<T> {
    match body {
        Ok(Json(value)) => Ok(value),
        Err(rejection) => match rejection.status() {
            StatusCode::PAYLOAD_TOO_LARGE => Err(WebmailError::payload_too_large(
                "request body exceeds the configured limit",
            )),
            StatusCode::UNSUPPORTED_MEDIA_TYPE => Err(WebmailError::unsupported_media_type()),
            _ => Err(WebmailError::invalid_json()),
        },
    }
}

fn parse_path<T: serde::de::DeserializeOwned>(
    path: Result<Path<T>, PathRejection>,
) -> WebmailResult<T> {
    match path {
        Ok(Path(value)) => Ok(value),
        Err(_) => Err(WebmailError::bad_request(
            "INVALID_PATH",
            "path parameters are not valid",
        )),
    }
}

fn parse_query<T: serde::de::DeserializeOwned>(
    query: Result<Query<T>, QueryRejection>,
) -> WebmailResult<T> {
    match query {
        Ok(Query(value)) => Ok(value),
        Err(_) => Err(WebmailError::bad_request(
            "INVALID_QUERY",
            "query parameters are not valid",
        )),
    }
}

fn parse_uid(raw: &str) -> WebmailResult<u32> {
    raw.parse::<u32>()
        .map_err(|_| WebmailError::bad_request("INVALID_UID", "uid must be a non-negative integer"))
}

fn truthy(value: Option<u8>) -> bool {
    matches!(value, Some(1))
}

fn limited(limit: Option<usize>) -> usize {
    limit.unwrap_or(DEFAULT_LIST_LIMIT).clamp(1, MAX_LIST_LIMIT)
}

fn folder_or_inbox(folder: Option<String>) -> String {
    folder
        .filter(|folder| !folder.trim().is_empty())
        .unwrap_or_else(|| "INBOX".to_string())
}

fn safe_content_type(raw: &str) -> HeaderValue {
    let token = |value: &str| {
        !value.is_empty()
            && value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(
                        byte,
                        b'!' | b'#'
                            | b'$'
                            | b'%'
                            | b'&'
                            | b'\''
                            | b'*'
                            | b'+'
                            | b'-'
                            | b'.'
                            | b'^'
                            | b'_'
                            | b'`'
                            | b'|'
                            | b'~'
                    )
            })
    };
    let valid = raw
        .split_once('/')
        .map(|(mime_type, subtype)| token(mime_type.trim()) && token(subtype.trim()))
        .unwrap_or(false);
    if valid {
        HeaderValue::from_str(raw.trim())
            .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream"))
    } else {
        HeaderValue::from_static("application/octet-stream")
    }
}

fn is_unsafe_render_type(content_type: &str) -> bool {
    matches!(
        content_type.trim().to_ascii_lowercase().as_str(),
        "text/html"
            | "application/xhtml+xml"
            | "image/svg+xml"
            | "text/xml"
            | "application/xml"
            | "application/javascript"
            | "text/javascript"
    )
}

fn content_disposition(disposition: &str, filename: Option<&str>) -> HeaderValue {
    let Some(filename) = filename.filter(|name| !name.trim().is_empty()) else {
        return HeaderValue::from_static("attachment");
    };
    let fallback: String = filename
        .chars()
        .map(|ch| {
            if ch.is_ascii() && !matches!(ch, '"' | '\\' | '\r' | '\n') {
                ch
            } else {
                '_'
            }
        })
        .collect();
    let encoded = rfc5987_encode(filename);
    let value = format!(
        "{disposition}; filename=\"{}\"; filename*=UTF-8''{}",
        fallback.replace('\\', "\\\\").replace('"', "\\\""),
        encoded
    );
    HeaderValue::from_str(&value).unwrap_or_else(|_| HeaderValue::from_static("attachment"))
}

fn rfc5987_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len() * 3);
    for byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric()
            || matches!(
                *byte,
                b'!' | b'#' | b'$' | b'&' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
            )
        {
            out.push(*byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

pub async fn health(State(state): State<AppState>) -> Response {
    Json(serde_json::json!({
        "ok": true,
        "status": "ok",
        "service": "mailstack-webmail",
        "version": VERSION,
        "node": state.inner.runtime_id,
        "frontend": state.inner.entry.is_some(),
    }))
    .into_response()
}

pub async fn login(
    State(state): State<AppState>,
    peer: Option<ConnectInfo<SocketAddr>>,
    headers: axum::http::HeaderMap,
    body: Result<Json<LoginRequest>, JsonRejection>,
) -> WebmailResult<Response> {
    let payload = parse_json(body)?;

    if !session::origin_matches_host(&headers) {
        return Err(WebmailError::origin_rejected());
    }

    let peer = peer_addr(peer);
    let ip_key = client_key(peer.as_ref());
    match state.inner.throttle.check(&ip_key, &payload.login) {
        ThrottleDecision::Allow => {}
        ThrottleDecision::Limited { retry_after_secs } => {
            tracing::warn!(
                target: "mailstack_webmail",
                ip = %ip_key,
                "login attempt rejected by the throttle"
            );
            return Err(WebmailError::too_many_attempts(retry_after_secs));
        }
    }
    state.inner.throttle.record_attempt(&ip_key, &payload.login);

    let accounts = std::sync::Arc::clone(&state.inner.accounts);
    let login_name = payload.login.clone();
    let password = payload.password.clone();
    let account = blocking(move || accounts.authenticate(&login_name, &password)).await?;
    let Some(account) = account else {
        state.inner.throttle.record_failure(&ip_key, &payload.login);
        return Err(WebmailError::invalid_credentials());
    };
    state.inner.throttle.record_success(&payload.login);

    let epochs = state.inner.epochs.clone();
    let email = account.email.clone();
    let epoch = blocking(move || Ok(epochs.current(&email))).await?;

    let (token, csrf) = state
        .inner
        .sessions
        .create(&account, epoch, OffsetDateTime::now_utc());
    let (cookie_name, secure) = cookie_context(&state, peer.as_ref(), &headers);
    let mut response = json_response(StatusCode::OK, session_view(&account, &csrf))?;
    session::append_set_cookie(
        &mut response,
        session::build_session_cookie(cookie_name, secure, &token),
    );
    tracing::info!(
        target: "mailstack_webmail",
        email = %account.email,
        "webmail login succeeded"
    );
    Ok(response)
}

pub async fn session_info(auth: AuthSession) -> WebmailResult<Response> {
    json_response(
        StatusCode::OK,
        session_view(auth.account(), &auth.session.csrf),
    )
}

pub async fn logout(
    State(state): State<AppState>,
    peer: Option<ConnectInfo<SocketAddr>>,
    headers: axum::http::HeaderMap,
    auth: AuthSession,
) -> WebmailResult<Response> {
    state
        .inner
        .sessions
        .remove_by_fingerprint(&auth.session.token_fingerprint);
    let peer = peer_addr(peer);
    let (cookie_name, secure) = cookie_context(&state, peer.as_ref(), &headers);
    let mut response = StatusCode::NO_CONTENT.into_response();
    session::append_set_cookie(
        &mut response,
        session::clear_session_cookie(cookie_name, secure),
    );
    tracing::info!(
        target: "mailstack_webmail",
        email = %auth.session.account.email,
        "webmail logout"
    );
    Ok(response)
}

pub async fn list_folders(auth: AuthSession) -> WebmailResult<Response> {
    let service = MaildirService::new(auth.account());
    let folders = blocking(move || service.list_folders()).await?;
    json_response(StatusCode::OK, serde_json::json!({ "folders": folders }))
}

pub async fn create_folder(
    auth: AuthSession,
    body: Result<Json<FolderNameRequest>, JsonRejection>,
) -> WebmailResult<Response> {
    let request = parse_json(body)?;
    let service = MaildirService::new(auth.account());
    let name = blocking(move || service.create_folder(&request.name)).await?;
    json_response(StatusCode::CREATED, serde_json::json!({ "name": name }))
}

pub async fn rename_folder(
    auth: AuthSession,
    path: Result<Path<String>, PathRejection>,
    body: Result<Json<FolderNameRequest>, JsonRejection>,
) -> WebmailResult<Response> {
    let from = parse_path(path)?;
    let request = parse_json(body)?;
    let service = MaildirService::new(auth.account());
    let name = blocking(move || service.rename_folder(&from, &request.name)).await?;
    json_response(StatusCode::OK, serde_json::json!({ "name": name }))
}

pub async fn delete_folder(
    auth: AuthSession,
    path: Result<Path<String>, PathRejection>,
) -> WebmailResult<Response> {
    let folder = parse_path(path)?;
    let service = MaildirService::new(auth.account());
    blocking(move || service.delete_folder(&folder)).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

pub async fn list_messages(
    auth: AuthSession,
    query: Result<Query<MessageListQuery>, QueryRejection>,
) -> WebmailResult<Response> {
    let query = parse_query(query)?;
    let sort = match query.sort.as_deref() {
        Some(value) => SortOrder::parse(value)
            .ok_or_else(|| WebmailError::bad_request("INVALID_SORT", "unknown sort order"))?,
        None => SortOrder::DateDesc,
    };
    let folder = folder_or_inbox(query.folder.clone());
    let options = ListOptions {
        offset: query.offset.unwrap_or(0),
        limit: limited(query.limit),
        unread_only: truthy(query.unread),
        flagged_only: truthy(query.flagged),
        sort,
        query: query.q.clone(),
    };
    let service = MaildirService::new(auth.account());
    let list = blocking(move || service.list_messages(&folder, &options)).await?;
    json_response(StatusCode::OK, list)
}

pub async fn message_detail(
    auth: AuthSession,
    path: Result<Path<(String, String)>, PathRejection>,
    query: Result<Query<DetailQuery>, QueryRejection>,
) -> WebmailResult<Response> {
    let (folder, uid) = parse_path(path)?;
    let uid = parse_uid(&uid)?;
    let query = parse_query(query)?;
    let service = MaildirService::new(auth.account());
    let detail =
        blocking(move || service.message_detail(&folder, uid, truthy(query.images))).await?;
    json_response(StatusCode::OK, serde_json::json!({ "message": detail }))
}

pub async fn raw_message(
    auth: AuthSession,
    path: Result<Path<(String, String)>, PathRejection>,
) -> WebmailResult<Response> {
    let (folder, uid) = parse_path(path)?;
    let uid = parse_uid(&uid)?;
    let service = MaildirService::new(auth.account());
    let raw = blocking(move || service.raw_message(&folder, uid)).await?;
    Ok((
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/rfc822; charset=utf-8"),
            ),
            (
                header::CONTENT_DISPOSITION,
                content_disposition("attachment", Some(&raw.filename)),
            ),
        ],
        raw.data,
    )
        .into_response())
}

pub async fn message_part(
    auth: AuthSession,
    path: Result<Path<(String, String, String)>, PathRejection>,
    query: Result<Query<PartQuery>, QueryRejection>,
) -> WebmailResult<Response> {
    let (folder, uid, part_id) = parse_path(path)?;
    let uid = parse_uid(&uid)?;
    let query = parse_query(query)?;
    let service = MaildirService::new(auth.account());
    let part = blocking(move || service.part(&folder, uid, &part_id)).await?;

    let force_download =
        truthy(query.download) || !part.inline || is_unsafe_render_type(&part.content_type);
    let disposition = if force_download {
        "attachment"
    } else {
        "inline"
    };
    let mut response = (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, safe_content_type(&part.content_type)),
            (
                header::CONTENT_DISPOSITION,
                content_disposition(disposition, part.filename.as_deref()),
            ),
        ],
        part.data,
    )
        .into_response();
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    Ok(response)
}

pub async fn patch_flags(
    auth: AuthSession,
    path: Result<Path<(String, String)>, PathRejection>,
    body: Result<Json<FlagPatch>, JsonRejection>,
) -> WebmailResult<Response> {
    let (folder, uid) = parse_path(path)?;
    let uid = parse_uid(&uid)?;
    let patch = parse_json(body)?;
    let service = MaildirService::new(auth.account());
    let flags = blocking(move || service.patch_flags(&folder, uid, &patch)).await?;
    json_response(StatusCode::OK, serde_json::json!({ "flags": flags }))
}

pub async fn move_message(
    auth: AuthSession,
    path: Result<Path<(String, String)>, PathRejection>,
    body: Result<Json<MoveRequest>, JsonRejection>,
) -> WebmailResult<Response> {
    let (folder, uid) = parse_path(path)?;
    let uid = parse_uid(&uid)?;
    let request = parse_json(body)?;
    let service = MaildirService::new(auth.account());
    let result = blocking(move || {
        service.move_message(&folder, uid, &request.to, request.copy.unwrap_or(false))
    })
    .await?;
    json_response(StatusCode::OK, result)
}

pub async fn delete_message(
    auth: AuthSession,
    path: Result<Path<(String, String)>, PathRejection>,
) -> WebmailResult<Response> {
    let (folder, uid) = parse_path(path)?;
    let uid = parse_uid(&uid)?;
    let service = MaildirService::new(auth.account());
    blocking(move || service.delete_message(&folder, uid)).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

pub async fn batch(
    auth: AuthSession,
    body: Result<Json<BatchRequest>, JsonRejection>,
) -> WebmailResult<Response> {
    let request = parse_json(body)?;
    let service = MaildirService::new(auth.account());
    let affected = blocking(move || service.batch(&request)).await?;
    json_response(StatusCode::OK, serde_json::json!({ "affected": affected }))
}

pub async fn search(
    auth: AuthSession,
    query: Result<Query<SearchQuery>, QueryRejection>,
) -> WebmailResult<Response> {
    let query = parse_query(query)?;
    let needle = query.q.unwrap_or_default();
    if needle.trim().is_empty() {
        return Err(WebmailError::bad_request(
            "INVALID_QUERY",
            "search query must not be empty",
        ));
    }
    let folder = folder_or_inbox(query.folder.clone());
    let offset = query.offset.unwrap_or(0);
    let limit = limited(query.limit);
    let service = MaildirService::new(auth.account());
    let list = blocking(move || service.search(&folder, &needle, offset, limit)).await?;
    json_response(StatusCode::OK, list)
}

pub async fn quota(auth: AuthSession) -> WebmailResult<Response> {
    let service = MaildirService::new(auth.account());
    let quota = blocking(move || service.quota()).await?;
    json_response(StatusCode::OK, quota)
}

pub async fn create_draft(
    auth: AuthSession,
    body: Result<Json<DraftRequest>, JsonRejection>,
) -> WebmailResult<Response> {
    let request = parse_json(body)?;
    let account = auth.account().clone();
    let (uid, folder) = blocking(move || crate::send::save_draft(&account, &request)).await?;
    json_response(
        StatusCode::CREATED,
        serde_json::json!({ "uid": uid, "folder": folder }),
    )
}

pub async fn send_message(
    State(state): State<AppState>,
    auth: AuthSession,
    body: Result<Json<ComposeRequest>, JsonRejection>,
) -> WebmailResult<Response> {
    let request = parse_json(body)?;
    let config = state.inner.config.clone();
    let account = auth.account().clone();
    let outcome = blocking(move || crate::send::send(&config, &account, &request)).await?;
    let mut payload = serde_json::json!({
        "queued": true,
        "queueId": outcome.queue_id,
        "sentUid": outcome.sent_uid,
    });

    if let Some(warning) = outcome.warning {
        payload["warning"] = serde_json::Value::String(warning);
    }
    json_response(StatusCode::ACCEPTED, payload)
}

pub async fn fallback(State(state): State<AppState>, uri: Uri) -> Response {
    if crate::http::is_api_path(uri.path()) {
        return crate::http::error::json_error(WebmailError::api_not_found());
    }
    assets::serve(
        &state.inner.config.dist,
        state.inner.entry.as_ref(),
        uri.path(),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsafe_render_types_are_forced_to_attachment() {
        for value in [
            "text/html",
            "TEXT/HTML",
            "application/xhtml+xml",
            "image/svg+xml",
            "application/xml",
            "text/xml",
            "application/javascript",
        ] {
            assert!(is_unsafe_render_type(value), "{value} 必须强制附件");
        }
        for value in ["text/plain", "image/png", "application/pdf"] {
            assert!(!is_unsafe_render_type(value), "{value} 可以 inline");
        }
    }

    #[test]
    fn content_disposition_is_ascii_safe_and_rfc5987_encoded() {
        let value = content_disposition("attachment", Some("报告.pdf"));
        let raw = value.to_str().unwrap();
        assert!(raw.contains("filename*=UTF-8''%E6%8A%A5%E5%91%8A.pdf"));
        assert!(raw.is_ascii(), "响应头必须是 ASCII：{raw}");

        let value = content_disposition("attachment", Some("a\"b\\c.txt"));
        let raw = value.to_str().unwrap();
        assert!(raw.is_ascii());
        assert!(!raw.contains("\r") && !raw.contains("\n"));
    }

    #[test]
    fn content_types_from_mail_are_downgraded_when_unsafe() {
        assert_eq!(
            safe_content_type("text/plain").to_str().unwrap(),
            "text/plain"
        );
        assert_eq!(
            safe_content_type("text/html\r\nX-Evil: 1")
                .to_str()
                .unwrap(),
            "application/octet-stream"
        );
        assert_eq!(
            safe_content_type("not a type").to_str().unwrap(),
            "application/octet-stream"
        );
    }

    #[test]
    fn uid_and_limit_parsing_is_strict() {
        assert_eq!(parse_uid("42").unwrap(), 42);
        for bad in ["", "-1", "abc", "1.0", "4294967296"] {
            assert!(parse_uid(bad).is_err(), "{bad:?} 必须被拒绝");
        }
        assert_eq!(limited(None), DEFAULT_LIST_LIMIT);
        assert_eq!(limited(Some(0)), 1);
        assert_eq!(limited(Some(10_000)), MAX_LIST_LIMIT);
    }

    #[test]
    fn folder_defaults_to_inbox() {
        assert_eq!(folder_or_inbox(None), "INBOX");
        assert_eq!(folder_or_inbox(Some("  ".to_string())), "INBOX");
        assert_eq!(folder_or_inbox(Some("Archive".to_string())), "Archive");
    }
}
