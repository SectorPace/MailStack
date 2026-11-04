use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use axum::extract::rejection::JsonRejection;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;

use crate::error::{api_not_found, ApiError};
use crate::ratelimit::{ERR_INVALID_CREDENTIALS, ERR_TOTP_REQUIRED};
use crate::session::forwarded_proto;
use crate::{AppState, AuthenticatedUser};

macro_rules! action_handlers {
    ($($name:ident => $action:literal),* $(,)?) => {
        $(
            pub async fn $name(
                State(state): State<AppState>,
                peer: Option<ConnectInfo<SocketAddr>>,
                path_params: Option<Path<HashMap<String, String>>>,
                headers: axum::http::HeaderMap,
                body: Result<Json<serde_json::Value>, JsonRejection>,
            ) -> Response {
                run_action(&state, $action, peer, path_params, &headers, body).await
            }
        )*

        pub const ACTION_HANDLER_BINDINGS: &[(&str, &str)] = &[
            $((stringify!($name), $action)),*
        ];
    };
}

action_handlers! {
    domains_list            => "domains.list",
    domains_add             => "domains.add",
    domains_delete          => "domains.delete",
    snapshot_get            => "snapshot",
    logs_list               => "logs.list",
    metrics_realtime        => "metrics.realtime",
    check_port              => "network.check_port",
    settings_get            => "settings.get",
    settings_set            => "settings.set",
    admin_get               => "admin.get",

    admin_set               => "admin.set",
    totp_enable             => "admin.totp.enable",
    totp_disable            => "admin.totp.disable",
    aliases_add             => "aliases.add",
    aliases_delete          => "aliases.delete",
    dkim_rotate             => "dkim.rotate",
    totp_begin              => "admin.totp.begin",
    system_doctor           => "system.doctor",
    setup_status            => "setup.status",
    setup_wizard_complete   => "setup.wizard.complete",
    queue_action            => "queue.action",
    services_action         => "services.action",
    security_scan           => "security.scan",
    security_ban            => "security.ban",
    security_unban          => "security.unban",
    backup_list             => "backup.list",
    backup_create           => "backup.create",
    backup_restore          => "backup.restore",
    backup_delete           => "backup.delete",
    certs_list              => "certs.list",
    setup_identity          => "setup.identity.apply",
    setup_dns_verify        => "setup.dns.verify",
    setup_relay_test        => "setup.relay.test",
    setup_relay_apply       => "setup.relay.apply",
    setup_mail_test         => "setup.mail.test",
    mail_test_loopback      => "mail.test_loopback",
    users_add               => "users.add",
    users_list              => "users.list",
    users_status            => "users.status",
    users_password          => "users.password",
    users_delete            => "users.delete",
    aliases_list            => "aliases.list",
    certs_renew             => "certs.renew",
    setup_cert_issue        => "setup.cert.issue",

    queue_list              => "queue.list",
    services_list           => "services.list",
    dkim_keys               => "dkim.keys",
    dns_records             => "dns.records",
    metrics_system          => "metrics.system",
    activity_list           => "activity.list",
}

async fn run_action(
    state: &AppState,
    action: &'static str,
    peer: Option<ConnectInfo<SocketAddr>>,
    path_params: Option<Path<HashMap<String, String>>>,
    headers: &axum::http::HeaderMap,
    body: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    let mut data = match json_payload(body, headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    if let Some(obj) = data.as_object_mut() {
        if let Some(Path(params)) = path_params {
            for (k, v) in params {
                obj.entry(k).or_insert(serde_json::Value::String(v));
            }
        }
    }

    match state.call_action(action, &data).await {
        Ok(value) => match finalize_successful_action(state, action, value) {
            Ok(value) => {
                let mut response = crate::error::ok_json(value);
                if crate::contract::revokes_sessions(action) {
                    let peer_addr = peer.map(|ConnectInfo(addr)| addr);
                    if let Some(error) = finish_after_revocation(
                        &mut response,
                        state,
                        peer_addr.as_ref(),
                        forwarded_proto(headers).as_deref(),
                    ) {
                        return error;
                    }
                }
                response
            }
            Err(error) => error.into_response(),
        },
        Err(e) => e.into_response(),
    }
}

fn finalize_successful_action(
    state: &AppState,
    action: &str,
    mut value: serde_json::Value,
) -> Result<serde_json::Value, ApiError> {
    if !crate::contract::revokes_sessions(action) {
        return Ok(value);
    }
    let Some(username) = admin_username(state) else {
        return Err(missing_admin_config_error());
    };
    let revoked = state.inner.sessions.revoke_user(&username);
    if let Some(obj) = value.as_object_mut() {
        obj.insert("revokedSessions".to_string(), revoked.into());
        obj.insert("reauthenticate".to_string(), true.into());
    }
    Ok(value)
}

#[allow(clippy::result_large_err)]
fn json_payload(
    body: Result<Json<serde_json::Value>, JsonRejection>,
    headers: &axum::http::HeaderMap,
) -> Result<serde_json::Value, Response> {
    match body {
        Ok(Json(value)) => Ok(if value.is_null() {
            serde_json::json!({})
        } else {
            value
        }),
        Err(rejection) => {
            if matches!(&rejection, JsonRejection::MissingJsonContentType(_))
                && !request_has_body(headers)
            {
                return Ok(serde_json::json!({}));
            }
            Err(
                ApiError::new(crate::ratelimit::ERR_REQUEST_FAILED, rejection.body_text())
                    .into_response(),
            )
        }
    }
}

fn request_has_body(headers: &axum::http::HeaderMap) -> bool {
    if let Some(length) = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
    {
        return length > 0;
    }
    headers.contains_key(header::TRANSFER_ENCODING)
}

fn admin_username(state: &AppState) -> Option<String> {
    mailstack_core::config::read_admin_config(state.paths()).map(|c| c.username)
}

fn missing_admin_config_error() -> ApiError {
    ApiError::new(
        crate::ratelimit::ERR_INTERNAL_ERROR,
        "administrator configuration is unreadable; sessions were not revoked",
    )
    .with_status(StatusCode::INTERNAL_SERVER_ERROR)
}

pub(crate) fn clear_session_cookie(
    response: &mut Response,
    state: &AppState,
    peer: Option<&SocketAddr>,
    forwarded_proto: Option<&str>,
) -> Result<(), String> {
    let (name, secure) = cookie_context(state, peer, forwarded_proto);
    let mut cookie = format!("{name}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0");
    if secure {
        cookie.push_str("; Secure");
    }

    let value = HeaderValue::from_str(&cookie)
        .map_err(|error| format!("session invalidation cookie is not serializable: {error}"))?;
    response.headers_mut().append(header::SET_COOKIE, value);
    Ok(())
}

fn finish_after_revocation(
    response: &mut Response,
    state: &AppState,
    peer: Option<&SocketAddr>,
    forwarded_proto: Option<&str>,
) -> Option<Response> {
    match clear_session_cookie(response, state, peer, forwarded_proto) {
        Ok(()) => None,
        Err(message) => Some(ApiError::internal(message).into_response()),
    }
}

fn cookie_context(
    state: &AppState,
    peer: Option<&SocketAddr>,
    forwarded_proto: Option<&str>,
) -> (&'static str, bool) {
    let mut headers = axum::http::HeaderMap::new();
    if let Some(proto) = forwarded_proto {
        if let Ok(value) = HeaderValue::from_str(proto) {
            headers.insert("x-forwarded-proto", value);
        }
    }
    let env_flag = std::env::var(crate::session::SESSION_COOKIE_SECURE_ENV).ok();
    crate::session::session_cookie_context(
        env_flag.as_deref(),
        state.inner.public_mode,
        peer,
        &headers,
    )
}

pub async fn rpc_bridge(
    State(state): State<AppState>,
    peer: Option<ConnectInfo<SocketAddr>>,
    headers: axum::http::HeaderMap,
    body: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    let body = match body {
        Ok(Json(value)) => value,
        Err(rejection) => {
            tracing::warn!(error = %rejection.body_text(), "rpc bridge rejected a malformed body");
            return crate::error::rpc_err_json(StatusCode::BAD_REQUEST, "malformed request body");
        }
    };

    let action = body.get("action").and_then(|v| v.as_str()).unwrap_or("");
    if !crate::contract::is_exposed_action(action) {
        return crate::error::rpc_err_json(StatusCode::BAD_REQUEST, "unknown action");
    }

    let data = body.get("data").cloned().unwrap_or(serde_json::Value::Null);
    let data = if data.is_null() {
        serde_json::json!({})
    } else {
        data
    };

    let peer_addr = peer.map(|ConnectInfo(addr)| addr);

    match state.call_action(action, &data).await {
        Ok(value) => {
            let value = match finalize_successful_action(&state, action, value) {
                Ok(value) => value,
                Err(error) => {
                    return crate::error::rpc_err_json(error.status, error.message.clone());
                }
            };
            let mut response = crate::error::rpc_ok_json(value);
            if crate::contract::revokes_sessions(action) {
                if let Some(error) = finish_after_revocation(
                    &mut response,
                    &state,
                    peer_addr.as_ref(),
                    forwarded_proto(&headers).as_deref(),
                ) {
                    return error;
                }
            }
            response
        }

        Err(e) => crate::error::rpc_err_json(e.status, e.message.clone()),
    }
}

pub fn client_key(peer: Option<&SocketAddr>) -> String {
    match peer {
        Some(addr) => normalize_ip(addr.ip()),

        None => "local".to_string(),
    }
}

fn normalize_ip(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return v4.to_string();
            }
            let mut s = v6.to_string();
            if let Some(idx) = s.find('%') {
                s.truncate(idx);
            }
            s.to_ascii_lowercase()
        }
    }
}

pub async fn login(
    State(state): State<AppState>,
    peer: Option<ConnectInfo<SocketAddr>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let username = body
        .get("username")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let password = body
        .get("password")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let code = body
        .get("code")
        .and_then(|v| v.as_str())
        .map(str::to_string);

    let peer_addr = peer.map(|ConnectInfo(addr)| addr);
    let client_ip = client_key(peer_addr.as_ref());
    match state.inner.login_limiter.check(&client_ip, &username) {
        crate::ratelimit::LimitVerdict::Allow => {}
        crate::ratelimit::LimitVerdict::Limited { retry_after_secs } => {
            return ApiError::rate_limited(retry_after_secs).into_response();
        }
    }

    let Some(config) = mailstack_core::config::read_admin_config(state.paths()) else {
        state
            .inner
            .login_limiter
            .record_failure(&client_ip, &username);
        return ApiError::new(ERR_INVALID_CREDENTIALS, "invalid credentials")
            .with_status(StatusCode::UNAUTHORIZED)
            .into_response();
    };

    let record = config.password_record();
    let password_ok = match tokio::task::spawn_blocking({
        let record = record.clone();
        let password = password.clone();
        move || mailstack_core::password::verify_password(&record, &password)
    })
    .await
    {
        Ok(verified) => verified,
        Err(error) => {
            tracing::error!("password verification task failed: {error}");
            return ApiError::internal("internal error").into_response();
        }
    };
    let username_ok = config.username == username;

    if !(password_ok && username_ok) {
        state
            .inner
            .login_limiter
            .record_failure(&client_ip, &username);
        return ApiError::new(ERR_INVALID_CREDENTIALS, "invalid credentials")
            .with_status(StatusCode::UNAUTHORIZED)
            .into_response();
    }

    let two_factor_enabled = config
        .totp
        .as_ref()
        .and_then(|t| t.get("enabled"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if two_factor_enabled {
        let Some(code) = code.as_deref().filter(|c| !c.is_empty()) else {
            return ApiError::new(ERR_TOTP_REQUIRED, "two-factor code required")
                .with_status(StatusCode::UNAUTHORIZED)
                .into_response();
        };

        let payload = serde_json::json!({ "username": username, "code": code });
        match state.inner.client.call("admin.totp.verify", &payload).await {
            Ok(result)
                if result
                    .get("valid")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false) => {}
            Ok(_) => {
                state
                    .inner
                    .login_limiter
                    .record_failure(&client_ip, &username);
                return ApiError::new(ERR_INVALID_CREDENTIALS, "invalid credentials")
                    .with_status(StatusCode::UNAUTHORIZED)
                    .into_response();
            }
            Err(e) => {
                return e.into_response();
            }
        }
    }

    state
        .inner
        .login_limiter
        .record_success(&client_ip, &username);

    let (sid, csrf) = state.inner.sessions.create_session(&username);

    let cookie = build_session_cookie(
        &sid,
        &state,
        peer_addr.as_ref(),
        forwarded_proto(&headers).as_deref(),
    );

    let mut response = Json(serde_json::json!({
        "ok": true,
        "csrf": csrf,
        "username": username,
    }))
    .into_response();

    let cookie_value = match HeaderValue::from_str(&cookie) {
        Ok(value) => value,
        Err(error) => {
            state.inner.sessions.remove(&sid);
            return ApiError::internal(format!("session cookie is not serializable: {error}"))
                .into_response();
        }
    };
    response
        .headers_mut()
        .append(header::SET_COOKIE, cookie_value);
    response
}

fn build_session_cookie(
    sid: &str,
    state: &AppState,
    peer: Option<&SocketAddr>,
    forwarded_proto: Option<&str>,
) -> String {
    let (name, secure) = cookie_context(state, peer, forwarded_proto);
    let mut cookie = format!(
        "{name}={sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age={}",
        crate::session::SESSION_ABSOLUTE_MAX_SECONDS
    );
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

pub async fn list_sessions(State(state): State<AppState>) -> Response {
    let sessions = state
        .inner
        .sessions
        .list_public(time::OffsetDateTime::now_utc());
    Json(serde_json::json!({ "ok": true, "sessions": sessions })).into_response()
}

pub async fn revoke_session(
    State(state): State<AppState>,
    peer: Option<ConnectInfo<SocketAddr>>,
    headers: axum::http::HeaderMap,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    body: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    let body = match body {
        Ok(Json(value)) => value,
        Err(_) => {
            return ApiError::new(
                crate::ratelimit::ERR_REQUEST_FAILED,
                "malformed request body",
            )
            .into_response();
        }
    };
    let Some(fingerprint) = body.get("id").and_then(|v| v.as_str()) else {
        return ApiError::new("REQUEST_FAILED", "missing session fingerprint").into_response();
    };
    let revoked = state.inner.sessions.revoke_by_fingerprint(fingerprint);

    let own = crate::session::fingerprint_of(&user.session_id);
    if !(revoked && fingerprint == own) {
        return Json(serde_json::json!({ "ok": revoked })).into_response();
    }

    let peer_addr = peer.map(|ConnectInfo(addr)| addr);
    let mut response = Json(serde_json::json!({
        "ok": true,
        "revoked": true,
        "reauthenticate": true,
    }))
    .into_response();
    if let Some(error) = finish_after_revocation(
        &mut response,
        &state,
        peer_addr.as_ref(),
        forwarded_proto(&headers).as_deref(),
    ) {
        return error;
    }
    response
}

pub async fn revoke_other_sessions(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
) -> Response {
    let revoked = state.inner.sessions.revoke_others(&user.session_id);
    Json(serde_json::json!({ "ok": true, "revoked": revoked })).into_response()
}

pub async fn admin_2fa(State(state): State<AppState>) -> Response {
    let public = mailstack_core::config::admin_public(state.paths());
    Json(serde_json::json!({
        "ok": true,
        "enabled": public.two_factor_enabled,
        "state": mailstack_core::totp::state_at(state.paths()).as_str(),
        "recoveryCodesRemaining": public.recovery_codes_remaining,
        "algorithm": "SHA1",
        "digits": mailstack_core::totp::TOTP_DIGITS,
        "period": mailstack_core::totp::TOTP_PERIOD_SECS,
    }))
    .into_response()
}

pub async fn metrics_telemetry(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let range = params.get("range").cloned();

    let Ok(permit) = std::sync::Arc::clone(&state.inner.telemetry_gate).try_acquire_owned() else {
        return ApiError::rate_limited(1).into_response();
    };
    let collector = std::sync::Arc::clone(&state.inner.telemetry);

    let result = tokio::task::spawn_blocking(move || {
        let body = collector.telemetry(range.as_deref());

        drop(permit);
        body
    })
    .await;
    match result {
        Ok(value) => Json(value).into_response(),
        Err(error) => {
            tracing::error!("telemetry sampling task failed: {error}");
            ApiError::internal("internal error").into_response()
        }
    }
}

pub async fn api_fallback() -> Response {
    api_not_found()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build_router;
    use axum::body::Body;
    use axum::http::Request as HttpRequest;
    use mailstack_core::paths::Paths;
    use tower::ServiceExt;

    fn test_state(tag: &str) -> (std::path::PathBuf, AppState) {
        let mut root = std::env::temp_dir();
        root.push(format!(
            "mailstack-routes-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        (root.clone(), AppState::new(Paths::rooted(&root)))
    }

    async fn body_json(response: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn session_listing_requires_authentication() {
        let (root, state) = test_state("sesslist");
        let app = build_router(state);
        let response = app
            .oneshot(
                HttpRequest::builder()
                    .uri("/api/auth/sessions")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn session_listing_returns_fingerprints_not_ids() {
        let (root, state) = test_state("sessfp");
        let sid = state.inner.sessions.create("admin");
        let app = build_router(state);
        let response = app
            .oneshot(
                HttpRequest::builder()
                    .uri("/api/auth/sessions")
                    .header(header::COOKIE, format!("{}={sid}", crate::SESSION_COOKIE))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let text = serde_json::to_string(&body_json(response).await).unwrap();
        assert!(!text.contains(&sid), "不得暴露原始会话 ID");
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn revoke_others_keeps_the_current_session() {
        let (root, state) = test_state("revokeothers");
        let keep = state.inner.sessions.create("admin");
        let csrf = state.inner.sessions.touch(&keep).unwrap().csrf;
        state.inner.sessions.create("admin");
        assert_eq!(state.inner.sessions.len(), 2);

        let app = build_router(state.clone());
        let response = app
            .oneshot(
                HttpRequest::builder()
                    .method(axum::http::Method::DELETE)
                    .uri("/api/auth/sessions")
                    .header(header::COOKIE, format!("{}={keep}", crate::SESSION_COOKIE))
                    .header("x-csrf-token", csrf)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["ok"], true);
        assert_eq!(body["revoked"], 1, "应吊销 1 个其它会话");
        assert!(
            state.inner.sessions.touch(&keep).is_some(),
            "当前会话必须保留"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn revoke_session_requires_an_id_field() {
        let (root, state) = test_state("revokenoid");
        let sid = state.inner.sessions.create("admin");
        let app = build_router(state);
        let response = app
            .oneshot(
                HttpRequest::builder()
                    .method(axum::http::Method::POST)
                    .uri("/api/auth/sessions/revoke")
                    .header(header::COOKIE, format!("{}={sid}", crate::SESSION_COOKIE))
                    .header("x-csrf-token", "wrong")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn public_mode_reads_never_fall_back_to_sudo() {
        let mut root = std::env::temp_dir();
        root.push(format!(
            "mailstack-routes-pubmode-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let paths = Paths::rooted(&root);
        std::fs::create_dir_all(&paths.etc).unwrap();
        std::fs::write(&paths.install_args_conf, "ACCESS_MODE=direct\n").unwrap();

        let state = AppState::new(paths);
        assert!(state.inner.public_mode, "应判定为公网模式");

        let sid = state.inner.sessions.create("admin");
        let csrf = state.inner.sessions.touch(&sid).unwrap().csrf;
        let app = build_router(state);

        let response = app
            .oneshot(
                HttpRequest::builder()
                    .uri("/api/domains")
                    .header(header::COOKIE, format!("{}={sid}", crate::SESSION_COOKIE))
                    .header("x-csrf-token", csrf)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_ne!(
            response.status(),
            StatusCode::OK,
            "公网模式 RO 不得经 sudo 成功"
        );
        assert_eq!(
            response.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "应返回 503（助手不可达），实际 {}",
            response.status()
        );
        let body = body_json(response).await;
        assert_eq!(body["error"]["code"], "PRIVILEGED_HELPER_UNAVAILABLE");
        std::fs::remove_dir_all(&root).ok();
    }

    async fn post_login(app: axum::Router, payload: serde_json::Value) -> Response {
        app.oneshot(
            HttpRequest::builder()
                .method(axum::http::Method::POST)
                .uri("/api/auth/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn login_with_correct_password_sets_httponly_cookie_and_returns_csrf() {
        let (root, state) = test_state("loginok");
        mailstack_core::config::admin_set(state.paths(), "admin", "Tr0ubadour9x").unwrap();
        let app = build_router(state.clone());

        let response = post_login(
            app,
            serde_json::json!({ "username": "admin", "password": "Tr0ubadour9x" }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        let cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        assert!(
            cookie.starts_with(&format!("{}=", crate::session::SESSION_COOKIE_PLAIN_NAME)),
            "cookie: {cookie}"
        );
        assert!(
            !cookie.contains("Secure"),
            "HTTP 默认部署不得带 Secure：{cookie}"
        );
        assert!(cookie.contains("HttpOnly"), "会话 Cookie 必须是 HttpOnly");
        assert!(cookie.contains("SameSite=Strict"));
        assert!(cookie.contains("Path=/"));

        assert!(
            cookie.contains(&format!(
                "Max-Age={}",
                crate::session::SESSION_ABSOLUTE_MAX_SECONDS
            )),
            "cookie 寿命必须对齐服务端绝对上限：{cookie}"
        );

        let body = body_json(response).await;
        assert_eq!(body["ok"], true);
        assert_eq!(body["username"], "admin");
        assert!(body["csrf"].as_str().unwrap().len() == 64);
        assert_eq!(state.inner.sessions.len(), 1, "应建立一个会话");
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn login_with_wrong_password_returns_indistinguishable_401() {
        let (root, state) = test_state("loginbad");
        mailstack_core::config::admin_set(state.paths(), "admin", "Tr0ubadour9x").unwrap();

        let wrong_password = post_login(
            build_router(state.clone()),
            serde_json::json!({ "username": "admin", "password": "Wr0ngPassword1" }),
        )
        .await;
        let unknown_user = post_login(
            build_router(state.clone()),
            serde_json::json!({ "username": "nosuchuser", "password": "Tr0ubadour9x" }),
        )
        .await;

        assert_eq!(wrong_password.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(unknown_user.status(), StatusCode::UNAUTHORIZED);

        let a = body_json(wrong_password).await;
        let b = body_json(unknown_user).await;
        assert_eq!(a, b, "两种失败必须返回完全相同的响应体");
        assert_eq!(a["error"]["code"], "INVALID_CREDENTIALS");

        let text = a.to_string();
        assert!(!text.contains("remaining"));
        assert_eq!(state.inner.sessions.len(), 0, "失败登录不得建立会话");
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn login_reports_totp_required_when_two_factor_is_enabled() {
        let (root, state) = test_state("login2fa");
        mailstack_core::config::admin_set(state.paths(), "admin", "Tr0ubadour9x").unwrap();

        let path = &state.paths().admin_config;
        let mut value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        value["totp"] = serde_json::json!({ "enabled": true, "recovery": [] });
        std::fs::write(path, serde_json::to_string_pretty(&value).unwrap()).unwrap();

        let response = post_login(
            build_router(state.clone()),
            serde_json::json!({ "username": "admin", "password": "Tr0ubadour9x" }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = body_json(response).await;
        assert_eq!(
            body["error"]["code"], "TOTP_REQUIRED",
            "密码正确但需 2FA 时必须回 TOTP_REQUIRED"
        );
        assert_eq!(state.inner.sessions.len(), 0, "未过 2FA 不得建立会话");
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn login_before_initialization_is_indistinguishable_from_bad_credentials() {
        let (root, state) = test_state("loginuninit");

        let response = post_login(
            build_router(state),
            serde_json::json!({ "username": "admin", "password": "Tr0ubadour9x" }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = body_json(response).await;
        assert_eq!(body["error"]["code"], "INVALID_CREDENTIALS");
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn repeated_failures_lock_the_account() {
        let (root, state) = test_state("loginlock");
        mailstack_core::config::admin_set(state.paths(), "admin", "Tr0ubadour9x").unwrap();

        for _ in 0..crate::ratelimit::FAILURE_LOCKOUT_THRESHOLD {
            let _ = post_login(
                build_router(state.clone()),
                serde_json::json!({ "username": "admin", "password": "Wr0ng1Password" }),
            )
            .await;
        }
        assert!(
            state.inner.login_limiter.is_locked("admin"),
            "连续失败达阈值必须锁定账号"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    fn enable_two_factor(state: &AppState) {
        let path = &state.paths().admin_config;
        let mut value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        value["totp"] = serde_json::json!({ "enabled": true });
        std::fs::write(path, value.to_string()).unwrap();
    }

    #[tokio::test]
    async fn a_wrong_username_costs_the_same_as_a_wrong_password() {
        let (root, state) = test_state("loginenum");

        let measure = |username: &'static str, password: &'static str| {
            let state = state.clone();
            async move {
                let started = std::time::Instant::now();
                let response = post_login(
                    build_router(state),
                    serde_json::json!({ "username": username, "password": password }),
                )
                .await;
                assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
                started.elapsed()
            }
        };

        let _ = measure("nosuchuser", "Tr0ubadour9x").await;

        let wrong_password = measure("admin", "Wr0ng1Password").await;
        let wrong_username = measure("nosuchuser", "Tr0ubadour9x").await;

        assert!(
            wrong_username >= wrong_password / 2,
            "错用户名耗时 {wrong_username:?} 明显短于错口令 {wrong_password:?} —— \
             PBKDF2 很可能被短路了，用户名可枚举"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn password_hashing_does_not_block_the_async_worker() {
        let (root, state) = test_state("loginblocking");
        mailstack_core::config::admin_set(state.paths(), "admin", "Tr0ubadour9x").unwrap();

        let hammer = tokio::spawn({
            let state = state.clone();
            async move {
                for _ in 0..3 {
                    let _ = post_login(
                        build_router(state.clone()),
                        serde_json::json!({ "username": "admin", "password": "Wr0ng1Password" }),
                    )
                    .await;
                }
            }
        });

        let started = std::time::Instant::now();
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        let elapsed = started.elapsed();

        hammer.await.unwrap();
        assert!(
            elapsed < std::time::Duration::from_millis(50),
            "一个 1ms 的 sleep 花了 {elapsed:?} —— async worker 被 PBKDF2 占住了"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn an_unreachable_helper_does_not_count_towards_account_lockout() {
        let (root, state) = test_state("login503");
        mailstack_core::config::admin_set(state.paths(), "admin", "Tr0ubadour9x").unwrap();
        enable_two_factor(&state);

        for attempt in 0..(crate::ratelimit::FAILURE_LOCKOUT_THRESHOLD + 2) {
            let response = post_login(
                build_router(state.clone()),
                serde_json::json!({
                    "username": "admin",
                    "password": "Tr0ubadour9x",
                    "code": "000000",
                }),
            )
            .await;
            assert!(
                response.status() != StatusCode::UNAUTHORIZED,
                "第 {attempt} 次：助手不可达必须报 503，绝不能变成凭证失败"
            );
        }

        assert!(
            !state.inner.login_limiter.is_locked("admin"),
            "基础设施故障不得把管理员锁在门外"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn a_successful_login_never_yields_an_empty_csrf_or_a_missing_cookie() {
        let (root, state) = test_state("logincsrf");
        mailstack_core::config::admin_set(state.paths(), "admin", "Tr0ubadour9x").unwrap();

        for round in 0..8 {
            let response = post_login(
                build_router(state.clone()),
                serde_json::json!({ "username": "admin", "password": "Tr0ubadour9x" }),
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);

            let cookie = response
                .headers()
                .get(header::SET_COOKIE)
                .expect("登录成功必须下发 Set-Cookie")
                .to_str()
                .unwrap()
                .to_string();
            assert!(
                cookie.starts_with(&format!("{}=", crate::session::SESSION_COOKIE_PLAIN_NAME)),
                "第 {round} 轮：cookie 不可用"
            );

            let body = body_json(response).await;
            let csrf = body["csrf"].as_str().unwrap_or_default().to_string();
            assert_eq!(csrf.len(), 64, "第 {round} 轮：csrf 不是 32 字节 hex");
            assert!(
                csrf.chars().all(|c| c.is_ascii_hexdigit()),
                "第 {round} 轮：csrf 含非 hex 字符：{csrf}"
            );

            let sid = cookie
                .split(';')
                .next()
                .unwrap()
                .split_once('=')
                .unwrap()
                .1
                .to_string();
            let response = build_router(state.clone())
                .oneshot(
                    HttpRequest::builder()
                        .method(axum::http::Method::DELETE)
                        .uri("/api/auth/sessions")
                        .header(header::COOKIE, format!("{}={sid}", crate::SESSION_COOKIE))
                        .header("x-csrf-token", csrf)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_ne!(
                response.status(),
                StatusCode::FORBIDDEN,
                "第 {round} 轮：刚下发的 csrf 立刻被 CSRF 校验拒绝"
            );
        }
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn issued_and_cleared_session_cookies_are_always_paired() {
        let (root, state) = test_state("cookiepair");

        let issued = build_session_cookie("sid-http", &state, None, None);
        let mut response = Response::builder().body(Body::empty()).unwrap();
        clear_session_cookie(&mut response, &state, None, None).unwrap();
        let cleared = response.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .to_string();

        for cookie in [&issued, &cleared] {
            assert!(
                cookie.starts_with(&format!("{}=", crate::session::SESSION_COOKIE_PLAIN_NAME)),
                "HTTP 默认部署必须用无前缀名：{cookie}"
            );
            assert!(
                !cookie.contains("Secure"),
                "HTTP 默认部署不得带 Secure：{cookie}"
            );
        }
        assert!(cleared.contains("Max-Age=0"), "作废必须立即过期：{cleared}");

        let peer: SocketAddr = "127.0.0.1:8443".parse().unwrap();
        let issued = build_session_cookie("sid-tls", &state, Some(&peer), Some("https"));
        let mut response = Response::builder().body(Body::empty()).unwrap();
        clear_session_cookie(&mut response, &state, Some(&peer), Some("https")).unwrap();
        let cleared = response.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .to_string();

        for cookie in [&issued, &cleared] {
            assert!(
                cookie.starts_with(&format!("{}=", crate::SESSION_COOKIE)),
                "HTTPS 部署必须用 `__Host-` 名：{cookie}"
            );
            assert!(
                cookie.contains("Secure"),
                "HTTPS 部署必须带 Secure：{cookie}"
            );
        }
        assert!(cleared.contains("Max-Age=0"), "作废必须立即过期：{cleared}");

        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn a_malformed_json_body_is_rejected_with_the_error_envelope() {
        let (root, state) = test_state("badjson");
        let (sid, csrf) = state.inner.sessions.create_session("admin");
        let app = build_router(state);

        let response = app
            .oneshot(
                HttpRequest::builder()
                    .method(axum::http::Method::POST)
                    .uri("/api/queue/action")
                    .header(header::COOKIE, format!("{}={sid}", crate::SESSION_COOKIE))
                    .header("x-csrf-token", csrf)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("{\"queue_id\": "))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = body_json(response).await;
        assert_eq!(body["ok"], false);
        assert!(
            body["error"]["code"].is_string() && body["error"]["message"].is_string(),
            "必须是既有错误外壳形状：{body}"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn a_json_body_with_the_wrong_content_type_is_rejected() {
        let (root, state) = test_state("wrongct");
        let (sid, csrf) = state.inner.sessions.create_session("admin");
        let app = build_router(state);

        let response = app
            .oneshot(
                HttpRequest::builder()
                    .method(axum::http::Method::POST)
                    .uri("/api/queue/action")
                    .header(header::COOKIE, format!("{}={sid}", crate::SESSION_COOKIE))
                    .header("x-csrf-token", csrf)
                    .header(header::CONTENT_TYPE, "text/plain")
                    .header(header::CONTENT_LENGTH, "19")
                    .body(Body::from("{\"queue_id\": \"abc\"}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = body_json(response).await;
        assert_eq!(body["ok"], false);
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn a_bodyless_request_still_reaches_the_action_with_an_empty_payload() {
        let mut root = std::env::temp_dir();
        root.push(format!(
            "mailstack-routes-bodyless-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let paths = Paths::rooted(&root);
        std::fs::create_dir_all(&paths.etc).unwrap();
        std::fs::write(&paths.install_args_conf, "ACCESS_MODE=direct\n").unwrap();
        let state = AppState::new(paths);

        let (sid, _csrf) = state.inner.sessions.create_session("admin");
        let app = build_router(state);

        let response = app
            .oneshot(
                HttpRequest::builder()
                    .uri("/api/queue")
                    .header(header::COOKIE, format!("{}={sid}", crate::SESSION_COOKIE))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "无主体的 GET 必须维持「空载荷继续」语义，实际 {}",
            response.status()
        );
        std::fs::remove_dir_all(&root).ok();
    }

    async fn post_rpc(
        app: axum::Router,
        sid: &str,
        csrf: &str,
        body: serde_json::Value,
    ) -> Response {
        app.oneshot(
            HttpRequest::builder()
                .method(axum::http::Method::POST)
                .uri("/api/rpc")
                .header(header::COOKIE, format!("{}={sid}", crate::SESSION_COOKIE))
                .header("x-csrf-token", csrf)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
    }

    fn recording_stub(calls: std::sync::Arc<std::sync::Mutex<Vec<String>>>) -> crate::ActionStub {
        std::sync::Arc::new(move |action: &str, _data: &serde_json::Value| {
            calls.lock().unwrap().push(action.to_string());

            Ok(serde_json::json!({ "ok": true, "recoveryCodes": ["AAAA-BBBB"] }))
        })
    }

    #[tokio::test]
    async fn the_rpc_bridge_revokes_sessions_exactly_like_the_dedicated_routes() {
        for (action, body) in [
            (
                "admin.set",
                serde_json::json!({"username": "admin", "password": "An0therGood1"}),
            ),
            ("admin.totp.enable", serde_json::json!({"code": "123456"})),
            ("admin.totp.disable", serde_json::json!({"confirm": true})),
        ] {
            let (root, state) = test_state("bridge-revoke");
            mailstack_core::config::admin_set(state.paths(), "admin", "Tr0ubadour9x").unwrap();
            let calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let state = state.with_action_stub(recording_stub(std::sync::Arc::clone(&calls)));

            let (sid, csrf) = state.inner.sessions.create_session("admin");
            let other = state.inner.sessions.create("admin");
            assert_eq!(state.inner.sessions.len(), 2);

            let response = post_rpc(
                build_router(state.clone()),
                &sid,
                &csrf,
                serde_json::json!({ "action": action, "data": body }),
            )
            .await;

            assert_eq!(response.status(), StatusCode::OK, "{action} 经桥应成功");
            let set_cookie = response
                .headers()
                .get(header::SET_COOKIE)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("")
                .to_string();
            assert!(
                set_cookie.contains("Max-Age=0"),
                "{action} 经桥成功后必须作废浏览器那枚 Cookie：{set_cookie:?}"
            );
            let payload = body_json(response).await;
            assert_eq!(payload["ok"], true);
            assert_eq!(payload["data"]["reauthenticate"], true, "{payload}");
            assert_eq!(payload["data"]["revokedSessions"], 2, "{payload}");

            assert!(
                state.inner.sessions.touch(&sid).is_none(),
                "{action} 经桥成功后旧会话（含发起者）必须失效"
            );
            assert!(state.inner.sessions.touch(&other).is_none());
            assert_eq!(state.inner.sessions.len(), 0);
            assert_eq!(calls.lock().unwrap().as_slice(), [action.to_string()]);

            std::fs::remove_dir_all(&root).ok();
        }
    }

    #[tokio::test]
    async fn the_dedicated_admin_route_still_revokes_sessions() {
        let (root, state) = test_state("rest-revoke");
        mailstack_core::config::admin_set(state.paths(), "admin", "Tr0ubadour9x").unwrap();
        let calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let state = state.with_action_stub(recording_stub(std::sync::Arc::clone(&calls)));
        let (sid, csrf) = state.inner.sessions.create_session("admin");

        let response = build_router(state.clone())
            .oneshot(
                HttpRequest::builder()
                    .method(axum::http::Method::POST)
                    .uri("/api/admin")
                    .header(header::COOKIE, format!("{}={sid}", crate::SESSION_COOKIE))
                    .header("x-csrf-token", csrf)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({"username": "admin", "password": "An0therGood1"})
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response
                .headers()
                .get(header::SET_COOKIE)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("")
                .contains("Max-Age=0"),
            "改密成功后必须作废会话 Cookie"
        );
        let payload = body_json(response).await;
        assert_eq!(payload["ok"], true, "REST 成功响应必须是裸对象");
        assert_eq!(payload["reauthenticate"], true);
        assert_eq!(payload["revokedSessions"], 1);
        assert!(state.inner.sessions.touch(&sid).is_none());
        assert_eq!(calls.lock().unwrap().as_slice(), ["admin.set".to_string()]);

        std::fs::remove_dir_all(&root).ok();
    }

    async fn post_login_from(
        app: axum::Router,
        peer: SocketAddr,
        payload: serde_json::Value,
    ) -> Response {
        let mut request = HttpRequest::builder()
            .method(axum::http::Method::POST)
            .uri("/api/auth/login")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(payload.to_string()))
            .unwrap();

        request.extensions_mut().insert(ConnectInfo(peer));
        app.oneshot(request).await.unwrap()
    }

    #[tokio::test]
    async fn an_attacker_cannot_lock_the_admin_out_from_another_source() {
        let (root, state) = test_state("login-src");
        mailstack_core::config::admin_set(state.paths(), "admin", "Tr0ubadour9x").unwrap();

        let attacker: SocketAddr = "198.51.100.9:4444".parse().unwrap();
        let operator: SocketAddr = "127.0.0.1:5555".parse().unwrap();
        let good = serde_json::json!({ "username": "admin", "password": "Tr0ubadour9x" });
        let bad = serde_json::json!({ "username": "admin", "password": "Wr0ng1Password" });

        for attempt in 0..crate::ratelimit::FAILURE_LOCKOUT_THRESHOLD {
            let response =
                post_login_from(build_router(state.clone()), attacker, bad.clone()).await;
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "第 {attempt} 次失败应为 401"
            );
        }
        assert!(
            state.inner.login_limiter.is_locked_from(
                "198.51.100.9",
                "admin",
                time::OffsetDateTime::now_utc()
            ),
            "攻击者自己的来源必须被锁定"
        );

        let blocked = post_login_from(build_router(state.clone()), attacker, good.clone()).await;
        assert_eq!(
            blocked.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "锁定中的来源必须被拒绝，实际 {}",
            blocked.status()
        );
        assert!(blocked.headers().get("retry-after").is_some());

        let allowed = post_login_from(build_router(state.clone()), operator, good).await;
        assert_eq!(
            allowed.status(),
            StatusCode::OK,
            "管理员从另一个来源必须仍能登录（否则匿名者可用 5 个请求锁死管理台）"
        );
        assert_eq!(state.inner.sessions.len(), 1);

        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn rotating_source_ips_cannot_renew_the_lockout() {
        let (root, state) = test_state("login-rotate");
        mailstack_core::config::admin_set(state.paths(), "admin", "Tr0ubadour9x").unwrap();
        let bad = serde_json::json!({ "username": "admin", "password": "Wr0ng1Password" });

        let first: SocketAddr = "203.0.113.5:1111".parse().unwrap();
        for _ in 0..crate::ratelimit::FAILURE_LOCKOUT_THRESHOLD {
            post_login_from(build_router(state.clone()), first, bad.clone()).await;
        }
        let remaining_before = match state.inner.login_limiter.check_at(
            "203.0.113.5",
            "admin",
            time::OffsetDateTime::now_utc(),
        ) {
            crate::ratelimit::LimitVerdict::Limited { retry_after_secs } => retry_after_secs,
            crate::ratelimit::LimitVerdict::Allow => panic!("首个来源应已锁定"),
        };

        for index in 0..40u32 {
            let ip: SocketAddr = format!("203.0.113.{}:2222", index % 200 + 1)
                .parse()
                .unwrap();
            post_login_from(build_router(state.clone()), ip, bad.clone()).await;
        }

        let remaining_after = match state.inner.login_limiter.check_at(
            "203.0.113.5",
            "admin",
            time::OffsetDateTime::now_utc(),
        ) {
            crate::ratelimit::LimitVerdict::Limited { retry_after_secs } => retry_after_secs,
            crate::ratelimit::LimitVerdict::Allow => panic!("原有锁定被轮换来源清掉了"),
        };
        assert!(
            remaining_after <= remaining_before,
            "轮换来源延长了已有锁定：{remaining_before} → {remaining_after}"
        );

        state.inner.login_limiter.reset();
        let operator: SocketAddr = "127.0.0.1:3333".parse().unwrap();
        let allowed = post_login_from(
            build_router(state.clone()),
            operator,
            serde_json::json!({ "username": "admin", "password": "Tr0ubadour9x" }),
        )
        .await;
        assert_eq!(allowed.status(), StatusCode::OK);

        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn the_rpc_bridge_rejects_a_malformed_body_with_its_own_json_error_shape() {
        let (root, state) = test_state("rpc-badjson");
        let (sid, csrf) = state.inner.sessions.create_session("admin");
        let app = build_router(state);

        let response = app
            .oneshot(
                HttpRequest::builder()
                    .method(axum::http::Method::POST)
                    .uri("/api/rpc")
                    .header(header::COOKIE, format!("{}={sid}", crate::SESSION_COOKIE))
                    .header("x-csrf-token", csrf)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("{\"action\": "))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("")
                .contains("application/json"),
            "畸形请求体不得回 text/plain（前端 bridge() 按 JSON 拆包）"
        );
        let payload = body_json(response).await;
        assert_eq!(payload["ok"], false);
        assert_eq!(payload["error"], "malformed request body");
        assert!(
            !payload.to_string().contains("column"),
            "错误模型不得泄漏 serde 的行列细节：{payload}"
        );

        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn revoking_the_current_session_also_expires_the_cookie() {
        let (root, state) = test_state("revoke-self");
        let (sid, csrf) = state.inner.sessions.create_session("admin");
        let own = crate::session::fingerprint_of(&sid);
        let app = build_router(state.clone());

        let response = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method(axum::http::Method::POST)
                    .uri("/api/auth/sessions/revoke")
                    .header(header::COOKIE, format!("{}={sid}", crate::SESSION_COOKIE))
                    .header("x-csrf-token", csrf)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::json!({ "id": own }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let set_cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert!(
            set_cookie.contains("Max-Age=0"),
            "吊销自己的会话必须作废 Cookie（否则界面仍显示已登录）：{set_cookie:?}"
        );
        let payload = body_json(response).await;
        assert_eq!(payload["reauthenticate"], true, "{payload}");
        assert!(state.inner.sessions.touch(&sid).is_none());

        let (sid2, csrf2) = state.inner.sessions.create_session("admin");
        let third = state.inner.sessions.create("admin");
        let third_fp = crate::session::fingerprint_of(&third);
        let response = build_router(state.clone())
            .oneshot(
                HttpRequest::builder()
                    .method(axum::http::Method::POST)
                    .uri("/api/auth/sessions/revoke")
                    .header(header::COOKIE, format!("{}={sid2}", crate::SESSION_COOKIE))
                    .header("x-csrf-token", csrf2)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({ "id": third_fp }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response.headers().get(header::SET_COOKIE).is_none(),
            "吊销别人的会话不应作废当前 Cookie"
        );
        assert!(state.inner.sessions.touch(&sid2).is_some());

        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn telemetry_sampling_is_gated_instead_of_filling_the_blocking_pool() {
        let (root, state) = test_state("telemetry-gate");
        let state = state.with_telemetry(std::sync::Arc::new(crate::telemetry::inert_collector(
            root.join("proc"),
        )));
        let (sid, _csrf) = state.inner.sessions.create_session("admin");

        let permit = state.inner.telemetry_gate.try_acquire().unwrap();
        let response = build_router(state.clone())
            .oneshot(
                HttpRequest::builder()
                    .uri("/api/metrics/telemetry")
                    .header(header::COOKIE, format!("{}={sid}", crate::SESSION_COOKIE))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "采样已满时必须立刻 429，绝不排进阻塞池等锁"
        );
        assert!(
            response.headers().get("retry-after").is_some(),
            "429 必须带 Retry-After"
        );

        drop(permit);
        let response = build_router(state)
            .oneshot(
                HttpRequest::builder()
                    .uri("/api/metrics/telemetry")
                    .header(header::COOKIE, format!("{}={sid}", crate::SESSION_COOKIE))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        std::fs::remove_dir_all(&root).ok();
    }
}
