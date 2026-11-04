pub mod contract;
pub mod ctl;
pub mod error;
pub mod ratelimit;
pub mod routes;
pub mod session;
pub mod telemetry;

pub mod time_fmt {
    pub use mailstack_core::time_fmt::{format_iso8601, now_iso8601_utc};
}

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderValue};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};

use mailstack_core::paths::Paths;

pub use contract::{RouteSpec, ROUTES};
pub use ctl::PrivilegedClient;
pub use error::ApiError;
pub use ratelimit::LoginLimiter;
pub use session::{SessionStore, SESSION_COOKIE};

pub const API_BODY_LIMIT_BYTES: usize = 256 * 1024;

pub const TELEMETRY_MAX_CONCURRENT_SAMPLES: usize = 1;

#[derive(Clone)]
pub struct AppState {
    pub inner: Arc<AppInner>,
}

pub struct AppInner {
    pub paths: Paths,
    pub sessions: SessionStore,
    pub login_limiter: LoginLimiter,
    pub client: PrivilegedClient,

    #[cfg(test)]
    test_action_stub: Option<ActionStub>,

    pub public_mode: bool,

    pub runtime_id: String,

    pub telemetry: Arc<telemetry::TelemetryCollector>,

    pub telemetry_gate: Arc<tokio::sync::Semaphore>,
}

#[cfg(test)]
#[doc(hidden)]
pub type ActionStub =
    Arc<dyn Fn(&str, &serde_json::Value) -> Result<serde_json::Value, ApiError> + Send + Sync>;

impl AppState {
    pub fn new(paths: Paths) -> Self {
        let public_mode = mailstack_core::mode::is_public_mode(&paths);
        Self {
            inner: Arc::new(AppInner {
                sessions: SessionStore::new(),
                login_limiter: LoginLimiter::new(),
                client: PrivilegedClient::new(public_mode),
                #[cfg(test)]
                test_action_stub: None,
                public_mode,
                runtime_id: format!("mailstackd/{} (rust)", mailstack_core::VERSION),
                telemetry: Arc::new(telemetry::TelemetryCollector::system()),
                telemetry_gate: Arc::new(tokio::sync::Semaphore::new(
                    TELEMETRY_MAX_CONCURRENT_SAMPLES,
                )),
                paths,
            }),
        }
    }

    pub fn with_telemetry(mut self, collector: Arc<telemetry::TelemetryCollector>) -> Self {
        let inner = Arc::get_mut(&mut self.inner).expect("AppState 尚未克隆");
        inner.telemetry = collector;
        self
    }

    pub fn with_runtime_id(mut self, runtime_id: impl Into<String>) -> Self {
        let inner = Arc::get_mut(&mut self.inner).expect("AppState 尚未克隆");
        inner.runtime_id = runtime_id.into();
        self
    }

    #[cfg(test)]
    pub fn with_action_stub(mut self, stub: ActionStub) -> Self {
        let inner = Arc::get_mut(&mut self.inner).expect("AppState 尚未克隆");
        inner.test_action_stub = Some(stub);
        self
    }

    pub(crate) async fn call_action(
        &self,
        action: &str,
        data: &serde_json::Value,
    ) -> Result<serde_json::Value, ApiError> {
        #[cfg(test)]
        if let Some(stub) = &self.inner.test_action_stub {
            return stub(action, data);
        }
        self.inner.client.call(action, data).await
    }

    pub fn paths(&self) -> &Paths {
        &self.inner.paths
    }
}

pub async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
             img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'",
        ),
    );
    headers.insert(
        header::HeaderName::from_static("cross-origin-opener-policy"),
        HeaderValue::from_static("same-origin"),
    );

    response
}

async fn no_store_api(request: Request, next: Next) -> Response {
    let is_api = request.uri().path().starts_with("/api/");
    let mut response = next.run(request).await;
    if is_api {
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    response
}

pub fn session_cookie(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;

    for name in crate::session::SESSION_COOKIE_NAMES {
        for part in raw.split(';') {
            let part = part.trim();
            if let Some(value) = part.strip_prefix(&format!("{name}=")) {
                if !value.is_empty() {
                    return Some(value.to_string());
                }
            }
        }
    }
    None
}

pub async fn require_auth(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let Some(sid) = session_cookie(request.headers()) else {
        return ApiError::auth_required().into_response();
    };

    let Some(session) = state.inner.sessions.touch(&sid) else {
        return ApiError::auth_required().into_response();
    };

    if session::method_requires_csrf(request.method().as_str()) {
        let provided = request
            .headers()
            .get("x-csrf-token")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !session::csrf_matches(&session.csrf, provided) {
            return ApiError::csrf_invalid().into_response();
        }
    }

    let mut request = request;
    request.extensions_mut().insert(AuthenticatedUser {
        username: session.username.clone(),
        session_id: sid,
        csrf: session.csrf.clone(),
    });

    next.run(request).await
}

#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub username: String,
    pub session_id: String,
    pub csrf: String,
}

static PROCESS_START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();

pub async fn health(State(state): State<AppState>) -> Response {
    let uptime = PROCESS_START
        .get_or_init(std::time::Instant::now)
        .elapsed()
        .as_secs();
    Json(serde_json::json!({

        "ok": true,
        "status": "ok",
        "version": mailstack_core::VERSION,
        "service": "mailstack",

        "node": state.inner.runtime_id,
        "builtAt": option_env!("MAILSTACK_BUILT_AT").unwrap_or(""),
        "uptimeSec": uptime,
        "time": mailstack_core::now_iso8601_utc(),
    }))
    .into_response()
}

pub async fn auth_session(axum::Extension(user): axum::Extension<AuthenticatedUser>) -> Response {
    Json(serde_json::json!({
        "ok": true,
        "csrf": user.csrf,
        "username": user.username,
    }))
    .into_response()
}

pub async fn auth_logout(
    State(state): State<AppState>,
    peer: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    headers: HeaderMap,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
) -> Response {
    state.inner.sessions.remove(&user.session_id);
    let mut response = Json(serde_json::json!({ "ok": true })).into_response();

    let peer_addr = peer.map(|axum::extract::ConnectInfo(addr)| addr);
    match crate::routes::clear_session_cookie(
        &mut response,
        &state,
        peer_addr.as_ref(),
        crate::session::forwarded_proto(&headers).as_deref(),
    ) {
        Ok(()) => response,
        Err(message) => ApiError::internal(message).into_response(),
    }
}

pub fn build_api_router(state: AppState) -> Router {
    let public = Router::new()
        .route("/api/health", get(health))
        .route("/api/auth/login", post(crate::routes::login));

    let protected = Router::new()
        .route("/api/auth/logout", post(auth_logout))
        .route("/api/auth/session", get(auth_session))
        .route("/api/auth/sessions", get(crate::routes::list_sessions))
        .route(
            "/api/auth/sessions/revoke",
            post(crate::routes::revoke_session),
        )
        .route(
            "/api/auth/sessions",
            delete(crate::routes::revoke_other_sessions),
        )
        .route("/api/rpc", post(crate::routes::rpc_bridge))
        .route(
            "/api/domains",
            get(crate::routes::domains_list).post(crate::routes::domains_add),
        )
        .route("/api/domains/:id", delete(crate::routes::domains_delete))
        .route(
            "/api/users",
            get(crate::routes::users_list).post(crate::routes::users_add),
        )
        .route("/api/users/status", post(crate::routes::users_status))
        .route("/api/users/password", post(crate::routes::users_password))
        .route("/api/users/:id", delete(crate::routes::users_delete))
        .route(
            "/api/aliases",
            get(crate::routes::aliases_list).post(crate::routes::aliases_add),
        )
        .route("/api/aliases/:id", delete(crate::routes::aliases_delete))
        .route("/api/dkim/rotate", post(crate::routes::dkim_rotate))
        .route("/api/dkim/keys", get(crate::routes::dkim_keys))
        .route("/api/dns/records", get(crate::routes::dns_records))
        .route("/api/activity", get(crate::routes::activity_list))
        .route("/api/snapshot", get(crate::routes::snapshot_get))
        .route("/api/status", get(crate::routes::snapshot_get))
        .route("/api/logs", get(crate::routes::logs_list))
        .route(
            "/api/metrics/realtime",
            get(crate::routes::metrics_realtime),
        )
        .route("/api/metrics/system", get(crate::routes::metrics_system))
        .route(
            "/api/metrics/telemetry",
            get(crate::routes::metrics_telemetry),
        )
        .route("/api/network/check-port", post(crate::routes::check_port))
        .route(
            "/api/settings",
            get(crate::routes::settings_get).post(crate::routes::settings_set),
        )
        .route(
            "/api/admin",
            get(crate::routes::admin_get).post(crate::routes::admin_set),
        )
        .route("/api/admin/2fa", get(crate::routes::admin_2fa))
        .route("/api/admin/2fa/begin", post(crate::routes::totp_begin))
        .route("/api/admin/2fa/enable", post(crate::routes::totp_enable))
        .route("/api/admin/2fa/disable", post(crate::routes::totp_disable))
        .route("/api/doctor", get(crate::routes::system_doctor))
        .route("/api/system/doctor", get(crate::routes::system_doctor))
        .route("/api/setup/status", get(crate::routes::setup_status))
        .route(
            "/api/setup/wizard/complete",
            post(crate::routes::setup_wizard_complete),
        )
        .route("/api/queue/action", post(crate::routes::queue_action))
        .route("/api/queue", get(crate::routes::queue_list))
        .route("/api/services/action", post(crate::routes::services_action))
        .route("/api/services", get(crate::routes::services_list))
        .route("/api/security/scan", post(crate::routes::security_scan))
        .route("/api/security/ban", post(crate::routes::security_ban))
        .route("/api/security/unban", post(crate::routes::security_unban))
        .route(
            "/api/backups",
            get(crate::routes::backup_list).post(crate::routes::backup_create),
        )
        .route("/api/backups/restore", post(crate::routes::backup_restore))
        .route("/api/backups/:name", delete(crate::routes::backup_delete))
        .route("/api/certificates", get(crate::routes::certs_list))
        .route("/api/certificates/renew", post(crate::routes::certs_renew))
        .route("/api/setup/identity", post(crate::routes::setup_identity))
        .route(
            "/api/setup/dns/verify",
            post(crate::routes::setup_dns_verify),
        )
        .route(
            "/api/setup/relay/test",
            post(crate::routes::setup_relay_test),
        )
        .route(
            "/api/setup/relay/apply",
            post(crate::routes::setup_relay_apply),
        )
        .route(
            "/api/setup/cert/issue",
            post(crate::routes::setup_cert_issue),
        )
        .route("/api/setup/mail/test", post(crate::routes::setup_mail_test))
        .route(
            "/api/mail/test-loopback",
            post(crate::routes::mail_test_loopback),
        )
        .layer(middleware::from_fn_with_state(state.clone(), require_auth));

    Router::new()
        .merge(public)
        .merge(protected)
        .with_state(state)
        .layer(axum::extract::DefaultBodyLimit::max(API_BODY_LIMIT_BYTES))
        .layer(middleware::from_fn(reject_oversized_bodies))
        .layer(middleware::from_fn(no_store_api))
}

async fn reject_oversized_bodies(request: Request, next: Next) -> Response {
    if let Some(length) = request
        .headers()
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
    {
        if length > API_BODY_LIMIT_BYTES as u64 {
            return ApiError::payload_too_large().into_response();
        }
    }
    next.run(request).await
}

pub fn build_router(state: AppState) -> Router {
    build_api_router(state)
        .fallback(crate::routes::api_fallback)
        .layer(middleware::from_fn(no_store_api))
        .layer(middleware::from_fn(security_headers))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request as HttpRequest;
    use axum::http::{header, Method, StatusCode};
    use tower::ServiceExt;

    fn test_state(tag: &str) -> (std::path::PathBuf, AppState) {
        let mut root = std::env::temp_dir();
        root.push(format!(
            "mailstack-web-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let paths = Paths::rooted(&root);
        (root, AppState::new(paths))
    }

    async fn body_json(response: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn an_oversized_request_body_is_rejected_before_it_is_buffered() {
        let (root, state) = test_state("bodylimit");
        let app = build_router(state);

        let oversized = "x".repeat(API_BODY_LIMIT_BYTES + 4096);
        let response = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method(Method::POST)
                    .uri("/api/auth/login")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({ "pad": oversized }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::PAYLOAD_TOO_LARGE,
            "超出 {} 字节的请求体必须回 413，实际 {}",
            API_BODY_LIMIT_BYTES,
            response.status()
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn an_oversized_body_is_rejected_even_for_an_authenticated_request() {
        let (root, state) = test_state("bodylimitauth");
        let (sid, csrf) = state.inner.sessions.create_session("admin");
        let app = build_router(state);

        let oversized = "x".repeat(API_BODY_LIMIT_BYTES + 4096);
        let payload = serde_json::json!({ "pad": oversized }).to_string();
        let response = app
            .oneshot(
                HttpRequest::builder()
                    .method(Method::POST)
                    .uri("/api/domains")
                    .header(header::COOKIE, format!("{}={sid}", SESSION_COOKIE))
                    .header("x-csrf-token", csrf)
                    .header("content-type", "application/json")
                    .header(header::CONTENT_LENGTH, payload.len().to_string())
                    .body(Body::from(payload))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::PAYLOAD_TOO_LARGE,
            "已认证的超大请求体同样必须回 413，实际 {}",
            response.status()
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn a_chunked_oversized_body_is_still_refused() {
        let (root, state) = test_state("bodylimitchunked");
        let (sid, csrf) = state.inner.sessions.create_session("admin");
        let app = build_router(state);

        let oversized = "x".repeat(API_BODY_LIMIT_BYTES + 4096);
        let payload = serde_json::json!({ "pad": oversized }).to_string();
        let response = app
            .oneshot(
                HttpRequest::builder()
                    .method(Method::POST)
                    .uri("/api/domains")
                    .header(header::COOKIE, format!("{}={sid}", SESSION_COOKIE))
                    .header("x-csrf-token", csrf)
                    .header("content-type", "application/json")
                    .body(Body::from(payload))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_ne!(
            response.status(),
            StatusCode::OK,
            "分块超大请求体必须被拒绝（内存由 DefaultBodyLimit 兜住）"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn a_body_just_under_the_limit_is_still_accepted_by_the_transport() {
        let (root, state) = test_state("bodylimitok");
        let app = build_router(state);
        let response = app
            .oneshot(
                HttpRequest::builder()
                    .method(Method::POST)
                    .uri("/api/auth/login")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "username": "admin",
                            "pad": "x".repeat(1024),
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(
            response.status(),
            StatusCode::PAYLOAD_TOO_LARGE,
            "限额之内的正常请求体不应被拒绝，实际 {}",
            response.status()
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn health_reports_a_monotonically_growing_uptime_instead_of_a_constant_zero() {
        let (root, state) = test_state("uptime");
        let app = build_router(state);

        let first = {
            let response = app
                .clone()
                .oneshot(
                    HttpRequest::builder()
                        .uri("/api/health")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let value = body_json(response).await;
            assert!(
                value["uptimeSec"].is_u64(),
                "uptimeSec 必须是数字，实际：{}",
                value["uptimeSec"]
            );
            value["uptimeSec"].as_u64().unwrap()
        };

        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

        let second = {
            let response = app
                .oneshot(
                    HttpRequest::builder()
                        .uri("/api/health")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            body_json(response).await["uptimeSec"].as_u64().unwrap()
        };

        assert!(
            second > first,
            "uptimeSec 没有随时间增长（{first} → {second}）—— 它被写死成常量了"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn health_is_reachable_without_authentication() {
        let (root, state) = test_state("health");
        let app = build_router(state);
        let response = app
            .oneshot(
                HttpRequest::builder()
                    .uri("/api/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["status"], "ok");
        assert_eq!(body["version"], mailstack_core::VERSION);
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn health_includes_the_node_field_required_by_the_contract() {
        let (root, state) = test_state("healthnode");
        let app = build_router(state);
        let response = app
            .oneshot(
                HttpRequest::builder()
                    .uri("/api/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = body_json(response).await;
        assert!(body.get("node").is_some(), "`node` 字段不可缺");
        assert!(
            body["node"].as_str().unwrap().contains("rust"),
            "值应为 Rust 运行时标识"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn protected_routes_return_401_without_a_session() {
        let (root, state) = test_state("noauth");
        let app = build_router(state);
        for uri in [
            "/api/snapshot",
            "/api/domains",
            "/api/logs",
            "/api/auth/session",
        ] {
            let response = app
                .clone()
                .oneshot(HttpRequest::builder().uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "{uri} 应返回 401"
            );
        }
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn mutating_requests_without_csrf_are_rejected() {
        let (root, state) = test_state("csrf");
        let sid = state.inner.sessions.create("admin");
        let app = build_router(state);

        let response = app
            .oneshot(
                HttpRequest::builder()
                    .method(Method::POST)
                    .uri("/api/queue/action")
                    .header(header::COOKIE, format!("{SESSION_COOKIE}={sid}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "缺少 CSRF token 的写请求必须被拒绝"
        );
        let body = body_json(response).await;
        assert_eq!(body["error"]["code"], "CSRF_INVALID");
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn read_requests_do_not_need_csrf() {
        let (root, state) = test_state("nocsrfget");
        let sid = state.inner.sessions.create("admin");
        let app = build_router(state);

        let response = app
            .oneshot(
                HttpRequest::builder()
                    .uri("/api/auth/session")
                    .header(header::COOKIE, format!("{SESSION_COOKIE}={sid}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["ok"], true);
        assert_eq!(body["username"], "admin");
        assert!(body.get("csrf").is_some(), "会话响应必须含 csrf");
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn unknown_api_paths_return_json_not_html() {
        let (root, state) = test_state("fallback");
        let app = build_router(state);
        let response = app
            .oneshot(
                HttpRequest::builder()
                    .uri("/api/does-not-exist")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = body_json(response).await;
        assert_eq!(body["error"]["code"], "API_NOT_FOUND");
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn security_headers_are_present_on_every_response() {
        let (root, state) = test_state("headers");
        let app = build_router(state);
        let response = app
            .oneshot(
                HttpRequest::builder()
                    .uri("/api/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let headers = response.headers();
        assert_eq!(headers["x-content-type-options"], "nosniff");
        assert_eq!(headers["x-frame-options"], "DENY");
        assert_eq!(headers["referrer-policy"], "no-referrer");
        assert!(headers.contains_key("content-security-policy"));
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn security_headers_are_present_on_error_responses_too() {
        let (root, state) = test_state("headersonerr");
        let app = build_router(state);
        let response = app
            .oneshot(
                HttpRequest::builder()
                    .uri("/api/snapshot")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers()["x-frame-options"], "DENY");
        assert_eq!(response.headers()["x-content-type-options"], "nosniff");
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn session_responses_carry_cache_control_no_store() {
        let (root, state) = test_state("nostore");
        let (sid, _csrf) = state.inner.sessions.create_session("admin");
        let app = build_router(state);

        let session = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .uri("/api/auth/session")
                    .header(header::COOKIE, format!("{SESSION_COOKIE}={sid}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(session.status(), StatusCode::OK);
        assert_eq!(
            session.headers()["cache-control"],
            "no-store",
            "会话响应（含 CSRF token）绝不可缓存"
        );

        let fallback = app
            .oneshot(
                HttpRequest::builder()
                    .uri("/api/does-not-exist")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(fallback.status(), StatusCode::NOT_FOUND);
        assert_eq!(fallback.headers()["cache-control"], "no-store");
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn two_factor_state_is_served_in_process_and_the_write_routes_are_wired() {
        let (root, state) = test_state("totproutes");
        let sid = state.inner.sessions.create("admin");
        let app = build_router(state);

        let response = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .uri("/api/admin/2fa")
                    .header(header::COOKIE, format!("{SESSION_COOKIE}={sid}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["state"], "disabled");
        assert_eq!(body["enabled"], false);
        assert_eq!(body["recoveryCodesRemaining"], 0);
        assert_eq!(body["digits"], 6);
        assert_eq!(body["period"], 30);

        for uri in [
            "/api/admin",
            "/api/admin/2fa/begin",
            "/api/admin/2fa/enable",
            "/api/admin/2fa/disable",
        ] {
            let response = app
                .clone()
                .oneshot(
                    HttpRequest::builder()
                        .method(Method::POST)
                        .uri(uri)
                        .header(header::COOKIE, format!("{SESSION_COOKIE}={sid}"))
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from("{}"))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::FORBIDDEN,
                "{uri} 应已接线并被 CSRF 层拦下（404 表示未接线）"
            );
            let body = body_json(response).await;
            assert_eq!(body["error"]["code"], "CSRF_INVALID");
        }
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn every_implemented_action_route_is_wired_and_behind_auth() {
        let (root, state) = test_state("wiring");
        let paths = Paths::rooted(&root);
        let registry = mailstack_priv::handlers::Registry::with_core_actions(paths.clone())
            .with_readers(std::sync::Arc::new(mailstack_priv::Readers::system(paths)));

        let app = build_router(state);

        for spec in ROUTES {
            let Some(action) = spec.action else { continue };
            if !registry.is_implemented(action) {
                continue;
            }

            let uri = spec
                .path
                .split('/')
                .map(|seg| if seg.starts_with(':') { "sample" } else { seg })
                .collect::<Vec<_>>()
                .join("/");

            let response = app
                .clone()
                .oneshot(
                    HttpRequest::builder()
                        .method(spec.method)
                        .uri(&uri)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "{} {}（动作 {action}）必须已接线且受认证保护；得到 {} 说明路由缺失或落在了免认证面",
                spec.method,
                spec.path,
                response.status()
            );
        }
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn every_route_reaches_exactly_the_action_the_contract_declares() {
        for spec in ROUTES {
            let (root, state) = test_state("actionbinding");
            let state = state.with_telemetry(std::sync::Arc::new(
                crate::telemetry::inert_collector(root.join("proc")),
            ));
            let calls: std::sync::Arc<std::sync::Mutex<Vec<String>>> =
                std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let state = state.with_action_stub({
                let calls = std::sync::Arc::clone(&calls);
                std::sync::Arc::new(move |action: &str, _data: &serde_json::Value| {
                    calls.lock().unwrap().push(action.to_string());
                    Ok(serde_json::json!({ "ok": true }))
                })
            });
            let (sid, csrf) = state.inner.sessions.create_session("admin");
            let app = build_router(state);

            let uri = spec
                .path
                .split('/')
                .map(|seg| if seg.starts_with(':') { "sample" } else { seg })
                .collect::<Vec<_>>()
                .join("/");
            let response = app
                .oneshot(
                    HttpRequest::builder()
                        .method(spec.method)
                        .uri(&uri)
                        .header(header::COOKIE, format!("{}={sid}", SESSION_COOKIE))
                        .header("x-csrf-token", &csrf)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from("{}"))
                        .unwrap(),
                )
                .await
                .unwrap();

            if spec.auth == crate::contract::Auth::Required {
                assert_ne!(
                    response.status(),
                    StatusCode::UNAUTHORIZED,
                    "{} {} 在带会话时仍回 401（认证层先于业务执行）",
                    spec.method,
                    spec.path
                );
            }

            let recorded = calls.lock().unwrap().clone();
            let expected: Vec<String> = spec
                .action
                .map(|action| vec![action.to_string()])
                .unwrap_or_default();
            assert_eq!(
                recorded, expected,
                "{} {} 实际调用了 {recorded:?}，契约声明的是 {:?} —— 动作绑定漂移",
                spec.method, spec.path, spec.action
            );
            std::fs::remove_dir_all(&root).ok();
        }
    }

    #[test]
    fn the_action_handler_table_covers_the_contract_exactly() {
        use std::collections::HashSet;

        let route_actions: HashSet<&str> = ROUTES.iter().filter_map(|spec| spec.action).collect();
        let handler_actions: HashSet<&str> = crate::routes::ACTION_HANDLER_BINDINGS
            .iter()
            .map(|(_, action)| *action)
            .collect();
        assert_eq!(
            route_actions, handler_actions,
            "契约表的动作集合与处理器绑定表的动作集合不一致"
        );

        let names: HashSet<&str> = crate::routes::ACTION_HANDLER_BINDINGS
            .iter()
            .map(|(name, _)| *name)
            .collect();
        assert_eq!(
            names.len(),
            crate::routes::ACTION_HANDLER_BINDINGS.len(),
            "处理器绑定表里有重复的处理器名"
        );
    }

    #[tokio::test]
    async fn telemetry_is_served_in_process_and_returns_the_raw_object() {
        let (root, state) = test_state("telemetry");

        let state = state.with_telemetry(std::sync::Arc::new(crate::telemetry::inert_collector(
            root.join("proc"),
        )));
        let sid = state.inner.sessions.create("admin");
        let app = build_router(state);

        let unauth = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .uri("/api/metrics/telemetry")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);

        let response = app
            .oneshot(
                HttpRequest::builder()
                    .uri("/api/metrics/telemetry?range=5m")
                    .header(header::COOKIE, format!("{SESSION_COOKIE}={sid}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["timeframe"], "5m");
        assert_eq!(body["intervalMs"], 5_000);
        assert!(body.get("points").is_some(), "必须是遥测对象本身");
        assert!(body.get("ok").is_none(), "不得套 {{ok,data}} 外壳");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn a_plain_cookie_cannot_shadow_the_host_prefixed_one() {
        let name = crate::session::SESSION_COOKIE_SECURE_NAME;
        let plain = crate::session::SESSION_COOKIE_PLAIN_NAME;
        for cookie in [
            format!("{plain}=attacker; {name}=victim"),
            format!("{name}=victim; {plain}=attacker"),
            format!("theme=dark; {plain}=attacker; {name}=victim; lang=zh"),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(header::COOKIE, HeaderValue::from_str(&cookie).unwrap());
            assert_eq!(
                session_cookie(&headers).as_deref(),
                Some("victim"),
                "无前缀 Cookie 顶掉了 __Host- 会话：{cookie}"
            );
        }

        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!("{plain}=only-plain")).unwrap(),
        );
        assert_eq!(session_cookie(&headers).as_deref(), Some("only-plain"));

        assert_eq!(
            crate::session::session_cookie_context(None, false, None, &HeaderMap::new()),
            (plain, false),
            "默认部署应下发无前缀名"
        );
        let peer: std::net::SocketAddr = "127.0.0.1:8443".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        assert_eq!(
            crate::session::session_cookie_context(None, false, Some(&peer), &headers),
            (name, true),
            "HTTPS 部署应下发 __Host- 名"
        );
    }

    #[test]
    fn session_cookie_parsing_handles_multiple_cookies() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("theme=dark; __Host-mailstack_session=abc123; lang=zh"),
        );
        assert_eq!(session_cookie(&headers).as_deref(), Some("abc123"));
    }

    #[test]
    fn session_cookie_parsing_accepts_both_conditional_names() {
        for name in crate::session::SESSION_COOKIE_NAMES {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::COOKIE,
                HeaderValue::from_str(&format!("{name}=abc123")).unwrap(),
            );
            assert_eq!(
                session_cookie(&headers).as_deref(),
                Some("abc123"),
                "{name} 必须被解析"
            );
        }
    }

    #[test]
    fn session_cookie_parsing_returns_none_when_absent() {
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, HeaderValue::from_static("theme=dark"));
        assert!(session_cookie(&headers).is_none());
        assert!(session_cookie(&HeaderMap::new()).is_none());
    }

    #[test]
    fn session_cookie_ignores_empty_value() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("__Host-mailstack_session=; other=1"),
        );
        assert!(session_cookie(&headers).is_none());
    }
}
