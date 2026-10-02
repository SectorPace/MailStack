//! MailStack 管理 API —— 从 `backend/server.production.ts` 等价移植（Axum）。
//!
//! 中间件顺序必须与现状语义一致（规格书 §5.1）：
//!
//! ```text
//! 1. 安全响应头
//! 2. 请求体大小限制（API JSON 256KB）
//! 3. POST /api/auth/login（未认证可达）+ GET /api/health（未认证可达）
//! 4. app.use("/api", auth) ← 自此以下全部需要认证
//! 5. 业务路由
//! 6. /api 兜底 404（JSON）
//! ```
//!
//! 注意 htmx 模式下**不再需要** SPA fallback：未匹配的 `/api/*` 必须回 JSON。

pub mod contract;
pub mod ctl;
pub mod error;
pub mod ratelimit;
pub mod routes;
pub mod session;

/// 时间格式化：直接复用 core 的实现，避免两侧各自定义格式串。
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

/// API JSON 请求体上限：256 KB（INV-12）。
pub const API_BODY_LIMIT_BYTES: usize = 256 * 1024;

/// 应用共享状态。
#[derive(Clone)]
pub struct AppState {
    pub inner: Arc<AppInner>,
}

pub struct AppInner {
    pub paths: Paths,
    pub sessions: SessionStore,
    pub login_limiter: LoginLimiter,
    pub client: PrivilegedClient,
    /// 公网模式（影响注册窗口与 RO fallback）。
    pub public_mode: bool,
    /// 构建标识（INV-22：`/api/health` 的 `node` 字段不可缺）。
    pub runtime_id: String,
}

impl AppState {
    pub fn new(paths: Paths) -> Self {
        let public_mode = mailstack_core::mode::is_public_mode(&paths);
        Self {
            inner: Arc::new(AppInner {
                sessions: SessionStore::new(),
                login_limiter: LoginLimiter::new(),
                client: PrivilegedClient::new(public_mode),
                public_mode,
                runtime_id: format!("mailstackd/{} (rust)", mailstack_core::VERSION),
                paths,
            }),
        }
    }

    /// 覆盖运行标识（测试用）。
    pub fn with_runtime_id(mut self, runtime_id: impl Into<String>) -> Self {
        let inner = Arc::get_mut(&mut self.inner).expect("AppState 尚未克隆");
        inner.runtime_id = runtime_id.into();
        self
    }

    pub fn paths(&self) -> &Paths {
        &self.inner.paths
    }
}

/// 安全响应头。所有响应都带，包括错误响应。
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

/// 从 Cookie 头里取出 `mailstack_session` 的值。
pub fn session_cookie(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        let part = part.trim();
        if let Some(value) = part.strip_prefix(&format!("{SESSION_COOKIE}=")) {
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// 认证 + CSRF 中间件（INV-6、INV-7）。
///
/// * 会话缺失/失效 → **401**（不是 403）
/// * 非 GET/HEAD 请求必须带匹配的 `x-csrf-token`
pub async fn require_auth(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let Some(sid) = session_cookie(request.headers()) else {
        return ApiError::auth_required().into_response();
    };

    let Some(session) = state.inner.sessions.touch(&sid) else {
        return ApiError::auth_required().into_response();
    };

    // CSRF：所有非安全方法都必须带正确的 token。
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

    // 把已认证用户名注入请求扩展，供处理器读取。
    let mut request = request;
    request.extensions_mut().insert(AuthenticatedUser {
        username: session.username.clone(),
        session_id: sid,
        csrf: session.csrf.clone(),
    });

    next.run(request).await
}

/// 已认证用户，注入到请求扩展。
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub username: String,
    pub session_id: String,
    pub csrf: String,
}

/// `GET /api/health` —— 免认证（INV-22：`node` 字段不可缺）。
pub async fn health(State(state): State<AppState>) -> Response {
    let uptime = 0u64; // Phase 1：进程启动时刻尚未接线到遥测模块
    Json(serde_json::json!({
        "status": "ok",
        "version": mailstack_core::VERSION,
        "service": "mailstack",
        // INV-22：字段名保留 `node`（src/api.ts 与契约测试依赖），
        // 值改为运行时标识 —— 生产环境已无 Node。
        "node": state.inner.runtime_id,
        "builtAt": option_env!("MAILSTACK_BUILT_AT").unwrap_or(""),
        "uptimeSec": uptime,
        "time": mailstack_core::now_iso8601_utc(),
    }))
    .into_response()
}

/// `GET /api/auth/session` —— 返回 `{ ok, csrf, username }`。
pub async fn auth_session(axum::Extension(user): axum::Extension<AuthenticatedUser>) -> Response {
    Json(serde_json::json!({
        "ok": true,
        "csrf": user.csrf,
        "username": user.username,
    }))
    .into_response()
}

/// `POST /api/auth/logout`。
pub async fn auth_logout(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
) -> Response {
    state.inner.sessions.remove(&user.session_id);
    Json(serde_json::json!({ "ok": true })).into_response()
}

/// 组装路由。
///
/// 认证层挂在**业务路由**上，而 `/api/health` 与 `/api/auth/login` 显式挂在认证层之前。
pub fn build_router(state: AppState) -> Router {
    // ── 免认证路由（必须在认证层之前） ──
    let public = Router::new()
        .route("/api/health", get(health))
        .route("/api/auth/login", post(crate::routes::login));

    // ── 需要认证的路由 ──
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
        // 资源路由：动作在**编译期**静态绑定（见 routes::action_handlers!）。
        .route(
            "/api/domains",
            get(crate::routes::domains_list).post(crate::routes::domains_add),
        )
        .route("/api/domains/:id", delete(crate::routes::domains_delete))
        .route("/api/aliases", post(crate::routes::aliases_add))
        .route("/api/aliases/:id", delete(crate::routes::aliases_delete))
        .route("/api/dkim/rotate", post(crate::routes::dkim_rotate))
        .route("/api/snapshot", get(crate::routes::snapshot_get))
        .route("/api/status", get(crate::routes::snapshot_get))
        .route("/api/logs", get(crate::routes::logs_list))
        .route(
            "/api/metrics/realtime",
            get(crate::routes::metrics_realtime),
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
        // 2FA：读状态由 Web 进程直接应答；三个写动作经助手（secret 不出助手）。
        .route("/api/admin/2fa", get(crate::routes::admin_2fa))
        .route("/api/admin/2fa/begin", post(crate::routes::totp_begin))
        .route("/api/admin/2fa/enable", post(crate::routes::totp_enable))
        .route("/api/admin/2fa/disable", post(crate::routes::totp_disable))
        .route("/api/doctor", get(crate::routes::system_doctor))
        .route("/api/system/doctor", get(crate::routes::system_doctor))
        .route("/api/setup/status", get(crate::routes::setup_status))
        .route("/api/ai/config", get(crate::routes::ai_config_get))
        .route("/api/queue/action", post(crate::routes::queue_action))
        .route("/api/services/action", post(crate::routes::services_action))
        .route("/api/security/scan", post(crate::routes::security_scan))
        .route("/api/backups", get(crate::routes::backup_list))
        .route("/api/certificates", get(crate::routes::certs_list))
        .layer(middleware::from_fn_with_state(state.clone(), require_auth));

    Router::new()
        .merge(public)
        .merge(protected)
        .fallback(crate::routes::api_fallback)
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request as HttpRequest;
    use axum::http::{Method, StatusCode};
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
        // INV-22：字段名 `node` 不可缺；值改为运行时标识。
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
        // INV-7：未认证回 401，不回 403。
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
        // INV-6。
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
        // §5.1：/api 兜底必须是 JSON。
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
        // 错误响应同样必须带安全头——否则 401 页面会成为攻击面。
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
    async fn two_factor_state_is_served_in_process_and_the_write_routes_are_wired() {
        let (root, state) = test_state("totproutes");
        let sid = state.inner.sessions.create("admin");
        let app = build_router(state);

        // 读状态：Web 进程自身应答，不经过助手。
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

        // 写路由是否已接线：**故意不带 CSRF**。已注册的路由会被 CSRF 层以 403 拦下，
        // 未注册的则落到 /api 兜底（404）。这样既能区分「接线/未接线」，又不会真的
        // 把请求送到特权助手 —— 本机可能装着真实的 helper，那会造成真实副作用。
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

    #[test]
    fn session_cookie_parsing_handles_multiple_cookies() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("theme=dark; mailstack_session=abc123; lang=zh"),
        );
        assert_eq!(session_cookie(&headers).as_deref(), Some("abc123"));
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
            HeaderValue::from_static("mailstack_session=; other=1"),
        );
        assert!(session_cookie(&headers).is_none());
    }
}
