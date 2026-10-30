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
pub mod telemetry;

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
pub use ratelimit::{AiRateLimiter, LoginLimiter};
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
    /// AI 路由独立限流（20 次/分/IP）。
    pub ai_limiter: AiRateLimiter,
    pub client: PrivilegedClient,
    /// 公网模式（影响注册窗口与 RO fallback）。
    pub public_mode: bool,
    /// 构建标识（INV-22：`/api/health` 的 `node` 字段不可缺）。
    pub runtime_id: String,
    /// 时序遥测采集器。契约里 `/api/metrics/telemetry` 的 `action` 是 `None`，
    /// 采样只能在本进程内做（动作白名单已冻结，不能为它新增动作）。
    pub telemetry: Arc<telemetry::TelemetryCollector>,
}

impl AppState {
    pub fn new(paths: Paths) -> Self {
        let public_mode = mailstack_core::mode::is_public_mode(&paths);
        Self {
            inner: Arc::new(AppInner {
                sessions: SessionStore::new(),
                login_limiter: LoginLimiter::new(),
                ai_limiter: AiRateLimiter::new(),
                client: PrivilegedClient::new(public_mode),
                public_mode,
                runtime_id: format!("mailstackd/{} (rust)", mailstack_core::VERSION),
                telemetry: Arc::new(telemetry::TelemetryCollector::system()),
                paths,
            }),
        }
    }

    /// 覆盖遥测采集器（测试用；生产用 [`telemetry::TelemetryCollector::system`]）。
    pub fn with_telemetry(mut self, collector: Arc<telemetry::TelemetryCollector>) -> Self {
        let inner = Arc::get_mut(&mut self.inner).expect("AppState 尚未克隆");
        inner.telemetry = collector;
        self
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

/// 本进程启动时刻（首次调用 `health` 时钉住）。
///
/// 用 [`std::time::Instant`] 而不是墙钟：它不受 NTP 校时与手动改时间影响，
/// 「进程跑了多久」本来就该是单调量。
static PROCESS_START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();

/// `GET /api/health` —— 免认证（INV-22：`node` 字段不可缺）。
pub async fn health(State(state): State<AppState>) -> Response {
    // 5.8：原先这里是 `let uptime = 0u64;`（注释「Phase 1：尚未接线」）——
    // 那不是「拿不到」，那是**谎报**：前端与运维都把 0 当成一个真实读数。
    // 进程启动时刻由 `Instant` 给出，不存在「拿不到」的情形，因此这里给不出 null，
    // 也就不会重新落回「用 0 假装有值」。
    let uptime = PROCESS_START
        .get_or_init(std::time::Instant::now)
        .elapsed()
        .as_secs();
    Json(serde_json::json!({
        // 管理前端的 `probe()` 用 `body.ok === true` 判定能否进入 live 模式，
        // 判 false 会**静默**降级到内置 mock —— 界面看起来完全正常，但全是演示数据。
        // 所以这个成功标志必须给，它不是可选的装饰字段。
        "ok": true,
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

/// AI 路由的独立限流（5.6）。
///
/// ## 为什么排在认证**之后**
///
/// 层是「后加的先执行」，所以本层加在 [`require_auth`] **之前**（即它被包裹在
/// 认证里面）。若反过来先查 AI 桶，一个未认证的洪水就能把同一出口 NAT 后
/// 所有正常管理员的 AI 额度全部消耗掉 —— 那等于把限流本身变成拒绝服务。
///
/// 非 `/api/ai/` 路径直接放行：本层挂在整个受保护路由树上，靠
/// [`contract::is_ai_path`] 判定适用性（这正是它此前「无调用点」的那一半）。
async fn ai_rate_limit(
    State(state): State<AppState>,
    // `Option<..>` 而非裸 `ConnectInfo`：宿主**可能**不注入连接信息
    // （纯 API 单元测试的 `oneshot`、未来的 in-process 调用）。写成裸提取器时
    // 提取失败会让整条中间件回 500，把「限流」变成「全站不可用」。
    peer: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    request: Request,
    next: Next,
) -> Response {
    if !contract::is_ai_path(request.uri().path()) {
        return next.run(request).await;
    }
    let peer_addr = peer.map(|axum::extract::ConnectInfo(addr)| addr);
    match state
        .inner
        .ai_limiter
        .check(&crate::routes::client_key(peer_addr.as_ref()))
    {
        crate::ratelimit::LimitVerdict::Allow => next.run(request).await,
        crate::ratelimit::LimitVerdict::Limited { retry_after_secs } => {
            ApiError::rate_limited(retry_after_secs).into_response()
        }
    }
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

/// 组装**只含 `/api` 面**的路由：不含兜底、不含安全响应头。
///
/// 认证层挂在**业务路由**上，而 `/api/health` 与 `/api/auth/login` 显式挂在认证层之前。
///
/// 拆出这一层是为了让宿主决定「未匹配的路径怎么办」。纯 API 宿主用 [`build_router`]
/// （`/api/*` 兜底回 JSON 404）；同时托管前端产物的宿主则必须让**非** `/api` 的
/// 路径落到 SPA，否则用户在界面上刷新一下就会看到 JSON 的「no such API endpoint」。
///
/// 安全响应头由调用方在**最后**统一加一次 —— 放在这里会让后加的兜底路由拿不到它。
pub fn build_api_router(state: AppState) -> Router {
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
        // RPC 桥（管理前端的兜底传输层）。**动作名来自请求体**，因此它自带一道
        // 「只放行已有路由的动作」的校验，见 `contract::is_exposed_action`。
        .route("/api/rpc", post(crate::routes::rpc_bridge))
        // 资源路由：动作在**编译期**静态绑定（见 routes::action_handlers!）。
        .route(
            "/api/domains",
            get(crate::routes::domains_list).post(crate::routes::domains_add),
        )
        .route("/api/domains/:id", delete(crate::routes::domains_delete))
        // 邮箱用户（`users.*`）。`DELETE /api/users/:id` 是破坏性动作，
        // `confirm: true` 由助手侧的 `ActionGate` 强制 —— web 层不得放行任何东西。
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
        // DKIM 密钥清单（只读 stat，不导出私钥）。
        .route("/api/dkim/keys", get(crate::routes::dkim_keys))
        // DNS 记录清单（出站解析 A/MX/TXT）。
        .route("/api/dns/records", get(crate::routes::dns_records))
        // 审计活动流（只读审计日志尾部）。
        .route("/api/activity", get(crate::routes::activity_list))
        .route("/api/snapshot", get(crate::routes::snapshot_get))
        .route("/api/status", get(crate::routes::snapshot_get))
        .route("/api/logs", get(crate::routes::logs_list))
        .route(
            "/api/metrics/realtime",
            get(crate::routes::metrics_realtime),
        )
        // `/api/metrics/system` 与 `/api/metrics/realtime` 是**不同形状**的两个端点：
        // 前者是给仪表盘资源环形图用的三格百分比，后者是完整的运行读数。
        .route("/api/metrics/system", get(crate::routes::metrics_system))
        // 遥测是**进程内**路由（契约里 action 为 None）：采样器就在本进程。
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
        // 2FA：读状态由 Web 进程直接应答；三个写动作经助手（secret 不出助手）。
        .route("/api/admin/2fa", get(crate::routes::admin_2fa))
        .route("/api/admin/2fa/begin", post(crate::routes::totp_begin))
        .route("/api/admin/2fa/enable", post(crate::routes::totp_enable))
        .route("/api/admin/2fa/disable", post(crate::routes::totp_disable))
        .route("/api/doctor", get(crate::routes::system_doctor))
        .route("/api/system/doctor", get(crate::routes::system_doctor))
        .route("/api/setup/status", get(crate::routes::setup_status))
        // AI 子系统：`GET /api/ai/config` 是只读公开配置；其余 9 条写/出站路由中，
        // `/api/ai/dns-chat`、`/api/ai/diagnose-dns`、`/api/ai/parse-dns-raw` 与
        // 各自的「非 dns」路由映射到**同一个动作**（契约如此，不新增动作）。
        .route(
            "/api/ai/config",
            get(crate::routes::ai_config_get).post(crate::routes::ai_config_set),
        )
        .route(
            "/api/ai/models",
            get(crate::routes::ai_models_list).post(crate::routes::ai_models_list),
        )
        .route("/api/ai/test", post(crate::routes::ai_test))
        .route("/api/ai/chat", post(crate::routes::ai_chat))
        .route("/api/ai/dns-chat", post(crate::routes::ai_chat))
        .route("/api/ai/diagnose", post(crate::routes::ai_diagnose))
        .route("/api/ai/diagnose-dns", post(crate::routes::ai_diagnose))
        .route("/api/ai/parse", post(crate::routes::ai_parse))
        .route("/api/ai/parse-dns-raw", post(crate::routes::ai_parse))
        .route("/api/queue/action", post(crate::routes::queue_action))
        .route("/api/queue", get(crate::routes::queue_list))
        .route("/api/services/action", post(crate::routes::services_action))
        .route("/api/services", get(crate::routes::services_list))
        .route("/api/security/scan", post(crate::routes::security_scan))
        .route("/api/security/ban", post(crate::routes::security_ban))
        .route("/api/security/unban", post(crate::routes::security_unban))
        // 备份：`/api/backups/restore` 与 `/api/backups/:name` 是同层级的
        // 「静态段 vs 命名参数」。matchit 0.7 允许二者共存且**静态段优先**，
        // 因此 `restore` 不会被 `:name` 抢走（这条依赖有回归测试兜底）。
        .route(
            "/api/backups",
            get(crate::routes::backup_list).post(crate::routes::backup_create),
        )
        .route("/api/backups/restore", post(crate::routes::backup_restore))
        .route("/api/backups/:name", delete(crate::routes::backup_delete))
        .route("/api/certificates", get(crate::routes::certs_list))
        .route("/api/certificates/renew", post(crate::routes::certs_renew))
        // setup 向导的写动作（§5.2 初始化分组）。
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
        .layer(middleware::from_fn_with_state(state.clone(), ai_rate_limit))
        .layer(middleware::from_fn_with_state(state.clone(), require_auth));

    Router::new()
        .merge(public)
        .merge(protected)
        .with_state(state)
        // INV-12 / 5.1：`API_BODY_LIMIT_BYTES` 在此之前只是一个**从未被引用的常量**
        // —— 模块头注释声称有 256KB 上限，实现里没有任何东西强制它。
        // 叠加 `panic = "abort"`（见批 6 的 6.9），单个超大请求就能把控制台进程打死。
        //
        // 两道防线缺一不可：
        // 1. `DefaultBodyLimit` 限制**实际读取量**（覆盖分块传输、无 Content-Length 的情形）；
        // 2. `reject_oversized_bodies` 在进处理器**之前**按 Content-Length 直接回 413
        //    —— 因为 `DefaultBodyLimit` 的 413 会被 `Option<Json<Value>>` 吞掉（见下）。
        .layer(axum::extract::DefaultBodyLimit::max(API_BODY_LIMIT_BYTES))
        .layer(middleware::from_fn(reject_oversized_bodies))
}

/// INV-12 / 5.1 的「快速拒绝」半边：在进任何提取器之前按 `Content-Length` 判定。
///
/// ## 为什么光有 `DefaultBodyLimit` 不够
///
/// 本项目的处理器绝大多数写成 `body: Option<Json<serde_json::Value>>`（允许空体）。
/// axum 0.7 对 `Option<T>` 的 `FromRequest` 实现会把**所有**拒绝都塌缩成 `None`：
///
/// ```ignore
/// match T::from_request(req, state).await {
///     Ok(v) => Ok(Some(v)),
///     Err(_) => Ok(None),      // ← 413 / 400 / 415 一并吞掉
/// }
/// ```
///
/// 于是超大请求体不会得到 413，而是被当成「没带请求体」继续往下走 ——
/// 实测表现为处理器拿着空对象去调助手，最终回 500（与上限毫无关系的一句错误）。
/// 在提取器之前判定，才能让「超限」这件事如实反映成 413。
///
/// 这条同时也堵住了 `Option<Json>` 更广的一类静默失败：畸形 JSON 会被当成 `{}`。
/// 彻底修掉需要把所有处理器改成非 `Option` 的 `Json`，属于契约层改动，另行登记。
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

/// 完整 API 路由：未匹配的路径回 **JSON** 404（不是 SPA 的 index.html）。
///
/// `/api` 兜底**必须**是 JSON（规格书 §5.1）—— 前端把非 2xx 当错误处理，回一段
/// HTML 会让它解析失败，最终显示一个毫无信息量的报错。
pub fn build_router(state: AppState) -> Router {
    build_api_router(state)
        .fallback(crate::routes::api_fallback)
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

    /// 5.1：超过 [`API_BODY_LIMIT_BYTES`] 的请求体必须被**提取器**拒绝。
    ///
    /// 这条在接线之前必然失败：常量没有任何调用点，`Json<Value>` 会把整个请求体
    /// 读进内存。叠加 release 的 `panic = "abort"`，单个几百 MB 的请求就能打死
    /// 控制台进程。
    ///
    /// 走的是 **免认证的 `/api/auth/login`** —— 未认证的洪水才是最需要被挡住的那一路
    /// （受保护路由会先被 `require_auth` 以 401 挡回，根本走不到体提取器）。
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

    /// 上限必须对**已认证**的受保护路由同样生效 —— 那是会话被劫持后的那条路。
    ///
    /// 这里显式带 `Content-Length`：真实 HTTP 客户端对非分块请求**必然**发送它，
    /// 而快速拒绝那一半正是按它判定的（`Body::from(..)` 不会自动补这个头，
    /// 所以测试必须自己补，否则测的就不是真实请求形态）。
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

    /// 无 `Content-Length`（分块）时内存仍必须被 `DefaultBodyLimit` 兜住。
    ///
    /// 这一路**不会**得到 413：`Option<Json<Value>>` 把限流拒绝吞成 `None`
    /// （见 `reject_oversized_bodies` 的注释）。此处只钉住「拒绝发生」这个事实，
    /// 不假装状态码是对的 —— 真正的修法是让处理器不再用 `Option<Json>`。
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
                    // 刻意不发 Content-Length：模拟分块传输。
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
        // 上限的另一面：不能把正常请求也一起挡掉。
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

    /// 5.8：`uptimeSec` 必须是真实读数，而不是恒为 0 的占位。
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

    #[tokio::test]
    async fn every_implemented_action_route_is_wired_and_behind_auth() {
        // 防的是两类回归：
        //   1. 「动作已实现、路由却没接线」—— 界面拿到 404，功能静默缺失；
        //   2. 「动作路由被误挂到免认证面」—— 特权动作可在无会话下触达。
        //
        // 真相源是助手侧的注册表（`Registry`），而不是本文件里的路由清单：
        // 路由清单正是被测对象，用它给自己打分等于同义反复。
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

            // 把 `:id` / `:name` 具体化成一个普通段。
            let uri = spec
                .path
                .split('/')
                .map(|seg| if seg.starts_with(':') { "sample" } else { seg })
                .collect::<Vec<_>>()
                .join("/");

            // 不带会话发请求：已接线且受认证保护 → 401；未接线 → `/api` 兜底 404。
            // 认证层先于业务执行，因此请求**不会**到达特权助手
            // （本机可能装着真实 helper，跑 `system.doctor` 会有真实副作用）。
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
    async fn telemetry_is_served_in_process_and_returns_the_raw_object() {
        // 遥测的 `action` 是 `None`，因此不在「动作×路由」守卫的覆盖范围里，
        // 这条测试单独把它钉住：受认证保护、且响应是遥测对象本身（不套 `{ok,data}`）。
        let (root, state) = test_state("telemetry");
        // 注入一个不读 `/proc`、不跑 `df`/`postqueue` 的采集器：
        // 这条测试关心的是接线与认证，不该在开发机上产生真实副作用。
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
    fn session_cookie_parsing_handles_multiple_cookies() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("theme=dark; __Host-mailstack_session=abc123; lang=zh"),
        );
        assert_eq!(session_cookie(&headers).as_deref(), Some("abc123"));
    }

    /// 回归守卫：`__Host-` 前缀是这次安全修复的一部分，解析侧必须认新名字。
    ///
    /// 若解析仍按旧名 `mailstack_session` 找 substring，`__Host-mailstack_session=…`
    /// 里恰好也含 `mailstack_session=`，所以**这条断言单独看不出问题**；
    /// 真正的风险是「下发新名、解析旧名」这种不一致。因此下面再钉一条
    /// 「旧名（无前缀）不再被接受」—— 强制所有浏览器重新登录正是本次改动的
    /// 明确意图（见 `SESSION_COOKIE` 的文档）。
    #[test]
    fn session_cookie_parsing_requires_the_host_prefix() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("mailstack_session=abc123"),
        );
        assert!(
            session_cookie(&headers).is_none(),
            "不带 `__Host-` 前缀的旧 cookie 不得再被接受"
        );
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
