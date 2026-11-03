//! HTTP 层：应用状态、中间件、路由装配。
//!
//! ## 层顺序（从外到内）
//!
//! ```text
//! 1. security_headers    —— 所有响应（含错误 / 静态 / 404）都带安全头
//! 2. no_store_api        —— /mail/api 响应不得被任何中间层缓存（含 CSRF token）
//! 3. body_limit_guard    —— 按路径区分 256 KiB / 32 MiB，Content-Length 快速拒绝
//! 4. DefaultBodyLimit    —— 实际读取量上限（覆盖分块传输）
//! 5. 路由 → 处理器       —— 认证 + CSRF 在 [`auth::AuthSession`] 提取器里
//! 6. fallback            —— /mail/api 未匹配 → JSON 404；其余 → 静态产物
//! ```
//!
//! `/mail/api` 的兜底必须是 JSON（契约 §3）：把 `mail.html` 回给一个打错的
//! API 路径，前端会把「接口不存在」解析成「服务端坏了」。这条边界由
//! `fallback` 与 `assets::serve` **两处**独立守卫。

pub mod assets;
pub mod auth;
pub mod error;
pub mod handlers;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, Request};
use axum::http::{header, HeaderMap, HeaderValue, Method};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, patch, post};
use axum::Router;

use crate::account::AccountDirectory;
use crate::auth::LoginThrottle;
use crate::error::{WebmailError, WebmailResult};
use crate::session::{self, EpochStore, SessionStore};
use crate::{WebmailConfig, API_BODY_LIMIT_BYTES, COMPOSE_BODY_LIMIT_BYTES, VERSION};

/// 应用共享状态。
#[derive(Clone)]
pub struct AppState {
    pub inner: Arc<AppInner>,
}

/// 应用内部状态（`Arc` 共享）。
pub struct AppInner {
    pub config: WebmailConfig,
    /// 账号目录（认证路径用 `spawn_blocking` 调，故用 `Arc` 共享）。
    pub accounts: Arc<AccountDirectory>,
    pub sessions: SessionStore,
    pub throttle: LoginThrottle,
    pub epochs: EpochStore,
    /// 静态产物入口（`mail.html`，缺失时回落 `index.html`）。
    pub entry: Option<assets::EntryPoint>,
    /// 运行标识（`/mail/api/health`）。
    pub runtime_id: String,
}

impl AppState {
    /// 构造状态：解析静态入口、准备会话表与纪元存储。
    pub fn new(config: WebmailConfig) -> Self {
        let entry = assets::resolve_entry(&config.dist);
        let epochs = EpochStore::new(config.paths.webmail_session_epoch.clone());
        let accounts = Arc::new(AccountDirectory::new(&config));
        Self {
            inner: Arc::new(AppInner {
                accounts,
                sessions: SessionStore::new(),
                throttle: LoginThrottle::new(),
                epochs,
                entry,
                runtime_id: format!("mailstack-webmail/{} (rust)", VERSION),
                config,
            }),
        }
    }

    pub fn config(&self) -> &WebmailConfig {
        &self.inner.config
    }

    /// 当前静态入口文件名（启动日志与测试用）。
    pub fn entry_file(&self) -> Option<&str> {
        self.inner.entry.as_ref().map(|entry| entry.file.as_str())
    }
}

/// 把一个同步闭包放到阻塞线程池执行（Maildir / 队列 / PBKDF2 都是 `std::fs` / CPU）。
///
/// 这是本进程**唯一**允许接触 Maildir 的入口：把「哪些调用可能阻塞 async
/// worker」变成结构上可检查的一件事。spawn_blocking 任务 panic 会被 JoinError
/// 捕获，转成 500，而不是打死进程。
pub async fn blocking<T, F>(work: F) -> WebmailResult<T>
where
    F: FnOnce() -> WebmailResult<T> + Send + 'static,
    T: Send + 'static,
{
    match tokio::task::spawn_blocking(work).await {
        Ok(result) => result,
        Err(error) => Err(WebmailError::internal("blocking task", error)),
    }
}

/// 会话 Cookie 上下文：`(名字, 是否 Secure)`，下发与作废共用。
pub fn cookie_context(
    state: &AppState,
    peer: Option<&SocketAddr>,
    headers: &HeaderMap,
) -> (&'static str, bool) {
    let env_flag = session::cookie_secure_env();
    session::session_cookie_context(
        env_flag.as_deref(),
        state.inner.config.public_mode,
        peer,
        headers,
    )
}

/// 安全响应头（契约 §3）。所有响应都要带，包括 401/404/静态文件。
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
    // 逐字取自契约 §3。邮件 HTML 在前端 sandbox iframe + srcdoc 里渲染，
    // 其内部 meta CSP 由前端负责；这里约束的是本站自己的文档。
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; \
             script-src 'self'; connect-src 'self'; frame-ancestors 'none'; \
             base-uri 'none'; form-action 'self'",
        ),
    );
    response
}

/// `/mail/api` 响应禁止缓存。
///
/// 会话/登录响应体里有 CSRF token；邮件正文与附件同样属于个人数据。任何一层
/// 缓存（浏览器磁盘缓存、企业代理）都会把凭据或内容二次分发。
async fn no_store_api(request: Request, next: Next) -> Response {
    let is_api = is_api_path(request.uri().path());
    let mut response = next.run(request).await;
    if is_api {
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    response
}

/// 请求体上限的快速拒绝（Content-Length 可判定时在进处理器前就回 413）。
///
/// 与 `DefaultBodyLimit` 是两道防线：前者挡「声明了就超大」的请求，后者兜住
/// 分块传输（没有 Content-Length）。只靠前者会被分块绕过，只靠后者则超大
/// 请求要先被读完才失败。
async fn body_limit_guard(request: Request, next: Next) -> Response {
    let limit = body_limit_for(request.method(), request.uri().path());
    if let Some(length) = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
    {
        if length > limit as u64 {
            return error::json_error(WebmailError::payload_too_large(
                "request body exceeds the configured limit",
            ));
        }
    }
    next.run(request).await
}

/// 某请求的请求体上限。
///
/// 写信 / 发信 32 MiB（契约 §2.2），其它 API 256 KiB。静态请求没有请求体，
/// 也按 256 KiB 处理（不让 GET 成为上传通道）。
fn body_limit_for(method: &Method, path: &str) -> usize {
    let is_compose =
        *method == Method::POST && matches!(path, "/mail/api/send" | "/mail/api/messages");
    if is_compose {
        COMPOSE_BODY_LIMIT_BYTES
    } else {
        API_BODY_LIMIT_BYTES
    }
}

/// `/mail/api` 与 `/mail/api/*`。
pub fn is_api_path(path: &str) -> bool {
    path == "/mail/api" || path.starts_with("/mail/api/")
}

/// 组装最终应用。
pub fn build_app(state: AppState) -> Router {
    Router::new()
        .route("/mail/api/health", get(handlers::health))
        .route(
            "/mail/api/session",
            post(handlers::login)
                .get(handlers::session_info)
                .delete(handlers::logout),
        )
        .route(
            "/mail/api/folders",
            get(handlers::list_folders).post(handlers::create_folder),
        )
        .route(
            "/mail/api/folders/:folder",
            patch(handlers::rename_folder).delete(handlers::delete_folder),
        )
        // 写信/存草稿：路由级 32 MiB 体上限（全局默认 256 KiB 会被内层覆盖）。
        .route(
            "/mail/api/messages",
            get(handlers::list_messages)
                .post(handlers::create_draft)
                .layer(DefaultBodyLimit::max(COMPOSE_BODY_LIMIT_BYTES)),
        )
        .route("/mail/api/messages/batch", post(handlers::batch))
        .route(
            "/mail/api/messages/:folder/:uid",
            get(handlers::message_detail)
                .patch(handlers::patch_flags)
                .delete(handlers::delete_message),
        )
        .route(
            "/mail/api/messages/:folder/:uid/raw",
            get(handlers::raw_message),
        )
        .route(
            "/mail/api/messages/:folder/:uid/parts/:part",
            get(handlers::message_part),
        )
        .route(
            "/mail/api/messages/:folder/:uid/move",
            post(handlers::move_message),
        )
        .route("/mail/api/search", get(handlers::search))
        .route("/mail/api/quota", get(handlers::quota))
        .route(
            "/mail/api/send",
            post(handlers::send_message).layer(DefaultBodyLimit::max(COMPOSE_BODY_LIMIT_BYTES)),
        )
        .fallback(handlers::fallback)
        .with_state(state)
        // 全局默认体上限；上面的路由级 layer 在更内层，会覆盖它。
        .layer(DefaultBodyLimit::max(API_BODY_LIMIT_BYTES))
        .layer(middleware::from_fn(body_limit_guard))
        .layer(middleware::from_fn(no_store_api))
        .layer(middleware::from_fn(security_headers))
}

/// 未匹配路径的兜底由 [`handlers::fallback`] 承担：`/mail/api/*` 一律 JSON 404，
/// 其余交给静态产物。
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_path_boundary_is_exact() {
        assert!(is_api_path("/mail/api"));
        assert!(is_api_path("/mail/api/"));
        assert!(is_api_path("/mail/api/messages"));
        assert!(is_api_path("/mail/api/definitely-not"));
        // 不得把相似前缀当成 API（否则静态路径会被 JSON 404 吃掉）。
        assert!(!is_api_path("/mail/apix"));
        assert!(!is_api_path("/mail/api-docs"));
        assert!(!is_api_path("/"));
        assert!(!is_api_path("/mail.html"));
    }

    #[test]
    fn body_limits_follow_the_contract_split() {
        assert_eq!(
            body_limit_for(&Method::POST, "/mail/api/send"),
            COMPOSE_BODY_LIMIT_BYTES
        );
        assert_eq!(
            body_limit_for(&Method::POST, "/mail/api/messages"),
            COMPOSE_BODY_LIMIT_BYTES
        );
        assert_eq!(
            body_limit_for(&Method::POST, "/mail/api/folders"),
            API_BODY_LIMIT_BYTES
        );
        assert_eq!(
            body_limit_for(&Method::GET, "/mail/api/messages"),
            API_BODY_LIMIT_BYTES
        );
        for path in ["/mail/api/session", "/mail/api/folders", "/mail/api/quota"] {
            assert_eq!(
                body_limit_for(&Method::POST, path),
                API_BODY_LIMIT_BYTES,
                "{path} 不能拿到写信口子的 32 MiB 额度"
            );
        }
    }
}
