//! 认证提取器：会话 Cookie → 已认证账号，顺带完成 CSRF 与纪元校验。
//!
//! ## 为什么认证 + CSRF 放在提取器而不是中间件
//!
//! 处理器只要在参数里写了 [`AuthSession`]，就**不可能**忘记做认证；而中间件
//! 需要维护「哪些路由挂、哪些不挂」的清单，漏挂一条就是未授权访问。契约要求
//! 「除登录本身外所有写操作必须带 CSRF」，提取器按 HTTP 方法自动判定，因此
//! 不存在「某个写路由忘了校验」的形态。
//!
//! ## 失败顺序与状态码
//!
//! 1. 没有会话 Cookie / 会话不存在 / 已过期 → **401**（不用 403 暴露资源存在性）；
//! 2. 纪元 bump → **401** 并删除会话（改密/锁定即踢下线）；
//! 3. 写方法缺 CSRF → **403**。
//!
//! 先认证再 CSRF：让未认证请求统一 401，而不是因为「没带 csrf」收到 403 ——
//! 后者会把「有没有会话」这件事暴露出去。
//!
//! ## 为什么手写 `Pin<Box<dyn Future>>`
//!
//! axum 0.7 的 `FromRequestParts` 用 `#[async_trait]` 声明；本仓库不允许为它新增
//! `async-trait` 直接依赖（契约「不引入新 Rust 依赖」）。`#[async_trait]` 只是把
//! `async fn` 脱糖成这个返回类型，手写同样的签名即可，不改变语义。

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;

use crate::error::WebmailError;
use crate::http::AppState;
use crate::session::{self, Session};

/// 已认证请求的上下文。
#[derive(Debug, Clone)]
pub struct AuthSession {
    /// 会话快照（账户信息、CSRF、纪元、时间戳）。
    pub session: Session,
}

impl AuthSession {
    /// 账号快照（含 Maildir 路径）。
    pub fn account(&self) -> &crate::account::Account {
        &self.session.account
    }
}

impl FromRequestParts<AppState> for AuthSession {
    type Rejection = WebmailError;

    fn from_request_parts<'life0, 'life1, 'async_trait>(
        parts: &'life0 mut Parts,
        state: &'life1 AppState,
    ) -> Pin<Box<dyn Future<Output = Result<Self, Self::Rejection>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            let token =
                session::session_cookie(&parts.headers).ok_or_else(WebmailError::unauthorized)?;
            let now = time::OffsetDateTime::now_utc();
            let session = state
                .inner
                .sessions
                .get(&token, now)
                .ok_or_else(WebmailError::unauthorized)?;

            // 会话纪元：当前值 > 登录时值 ⇒ 立即失效并删除会话。
            // 纪元文件是小文件，但仍是磁盘 I/O：放到阻塞线程池，不占 async worker。
            let epochs = state.inner.epochs.clone();
            let email = session.account.email.clone();
            let current = tokio::task::spawn_blocking(move || epochs.current(&email))
                .await
                .map_err(|error| WebmailError::internal("epoch lookup", error))?;
            if current > session.epoch {
                state
                    .inner
                    .sessions
                    .remove_by_fingerprint(&session.token_fingerprint);
                tracing::info!(
                    target: "mailstack_webmail",
                    email = %session.account.email,
                    "webmail session invalidated by a session-epoch bump"
                );
                return Err(WebmailError::unauthorized());
            }

            // CSRF：所有非安全方法都必须带与会话绑定的 token。
            if session::method_requires_csrf(&parts.method) {
                let provided = parts
                    .headers
                    .get("x-csrf-token")
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or("");
                if !session::csrf_matches(&session.csrf, provided) {
                    return Err(WebmailError::csrf_rejected());
                }
            }

            Ok(AuthSession { session })
        })
    }
}

/// 解析传输层对端地址（无注入时返回 `None`）。
pub fn peer_addr(peer: Option<ConnectInfo<SocketAddr>>) -> Option<SocketAddr> {
    peer.map(|ConnectInfo(address)| address)
}

/// 限流用的客户端键：**只认传输层对端**，绝不读 `X-Forwarded-For`。
///
/// 那个头是请求可控的明文：读它等于让攻击者随意伪造来源、绕过 per-IP 限流。
/// 本进程默认只绑回环，真实来源由反向代理的传输层连接给出（若要支持多级代理，
/// 那是部署层要显式解决的信任边界问题，不是一个头能解决的）。
pub fn client_key(peer: Option<&SocketAddr>) -> String {
    peer.map(|address| address.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}
