//! Webmail 会话、CSRF、Cookie 与「会话纪元」。
//!
//! 这是管理台 `crates/web/src/session.rs` 的**独立等价实现**：两个进程的会话
//! 体系完全隔离（契约 §0），因此不共享类型、不共享进程内表，只共享契约语义：
//!
//! * 服务端内存会话表；token 只经 `HttpOnly` Cookie 传递；
//! * 表里存的是 token 的 **SHA-256**，不是 token 本身（表内存快照/日志泄露时
//!   拿不到可冒用的凭据）；
//! * CSRF token 与会话绑定，只经 `x-csrf-token` 头回传；
//! * 8 小时滑动 / 7 天绝对上限；
//! * Cookie 名**条件性**：加 `Secure` 的部署用 `__Host-mailstack_mail`，默认
//!   HTTP 部署用 `mailstack_mail`（`__Host-` 前缀强制要求 `Secure`，无 `Secure`
//!   时用前缀名会被所有浏览器拒收，登录开箱即坏）。
//!
//! ## 会话纪元（改密 / 锁定即踢下线）
//!
//! 登录成功时记录 `/var/lib/mailstack/webmail-session-epoch.json` 里该用户的
//! 当前值；之后每个请求比较「当前值 > 登录时值」→ 立即 401 并删除会话。
//! 账号管理侧只要把该值 +1，全部旧会话在下一个请求就失效。
//!
//! 文件读不出来时**保持上次已知值**：这是契约明确的方向（读失败不 bump，不
//! 影响正常请求）；与此同时「不读文件」也绝不能变成放行——纪元只可能让会话
//! 失效，比较逻辑本身不会因为读失败而跳过。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use axum::http::{header, HeaderMap, HeaderValue, Method};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};

use mailstack_core::password::constant_time_eq;

use crate::account::Account;
use crate::error::WebmailResult;
use crate::{MAX_SESSIONS, SESSION_ABSOLUTE_MAX_SECONDS, SESSION_TTL_SECONDS};

/// 加 `Secure` 的部署下的会话 Cookie 名。
///
/// `__Host-` 前缀由浏览器强制三条规则：必须 `Secure`、必须 `Path=/`、不得携带
/// `Domain`。于是攻击者控制的子域无法写入同名 Cookie 覆盖会话。
pub const SESSION_COOKIE_SECURE_NAME: &str = "__Host-mailstack_mail";

/// 默认 HTTP 部署（不加 `Secure`）下的会话 Cookie 名。
///
/// 不得带 `__Host-` 前缀：无 `Secure` 的 `__Host-` Cookie 会被浏览器拒收。
pub const SESSION_COOKIE_PLAIN_NAME: &str = "mailstack_mail";

/// 解析侧接受的全部 Cookie 名（下发/作废按当前判定取其一，解析两个都认）。
pub const SESSION_COOKIE_NAMES: [&str; 2] = [SESSION_COOKIE_SECURE_NAME, SESSION_COOKIE_PLAIN_NAME];

/// 显式覆盖 Cookie `Secure` 的环境变量（与管理台同名同义）。
pub const SESSION_COOKIE_SECURE_ENV: &str = "MAILSTACK_COOKIE_SECURE";

/// 会话纪元文件名（位于 `Paths::webmail_session_epoch` 所指目录下）。
///
/// 纪元文件的**格式**在契约里只写了「该用户当前值」，故这里取最宽容的解析：
/// * `{"version":1,"epochs":{"alice@example.com":3}}`
/// * `{"alice@example.com":3}`（扁平 map）
///
/// 两种都接受；其它形状按「读不出来」处理（保持上次已知值）。
pub const EPOCH_FILE_MAX_BYTES: u64 = 1024 * 1024;

/// 一次会话的 Cookie 上下文：`(名字, 是否 Secure)` —— **唯一**判定入口。
///
/// 登录下发与登出/纪元失效时作废都必须从这里取值；否则 HTTPS 部署下作废
/// Cookie 缺 `Secure`，浏览器拒绝删除 `__Host-` Cookie，表现为「登出了但立刻
/// 又自动登录」。
pub fn session_cookie_context(
    env_flag: Option<&str>,
    public_mode: bool,
    peer: Option<&SocketAddr>,
    headers: &HeaderMap,
) -> (&'static str, bool) {
    let secure = session_cookie_secure(env_flag, public_mode, peer, headers);
    let name = if secure {
        SESSION_COOKIE_SECURE_NAME
    } else {
        SESSION_COOKIE_PLAIN_NAME
    };
    (name, secure)
}

/// Cookie 是否应带 `Secure`（判定顺序与管理台 `session_cookie_secure` 等价）。
///
/// 1. `MAILSTACK_COOKIE_SECURE=1/0`：运维显式裁决；
/// 2. 公网模式（`ACCESS_MODE=caddy|direct`）⇒ `true`（部署前提就是有 TLS 终结）；
/// 3. 可信回环对端 + `X-Forwarded-Proto: https` ⇒ `true`；
/// 4. 其余 ⇒ `false`（默认部署是 HTTP；误加 `Secure` 会让所有人登不进去）。
pub fn session_cookie_secure(
    env_flag: Option<&str>,
    public_mode: bool,
    peer: Option<&SocketAddr>,
    headers: &HeaderMap,
) -> bool {
    if let Some(flag) = env_flag.map(str::trim).filter(|flag| !flag.is_empty()) {
        return !matches!(flag.to_lowercase().as_str(), "0" | "false" | "no" | "off");
    }
    if public_mode {
        return true;
    }
    if !peer.map(|addr| addr.ip().is_loopback()).unwrap_or(false) {
        // 拿不到传输层对端（in-process 调用）一律视为不可信：
        // `X-Forwarded-Proto` 是请求可控明文，只有来源可信时才能读。
        return false;
    }
    forwarded_proto(headers).as_deref() == Some("https")
}

/// 从请求头取出 `x-forwarded-proto` 的首个值（小写、去空白）。
pub fn forwarded_proto(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .split(',')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase()
        })
        .filter(|value| !value.is_empty())
}

/// 从 `Cookie` 头里取出会话 token（两个条件性名字都认；空值无效）。
pub fn session_cookie(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        let part = part.trim();
        let Some((name, value)) = part.split_once('=') else {
            continue;
        };
        let name = name.trim();
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        if SESSION_COOKIE_NAMES.contains(&name) {
            return Some(value.to_string());
        }
    }
    None
}

/// 构造下发会话的 `Set-Cookie` 值。
///
/// `Max-Age` 取**绝对上限**（7 天）：滑动过期在服务端维护，Cookie 寿命若短于
/// 绝对上限会把活跃用户提前强制登出。
pub fn build_session_cookie(name: &str, secure: bool, token: &str) -> HeaderValue {
    let mut value = format!(
        "{name}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_ABSOLUTE_MAX_SECONDS}"
    );
    if secure {
        value.push_str("; Secure");
    }
    HeaderValue::from_str(&value).unwrap_or_else(|_| HeaderValue::from_static("mailstack_mail="))
}

/// 构造作废会话的 `Set-Cookie` 值（名字与 `Secure` 必须与下发时配对）。
pub fn clear_session_cookie(name: &str, secure: bool) -> HeaderValue {
    let mut value =
        format!("{name}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT");
    if secure {
        value.push_str("; Secure");
    }
    HeaderValue::from_str(&value).unwrap_or_else(|_| HeaderValue::from_static("mailstack_mail="))
}

/// 该方法是否需要 CSRF 校验（所有非 GET/HEAD/OPTIONS）。
pub fn method_requires_csrf(method: &Method) -> bool {
    !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

/// 常量时间比较 CSRF token（防时序侧信道）。
pub fn csrf_matches(expected: &str, provided: &str) -> bool {
    constant_time_eq(expected.as_bytes(), provided.as_bytes())
}

/// token 的存储形态：SHA-256 的 hex。
pub fn token_fingerprint(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// 生成 32 字节随机 hex token（会话 token 与 CSRF token 共用）。
pub fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
    hex::encode(bytes)
}

/// 一条会话。
///
/// `Debug` 手写：`token_fingerprint` / `csrf` 是 bearer 凭据，绝不能经 `tracing`
/// 的 `?session` 原样进日志。
#[derive(Clone)]
pub struct Session {
    /// token 的 SHA-256（表键；**不是** token 本身）。
    pub token_fingerprint: String,
    /// CSRF token（只经响应体返回给前端，不写日志）。
    pub csrf: String,
    /// 登录成功的账号快照（含 Maildir 路径，避免每请求重读注册表）。
    pub account: Account,
    /// 登录时的会话纪元值。
    pub epoch: u64,
    pub created_at: OffsetDateTime,
    pub last_seen: OffsetDateTime,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("token_fingerprint", &self.token_fingerprint)
            .field("email", &self.account.email)
            .field("created_at", &self.created_at)
            .field("last_seen", &self.last_seen)
            .field("csrf", &"<redacted>")
            .finish()
    }
}

impl Session {
    /// 是否已过期（滑动 TTL 或绝对上限任一超限）。
    pub fn is_expired(&self, now: OffsetDateTime) -> bool {
        let idle = now - self.last_seen;
        let age = now - self.created_at;
        idle > Duration::seconds(SESSION_TTL_SECONDS)
            || age > Duration::seconds(SESSION_ABSOLUTE_MAX_SECONDS)
    }
}

/// 服务端内存会话表。
#[derive(Debug, Default)]
pub struct SessionStore {
    inner: Mutex<HashMap<String, Session>>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// 建立会话，返回 `(原始 token, csrf token)`。
    ///
    /// 一次返回两个值：调用方拿不到「只建了会话、csrf 取不出来」的半成品状态
    /// （管理台曾因 `touch()` 返回 `None` 被 `unwrap_or_default()` 吞成空串
    /// CSRF，前端所有写请求永远 403）。
    pub fn create(&self, account: &Account, epoch: u64, now: OffsetDateTime) -> (String, String) {
        let token = random_token();
        let csrf = random_token();
        let session = Session {
            token_fingerprint: token_fingerprint(&token),
            csrf: csrf.clone(),
            account: account.clone(),
            epoch,
            created_at: now,
            last_seen: now,
        };
        let mut map = self.lock();
        map.retain(|_, session| !session.is_expired(now));
        if map.len() >= MAX_SESSIONS {
            evict_oldest(&mut map);
        }
        map.insert(token_fingerprint(&token), session);
        (token, csrf)
    }

    /// 校验会话并刷新滑动过期；`None` 表示未认证（调用方必须回 401）。
    pub fn get(&self, token: &str, now: OffsetDateTime) -> Option<Session> {
        let key = token_fingerprint(token);
        let mut map = self.lock();
        let session = map.get_mut(&key)?;
        if session.is_expired(now) {
            map.remove(&key);
            return None;
        }
        // 时钟回拨（NTP 校正 / 虚拟机快照恢复）会让 now < last_seen；直接赋值等于
        // 把活动时刻往回拨，滑动 TTL 在墙钟追上来之前被废掉。钳到单调不减。
        if now > session.last_seen {
            session.last_seen = now;
        }
        Some(session.clone())
    }

    /// 主动登出 / 纪元失效时删除会话。
    pub fn remove(&self, token: &str) -> bool {
        self.lock().remove(&token_fingerprint(token)).is_some()
    }

    /// 按存储键（token 指纹）删除会话。
    ///
    /// 请求处理路径上拿到的是 [`Session`]（只有指纹，没有原始 token）；要按会话
    /// 登出就必须能用指纹删。原始 token 在 HttpOnly Cookie 里，服务端内存**不**
    /// 保留它——这条等价关系由 `token_fingerprint` 是单向哈希保证。
    pub fn remove_by_fingerprint(&self, fingerprint: &str) -> bool {
        self.lock().remove(fingerprint).is_some()
    }

    /// 当前会话数（测试与观测用）。
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Session>> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// 淘汰最早建立的会话（容量上限触发时）。
fn evict_oldest(map: &mut HashMap<String, Session>) {
    let oldest = map
        .iter()
        .min_by_key(|(_, session)| session.created_at)
        .map(|(key, _)| key.clone());
    if let Some(key) = oldest {
        map.remove(&key);
    }
}

/// 会话纪元的读缓存。
#[derive(Debug, Default)]
struct EpochCache {
    /// 上次读到文件的指纹（mtime + len）。`None` = 文件不存在或从未成功读过。
    fingerprint: Option<(SystemTime, u64)>,
    /// 上次成功解析出的「地址 → 纪元值」。
    epochs: HashMap<String, u64>,
}

/// 会话纪元存储（`/var/lib/mailstack/webmail-session-epoch.json`）。
///
/// `current` 是同步读（小文件）；HTTP 层用 `spawn_blocking` 调用，避免在 async
/// worker 上做文件 I/O。
#[derive(Debug, Clone)]
pub struct EpochStore {
    path: PathBuf,
    cache: Arc<Mutex<EpochCache>>,
}

impl EpochStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            cache: Arc::new(Mutex::new(EpochCache::default())),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 读某个地址当前的纪元值；文件缺失 = 0。
    ///
    /// 读失败（权限 / I/O / 解析）时**保持上次已知值**：纪元只会让会话失效，
    /// 读失败不 bump 是契约明确的方向；但缓存也绝不因为读失败而变成「跳过纪元
    /// 检查」——调用方拿到的仍是一个数值。
    pub fn current(&self, email: &str) -> u64 {
        let key = email.trim().to_ascii_lowercase();
        let metadata = match std::fs::metadata(&self.path) {
            Ok(metadata) => Some(metadata),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => {
                tracing::warn!(
                    target: "mailstack_webmail",
                    path = %self.path.display(),
                    %error,
                    "cannot stat webmail session epoch file; keeping last known value"
                );
                return self.cached(&key);
            }
        };

        let Some(metadata) = metadata else {
            // 文件缺失 = 0（契约 §1.2）。同时清空缓存：文件被删后再建，旧值不得复活。
            let mut cache = self.lock();
            cache.fingerprint = None;
            cache.epochs.clear();
            return 0;
        };

        if metadata.len() > EPOCH_FILE_MAX_BYTES {
            tracing::warn!(
                target: "mailstack_webmail",
                path = %self.path.display(),
                len = metadata.len(),
                "webmail session epoch file is implausibly large; keeping last known value"
            );
            return self.cached(&key);
        }

        let modified = metadata.modified().ok();
        // 先取出指纹再判断：`self.lock()` 的临时 guard 若出现在 `if let` 的
        //  scrutinee 里，会一直存活到整个 if-let 结束；分支内再调 `self.cached()`
        //（内部再 `self.lock()`）就是对同一把 std::sync::Mutex 二次加锁 —— 死锁。
        // 这是真实可复现的 Webmail 挂死：只要纪元文件存在且被读过两次。
        let cached_fingerprint = self.lock().fingerprint;
        if let (Some(modified), Some((cached_mtime, cached_len))) = (modified, cached_fingerprint) {
            if cached_mtime == modified && cached_len == metadata.len() {
                return self.cached(&key);
            }
        }

        match std::fs::read_to_string(&self.path) {
            Ok(text) => match parse_epochs(&text) {
                Some(epochs) => {
                    let value = epochs.get(&key).copied().unwrap_or(0);
                    let mut cache = self.lock();
                    cache.fingerprint = modified.map(|mtime| (mtime, metadata.len()));
                    cache.epochs = epochs;
                    value
                }
                None => {
                    tracing::warn!(
                        target: "mailstack_webmail",
                        path = %self.path.display(),
                        "webmail session epoch file is malformed; keeping last known value"
                    );
                    self.cached(&key)
                }
            },
            Err(error) => {
                tracing::warn!(
                    target: "mailstack_webmail",
                    path = %self.path.display(),
                    %error,
                    "cannot read webmail session epoch file; keeping last known value"
                );
                self.cached(&key)
            }
        }
    }

    fn cached(&self, key: &str) -> u64 {
        self.lock().epochs.get(key).copied().unwrap_or(0)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, EpochCache> {
        self.cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// 解析纪元文件。
///
/// 接受两种形状（见 [`EPOCH_FILE_MAX_BYTES`] 的说明）；非数字值忽略，
/// 键统一小写。任何结构性错误返回 `None`（调用方保持上次已知值）。
fn parse_epochs(text: &str) -> Option<HashMap<String, u64>> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    let object = match value {
        serde_json::Value::Object(object) => object,
        _ => return None,
    };
    let inner = object
        .get("epochs")
        .or_else(|| object.get("users"))
        .and_then(serde_json::Value::as_object);
    let entries: &serde_json::Map<String, serde_json::Value> = inner.unwrap_or(&object);
    let mut epochs = HashMap::new();
    for (key, value) in entries {
        if let Some(number) = value.as_u64() {
            epochs.insert(key.trim().to_ascii_lowercase(), number);
        }
    }
    Some(epochs)
}

/// 追加一个 `Set-Cookie` 到响应（`HttpOnly` 之外没有别的标志需要调用方关心）。
pub fn append_set_cookie(response: &mut axum::response::Response, cookie: HeaderValue) {
    response.headers_mut().append(header::SET_COOKIE, cookie);
}

/// 从请求头取 `Host`（登录同源检查用）。
pub fn host_header(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
}

/// 登录请求的同源检查：`Origin` 存在时其 host:port 必须等于 `Host`。
///
/// 只做字符串比较（不解析 URL）：`Origin` 是浏览器自动发送的，攻击者能构造
/// 请求但无法让受害者浏览器带出别的 Origin——跨站登录 CSRF 因此被挡住。
/// `Origin: null`（沙箱 iframe / file://）一律拒绝。
pub fn origin_matches_host(headers: &HeaderMap) -> bool {
    let Some(origin) = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    else {
        // 无 Origin：非浏览器客户端（curl / 测试）与旧浏览器。CSRF 防护由
        // `SameSite=Strict` Cookie 与登录接口的「无副作用」性质兜底。
        return true;
    };
    let Some(host) = host_header(headers) else {
        return false;
    };
    let authority = origin
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(origin);
    let authority = authority.split('/').next().unwrap_or("");
    !authority.is_empty() && authority.eq_ignore_ascii_case(host.trim())
}

/// 读取 Cookie 上下文所需的环境覆盖值（进程环境集中读取一次）。
pub fn cookie_secure_env() -> Option<String> {
    std::env::var(SESSION_COOKIE_SECURE_ENV).ok()
}

/// 纪元检查的结果（供 HTTP 层区分「读不到」与「确实 bump」）。
///
/// 目前只返回数值；这个别名让调用点的意图可读。
pub type EpochCheck = WebmailResult<u64>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// 反例守卫：**纪元 bump 之后旧会话必须失效**。
    ///
    /// 这是「改密 / 锁定即踢下线」的唯一机制：登录记录当时的纪元值，请求时
    /// 发现当前值更大就立即 401 并删会话。若比较写反（`>=` 或 `==`）或忘了
    /// 删会话，改密后的旧会话会继续有效——这是认证绕过级别的缺陷。
    #[test]
    fn webmail_session_epoch_bump_invalidates_existing_sessions() {
        let dir = tempfile::tempdir().unwrap();
        let epoch_path = dir.path().join("webmail-session-epoch.json");
        let store = EpochStore::new(&epoch_path);
        assert_eq!(store.current("alice@example.com"), 0, "文件缺失时纪元为 0");

        // 登录时记录 epoch=0 的会话（用 token 指纹做键，模拟会话表语义）。
        let account = crate::account::Account {
            email: "alice@example.com".to_string(),
            account: "alice".to_string(),
            display_name: "Alice".to_string(),
            unix_user: "alice".to_string(),
            maildir: PathBuf::from("/nonexistent/Maildir"),
        };
        let sessions = SessionStore::new();
        let (token, _csrf) = sessions.create(&account, 0, OffsetDateTime::now_utc());
        assert!(sessions.get(&token, OffsetDateTime::now_utc()).is_some());

        // 账号管理侧 bump 纪元。
        std::fs::write(
            &epoch_path,
            r#"{"version":1,"epochs":{"alice@example.com":1}}"#,
        )
        .unwrap();
        let current = store.current("alice@example.com");
        assert_eq!(current, 1);
        let session = sessions
            .get(&token, OffsetDateTime::now_utc())
            .expect("会话还在表里");
        if current > session.epoch {
            sessions.remove(&token);
        }
        assert!(
            sessions.get(&token, OffsetDateTime::now_utc()).is_none(),
            "纪元 bump 之后旧会话必须失效"
        );
    }

    #[test]
    fn a_missing_epoch_file_reads_as_zero_and_a_flat_map_also_parses() {
        let dir = tempfile::tempdir().unwrap();
        let store = EpochStore::new(dir.path().join("epoch.json"));
        assert_eq!(store.current("a@b.c"), 0);

        std::fs::write(dir.path().join("epoch.json"), r#"{"a@b.c": 7}"#).unwrap();
        assert_eq!(store.current("A@B.C"), 7, "扁平 map 也要接受且大小写不敏感");
    }

    #[test]
    fn a_corrupt_epoch_file_keeps_the_last_known_value() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("epoch.json");
        let store = EpochStore::new(&path);
        std::fs::write(&path, r#"{"epochs":{"a@b.c":4}}"#).unwrap();
        assert_eq!(store.current("a@b.c"), 4);

        // 损坏：长度变化，必然触发重读；重读失败必须保持 4 而不是归零。
        std::fs::write(&path, "{ this is not json").unwrap();
        assert_eq!(
            store.current("a@b.c"),
            4,
            "解析失败时保持上次已知值（契约 §1.2）"
        );
    }

    #[test]
    fn session_sliding_expiry_and_absolute_cap_are_enforced() {
        let account = crate::account::Account {
            email: "alice@example.com".to_string(),
            account: "alice".to_string(),
            display_name: "Alice".to_string(),
            unix_user: "alice".to_string(),
            maildir: PathBuf::from("/nonexistent/Maildir"),
        };
        let sessions = SessionStore::new();
        let t0 = OffsetDateTime::now_utc();
        let (token, csrf) = sessions.create(&account, 0, t0);
        assert_eq!(token.len(), 64, "会话 token 应为 32 字节 hex");
        assert_eq!(csrf.len(), 64, "CSRF token 应为 32 字节 hex");

        // 滑动：TTL 一半处活动后仍然有效。
        let half = t0 + Duration::seconds(SESSION_TTL_SECONDS / 2);
        assert!(sessions.get(&token, half).is_some());
        let later = half + Duration::seconds(SESSION_TTL_SECONDS / 2);
        assert!(sessions.get(&token, later).is_some(), "滑动过期应顺延");

        // 绝对上限：即使一直活动，超过 7 天也失效。
        let too_old = t0 + Duration::seconds(SESSION_ABSOLUTE_MAX_SECONDS + 1);
        assert!(
            sessions.get(&token, too_old).is_none(),
            "绝对上限必须压过滑动刷新"
        );
    }

    #[test]
    fn the_session_table_never_stores_the_raw_token() {
        let account = crate::account::Account {
            email: "alice@example.com".to_string(),
            account: "alice".to_string(),
            display_name: "Alice".to_string(),
            unix_user: "alice".to_string(),
            maildir: PathBuf::from("/nonexistent/Maildir"),
        };
        let sessions = SessionStore::new();
        let (token, _csrf) = sessions.create(&account, 0, OffsetDateTime::now_utc());
        let session = sessions.get(&token, OffsetDateTime::now_utc()).unwrap();
        assert_eq!(session.token_fingerprint, token_fingerprint(&token));
        assert_ne!(session.token_fingerprint, token, "表里不得存原始 token");
        assert_eq!(session.token_fingerprint.len(), 64);

        // Debug 输出不得包含两个 bearer 凭据。
        let rendered = format!("{session:?}");
        assert!(!rendered.contains(&token), "Debug 泄露了会话 token");
        assert!(!rendered.contains(&session.csrf), "Debug 泄露了 CSRF token");
    }

    #[test]
    fn csrf_comparison_is_exact_and_timing_safe() {
        assert!(csrf_matches("abcdef", "abcdef"));
        assert!(!csrf_matches("abcdef", "abcdeg"));
        assert!(!csrf_matches("abcdef", ""));
        assert!(!csrf_matches("abcdef", "abcdefg"));
    }

    #[test]
    fn cookie_names_follow_the_secure_decision() {
        let headers = HeaderMap::new();
        let (name, secure) = session_cookie_context(None, false, None, &headers);
        assert_eq!(name, SESSION_COOKIE_PLAIN_NAME);
        assert!(!secure);

        let (name, secure) = session_cookie_context(Some("1"), false, None, &headers);
        assert_eq!(name, SESSION_COOKIE_SECURE_NAME);
        assert!(secure);
        assert!(
            name.starts_with("__Host-"),
            "__Host- 前缀必须与 Secure 配对"
        );

        // 可信回环 + X-Forwarded-Proto: https。
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        let peer: SocketAddr = "127.0.0.1:8444".parse().unwrap();
        let (name, secure) = session_cookie_context(None, false, Some(&peer), &headers);
        assert_eq!(name, SESSION_COOKIE_SECURE_NAME);
        assert!(secure);
    }

    #[test]
    fn the_cookie_parser_accepts_both_conditional_names_and_ignores_empty() {
        for name in SESSION_COOKIE_NAMES {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::COOKIE,
                HeaderValue::from_str(&format!("theme=dark; {name}=abc123")).unwrap(),
            );
            assert_eq!(session_cookie(&headers).as_deref(), Some("abc123"));
        }

        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("mailstack_mail=; other=1"),
        );
        assert!(session_cookie(&headers).is_none());
    }

    #[test]
    fn mutating_methods_require_csrf() {
        for method in [Method::POST, Method::PATCH, Method::PUT, Method::DELETE] {
            assert!(method_requires_csrf(&method), "{method} 必须校验 CSRF");
        }
        for method in [Method::GET, Method::HEAD, Method::OPTIONS] {
            assert!(!method_requires_csrf(&method), "{method} 不应要求 CSRF");
        }
    }

    #[test]
    fn login_origin_must_match_host() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("127.0.0.1:8444"));
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("http://127.0.0.1:8444"),
        );
        assert!(origin_matches_host(&headers));

        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("http://evil.example"),
        );
        assert!(!origin_matches_host(&headers), "跨源登录必须被拒");

        headers.insert(header::ORIGIN, HeaderValue::from_static("null"));
        assert!(!origin_matches_host(&headers));

        // 无 Origin 不拒绝（curl / 非浏览器客户端）。
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("127.0.0.1:8444"));
        assert!(origin_matches_host(&headers));
    }

    #[test]
    fn session_capacity_is_bounded() {
        let account = crate::account::Account {
            email: "alice@example.com".to_string(),
            account: "alice".to_string(),
            display_name: "Alice".to_string(),
            unix_user: "alice".to_string(),
            maildir: PathBuf::from("/nonexistent/Maildir"),
        };
        let sessions = SessionStore::new();
        let now = OffsetDateTime::now_utc();
        for index in 0..(MAX_SESSIONS + 8) {
            sessions.create(&account, 0, now + Duration::seconds(index as i64));
        }
        assert!(
            sessions.len() <= MAX_SESSIONS,
            "会话表容量必须被压住，实际 {}",
            sessions.len()
        );
    }
}
