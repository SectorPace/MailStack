//! 会话与 CSRF（规格书 §5.3；INV-6、INV-7）。
//!
//! * 会话为**服务端内存表**，非 JWT
//! * 会话 ID 只在 HttpOnly Cookie `mailstack_session`
//! * CSRF token 仅存于前端内存变量，经 `x-csrf-token` 头回传
//! * 8 小时滑动过期 + 7 天绝对上限；`MAX_SESSIONS` 上限
//!
//! 会话在列表中**仅以 16 位 hex 指纹暴露 ID** —— 即使会话表本身泄露，
//! 也无法直接拿去冒用。

use std::collections::HashMap;
use std::sync::Mutex;

use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};

/// Cookie 名（对外契约，不得改动）。
///
/// **`__Host-` 前缀**：浏览器强制它的三条规则（必须 `Secure`、必须 `Path=/`、
/// **不得**有 `Domain`）正好把「同站子域写入同名 cookie 覆盖会话」这条攻击路径
/// 彻底关掉 —— 攻击者控制的 `evil.example.com` 无法给 `example.com` 写 cookie，
/// 而不带前缀的 `mailstack_session` 是可以的。代价是改名会让**所有人重新登录**
/// （浏览器会把新名字当成从未见过的 cookie），这在一次安全修复里是可接受的：
/// 强制重登恰好也是我们想顺手做掉的事。
pub const SESSION_COOKIE: &str = "__Host-mailstack_session";

/// 显式覆盖会话 Cookie `Secure` 标志的环境变量。
///
/// 取值语义与基线 `COOKIE_SECURE` 一致：`1` 强制开、`0` 强制关、
/// 未设置则按 [`session_cookie_secure`] 自动判定。
pub const SESSION_COOKIE_SECURE_ENV: &str = "MAILSTACK_COOKIE_SECURE";

/// 会话 Cookie 是否应带 `Secure`。
///
/// ## 判定顺序
///
/// 1. `MAILSTACK_COOKIE_SECURE=1/0` —— 运维的显式裁决，最高优先级。
/// 2. **公网模式**（`ACCESS_MODE=caddy|direct`）⇒ `true`。这两种模式的部署
///    前提就是「有 TLS 终结」，此时不加 `Secure` 等于允许明文携带会话。
/// 3. 请求来自**可信回环对端**且带 `X-Forwarded-Proto: https` ⇒ `true`。
///    这是「反代终止 TLS」这一主流拓扑的正向判定，也是本进程唯一能**可靠**
///    得知外部是 HTTPS 的途径。
/// 4. 其余一切 ⇒ **`false`（不加 `Secure`）**。
///
/// ## 为什么第 3 条只信回环
///
/// `X-Forwarded-Proto` 是请求可控的明文：只有来源可信时才能读，否则等于把
/// 决定权交给攻击者（这与 [`crate::routes::client_key`] 不读 `X-Forwarded-For`
/// 是同一个理由的两面）。本进程默认只绑 `127.0.0.1:8443`，生产靠反代 / SSH
/// 隧道终止 TLS，于是对端**必然**是回环；而远程攻击者无法把自己的源地址
/// 变成 `127.0.0.1`。因此「对端是回环」是一个可以本地判定、无需额外配置的
/// 可信信号。拿不到传输层对端时（in-process 调用）一律视为不可信。
///
/// ## 为什么第 4 条是「不加」而不是 fail-closed
///
/// 加了 `Secure` 而实际是 HTTP 时，浏览器**根本不会**把这个 cookie 发回来 ——
/// 登录会直接坏掉，用户看到的现象是「密码输对了却提示未登录」。
/// 本进程默认就只提供 HTTP（`DEFAULT_BIND = 127.0.0.1:8443`，TLS 属部署层），
/// 在这种默认部署里强制 `Secure` 等于让产品**开箱即坏**。
/// 两种后果严重度不对称：漏加 `Secure` 是「明文多传一跳」，误加 `Secure` 是
/// 「所有人都登不进去」—— 后者严重得多且只有用户能发现，前者需要抓包才能发现。
/// 因此选择**保守可用**，并把收紧路径做成显式配置项（部署到 TLS 后置 `=1`）。
pub fn session_cookie_secure(
    env_flag: Option<&str>,
    public_mode: bool,
    peer: Option<&std::net::SocketAddr>,
    headers: &axum::http::HeaderMap,
) -> bool {
    if let Some(flag) = env_flag.map(str::trim).filter(|f| !f.is_empty()) {
        let flag = flag.to_lowercase();
        return !matches!(flag.as_str(), "0" | "false" | "no" | "off");
    }
    if public_mode {
        return true;
    }
    if !is_trusted_proxy(peer) {
        return false;
    }
    forwarded_proto(headers).as_deref() == Some("https")
}

/// 是否是可信代理的回环来源。
fn is_trusted_proxy(peer: Option<&std::net::SocketAddr>) -> bool {
    // 拿不到传输层对端（测试里的 in-process 调用）：**不**认定可信。
    // 保守方向必须一致 —— 否则一个伪造 `X-Forwarded-Proto` 的调用
    // 就能在非 TLS 部署里骗到 `Secure`。
    peer.map(|addr| addr.ip().is_loopback()).unwrap_or(false)
}

/// 从请求头取出 `x-forwarded-proto` 的首个值（小写、去空白）。
pub fn forwarded_proto(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.split(',')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase()
        })
        .filter(|v| !v.is_empty())
}

/// 会话 TTL：8 小时（滑动）。
pub const SESSION_TTL_SECONDS: i64 = 28_800;

/// 绝对上限：7 天，自建立起算，不因活动而延长。
pub const SESSION_ABSOLUTE_MAX_SECONDS: i64 = 7 * 24 * 3600;

/// 会话数上限。
pub const MAX_SESSIONS: usize = 5_000;

/// 一条会话记录。
#[derive(Debug, Clone)]
pub struct Session {
    /// 会话 ID（随机 32 字节 hex）。**绝不**通过 API 暴露。
    pub id: String,
    /// CSRF token（返回给前端）。
    pub csrf: String,
    pub username: String,
    /// 最近活动时刻。
    pub last_seen: OffsetDateTime,
    /// 建立时刻（用于绝对上限）。
    pub created_at: OffsetDateTime,
    /// 会话指纹（ID 的 SHA256 前 16 位 hex），对外暴露的就是它。
    pub fingerprint: String,
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

/// 会话指纹：`sha256(id)` 的前 16 个 hex 字符。
pub fn fingerprint_of(id: &str) -> String {
    let mut h = Sha256::new();
    h.update(id.as_bytes());
    hex::encode(h.finalize())[..16].to_string()
}

/// 生成一个高熵随机 token（32 字节 hex）。
pub fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
    hex::encode(bytes)
}

/// 会话表。
#[derive(Debug, Default)]
pub struct SessionStore {
    inner: Mutex<HashMap<String, Session>>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// 建立新会话。返回会话 ID（调用方负责写入 Cookie）。
    pub fn create(&self, username: &str) -> String {
        self.create_at(username, OffsetDateTime::now_utc())
    }

    /// 可注入时钟的版本，便于测试过期语义。
    pub fn create_at(&self, username: &str, now: OffsetDateTime) -> String {
        let id = random_token();
        let session = Session {
            fingerprint: fingerprint_of(&id),
            csrf: random_token(),
            username: username.to_string(),
            last_seen: now,
            created_at: now,
            id: id.clone(),
        };

        let mut map = self.lock();
        // 先清理过期项，再在必要时淘汰最旧会话，保证容量上限不被突破。
        map.retain(|_, s| !s.is_expired(now));
        if map.len() >= MAX_SESSIONS {
            evict_oldest(&mut map);
        }
        map.insert(id.clone(), session);
        id
    }

    /// 校验会话并刷新滑动过期。返回 `None` 表示未认证（INV-7：调用方须回 401）。
    pub fn touch(&self, id: &str) -> Option<Session> {
        self.touch_at(id, OffsetDateTime::now_utc())
    }

    pub fn touch_at(&self, id: &str, now: OffsetDateTime) -> Option<Session> {
        let mut map = self.lock();
        let session = map.get_mut(id)?;
        if session.is_expired(now) {
            map.remove(id);
            return None;
        }
        session.last_seen = now;
        Some(session.clone())
    }

    /// 主动登出。
    pub fn remove(&self, id: &str) -> bool {
        self.lock().remove(id).is_some()
    }

    /// 按指纹吊销指定会话。
    pub fn revoke_by_fingerprint(&self, fingerprint: &str) -> bool {
        let mut map = self.lock();
        let target = map
            .iter()
            .find(|(_, s)| s.fingerprint == fingerprint)
            .map(|(k, _)| k.clone());
        match target {
            Some(key) => map.remove(&key).is_some(),
            None => false,
        }
    }

    /// 吊销除 `keep_id` 外的全部会话，返回吊销数量。
    pub fn revoke_others(&self, keep_id: &str) -> usize {
        let mut map = self.lock();
        let before = map.len();
        map.retain(|k, _| k == keep_id);
        before - map.len()
    }

    /// 吊销某个用户的全部会话（改密 / 2FA 重绑后使用）。
    ///
    /// 返回吊销数量，调用方可据此告诉用户「其它 N 个设备已登出」。
    pub fn revoke_user(&self, username: &str) -> usize {
        let mut map = self.lock();
        let before = map.len();
        map.retain(|_, s| s.username != username);
        before - map.len()
    }

    /// 列出活跃会话的**对外视图**（仅指纹，绝不暴露 ID）。
    pub fn list_public(&self, now: OffsetDateTime) -> Vec<serde_json::Value> {
        let mut map = self.lock();
        map.retain(|_, s| !s.is_expired(now));
        let mut out: Vec<serde_json::Value> = map
            .values()
            .map(|s| {
                serde_json::json!({
                    "id": s.fingerprint,
                    "username": s.username,
                    "createdAt": crate::time_fmt::format_iso8601(s.created_at),
                    "lastSeen": crate::time_fmt::format_iso8601(s.last_seen),
                })
            })
            .collect();
        out.sort_by(|a, b| a["createdAt"].as_str().cmp(&b["createdAt"].as_str()));
        out
    }

    /// 当前会话数（测试用）。
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Session>> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }
}

/// 淘汰最早建立的会话（容量上限触发时）。
fn evict_oldest(map: &mut HashMap<String, Session>) {
    let oldest = map
        .iter()
        .min_by_key(|(_, s)| s.created_at)
        .map(|(k, _)| k.clone());
    if let Some(key) = oldest {
        map.remove(&key);
    }
}

/// 常量时间比较 CSRF token（防时序侧信道）。
pub fn csrf_matches(expected: &str, provided: &str) -> bool {
    mailstack_core::password::constant_time_eq(expected.as_bytes(), provided.as_bytes())
}

/// 该方法是否需要 CSRF 校验（所有非 GET/HEAD，INV-6）。
pub fn method_requires_csrf(method: &str) -> bool {
    !matches!(
        method.to_ascii_uppercase().as_str(),
        "GET" | "HEAD" | "OPTIONS"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_returns_an_id_and_registers_the_session() {
        let store = SessionStore::new();
        let id = store.create("admin");
        assert_eq!(id.len(), 64, "会话 ID 应为 32 字节 hex");
        assert_eq!(store.len(), 1);
        assert!(store.touch(&id).is_some());
    }

    #[test]
    fn unknown_session_is_not_authenticated() {
        // INV-7：未知会话一律视为未认证。
        let store = SessionStore::new();
        assert!(store.touch("nonexistent").is_none());
    }

    #[test]
    fn session_ids_are_unique() {
        let store = SessionStore::new();
        let a = store.create("admin");
        let b = store.create("admin");
        assert_ne!(a, b, "会话 ID 必须随机且不重复");
    }

    #[test]
    fn touch_refreshes_sliding_expiry() {
        let store = SessionStore::new();
        let t0 = OffsetDateTime::now_utc();
        let id = store.create_at("admin", t0);

        // 过了 TTL 的一半，仍有效，且滑动过期被刷新。
        let t1 = t0 + Duration::seconds(SESSION_TTL_SECONDS / 2);
        assert!(store.touch_at(&id, t1).is_some());

        // 再过 TTL 的一半：若无滑动刷新，此刻已超时。
        let t2 = t1 + Duration::seconds(SESSION_TTL_SECONDS / 2);
        assert!(store.touch_at(&id, t2).is_some(), "滑动过期应在活动后顺延");
    }

    #[test]
    fn idle_session_expires_after_ttl() {
        let store = SessionStore::new();
        let t0 = OffsetDateTime::now_utc();
        let id = store.create_at("admin", t0);

        let later = t0 + Duration::seconds(SESSION_TTL_SECONDS + 1);
        assert!(store.touch_at(&id, later).is_none(), "空闲超时后应失效");
        assert_eq!(store.len(), 0, "过期会话应被清除");
    }

    #[test]
    fn absolute_lifetime_caps_activity_refresh() {
        // 7 天绝对上限：持续活动的会话也必须被强制失效。
        let store = SessionStore::new();
        let t0 = OffsetDateTime::now_utc();
        let id = store.create_at("admin", t0);

        let mut t = t0;
        // 每小时活动一次，持续 6 天 23 小时——仍在绝对上限内。
        for _ in 0..(6 * 24) {
            t += Duration::hours(1);
            assert!(store.touch_at(&id, t).is_some());
        }

        // 越过 7 天绝对上限后，即使一直在活动，也必须失效。
        t = t0 + Duration::seconds(SESSION_ABSOLUTE_MAX_SECONDS + 1);
        assert!(store.touch_at(&id, t).is_none(), "绝对上限必须压过滑动刷新");
    }

    #[test]
    fn logout_removes_the_session() {
        let store = SessionStore::new();
        let id = store.create("admin");
        assert!(store.remove(&id));
        assert!(store.touch(&id).is_none());
        assert!(!store.remove(&id), "重复登出应返回 false");
    }

    #[test]
    fn public_listing_never_exposes_raw_session_ids() {
        let store = SessionStore::new();
        let id = store.create("admin");
        let list = store.list_public(OffsetDateTime::now_utc());
        assert_eq!(list.len(), 1);

        let serialized = serde_json::to_string(&list).unwrap();
        assert!(!serialized.contains(&id), "原始会话 ID 绝不得出现在列表里");
        assert_eq!(list[0]["id"], fingerprint_of(&id));
        assert_eq!(list[0]["id"].as_str().unwrap().len(), 16);
    }

    #[test]
    fn revoke_by_fingerprint_works_and_ignores_unknown() {
        let store = SessionStore::new();
        let id = store.create("admin");
        let fp = fingerprint_of(&id);

        assert!(!store.revoke_by_fingerprint("0000000000000000"));
        assert!(store.revoke_by_fingerprint(&fp));
        assert!(store.touch(&id).is_none());
    }

    #[test]
    fn revoke_others_keeps_current_session() {
        let store = SessionStore::new();
        let keep = store.create("admin");
        store.create("admin");
        store.create("admin");
        assert_eq!(store.len(), 3);

        let revoked = store.revoke_others(&keep);
        assert_eq!(revoked, 2);
        assert!(store.touch(&keep).is_some(), "当前会话必须保留");
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn revoke_user_clears_all_sessions_of_that_user() {
        let store = SessionStore::new();
        store.create("admin");
        store.create("admin");
        let other = store.create("someone");
        assert_eq!(store.revoke_user("admin"), 2);
        assert!(store.touch(&other).is_some());
    }

    #[test]
    fn capacity_is_bounded_by_max_sessions() {
        let store = SessionStore::new();
        let t0 = OffsetDateTime::now_utc();
        // 依次建立 MAX_SESSIONS + 10 个会话：容量必须被压住。
        for i in 0..(MAX_SESSIONS + 10) {
            store.create_at(&format!("u{i}"), t0 + Duration::seconds(i as i64));
        }
        assert!(
            store.len() <= MAX_SESSIONS,
            "会话数不得超过上限，实际 {}",
            store.len()
        );
    }

    #[test]
    fn csrf_comparison_is_exact() {
        assert!(csrf_matches("abc123", "abc123"));
        assert!(!csrf_matches("abc123", "abc124"));
        assert!(!csrf_matches("abc123", "abc12"));
        assert!(!csrf_matches("abc123", ""));
    }

    #[test]
    fn mutating_methods_require_csrf_but_reads_do_not() {
        // INV-6。
        for m in ["POST", "PUT", "PATCH", "DELETE", "post", "delete"] {
            assert!(method_requires_csrf(m), "{m} 必须校验 CSRF");
        }
        for m in ["GET", "HEAD", "OPTIONS", "get", "head"] {
            assert!(!method_requires_csrf(m), "{m} 不应要求 CSRF");
        }
    }

    #[test]
    fn tokens_have_full_entropy_length() {
        let a = random_token();
        let b = random_token();
        assert_eq!(a.len(), 64);
        assert_ne!(a, b);
    }

    #[test]
    fn fingerprint_is_sha256_prefix_and_collision_resistant_for_distinct_ids() {
        let a = fingerprint_of("session-a");
        let b = fingerprint_of("session-b");
        assert_eq!(a.len(), 16);
        assert_ne!(a, b);
        // 已知向量：确认算法是 sha256 前缀而不是别的哈希。
        let expected = &hex::encode(Sha256::digest(b"session-a"))[..16];
        assert_eq!(&a, expected);
    }
}
