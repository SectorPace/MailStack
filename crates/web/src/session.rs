use std::collections::HashMap;
use std::sync::Mutex;

use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};

pub const SESSION_COOKIE_SECURE_NAME: &str = "__Host-mailstack_session";

pub const SESSION_COOKIE_PLAIN_NAME: &str = "mailstack_session";

pub const SESSION_COOKIE_NAMES: &[&str] = &[SESSION_COOKIE_SECURE_NAME, SESSION_COOKIE_PLAIN_NAME];

pub const SESSION_COOKIE: &str = SESSION_COOKIE_SECURE_NAME;

pub const SESSION_COOKIE_SECURE_ENV: &str = "MAILSTACK_COOKIE_SECURE";

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

pub fn session_cookie_context(
    env_flag: Option<&str>,
    public_mode: bool,
    peer: Option<&std::net::SocketAddr>,
    headers: &axum::http::HeaderMap,
) -> (&'static str, bool) {
    let secure = session_cookie_secure(env_flag, public_mode, peer, headers);
    let name = if secure {
        SESSION_COOKIE_SECURE_NAME
    } else {
        SESSION_COOKIE_PLAIN_NAME
    };
    (name, secure)
}

fn is_trusted_proxy(peer: Option<&std::net::SocketAddr>) -> bool {
    peer.map(|addr| addr.ip().is_loopback()).unwrap_or(false)
}

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

pub const SESSION_TTL_SECONDS: i64 = 28_800;

pub const SESSION_ABSOLUTE_MAX_SECONDS: i64 = 7 * 24 * 3600;

pub const MAX_SESSIONS: usize = 5_000;

#[derive(Clone)]
pub struct Session {
    pub id: String,

    pub csrf: String,
    pub username: String,

    pub last_seen: OffsetDateTime,

    pub created_at: OffsetDateTime,

    pub fingerprint: String,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("fingerprint", &self.fingerprint)
            .field("username", &self.username)
            .field("last_seen", &self.last_seen)
            .field("created_at", &self.created_at)
            .field("id", &"<redacted>")
            .field("csrf", &"<redacted>")
            .finish()
    }
}

impl Session {
    pub fn is_expired(&self, now: OffsetDateTime) -> bool {
        let idle = now - self.last_seen;
        let age = now - self.created_at;
        idle > Duration::seconds(SESSION_TTL_SECONDS)
            || age > Duration::seconds(SESSION_ABSOLUTE_MAX_SECONDS)
    }
}

pub fn fingerprint_of(id: &str) -> String {
    let mut h = Sha256::new();
    h.update(id.as_bytes());
    hex::encode(h.finalize())[..16].to_string()
}

pub fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
    hex::encode(bytes)
}

#[derive(Debug, Default)]
pub struct SessionStore {
    inner: Mutex<HashMap<String, Session>>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn create_session(&self, username: &str) -> (String, String) {
        self.create_session_at(username, OffsetDateTime::now_utc())
    }

    pub fn create_session_at(&self, username: &str, now: OffsetDateTime) -> (String, String) {
        let id = random_token();
        let csrf = random_token();
        let session = Session {
            fingerprint: fingerprint_of(&id),
            csrf: csrf.clone(),
            username: username.to_string(),
            last_seen: now,
            created_at: now,
            id: id.clone(),
        };

        let mut map = self.lock();

        map.retain(|_, s| !s.is_expired(now));
        if map.len() >= MAX_SESSIONS {
            evict_oldest(&mut map);
        }
        map.insert(id.clone(), session);
        (id, csrf)
    }

    pub fn create(&self, username: &str) -> String {
        self.create_at(username, OffsetDateTime::now_utc())
    }

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

        map.retain(|_, s| !s.is_expired(now));
        if map.len() >= MAX_SESSIONS {
            evict_oldest(&mut map);
        }
        map.insert(id.clone(), session);
        id
    }

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

        if now > session.last_seen {
            session.last_seen = now;
        }
        Some(session.clone())
    }

    pub fn remove(&self, id: &str) -> bool {
        self.lock().remove(id).is_some()
    }

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

    pub fn revoke_others(&self, keep_id: &str) -> usize {
        let mut map = self.lock();
        let before = map.len();
        map.retain(|k, _| k == keep_id);
        before - map.len()
    }

    pub fn revoke_user(&self, username: &str) -> usize {
        let mut map = self.lock();
        let before = map.len();
        map.retain(|_, s| s.username != username);
        before - map.len()
    }

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

fn evict_oldest(map: &mut HashMap<String, Session>) {
    let oldest = map
        .iter()
        .min_by_key(|(_, s)| s.created_at)
        .map(|(k, _)| k.clone());
    if let Some(key) = oldest {
        map.remove(&key);
    }
}

pub fn csrf_matches(expected: &str, provided: &str) -> bool {
    mailstack_core::password::constant_time_eq(expected.as_bytes(), provided.as_bytes())
}

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
    fn a_clock_rollback_cannot_extend_a_session_past_its_ttl() {
        let store = SessionStore::new();
        let t0 = OffsetDateTime::now_utc();
        let id = store.create_at("admin", t0);

        let used = t0 + Duration::hours(1);
        let touched = store.touch_at(&id, used).expect("正常活动应有效");
        assert_eq!(touched.last_seen, used);

        let rolled_back = t0 + Duration::minutes(5);
        let after = store
            .touch_at(&id, rolled_back)
            .expect("刚活动过，回拨不该立刻失效");
        assert!(
            after.last_seen >= used,
            "活动时刻被拨回去了：{} → {}",
            used,
            after.last_seen
        );

        let past = after.last_seen + Duration::seconds(SESSION_TTL_SECONDS + 1);
        assert!(
            store.touch_at(&id, past).is_none(),
            "回拨之后仍必须按滑动 TTL 过期"
        );
    }

    #[test]
    fn debug_output_redacts_the_session_id_and_the_csrf_token() {
        let store = SessionStore::new();
        let (id, csrf) = store.create_session("admin");
        let session = store.touch(&id).expect("刚建的会话应有效");

        let rendered = format!("{session:?}");
        assert!(
            !rendered.contains(&id),
            "Debug 泄露了会话 ID（拿到它即可冒用）：{rendered}"
        );
        assert!(
            !rendered.contains(&csrf),
            "Debug 泄露了 CSRF token：{rendered}"
        );
        assert!(
            rendered.contains(&session.fingerprint),
            "指纹是对外可暴露的那一份，应当仍在：{rendered}"
        );
    }

    #[test]
    fn create_session_returns_a_usable_id_and_a_non_empty_csrf() {
        let store = SessionStore::new();
        for _ in 0..64 {
            let (id, csrf) = store.create_session("admin");
            assert_eq!(id.len(), 64, "会话 ID 应为 32 字节 hex");
            assert_eq!(csrf.len(), 64, "csrf 应为 32 字节 hex");
            assert!(!csrf.is_empty());
            let stored = store.touch(&id).expect("刚建的会话应有效");
            assert_eq!(stored.csrf, csrf, "返回的 csrf 必须与表里那一份逐字一致");
        }
    }

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

        let t1 = t0 + Duration::seconds(SESSION_TTL_SECONDS / 2);
        assert!(store.touch_at(&id, t1).is_some());

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
        let store = SessionStore::new();
        let t0 = OffsetDateTime::now_utc();
        let id = store.create_at("admin", t0);

        let mut t = t0;

        for _ in 0..(6 * 24) {
            t += Duration::hours(1);
            assert!(store.touch_at(&id, t).is_some());
        }

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

        let expected = &hex::encode(Sha256::digest(b"session-a"))[..16];
        assert_eq!(&a, expected);
    }

    #[test]
    fn the_cookie_name_follows_the_secure_decision() {
        let (name, secure) =
            session_cookie_context(None, false, None, &axum::http::HeaderMap::new());
        assert_eq!(name, SESSION_COOKIE_PLAIN_NAME);
        assert!(!secure);

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "x-forwarded-proto",
            axum::http::HeaderValue::from_static("https"),
        );
        let peer: std::net::SocketAddr = "127.0.0.1:8443".parse().unwrap();
        let (name, secure) = session_cookie_context(None, false, Some(&peer), &headers);
        assert_eq!(name, SESSION_COOKIE_SECURE_NAME);
        assert!(secure);

        let (name, secure) =
            session_cookie_context(None, true, None, &axum::http::HeaderMap::new());
        assert_eq!(name, SESSION_COOKIE_SECURE_NAME);
        assert!(secure);

        assert_ne!(
            SESSION_COOKIE_SECURE_NAME, SESSION_COOKIE_PLAIN_NAME,
            "两个条件性名字不得撞名，否则前缀保护形同虚设"
        );
    }
}
