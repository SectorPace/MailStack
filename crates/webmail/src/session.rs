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

pub const SESSION_COOKIE_SECURE_NAME: &str = "__Host-mailstack_mail";

pub const SESSION_COOKIE_PLAIN_NAME: &str = "mailstack_mail";

pub const SESSION_COOKIE_NAMES: [&str; 2] = [SESSION_COOKIE_SECURE_NAME, SESSION_COOKIE_PLAIN_NAME];

pub const SESSION_COOKIE_SECURE_ENV: &str = "MAILSTACK_COOKIE_SECURE";

pub const EPOCH_FILE_MAX_BYTES: u64 = 1024 * 1024;

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
        return false;
    }
    forwarded_proto(headers).as_deref() == Some("https")
}

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

pub fn build_session_cookie(name: &str, secure: bool, token: &str) -> HeaderValue {
    let mut value = format!(
        "{name}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_ABSOLUTE_MAX_SECONDS}"
    );
    if secure {
        value.push_str("; Secure");
    }
    HeaderValue::from_str(&value).unwrap_or_else(|_| HeaderValue::from_static("mailstack_mail="))
}

pub fn clear_session_cookie(name: &str, secure: bool) -> HeaderValue {
    let mut value =
        format!("{name}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT");
    if secure {
        value.push_str("; Secure");
    }
    HeaderValue::from_str(&value).unwrap_or_else(|_| HeaderValue::from_static("mailstack_mail="))
}

pub fn method_requires_csrf(method: &Method) -> bool {
    !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

pub fn csrf_matches(expected: &str, provided: &str) -> bool {
    constant_time_eq(expected.as_bytes(), provided.as_bytes())
}

pub fn token_fingerprint(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

pub fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
    hex::encode(bytes)
}

#[derive(Clone)]
pub struct Session {
    pub token_fingerprint: String,

    pub csrf: String,

    pub account: Account,

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
    pub fn is_expired(&self, now: OffsetDateTime) -> bool {
        let idle = now - self.last_seen;
        let age = now - self.created_at;
        idle > Duration::seconds(SESSION_TTL_SECONDS)
            || age > Duration::seconds(SESSION_ABSOLUTE_MAX_SECONDS)
    }
}

#[derive(Debug, Default)]
pub struct SessionStore {
    inner: Mutex<HashMap<String, Session>>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self::default()
    }

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

    pub fn get(&self, token: &str, now: OffsetDateTime) -> Option<Session> {
        let key = token_fingerprint(token);
        let mut map = self.lock();
        let session = map.get_mut(&key)?;
        if session.is_expired(now) {
            map.remove(&key);
            return None;
        }

        if now > session.last_seen {
            session.last_seen = now;
        }
        Some(session.clone())
    }

    pub fn remove(&self, token: &str) -> bool {
        self.lock().remove(&token_fingerprint(token)).is_some()
    }

    pub fn remove_by_fingerprint(&self, fingerprint: &str) -> bool {
        self.lock().remove(fingerprint).is_some()
    }

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

fn evict_oldest(map: &mut HashMap<String, Session>) {
    let oldest = map
        .iter()
        .min_by_key(|(_, session)| session.created_at)
        .map(|(key, _)| key.clone());
    if let Some(key) = oldest {
        map.remove(&key);
    }
}

#[derive(Debug, Default)]
struct EpochCache {
    fingerprint: Option<(SystemTime, u64)>,

    epochs: HashMap<String, u64>,
}

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

pub fn append_set_cookie(response: &mut axum::response::Response, cookie: HeaderValue) {
    response.headers_mut().append(header::SET_COOKIE, cookie);
}

pub fn host_header(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
}

pub fn origin_matches_host(headers: &HeaderMap) -> bool {
    let Some(origin) = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    else {
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

pub fn cookie_secure_env() -> Option<String> {
    std::env::var(SESSION_COOKIE_SECURE_ENV).ok()
}

pub type EpochCheck = WebmailResult<u64>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn webmail_session_epoch_bump_invalidates_existing_sessions() {
        let dir = tempfile::tempdir().unwrap();
        let epoch_path = dir.path().join("webmail-session-epoch.json");
        let store = EpochStore::new(&epoch_path);
        assert_eq!(store.current("alice@example.com"), 0, "文件缺失时纪元为 0");

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

        let half = t0 + Duration::seconds(SESSION_TTL_SECONDS / 2);
        assert!(sessions.get(&token, half).is_some());
        let later = half + Duration::seconds(SESSION_TTL_SECONDS / 2);
        assert!(sessions.get(&token, later).is_some(), "滑动过期应顺延");

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
