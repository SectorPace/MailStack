use std::collections::HashMap;
use std::sync::Mutex;

use time::OffsetDateTime;

use crate::{
    LOGIN_ATTEMPTS_PER_WINDOW, LOGIN_BASE_LOCK_SECONDS, LOGIN_FAILURE_THRESHOLD,
    LOGIN_MAX_LOCK_SECONDS, LOGIN_WINDOW_SECONDS, MAX_LOGIN_KEY_LEN, MAX_TRACKED_LOGIN_KEYS,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThrottleDecision {
    Allow,

    Limited { retry_after_secs: i64 },
}

impl ThrottleDecision {
    pub fn is_allowed(self) -> bool {
        matches!(self, ThrottleDecision::Allow)
    }
}

#[derive(Debug, Clone, Default)]
struct KeyState {
    window_start: i64,

    attempts: u32,

    failures: u32,

    locked_until: i64,

    last_failure: i64,
}

impl KeyState {
    fn window_verdict(&self, now: i64) -> ThrottleDecision {
        let elapsed = now.saturating_sub(self.window_start);
        if elapsed < LOGIN_WINDOW_SECONDS && self.attempts >= LOGIN_ATTEMPTS_PER_WINDOW {
            return ThrottleDecision::Limited {
                retry_after_secs: (LOGIN_WINDOW_SECONDS - elapsed).max(1),
            };
        }
        ThrottleDecision::Allow
    }

    fn lock_verdict(&self, now: i64) -> ThrottleDecision {
        if self.locked_until > now {
            return ThrottleDecision::Limited {
                retry_after_secs: (self.locked_until - now).max(1),
            };
        }
        ThrottleDecision::Allow
    }

    fn record_attempt(&mut self, now: i64) {
        if now.saturating_sub(self.window_start) >= LOGIN_WINDOW_SECONDS {
            self.window_start = now;
            self.attempts = 0;
        }
        self.attempts = self.attempts.saturating_add(1);
    }

    fn record_failure(&mut self, now: i64) {
        if self.last_failure != 0 && now.saturating_sub(self.last_failure) > 86_400 {
            self.failures = 0;
        }
        if self.locked_until != 0 && now >= self.locked_until {
            self.locked_until = 0;
        }
        self.last_failure = now;
        self.failures = self.failures.saturating_add(1);
        if self.failures >= LOGIN_FAILURE_THRESHOLD {
            let over = self.failures - LOGIN_FAILURE_THRESHOLD;

            let multiplier = 1i64.checked_shl(over.min(16)).unwrap_or(i64::MAX);
            let lock = LOGIN_BASE_LOCK_SECONDS
                .saturating_mul(multiplier)
                .min(LOGIN_MAX_LOCK_SECONDS);
            self.locked_until = now.saturating_add(lock);
        }
    }
}

#[derive(Debug, Default)]
pub struct LoginThrottle {
    inner: Mutex<ThrottleState>,
}

#[derive(Debug, Default)]
struct ThrottleState {
    by_ip: HashMap<String, KeyState>,
    by_login: HashMap<String, KeyState>,
}

impl LoginThrottle {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn check(&self, ip: &str, login: &str) -> ThrottleDecision {
        self.check_at(ip, login, unix_now())
    }

    pub fn check_at(&self, ip: &str, login: &str, now: i64) -> ThrottleDecision {
        let ip_key = normalized_key(ip);
        let login_key = normalized_key(login);
        let state = self.lock();

        for (map, key) in [(&state.by_ip, &ip_key), (&state.by_login, &login_key)] {
            if let Some(entry) = map.get(key.as_str()) {
                let verdict = entry.lock_verdict(now);
                if !verdict.is_allowed() {
                    return verdict;
                }
                let verdict = entry.window_verdict(now);
                if !verdict.is_allowed() {
                    return verdict;
                }
            }
        }
        ThrottleDecision::Allow
    }

    pub fn record_attempt(&self, ip: &str, login: &str) {
        self.record_attempt_at(ip, login, unix_now());
    }

    pub fn record_attempt_at(&self, ip: &str, login: &str, now: i64) {
        let ip_key = normalized_key(ip);
        let login_key = normalized_key(login);
        let mut state = self.lock();
        {
            let entry = state.by_ip.entry(ip_key).or_default();
            if entry.window_start == 0 {
                entry.window_start = now;
            }
            entry.record_attempt(now);
        }
        {
            let entry = state.by_login.entry(login_key).or_default();
            if entry.window_start == 0 {
                entry.window_start = now;
            }
            entry.record_attempt(now);
        }
        state.evict_if_needed(now);
    }

    pub fn record_failure(&self, ip: &str, login: &str) {
        self.record_failure_at(ip, login, unix_now());
    }

    pub fn record_failure_at(&self, ip: &str, login: &str, now: i64) {
        let ip_key = normalized_key(ip);
        let login_key = normalized_key(login);
        let mut state = self.lock();
        state.by_ip.entry(ip_key).or_default().record_failure(now);
        state
            .by_login
            .entry(login_key)
            .or_default()
            .record_failure(now);

        state.evict_if_needed(now);
    }

    pub fn record_success(&self, login: &str) {
        let login_key = normalized_key(login);
        self.lock().by_login.remove(&login_key);
    }

    pub fn is_limited(&self, ip: &str, login: &str) -> bool {
        !self.check(ip, login).is_allowed()
    }

    #[doc(hidden)]
    pub fn reset(&self) {
        let mut state = self.lock();
        *state = ThrottleState::default();
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ThrottleState> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl ThrottleState {
    fn evict_if_needed(&mut self, now: i64) {
        if self.by_ip.len() <= MAX_TRACKED_LOGIN_KEYS
            && self.by_login.len() <= MAX_TRACKED_LOGIN_KEYS
        {
            return;
        }
        for map in [&mut self.by_ip, &mut self.by_login] {
            map.retain(|_, entry| {
                entry.locked_until > now
                    || now.saturating_sub(entry.window_start) < LOGIN_WINDOW_SECONDS
            });
            while map.len() > MAX_TRACKED_LOGIN_KEYS {
                let oldest = map
                    .iter()
                    .min_by_key(|(_, entry)| entry.window_start)
                    .map(|(key, _)| key.clone());
                match oldest {
                    Some(key) => {
                        map.remove(&key);
                    }
                    None => break,
                }
            }
        }
    }
}

fn normalized_key(value: &str) -> String {
    let trimmed = value.trim().to_ascii_lowercase();
    if trimmed.len() <= MAX_LOGIN_KEY_LEN {
        return trimmed;
    }
    let mut end = MAX_LOGIN_KEY_LEN;
    while !trimmed.is_char_boundary(end) {
        end -= 1;
    }
    trimmed[..end].to_string()
}

#[doc(hidden)]
pub fn unix_now() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_failures_trigger_an_exponential_lock() {
        let throttle = LoginThrottle::new();
        let t0 = unix_now();
        assert!(throttle
            .check_at("1.2.3.4", "alice@example.com", t0)
            .is_allowed());

        for _ in 0..LOGIN_FAILURE_THRESHOLD {
            throttle.record_failure_at("1.2.3.4", "alice@example.com", t0);
        }
        let verdict = throttle.check_at("1.2.3.4", "alice@example.com", t0);
        assert!(!verdict.is_allowed(), "连续失败达到阈值后必须拒绝");

        match verdict {
            ThrottleDecision::Limited { retry_after_secs } => {
                assert_eq!(retry_after_secs, LOGIN_BASE_LOCK_SECONDS)
            }
            ThrottleDecision::Allow => panic!("应处于锁定"),
        }

        let after = t0 + LOGIN_BASE_LOCK_SECONDS + 1;
        assert!(throttle
            .check_at("1.2.3.4", "alice@example.com", after)
            .is_allowed());
        throttle.record_failure_at("1.2.3.4", "alice@example.com", after);
        match throttle.check_at("1.2.3.4", "alice@example.com", after) {
            ThrottleDecision::Limited { retry_after_secs } => {
                assert_eq!(
                    retry_after_secs,
                    LOGIN_BASE_LOCK_SECONDS * 2,
                    "第二次锁定必须指数退避（60s）"
                );
            }
            ThrottleDecision::Allow => panic!("应处于锁定"),
        }
    }

    #[test]
    fn a_success_clears_only_the_login_key_not_the_ip_key() {
        let throttle = LoginThrottle::new();
        let t0 = unix_now();
        for index in 0..LOGIN_FAILURE_THRESHOLD {
            throttle.record_failure_at("1.2.3.4", "alice@example.com", t0 + index as i64);
        }
        let blocked = throttle.check_at("1.2.3.4", "alice@example.com", t0 + 10);
        assert!(!blocked.is_allowed());

        throttle.record_success("alice@example.com");

        assert!(
            throttle
                .check_at("5.6.7.8", "alice@example.com", t0 + 10)
                .is_allowed(),
            "成功登录必须清除登录名的失败锁定"
        );

        let other = throttle.check_at("1.2.3.4", "bob@example.com", t0 + 10);
        assert!(!other.is_allowed(), "IP 键不得因某个账号成功而清零");
    }

    #[test]
    fn the_attempt_window_stops_one_ip_from_probing_many_accounts() {
        let throttle = LoginThrottle::new();
        let t0 = unix_now();
        for index in 0..LOGIN_ATTEMPTS_PER_WINDOW {
            throttle.record_attempt_at("9.9.9.9", &format!("user{index}@example.com"), t0);
        }
        let verdict = throttle.check_at("9.9.9.9", "brand-new@example.com", t0 + 1);
        match verdict {
            ThrottleDecision::Limited { retry_after_secs } => {
                assert!(retry_after_secs > 0)
            }
            ThrottleDecision::Allow => panic!("同一 IP 的尝试窗口必须挡住撞库"),
        }
    }

    #[test]
    fn an_over_long_login_key_is_truncated_instead_of_growing_the_table() {
        let throttle = LoginThrottle::new();
        let t0 = unix_now();
        let huge = "a".repeat(10_000);
        for _ in 0..LOGIN_FAILURE_THRESHOLD {
            throttle.record_failure_at("1.1.1.1", &huge, t0);
        }

        assert!(!throttle.check_at("1.1.1.1", &huge, t0).is_allowed());
        assert!(max_key_len(&throttle) <= MAX_LOGIN_KEY_LEN);
    }

    #[test]
    fn the_lock_cap_is_respected_after_many_failures() {
        let throttle = LoginThrottle::new();
        let t0 = unix_now();
        for index in 0..200 {
            throttle.record_failure_at("1.2.3.4", "alice@example.com", t0 + index as i64);
        }
        match throttle.check_at("1.2.3.4", "alice@example.com", t0 + 200) {
            ThrottleDecision::Limited { retry_after_secs } => {
                assert!(
                    retry_after_secs <= LOGIN_MAX_LOCK_SECONDS,
                    "锁定不得突破上限：{retry_after_secs}"
                );
            }
            ThrottleDecision::Allow => panic!("应处于锁定"),
        }
    }

    fn max_key_len(throttle: &LoginThrottle) -> usize {
        let state = throttle.lock();
        state
            .by_login
            .keys()
            .chain(state.by_ip.keys())
            .map(String::len)
            .max()
            .unwrap_or(0)
    }
}
