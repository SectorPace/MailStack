//! 登录限流（独立实现，不依赖 `crates/web`）。
//!
//! 契约 §1.1 要求「每 IP + 每登录名失败计数（指数退避窗口）」，超限回
//! `429 {"error":{"code":"TOO_MANY_ATTEMPTS"}}`。这里把它拆成两个互补的闸：
//!
//! 1. **失败锁定（指数退避）**：连续失败达到阈值后，该键被锁 `30s → 60s → …`
//!    （封顶 15 分钟）。这是对已知账号/来源的持续猜解的直接压制。
//! 2. **尝试窗口**：每个键每 60 秒最多 30 次**尝试**（成功失败都算）。单靠第 1
//!    条挡不住「一个 IP 对 10 万个登录名各试一次」的撞库——每个登录名都只有 1 次
//!    失败，永远到不了阈值。
//!
//! ## 键的处理
//!
//! * 键来自匿名请求体，必须先截断（[`MAX_LOGIN_KEY_LEN`]）再入表；
//! * 表有硬上限（[`MAX_TRACKED_LOGIN_KEYS`]），到达上限时按最旧窗口淘汰，
//!   而不是「满了就拒新键」（那会让攻击者先占满表、把真实用户锁在门外）；
//! * 被拒绝的请求**不写入任何状态**——否则 429 本身也成了状态放大器。
//!
//! 计时口径：判定在 PBKDF2 **之前**（否则一次撞库就能用 31 万次迭代把 CPU
//! 打满）；而认证失败后的 401 响应时间不得早于一次 PBKDF2——那条约束由
//! [`crate::account::AccountDirectory::authenticate`] 保证，与本模块无关。

use std::collections::HashMap;
use std::sync::Mutex;

use time::OffsetDateTime;

use crate::{
    LOGIN_ATTEMPTS_PER_WINDOW, LOGIN_BASE_LOCK_SECONDS, LOGIN_FAILURE_THRESHOLD,
    LOGIN_MAX_LOCK_SECONDS, LOGIN_WINDOW_SECONDS, MAX_LOGIN_KEY_LEN, MAX_TRACKED_LOGIN_KEYS,
};

/// 限流判决。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThrottleDecision {
    /// 放行（允许继续做真正的口令校验）。
    Allow,
    /// 拒绝，`retry_after_secs` 用于 `Retry-After` 头与 429 响应。
    Limited { retry_after_secs: i64 },
}

impl ThrottleDecision {
    pub fn is_allowed(self) -> bool {
        matches!(self, ThrottleDecision::Allow)
    }
}

/// 一个键的状态。
#[derive(Debug, Clone, Default)]
struct KeyState {
    /// 窗口起点（Unix 秒）。
    window_start: i64,
    /// 当前窗口内的尝试次数。
    attempts: u32,
    /// 连续失败次数。
    failures: u32,
    /// 锁定截止时刻（Unix 秒）；0 = 未锁定。
    locked_until: i64,
    /// 最近一次失败时刻（Unix 秒）；用于「长期无失败才重置退避档位」。
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

    /// 记录一次尝试（只在该次尝试被放行后调用）。
    fn record_attempt(&mut self, now: i64) {
        if now.saturating_sub(self.window_start) >= LOGIN_WINDOW_SECONDS {
            self.window_start = now;
            self.attempts = 0;
        }
        self.attempts = self.attempts.saturating_add(1);
    }

    fn record_failure(&mut self, now: i64) {
        // 锁定过期只清 `locked_until`，**不清** `failures` —— 指数退避必须跨锁定生效
        // （30s → 60s → 120s …，封顶 900s）。若每次锁定期满就把计数清零，攻击者
        // 只要等一期就能回到 30s 档，退避形同虚设。
        // 只有「24 小时内一次失败都没有」才真正重置档位，避免偶发失败永久抬价。
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
            // 30s, 60s, 120s, ... 封顶 900s。越界的移位直接按上限处理，避免溢出。
            let multiplier = 1i64.checked_shl(over.min(16)).unwrap_or(i64::MAX);
            let lock = LOGIN_BASE_LOCK_SECONDS
                .saturating_mul(multiplier)
                .min(LOGIN_MAX_LOCK_SECONDS);
            self.locked_until = now.saturating_add(lock);
        }
    }
}

/// 登录限流器（进程内内存表）。
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

    /// 判定本次登录尝试是否放行。IP 与登录名**两个键都要过**。
    pub fn check(&self, ip: &str, login: &str) -> ThrottleDecision {
        self.check_at(ip, login, unix_now())
    }

    /// 可注入时钟的版本（测试用）。
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

    /// 记录一次**被放行**的尝试（成功与失败都要记，窗口才不会失效）。
    pub fn record_attempt(&self, ip: &str, login: &str) {
        self.record_attempt_at(ip, login, unix_now());
    }

    pub fn record_attempt_at(&self, ip: &str, login: &str, now: i64) {
        let ip_key = normalized_key(ip);
        let login_key = normalized_key(login);
        let mut state = self.lock();
        {
            // 通过 MutexGuard 的两次 `&mut` 无法同时存在（两次解引用都借用了
            // guard 本身），因此两个键分开取。
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

    /// 记录一次认证失败（同时推进两个键的连续失败计数）。
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
        // IP 的失败计数刻意不因「某个账号成功」而清零：否则攻击者只要掌握任意
        // 一个有效账号，就能在每次失败后用它重置 IP 计数，per-IP 防护形同虚设。
        state.evict_if_needed(now);
    }

    /// 记录一次认证成功：清除**该登录名**的失败计数与锁定。
    pub fn record_success(&self, login: &str) {
        let login_key = normalized_key(login);
        self.lock().by_login.remove(&login_key);
    }

    /// 当前是否处于锁定状态（诊断/测试用）。
    pub fn is_limited(&self, ip: &str, login: &str) -> bool {
        !self.check(ip, login).is_allowed()
    }

    /// 清空全部状态（测试用）。
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
    /// 表顶到上限时清扫过期项；仍超则淘汰最旧窗口的键。
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

/// 键规范化：去空白、转小写、截断到 [`MAX_LOGIN_KEY_LEN`]。
///
/// 截断必须落在 char 边界上，否则一个多字节字符被切断会 panic。登录名正常是
/// 邮箱地址（ASCII），但输入来自匿名请求体，不能假设。
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

/// 限流器使用的当前 Unix 秒（测试可注入 [`LoginThrottle::check_at`] 等版本）。
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

        // 同一时刻记录到阈值：锁定从最后一次失败起算，check 时刻 = 失败时刻。
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

        // 锁定期满后放行；再失败一次 → 处罚档位升级，锁定翻倍。
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
        // 登录名键已清：换一个从未失败过的来源用同一账号登录必须放行。
        assert!(
            throttle
                .check_at("5.6.7.8", "alice@example.com", t0 + 10)
                .is_allowed(),
            "成功登录必须清除登录名的失败锁定"
        );
        // 原 IP 键仍保留：同 IP 的其它账号继续被拦（防「用一个有效账号刷掉 IP 计数」）。
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
        // 截断后的键与超长键命中同一个桶。
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
