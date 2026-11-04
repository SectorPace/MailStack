use std::collections::HashMap;
use std::sync::Mutex;

use time::{Duration, OffsetDateTime};

pub const GLOBAL_LIMIT_PER_MINUTE: u32 = 600;

pub const IP_LIMIT_PER_MINUTE: u32 = 20;

pub const ACCOUNT_LIMIT_PER_MINUTE: u32 = 10;

pub const FAILURE_LOCKOUT_THRESHOLD: u32 = 5;

pub const LOCKOUT_SECONDS: i64 = 900;

pub const LOCKOUT_ESCALATION_SECONDS: &[i64] = &[900, 3_600, 21_600];

pub const LOCKOUT_ESCALATION_WINDOW_SECONDS: i64 = 24 * 3_600;

pub const MAX_KEY_LEN: usize = 256;

pub const MAX_TRACKED_KEYS: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bucket {
    Global,
    Ip,
    Account,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LimitVerdict {
    Allow,

    Limited { retry_after_secs: i64 },
}

impl LimitVerdict {
    pub fn is_allowed(&self) -> bool {
        matches!(self, LimitVerdict::Allow)
    }
}

#[derive(Debug, Clone)]
struct Counter {
    window_start: OffsetDateTime,
    count: u32,
}

impl Counter {
    fn new(now: OffsetDateTime) -> Self {
        Self {
            window_start: now,
            count: 0,
        }
    }
}

#[derive(Debug, Default)]
pub struct LoginLimiter {
    inner: Mutex<LimiterState>,
}

#[derive(Debug, Default)]
struct LimiterState {
    global: Option<Counter>,
    by_ip: HashMap<String, Counter>,
    by_account: HashMap<String, Counter>,

    failures: HashMap<(String, String), FailureRecord>,
}

#[derive(Debug, Clone)]
struct FailureRecord {
    failures: u32,

    locked_until: Option<OffsetDateTime>,

    lockouts: u32,

    window_start: OffsetDateTime,
}

impl FailureRecord {
    fn new(now: OffsetDateTime) -> Self {
        Self {
            failures: 0,
            locked_until: None,
            lockouts: 0,
            window_start: now,
        }
    }

    fn lock_seconds(&self) -> i64 {
        let index =
            (self.lockouts.saturating_sub(1) as usize).min(LOCKOUT_ESCALATION_SECONDS.len() - 1);
        LOCKOUT_ESCALATION_SECONDS[index]
    }
}

impl LoginLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn check(&self, ip: &str, account: &str) -> LimitVerdict {
        self.check_at(ip, account, OffsetDateTime::now_utc())
    }

    pub fn check_at(&self, ip: &str, account: &str, now: OffsetDateTime) -> LimitVerdict {
        let mut state = self.lock();

        let ip_key = sanitized(ip);
        let account_key = sanitized(account);
        let source_key = (ip_key.to_string(), account_key.to_string());

        if let Some(record) = state.failures.get_mut(&source_key) {
            if let Some(until) = record.locked_until {
                if until > now {
                    return LimitVerdict::Limited {
                        retry_after_secs: (until - now).whole_seconds().max(1),
                    };
                }

                record.locked_until = None;
                record.failures = 0;
                if now - record.window_start >= Duration::seconds(LOCKOUT_ESCALATION_WINDOW_SECONDS)
                {
                    record.lockouts = 0;
                    record.window_start = now;
                }
            }
        }

        let global_verdict = match state.global.as_mut() {
            Some(counter) => counter.peek(now, GLOBAL_LIMIT_PER_MINUTE),
            None => LimitVerdict::Allow,
        };
        let ip_verdict = match state.by_ip.get_mut(ip_key.as_ref()) {
            Some(counter) => counter.peek(now, IP_LIMIT_PER_MINUTE),
            None => LimitVerdict::Allow,
        };
        let account_verdict = match state.by_account.get_mut(account_key.as_ref()) {
            Some(counter) => counter.peek(now, ACCOUNT_LIMIT_PER_MINUTE),
            None => LimitVerdict::Allow,
        };

        for verdict in [&global_verdict, &ip_verdict, &account_verdict] {
            if let LimitVerdict::Limited { retry_after_secs } = verdict {
                return LimitVerdict::Limited {
                    retry_after_secs: *retry_after_secs,
                };
            }
        }

        let global = state.global.get_or_insert_with(|| Counter::new(now));
        global.count += 1;
        state
            .by_ip
            .entry(ip_key.into_owned())
            .or_insert_with(|| Counter::new(now))
            .count += 1;
        state
            .by_account
            .entry(account_key.into_owned())
            .or_insert_with(|| Counter::new(now))
            .count += 1;

        if state.by_ip.len() > MAX_TRACKED_KEYS
            || state.by_account.len() > MAX_TRACKED_KEYS
            || state.failures.len() > MAX_TRACKED_KEYS
        {
            state.evict_expired(now);
        }
        LimitVerdict::Allow
    }

    pub fn record_failure(&self, ip: &str, account: &str) {
        self.record_failure_at(ip, account, OffsetDateTime::now_utc());
    }

    pub fn record_failure_at(&self, ip: &str, account: &str, now: OffsetDateTime) {
        let mut state = self.lock();

        let source_key = (sanitized(ip).into_owned(), sanitized(account).into_owned());
        let record = state
            .failures
            .entry(source_key)
            .or_insert_with(|| FailureRecord::new(now));

        if now - record.window_start >= Duration::seconds(LOCKOUT_ESCALATION_WINDOW_SECONDS) {
            record.lockouts = 0;
            record.window_start = now;
        }
        record.failures = record.failures.saturating_add(1);
        if record.failures >= FAILURE_LOCKOUT_THRESHOLD {
            record.lockouts = record.lockouts.saturating_add(1);
            record.locked_until = Some(now + Duration::seconds(record.lock_seconds()));
            record.failures = 0;
        }

        if state.failures.len() > MAX_TRACKED_KEYS {
            state.evict_expired(now);
        }
    }

    pub fn record_success(&self, ip: &str, account: &str) {
        let key = (sanitized(ip).into_owned(), sanitized(account).into_owned());
        self.lock().failures.remove(&key);
    }

    pub fn is_locked(&self, account: &str) -> bool {
        self.is_locked_at(account, OffsetDateTime::now_utc())
    }

    pub fn is_locked_at(&self, account: &str, now: OffsetDateTime) -> bool {
        let state = self.lock();
        let account_key = sanitized(account);
        state.failures.iter().any(|((_, stored_account), record)| {
            stored_account.as_str() == account_key.as_ref()
                && matches!(record.locked_until, Some(until) if until > now)
        })
    }

    pub fn is_locked_from(&self, ip: &str, account: &str, now: OffsetDateTime) -> bool {
        let state = self.lock();
        let key = (sanitized(ip).into_owned(), sanitized(account).into_owned());
        matches!(
            state.failures.get(&key).and_then(|record| record.locked_until),
            Some(until) if until > now
        )
    }

    pub fn lockouts_from(&self, ip: &str, account: &str) -> u32 {
        let state = self.lock();
        let key = (sanitized(ip).into_owned(), sanitized(account).into_owned());
        state
            .failures
            .get(&key)
            .map(|record| record.lockouts)
            .unwrap_or(0)
    }

    #[doc(hidden)]
    pub fn reset(&self) {
        let mut state = self.lock();
        *state = LimiterState::default();
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, LimiterState> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }
}

impl LimiterState {
    fn evict_expired(&mut self, now: OffsetDateTime) {
        let window = Duration::minutes(1);
        self.by_ip.retain(|_, c| now - c.window_start < window);
        self.by_account.retain(|_, c| now - c.window_start < window);

        self.failures.retain(|_, record| {
            matches!(record.locked_until, Some(until) if until > now) || record.failures > 0
        });

        for map in [&mut self.by_ip, &mut self.by_account] {
            while map.len() > MAX_TRACKED_KEYS {
                let Some(oldest) = map
                    .iter()
                    .min_by_key(|(_, c)| c.window_start)
                    .map(|(k, _)| k.clone())
                else {
                    break;
                };
                map.remove(&oldest);
            }
        }
        while self.failures.len() > MAX_TRACKED_KEYS {
            let Some(victim) = self
                .failures
                .iter()
                .find(|(_, record)| record.locked_until.is_none())
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            self.failures.remove(&victim);
        }
    }
}

fn sanitized(key: &str) -> std::borrow::Cow<'_, str> {
    if key.len() <= MAX_KEY_LEN {
        return std::borrow::Cow::Borrowed(key);
    }

    let cut = key
        .char_indices()
        .map(|(i, _)| i)
        .take_while(|i| *i <= MAX_KEY_LEN)
        .last()
        .unwrap_or(0);
    std::borrow::Cow::Owned(format!("{}\u{0}", &key[..cut]))
}

impl Counter {
    fn peek(&mut self, now: OffsetDateTime, limit: u32) -> LimitVerdict {
        if now - self.window_start >= Duration::minutes(1) {
            self.window_start = now;
            self.count = 0;
        }
        if self.count >= limit {
            let elapsed = (now - self.window_start).whole_seconds();
            return LimitVerdict::Limited {
                retry_after_secs: (60 - elapsed).max(1),
            };
        }
        LimitVerdict::Allow
    }
}

pub const ERR_INVALID_CREDENTIALS: &str = "INVALID_CREDENTIALS";

pub const ERR_TOTP_REQUIRED: &str = "TOTP_REQUIRED";

pub const ERR_REQUEST_FAILED: &str = "REQUEST_FAILED";

pub const ERR_LOGIN_FAILED: &str = "LOGIN_FAILED";

pub const ERR_AUTH_REQUIRED: &str = "AUTH_REQUIRED";

pub const ERR_CSRF_INVALID: &str = "CSRF_INVALID";

pub const ERR_RATE_LIMITED: &str = "RATE_LIMITED";

pub const ERR_ENROLL_WINDOW_ACTIVE: &str = "ENROLL_WINDOW_ACTIVE";

pub const ERR_API_NOT_FOUND: &str = "API_NOT_FOUND";

pub const ERR_PAYLOAD_TOO_LARGE: &str = "PAYLOAD_TOO_LARGE";

pub const ERR_INTERNAL_ERROR: &str = "INTERNAL_ERROR";

pub const ERR_PRIVILEGED_HELPER_UNAVAILABLE: &str = "PRIVILEGED_HELPER_UNAVAILABLE";

pub const ERR_PRIVILEGED_OPERATION_FAILED: &str = "PRIVILEGED_OPERATION_FAILED";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_normal_traffic() {
        let limiter = LoginLimiter::new();
        for _ in 0..5 {
            assert!(limiter.check("1.2.3.4", "admin").is_allowed());
        }
    }

    #[test]
    fn per_account_bucket_trips_after_limit() {
        let limiter = LoginLimiter::new();
        let t0 = OffsetDateTime::now_utc();
        for _ in 0..ACCOUNT_LIMIT_PER_MINUTE {
            assert!(limiter.check_at("1.2.3.4", "admin", t0).is_allowed());
        }
        let verdict = limiter.check_at("1.2.3.4", "admin", t0);
        assert!(!verdict.is_allowed(), "账户桶应触发限流");
        match verdict {
            LimitVerdict::Limited { retry_after_secs } => {
                assert!(retry_after_secs > 0 && retry_after_secs <= 60)
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn per_ip_bucket_is_independent_of_account() {
        let limiter = LoginLimiter::new();
        let t0 = OffsetDateTime::now_utc();

        for i in 0..IP_LIMIT_PER_MINUTE {
            assert!(limiter
                .check_at("9.9.9.9", &format!("acct{i}"), t0)
                .is_allowed());
        }
        assert!(
            !limiter.check_at("9.9.9.9", "brandnew", t0).is_allowed(),
            "同一 IP 换账号也应被限流"
        );

        assert!(limiter.check_at("8.8.8.8", "brandnew", t0).is_allowed());
    }

    #[test]
    fn denied_requests_do_not_consume_other_buckets() {
        let limiter = LoginLimiter::new();
        let t0 = OffsetDateTime::now_utc();
        for _ in 0..ACCOUNT_LIMIT_PER_MINUTE {
            limiter.check_at("1.1.1.1", "admin", t0);
        }

        for _ in 0..50 {
            assert!(!limiter.check_at("1.1.1.1", "admin", t0).is_allowed());
        }

        assert!(limiter.check_at("1.1.1.1", "other", t0).is_allowed());
    }

    #[test]
    fn window_slides_after_a_minute() {
        let limiter = LoginLimiter::new();
        let t0 = OffsetDateTime::now_utc();
        for _ in 0..ACCOUNT_LIMIT_PER_MINUTE {
            limiter.check_at("1.2.3.4", "admin", t0);
        }
        assert!(!limiter.check_at("1.2.3.4", "admin", t0).is_allowed());

        let later = t0 + Duration::seconds(61);
        assert!(limiter.check_at("1.2.3.4", "admin", later).is_allowed());
    }

    #[test]
    fn five_failures_lock_the_source() {
        let limiter = LoginLimiter::new();
        let t0 = OffsetDateTime::now_utc();
        for _ in 0..(FAILURE_LOCKOUT_THRESHOLD - 1) {
            limiter.record_failure_at("203.0.113.7", "admin", t0);
        }
        assert!(!limiter.is_locked_at("admin", t0), "未达阈值不应锁定");
        assert!(!limiter.is_locked_from("203.0.113.7", "admin", t0));

        limiter.record_failure_at("203.0.113.7", "admin", t0);
        assert!(limiter.is_locked_at("admin", t0), "达阈值必须锁定");
        assert!(
            limiter.is_locked_from("203.0.113.7", "admin", t0),
            "锁定必须记在触发它的那个来源上"
        );
    }

    #[test]
    fn rotating_source_ips_cannot_lock_out_or_extend_another_source() {
        let limiter = LoginLimiter::new();
        let t0 = OffsetDateTime::now_utc();

        for _ in 0..FAILURE_LOCKOUT_THRESHOLD {
            limiter.record_failure_at("198.51.100.9", "admin", t0);
        }
        assert!(limiter.is_locked_from("198.51.100.9", "admin", t0));
        let blocked = limiter.check_at("198.51.100.9", "admin", t0);
        assert!(!blocked.is_allowed(), "攻击者自己的来源必须被挡住");
        let locked_until_secs = match blocked {
            LimitVerdict::Limited { retry_after_secs } => retry_after_secs,
            LimitVerdict::Allow => unreachable!(),
        };

        assert!(
            limiter.check_at("127.0.0.1", "admin", t0).is_allowed(),
            "攻击者的锁定不得波及另一个来源"
        );
        assert!(!limiter.is_locked_from("127.0.0.1", "admin", t0));

        for index in 0..50u32 {
            let ip = format!("198.51.100.{}", index % 250 + 1);
            limiter.record_failure_at(&ip, "admin", t0 + Duration::seconds(index as i64));
        }
        let still = match limiter.check_at("198.51.100.9", "admin", t0) {
            LimitVerdict::Limited { retry_after_secs } => retry_after_secs,
            LimitVerdict::Allow => panic!("原锁定的剩余时间不该被轮换来源重置"),
        };
        assert_eq!(
            still, locked_until_secs,
            "轮换来源的失败不得延长已有锁定的剩余时间"
        );
        assert!(
            limiter.check_at("127.0.0.1", "admin", t0).is_allowed(),
            "轮换来源的失败也不得波及管理员自己的来源"
        );
    }

    #[test]
    fn a_single_source_is_still_locked_and_recovers_after_the_lock_expires() {
        let limiter = LoginLimiter::new();
        let t0 = OffsetDateTime::now_utc();
        for _ in 0..FAILURE_LOCKOUT_THRESHOLD {
            limiter.record_failure_at("127.0.0.1", "admin", t0);
        }
        assert!(limiter.is_locked_from("127.0.0.1", "admin", t0));
        assert!(
            !limiter.check_at("127.0.0.1", "admin", t0).is_allowed(),
            "锁定中的来源即使口令正确也必须拒绝"
        );

        let after = t0 + Duration::seconds(LOCKOUT_SECONDS + 1);
        assert!(
            !limiter.is_locked_from("127.0.0.1", "admin", after),
            "锁定期满应自动解除"
        );
        assert!(limiter.check_at("127.0.0.1", "admin", after).is_allowed());
    }

    #[test]
    fn repeated_lockouts_from_one_source_escalate() {
        let limiter = LoginLimiter::new();
        let mut t = OffsetDateTime::now_utc();
        let mut observed = Vec::new();
        for _ in 0..LOCKOUT_ESCALATION_SECONDS.len() {
            for _ in 0..FAILURE_LOCKOUT_THRESHOLD {
                limiter.record_failure_at("198.51.100.9", "admin", t);
            }
            let verdict = limiter.check_at("198.51.100.9", "admin", t);
            match verdict {
                LimitVerdict::Limited { retry_after_secs } => observed.push(retry_after_secs),
                LimitVerdict::Allow => panic!("第 {} 次锁定没有生效", observed.len() + 1),
            }

            t += Duration::seconds(observed.last().copied().unwrap_or(0) + 1);
        }
        assert_eq!(
            observed,
            LOCKOUT_ESCALATION_SECONDS.to_vec(),
            "同一来源重复锁定必须按 900s → 1h → 6h 升级"
        );
        assert!(
            *observed.last().unwrap() <= *LOCKOUT_ESCALATION_SECONDS.last().unwrap(),
            "升级必须封顶"
        );
        assert_eq!(observed[0], LOCKOUT_SECONDS, "首次锁定时长不得改变");
    }

    #[test]
    fn success_clears_failure_counter_and_lock() {
        let limiter = LoginLimiter::new();
        let t0 = OffsetDateTime::now_utc();
        for _ in 0..FAILURE_LOCKOUT_THRESHOLD {
            limiter.record_failure_at("127.0.0.1", "admin", t0);
        }
        assert!(limiter.is_locked("admin"));

        limiter.record_success("127.0.0.1", "admin");
        assert!(!limiter.is_locked("admin"), "成功登录必须清除锁定");

        for _ in 0..(FAILURE_LOCKOUT_THRESHOLD - 1) {
            limiter.record_failure_at("127.0.0.1", "admin", t0);
        }
        assert!(!limiter.is_locked_at("admin", t0));
    }

    #[test]
    fn success_only_clears_the_source_that_succeeded() {
        let limiter = LoginLimiter::new();
        let t0 = OffsetDateTime::now_utc();
        for _ in 0..FAILURE_LOCKOUT_THRESHOLD {
            limiter.record_failure_at("198.51.100.9", "admin", t0);
        }
        assert!(limiter.is_locked_from("198.51.100.9", "admin", t0));

        limiter.record_success("127.0.0.1", "admin");
        assert!(
            limiter.is_locked_from("198.51.100.9", "admin", t0),
            "另一个来源的成功登录不得清掉攻击者来源的锁定"
        );
    }

    #[test]
    fn lockout_is_per_account() {
        let limiter = LoginLimiter::new();
        let t0 = OffsetDateTime::now_utc();
        for _ in 0..FAILURE_LOCKOUT_THRESHOLD {
            limiter.record_failure_at("127.0.0.1", "admin", t0);
        }
        assert!(limiter.is_locked_at("admin", t0));
        assert!(!limiter.is_locked_at("other", t0), "锁定不得影响其它账号");
        assert!(!limiter.is_locked_from("127.0.0.1", "other", t0));
    }

    #[test]
    fn lockout_uses_the_sanitized_key_everywhere() {
        let limiter = LoginLimiter::new();
        let t0 = OffsetDateTime::now_utc();
        let long_account = format!("admin-{}", "x".repeat(MAX_KEY_LEN + 64));

        for _ in 0..FAILURE_LOCKOUT_THRESHOLD {
            limiter.record_failure_at("127.0.0.1", &long_account, t0);
        }
        assert!(
            limiter.is_locked_at(&long_account, t0),
            "长账号键必须能上锁"
        );
        assert!(limiter.is_locked_from("127.0.0.1", &long_account, t0));

        limiter.record_success("127.0.0.1", &long_account);
        assert!(
            !limiter.is_locked_at(&long_account, t0),
            "成功登录必须能清掉长账号键的锁定"
        );

        for _ in 0..FAILURE_LOCKOUT_THRESHOLD {
            limiter.record_failure_at("127.0.0.1", &long_account, t0);
        }
        assert!(limiter.is_locked_at(&long_account, t0));
    }

    #[test]
    fn global_bucket_caps_total_throughput() {
        let limiter = LoginLimiter::new();
        let t0 = OffsetDateTime::now_utc();
        let mut allowed = 0u32;

        for i in 0..(GLOBAL_LIMIT_PER_MINUTE + 50) {
            if limiter
                .check_at(
                    &format!("10.0.{}.{}", i / 256, i % 256),
                    &format!("a{i}"),
                    t0,
                )
                .is_allowed()
            {
                allowed += 1;
            }
        }
        assert!(
            allowed <= GLOBAL_LIMIT_PER_MINUTE,
            "全局桶必须封顶，实际放行 {allowed}"
        );
    }

    #[test]
    fn error_codes_match_documented_contract() {
        assert_eq!(ERR_INVALID_CREDENTIALS, "INVALID_CREDENTIALS");
        assert_eq!(ERR_TOTP_REQUIRED, "TOTP_REQUIRED");
        assert_eq!(ERR_LOGIN_FAILED, "LOGIN_FAILED");
        assert_eq!(ERR_REQUEST_FAILED, "REQUEST_FAILED");
        assert_eq!(ERR_ENROLL_WINDOW_ACTIVE, "ENROLL_WINDOW_ACTIVE");
        assert_eq!(ERR_API_NOT_FOUND, "API_NOT_FOUND");
        assert_eq!(
            ERR_PRIVILEGED_HELPER_UNAVAILABLE,
            "PRIVILEGED_HELPER_UNAVAILABLE"
        );
    }
}
