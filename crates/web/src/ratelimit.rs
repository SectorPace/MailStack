//! 登录限流（规格书 §5.2；INV-23）。
//!
//! 三档桶叠加 **5 次失败账号锁定**：
//!
//! * **global** —— 全局总量，防分布式撞库
//! * **per-IP** —— 单来源
//! * **per-account** —— 单账号
//!
//! 关键语义：`401 INVALID_CREDENTIALS` 响应体**不区分**失败原因（不返回剩余次数、
//! 不提示哪个因子失败）——这是**枚举防护**。唯一的文档化例外是
//! `401 TOTP_REQUIRED`（密码正确但需要 2FA）。

use std::collections::HashMap;
use std::sync::Mutex;

use time::{Duration, OffsetDateTime};

/// 全局桶：每分钟允许的登录尝试总数。
pub const GLOBAL_LIMIT_PER_MINUTE: u32 = 600;
/// 单 IP 桶：每分钟允许的尝试数。
pub const IP_LIMIT_PER_MINUTE: u32 = 20;
/// 单账号桶：每分钟允许的尝试数。
pub const ACCOUNT_LIMIT_PER_MINUTE: u32 = 10;
/// 连续失败达到该次数即锁定账号。
pub const FAILURE_LOCKOUT_THRESHOLD: u32 = 5;
/// 锁定时长。
pub const LOCKOUT_SECONDS: i64 = 900;

/// 桶类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bucket {
    Global,
    Ip,
    Account,
}

/// 限流判决。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LimitVerdict {
    Allow,
    /// 已被限流；`retry_after_secs` 用于 `Retry-After` 头。
    Limited {
        retry_after_secs: i64,
    },
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

/// 登录限流器。
#[derive(Debug, Default)]
pub struct LoginLimiter {
    inner: Mutex<LimiterState>,
}

#[derive(Debug, Default)]
struct LimiterState {
    global: Option<Counter>,
    by_ip: HashMap<String, Counter>,
    by_account: HashMap<String, Counter>,
    /// 连续失败计数与锁定截止时刻。
    failures: HashMap<String, (u32, Option<OffsetDateTime>)>,
}

impl LoginLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// 记录一次登录尝试，返回是否放行。
    ///
    /// 三个桶**全部**检查后才累加，避免被限流的请求仍然消耗其它桶的额度。
    pub fn check(&self, ip: &str, account: &str) -> LimitVerdict {
        self.check_at(ip, account, OffsetDateTime::now_utc())
    }

    pub fn check_at(&self, ip: &str, account: &str, now: OffsetDateTime) -> LimitVerdict {
        let mut state = self.lock();

        // 账号锁定优先于桶限流。
        if let Some((_, Some(until))) = state.failures.get(account) {
            if *until > now {
                return LimitVerdict::Limited {
                    retry_after_secs: (*until - now).whole_seconds().max(1),
                };
            }
            // 锁定期已过，清除。
            state.failures.remove(account);
        }

        let global_verdict = {
            let counter = state.global.get_or_insert_with(|| Counter::new(now));
            counter.peek(now, GLOBAL_LIMIT_PER_MINUTE)
        };
        let ip_verdict = state
            .by_ip
            .entry(ip.to_string())
            .or_insert_with(|| Counter::new(now))
            .peek(now, IP_LIMIT_PER_MINUTE);
        let account_verdict = state
            .by_account
            .entry(account.to_string())
            .or_insert_with(|| Counter::new(now))
            .peek(now, ACCOUNT_LIMIT_PER_MINUTE);

        // 任一桶超限即拒绝；此时**不**累加任何桶。
        for verdict in [&global_verdict, &ip_verdict, &account_verdict] {
            if let LimitVerdict::Limited { retry_after_secs } = verdict {
                return LimitVerdict::Limited {
                    retry_after_secs: *retry_after_secs,
                };
            }
        }

        // 全部放行：统一累加。
        if let Some(c) = state.global.as_mut() {
            c.count += 1;
        }
        if let Some(c) = state.by_ip.get_mut(ip) {
            c.count += 1;
        }
        if let Some(c) = state.by_account.get_mut(account) {
            c.count += 1;
        }
        LimitVerdict::Allow
    }

    /// 记录一次失败。达到阈值即锁定账号。
    pub fn record_failure(&self, account: &str) {
        self.record_failure_at(account, OffsetDateTime::now_utc());
    }

    pub fn record_failure_at(&self, account: &str, now: OffsetDateTime) {
        let mut state = self.lock();
        let entry = state
            .failures
            .entry(account.to_string())
            .or_insert((0, None));
        entry.0 += 1;
        if entry.0 >= FAILURE_LOCKOUT_THRESHOLD {
            entry.1 = Some(now + Duration::seconds(LOCKOUT_SECONDS));
        }
    }

    /// 记录一次成功：清除失败计数与锁定。
    pub fn record_success(&self, account: &str) {
        self.lock().failures.remove(account);
    }

    /// 该账号当前是否处于锁定期。
    pub fn is_locked(&self, account: &str) -> bool {
        self.is_locked_at(account, OffsetDateTime::now_utc())
    }

    pub fn is_locked_at(&self, account: &str, now: OffsetDateTime) -> bool {
        let state = self.lock();
        matches!(state.failures.get(account), Some((_, Some(until))) if *until > now)
    }

    /// 清除全部状态（仅供测试）。
    #[doc(hidden)]
    pub fn reset(&self) {
        let mut state = self.lock();
        *state = LimiterState::default();
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, LimiterState> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }
}

impl Counter {
    /// 只读检查：不累加。
    fn peek(&self, now: OffsetDateTime, limit: u32) -> LimitVerdict {
        let effective_start = if now - self.window_start >= Duration::minutes(1) {
            now
        } else {
            self.window_start
        };
        if now - self.window_start >= Duration::minutes(1) {
            return LimitVerdict::Allow; // 窗口已过期，视为空
        }
        if self.count >= limit {
            let elapsed = (now - effective_start).whole_seconds();
            return LimitVerdict::Limited {
                retry_after_secs: (60 - elapsed).max(1),
            };
        }
        LimitVerdict::Allow
    }
}

/// 固定的对外错误码（不得改动，前端依赖）。
pub const ERR_INVALID_CREDENTIALS: &str = "INVALID_CREDENTIALS";
/// 登录响应中「密码正确但需要 2FA」的唯一文档化例外。
pub const ERR_TOTP_REQUIRED: &str = "TOTP_REQUIRED";
/// 请求失败默认码。
pub const ERR_REQUEST_FAILED: &str = "REQUEST_FAILED";
/// 登录失败默认码。
pub const ERR_LOGIN_FAILED: &str = "LOGIN_FAILED";
/// 未认证（INV-7：用 401 而不是 403，以免泄露资源存在性）。
pub const ERR_AUTH_REQUIRED: &str = "AUTH_REQUIRED";
/// CSRF 校验失败。
pub const ERR_CSRF_INVALID: &str = "CSRF_INVALID";
/// 限流。
pub const ERR_RATE_LIMITED: &str = "RATE_LIMITED";
/// 注册窗口（公网模式未启 2FA）。
pub const ERR_ENROLL_WINDOW_ACTIVE: &str = "ENROLL_WINDOW_ACTIVE";
/// 未匹配的 API 路径。
pub const ERR_API_NOT_FOUND: &str = "API_NOT_FOUND";
/// 请求体过大。
pub const ERR_PAYLOAD_TOO_LARGE: &str = "PAYLOAD_TOO_LARGE";
/// 内部错误。
pub const ERR_INTERNAL_ERROR: &str = "INTERNAL_ERROR";
/// 特权助手不可达（INV-8）。
pub const ERR_PRIVILEGED_HELPER_UNAVAILABLE: &str = "PRIVILEGED_HELPER_UNAVAILABLE";
/// 特权操作失败。
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
        // 用不同账号把单 IP 桶打满。
        for i in 0..IP_LIMIT_PER_MINUTE {
            assert!(limiter
                .check_at("9.9.9.9", &format!("acct{i}"), t0)
                .is_allowed());
        }
        assert!(
            !limiter.check_at("9.9.9.9", "brandnew", t0).is_allowed(),
            "同一 IP 换账号也应被限流"
        );
        // 另一个 IP 不受影响。
        assert!(limiter.check_at("8.8.8.8", "brandnew", t0).is_allowed());
    }

    #[test]
    fn denied_requests_do_not_consume_other_buckets() {
        let limiter = LoginLimiter::new();
        let t0 = OffsetDateTime::now_utc();
        for _ in 0..ACCOUNT_LIMIT_PER_MINUTE {
            limiter.check_at("1.1.1.1", "admin", t0);
        }
        // 已被账户桶拒绝的一批请求，不应额外消耗 IP 桶额度。
        for _ in 0..50 {
            assert!(!limiter.check_at("1.1.1.1", "admin", t0).is_allowed());
        }
        // 同 IP 的另一账号应仍有余量（IP 桶未被那 50 次拒绝耗尽）。
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

        // 一分钟后窗口重置。
        let later = t0 + Duration::seconds(61);
        assert!(limiter.check_at("1.2.3.4", "admin", later).is_allowed());
    }

    #[test]
    fn five_failures_lock_the_account() {
        let limiter = LoginLimiter::new();
        let t0 = OffsetDateTime::now_utc();
        for _ in 0..(FAILURE_LOCKOUT_THRESHOLD - 1) {
            limiter.record_failure_at("admin", t0);
        }
        assert!(!limiter.is_locked_at("admin", t0), "未达阈值不应锁定");

        limiter.record_failure_at("admin", t0);
        assert!(limiter.is_locked_at("admin", t0), "达阈值必须锁定");
    }

    #[test]
    fn locked_account_is_rejected_even_with_capacity() {
        let limiter = LoginLimiter::new();
        let t0 = OffsetDateTime::now_utc();
        for _ in 0..FAILURE_LOCKOUT_THRESHOLD {
            limiter.record_failure_at("admin", t0);
        }
        // 新 IP、新时间窗，但账号仍锁定 → 必须拒绝。
        let verdict = limiter.check_at("5.5.5.5", "admin", t0);
        assert!(!verdict.is_allowed(), "锁定中的账号必须被拒绝");
    }

    #[test]
    fn lockout_expires_after_its_window() {
        let limiter = LoginLimiter::new();
        let t0 = OffsetDateTime::now_utc();
        for _ in 0..FAILURE_LOCKOUT_THRESHOLD {
            limiter.record_failure_at("admin", t0);
        }
        assert!(limiter.is_locked_at("admin", t0));

        let after = t0 + Duration::seconds(LOCKOUT_SECONDS + 1);
        assert!(!limiter.is_locked_at("admin", after), "锁定期满应自动解除");
        assert!(limiter.check_at("5.5.5.5", "admin", after).is_allowed());
    }

    #[test]
    fn success_clears_failure_counter_and_lock() {
        let limiter = LoginLimiter::new();
        let t0 = OffsetDateTime::now_utc();
        for _ in 0..FAILURE_LOCKOUT_THRESHOLD {
            limiter.record_failure_at("admin", t0);
        }
        assert!(limiter.is_locked("admin"));

        limiter.record_success("admin");
        assert!(!limiter.is_locked("admin"), "成功登录必须清除锁定");

        // 失败计数也确实归零：再失败 4 次仍不应锁定。
        for _ in 0..(FAILURE_LOCKOUT_THRESHOLD - 1) {
            limiter.record_failure_at("admin", t0);
        }
        assert!(!limiter.is_locked_at("admin", t0));
    }

    #[test]
    fn lockout_is_per_account() {
        let limiter = LoginLimiter::new();
        let t0 = OffsetDateTime::now_utc();
        for _ in 0..FAILURE_LOCKOUT_THRESHOLD {
            limiter.record_failure_at("admin", t0);
        }
        assert!(limiter.is_locked_at("admin", t0));
        assert!(!limiter.is_locked_at("other", t0), "锁定不得影响其它账号");
    }

    #[test]
    fn global_bucket_caps_total_throughput() {
        let limiter = LoginLimiter::new();
        let t0 = OffsetDateTime::now_utc();
        let mut allowed = 0u32;
        // 用不同 IP 与账号绕开分档桶，验证全局桶兜底。
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
        // 这些字符串是前端依赖的对外契约。
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
