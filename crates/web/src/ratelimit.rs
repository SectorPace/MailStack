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
/// 单个键（IP 或账号名）的最大长度。
///
/// ## 为什么需要它
///
/// 键直接取自请求体，而登录接口是**免认证**的。没有上界时，攻击者每次请求发一个
/// 2 MB 的 `username`，就往 `by_account` 与 `failures` 各插入一条常驻字符串 ——
/// 未认证的内存耗尽。原实现对键长与表大小都无约束，且**没有任何淘汰路径**
/// （唯一的 `remove` 只删当前正在检查的那一个键）。
pub const MAX_KEY_LEN: usize = 256;
/// 三张表各自允许的最大条目数。
///
/// 上界配合淘汰：只要条目数超限就在每次判定前清扫已过窗口的项，因此攻击者
/// 无法靠「窗口内高基数」把内存顶起来。
pub const MAX_TRACKED_KEYS: usize = 4096;

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

        let ip_key = sanitized(ip);
        let account_key = sanitized(account);

        // 账号锁定优先于桶限流。
        if let Some((_, Some(until))) = state.failures.get(account_key.as_ref()) {
            if *until > now {
                return LimitVerdict::Limited {
                    retry_after_secs: (*until - now).whole_seconds().max(1),
                };
            }
            // 锁定期已过，清除。
            state.failures.remove(account_key.as_ref());
        }

        // 淘汰必须在下面查表**之前**做完。原实现把 `entry().or_insert_with(..)`
        // 放在判决前，于是「被限流的请求」也留下新键 —— 限流器本身成了内存增长来源。
        state.evict_expired(now);

        // 先只读判决：不存在的桶不新建。这样「判决」不会产生副作用。
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

        // 任一桶超限即拒绝；此时**不**累加任何桶，也不新建任何桶。
        for verdict in [&global_verdict, &ip_verdict, &account_verdict] {
            if let LimitVerdict::Limited { retry_after_secs } = verdict {
                return LimitVerdict::Limited {
                    retry_after_secs: *retry_after_secs,
                };
            }
        }

        // 全部放行：这时才累加，并**顺带**为首次出现的键建立计数器。
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
        LimitVerdict::Allow
    }

    /// 记录一次失败。达到阈值即锁定账号。
    pub fn record_failure(&self, account: &str) {
        self.record_failure_at(account, OffsetDateTime::now_utc());
    }

    pub fn record_failure_at(&self, account: &str, now: OffsetDateTime) {
        let mut state = self.lock();
        state.evict_expired(now);
        // 键与 `check_at` 用同一个规范化函数，否则两者会记到不同桶上。
        let key = sanitized(account);
        let entry = state.failures.entry(key.into_owned()).or_insert((0, None));
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

impl LimiterState {
    /// 清扫已过窗口的条目，并在表超上界时强制收缩。
    ///
    /// ## 为什么必须有这一步
    ///
    /// 三张表原先只增不减，唯一的 `remove` 恰好删的是当前正在检查的那个键 ——
    /// 于是未认证的匿名者用随机 `username` 就能让 `by_account` / `failures`
    /// 无限增长（长期运行必然 OOM，而这是唯一的管理台）。
    ///
    /// 为什么不简单地「超限就拒绝新键」：那样攻击者能用**先占满**的方式让真实
    /// 管理员进不来（登录 DoS）。所以先按窗口清扫；仍超上界时按**最旧窗口**淘汰，
    /// 保证「最热的键」优先留下。
    fn evict_expired(&mut self, now: OffsetDateTime) {
        let window = Duration::minutes(1);
        self.by_ip.retain(|_, c| now - c.window_start < window);
        self.by_account.retain(|_, c| now - c.window_start < window);
        // `failures` 的过期判定与桶不同：**已过锁定期**的条目没有价值，直接删。
        // 但 `until == None` 表示「失败次数还没攒到阈值」—— 那是正在计数的条目，
        // 必须留下（早先写成「只留 `until > now`」会把第一次失败就抹掉，
        // 于是账号永远锁不上：计数在 1 处被清空，永远到不了 5）。
        self.failures
            .retain(|_, (_, until)| until.is_none_or(|until| until > now));

        // 仍超上界（攻击者在**同一个窗口内**制造高基数）：按窗口起点最旧者淘汰。
        // 排序键是 `window_start`，取最旧 = 留最热。
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
            // 失败计数没有窗口起点，用「是否锁定」+ 插入序不可得，故直接清掉
            // 一个已过锁定期的条目；全都在锁定期时按任意一个删，内存上界优先。
            let Some(victim) = self
                .failures
                .iter()
                .find(|(_, (_, until))| until.is_none())
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            self.failures.remove(&victim);
        }
    }
}

/// 把键规范化成一个**有界**的 `Cow<str>`。
///
/// 键取自免认证的登录请求体，因此：
/// * 超长截断 —— 否则单个 2 MB 的 `username` 就能常驻一份；
/// * 截断标记不可省略 —— 否则 `"admin"` 与 256 字节前缀相同的攻击者会**共用一个桶**，
///   反而给攻击者提供了撞库掩护。
fn sanitized(key: &str) -> std::borrow::Cow<'_, str> {
    if key.len() <= MAX_KEY_LEN {
        return std::borrow::Cow::Borrowed(key);
    }
    // 按字符边界截断，避免 panic。`MAX_KEY_LEN` 处的边界用 `floor_char_boundary`
    // 之类不可得，故退到 `char_indices` 找最后一个合法边界。
    let cut = key
        .char_indices()
        .map(|(i, _)| i)
        .take_while(|i| *i <= MAX_KEY_LEN)
        .last()
        .unwrap_or(0);
    std::borrow::Cow::Owned(format!("{}\u{0}", &key[..cut]))
}

impl Counter {
    /// 只读检查：不累加。
    ///
    /// 窗口过期时必须重置 `window_start` 和 `count`；否则计数器一旦建立超过
    /// 60 秒，此后每次检查都会直接返回 `Allow`，导致该桶永久失效。
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

/// AI 路由的独立限流（`contract::AI_RATE_LIMIT_PER_MINUTE`，20 次/分/IP）。
///
/// ## 为什么必须存在
///
/// `AI_RATE_LIMIT_PER_MINUTE` 与 `contract::is_ai_path` 在本轮之前**定义了却
/// 没有任何调用点** —— 「AI 路由独立限流 20 次/分」是一句纯粹的文档。
/// 而 AI 路由背后是**出站付费 LLM 调用**：认证后的会话一旦被拿到（劫持、
/// XSS、或用户自己写脚本），就能在几秒内把一整月的额度烧光，且这些请求
/// 在服务端留下的痕迹与正常调用**没有区别**。
///
/// 复用 [`LoginLimiter`] 是不行的：它的三档桶与账号锁定语义都是登录专属的，
/// 把 AI 流量塞进去会让「登录失败」与「AI 调用频繁」共用失败计数。
///
/// ## 语义
///
/// * 固定窗口 60 秒，按**传输层真实对端**分桶（与登录限流同一口径，不读 XFF）。
/// * 判定不产生副作用：先 `peek`，只有全部通过才累加。
/// * 表有上界并清扫，与登录限流同一套纪律，避免限流器自己成为内存增长来源。
#[derive(Debug, Default)]
pub struct AiRateLimiter {
    by_ip: Mutex<HashMap<String, Counter>>,
}

impl AiRateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn check(&self, ip: &str) -> LimitVerdict {
        self.check_at(ip, OffsetDateTime::now_utc())
    }

    pub fn check_at(&self, ip: &str, now: OffsetDateTime) -> LimitVerdict {
        let mut map = self
            .by_ip
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let window = Duration::minutes(1);
        map.retain(|_, counter| now - counter.window_start < window);

        let limit = crate::contract::AI_RATE_LIMIT_PER_MINUTE;
        let key = sanitized(ip);

        // 判决**不新建**条目：只有真的放行时才建。
        if let Some(counter) = map.get_mut(key.as_ref()) {
            if let LimitVerdict::Limited { retry_after_secs } = counter.peek(now, limit) {
                return LimitVerdict::Limited { retry_after_secs };
            }
        }

        // 累加之后才收缩上界 —— 先收缩再插入会留下 `MAX + 1` 条，
        // 而「限流器自己有上界」正是这里要保证的性质。
        map.entry(key.into_owned())
            .or_insert_with(|| Counter::new(now))
            .count += 1;

        // 同窗口内的高基数来源：按最旧窗口淘汰，保证「最热」优先留下。
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

        LimitVerdict::Allow
    }

    /// 清除全部状态（仅供测试）。
    #[doc(hidden)]
    pub fn reset(&self) {
        self.by_ip
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
    }
}

#[cfg(test)]
mod ai_limiter_tests {
    use super::*;

    /// 5.6 的反例测试：配额必须在第 N+1 次调用上生效，且**按来源**分开计。
    ///
    /// 在接线之前，`AI_RATE_LIMIT_PER_MINUTE` 没有任何调用点，这个测试压根
    /// 不存在 —— 「AI 路由独立限流 20 次/分」只是一句文档。
    #[test]
    fn the_ai_quota_is_enforced_and_scoped_per_source() {
        let limiter = AiRateLimiter::new();
        let limit = crate::contract::AI_RATE_LIMIT_PER_MINUTE;
        let t0 = OffsetDateTime::now_utc();

        for attempt in 0..limit {
            assert!(
                limiter.check_at("198.51.100.7", t0).is_allowed(),
                "第 {attempt} 次必须在配额内"
            );
        }

        let verdict = limiter.check_at("198.51.100.7", t0);
        assert!(
            !verdict.is_allowed(),
            "第 {} 次必须被限流（AI 出站是付费调用）",
            limit + 1
        );
        assert!(matches!(
            verdict,
            LimitVerdict::Limited {
                retry_after_secs: 1..=60
            }
        ));

        // 另一个来源不受牵连。
        assert!(
            limiter.check_at("203.0.113.9", t0).is_allowed(),
            "限流必须按来源分桶，不能一个 IP 超量就把所有人一起封掉"
        );

        // 窗口推进后恢复。
        let next_window = t0 + Duration::minutes(1) + Duration::seconds(1);
        assert!(
            limiter.check_at("198.51.100.7", next_window).is_allowed(),
            "窗口推进后必须恢复放行"
        );
    }

    /// 判定本身不得产生副作用，否则被限流的请求会持续消耗自己的窗口。
    #[test]
    fn a_rejected_ai_call_does_not_extend_its_own_window() {
        let limiter = AiRateLimiter::new();
        let limit = crate::contract::AI_RATE_LIMIT_PER_MINUTE;
        let t0 = OffsetDateTime::now_utc();

        for _ in 0..limit {
            assert!(limiter.check_at("198.51.100.7", t0).is_allowed());
        }
        // 连续 5 次被拒：每次都必须返回**递减**的 retry-after，
        // 若被拒时也在累加，窗口会被无限续期。
        let mut previous = i64::MAX;
        for _ in 0..5 {
            match limiter.check_at("198.51.100.7", t0) {
                LimitVerdict::Allow => panic!("超限后不得放行"),
                LimitVerdict::Limited { retry_after_secs } => {
                    assert!(
                        retry_after_secs <= previous,
                        "被拒的请求在续自己的窗口：{retry_after_secs} > {previous}"
                    );
                    previous = retry_after_secs;
                }
            }
        }
    }

    /// 限流表自身不得成为未认证内存增长来源（与登录限流同一纪律）。
    #[test]
    fn the_ai_limiter_table_stays_bounded() {
        let limiter = AiRateLimiter::new();
        let t0 = OffsetDateTime::now_utc();
        for i in 0..(MAX_TRACKED_KEYS * 2) {
            limiter.check_at(&format!("198.51.100.{}", i % 256), t0);
            // 高基数来源必须靠不同的 IP 区分，这里用序号拼出足够多的键。
            limiter.check_at(&format!("10.0.{}.{}", i / 256, i % 256), t0);
        }
        let size = limiter
            .by_ip
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len();
        assert!(
            size <= MAX_TRACKED_KEYS,
            "限流表长到 {size} 条，超过上界 {MAX_TRACKED_KEYS}"
        );
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
