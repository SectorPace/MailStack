//! 每 IP 连接限速（令牌窗口），时钟注入。
//!
//! ## 为什么邮箱服务也要限速
//!
//! IMAP/POP3 的认证是**昂贵**的：每次失败要跑 310,000 次 PBKDF2（约几十毫秒 CPU）。
//! 不加限制时，一个连接循环就足以让单核饱和 —— 这不需要「打垮协议」，只需要
//! 反复提交错口令。连接数上限挡不住它（每次都新建连接、用完即关）。
//!
//! 计数按**固定窗口**而非严格令牌桶：窗口语义足够挡住暴力重连，且可以在测试里
//! 用固定时钟精确验证边界。宁可少一个平滑度，也要一个可复现的判据。

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitConfig {
    /// 每个窗口内允许的新连接数。
    pub max_per_window: u32,
    /// 窗口长度（秒）。
    pub window_secs: i64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_per_window: 60,
            window_secs: 60,
        }
    }
}

/// 单表上限。攻击者可以伪造源地址吗？不能（TCP 握手需要可达地址），但 NAT 后
/// 可能有大量真实客户端；超过后先清理过期条目，仍满则拒绝**新** IP，避免内存
/// 被无限拉扯。
const MAX_TRACKED_IPS: usize = 65_536;

#[derive(Debug, Clone, Copy)]
struct Window {
    start: i64,
    count: u32,
}

pub struct RateLimiter {
    config: RateLimitConfig,
    windows: Mutex<HashMap<IpAddr, Window>>,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            windows: Mutex::new(HashMap::new()),
        }
    }

    /// `now` 是 Unix 秒（来自 [`Clock`]，测试可注入）。
    pub fn allow(&self, ip: IpAddr, now: i64) -> bool {
        if self.config.max_per_window == 0 {
            return false;
        }
        let mut windows = match self.windows.lock() {
            Ok(windows) => windows,
            // 锁中毒意味着上一次 check 在持有锁时 panic —— 那本身就是缺陷；
            // 这里 fail-closed（拒绝连接）而不是放行。
            Err(_) => return false,
        };

        if windows.len() >= MAX_TRACKED_IPS {
            windows.retain(|_, window| now.saturating_sub(window.start) < self.config.window_secs);
            if windows.len() >= MAX_TRACKED_IPS && !windows.contains_key(&ip) {
                return false;
            }
        }

        let window = windows.entry(ip).or_insert(Window {
            start: now,
            count: 0,
        });
        if now.saturating_sub(window.start) >= self.config.window_secs || now < window.start {
            // `now < window.start` 视作时钟回拨：重开窗口，而不是把客户端锁死到
            // 时间追上来为止。
            window.start = now;
            window.count = 0;
        }
        if window.count >= self.config.max_per_window {
            return false;
        }
        window.count += 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    #[test]
    fn the_window_limits_and_then_resets() {
        let limiter = RateLimiter::new(RateLimitConfig {
            max_per_window: 2,
            window_secs: 60,
        });
        let peer = ip("192.0.2.1");
        assert!(limiter.allow(peer, 1000));
        assert!(limiter.allow(peer, 1001));
        assert!(!limiter.allow(peer, 1002), "窗口内第三次必须被拒");
        assert!(limiter.allow(peer, 1060), "窗口结束后应恢复");
        assert!(limiter.allow(ip("192.0.2.2"), 1002), "不同 IP 独立计数");
    }

    #[test]
    fn zero_limit_denies_everything_and_clock_rollback_reopens() {
        let limiter = RateLimiter::new(RateLimitConfig {
            max_per_window: 0,
            window_secs: 60,
        });
        assert!(!limiter.allow(ip("192.0.2.1"), 0));

        let limiter = RateLimiter::new(RateLimitConfig {
            max_per_window: 1,
            window_secs: 60,
        });
        assert!(limiter.allow(ip("192.0.2.1"), 100));
        assert!(!limiter.allow(ip("192.0.2.1"), 101));
        assert!(limiter.allow(ip("192.0.2.1"), 50), "时钟回拨应重开窗口");
    }
}
