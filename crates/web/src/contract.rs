//! HTTP API 契约全表（规格书 §5.2）。
//!
//! 本表是**路由的唯一真相源**：Axum 路由注册与契约测试都从这里读，
//! 避免「测试断言的路由」与「实际注册的路由」各自漂移。
//!
//! 每条路由声明：
//! * `method` / `path` —— 对外契约（不得改动）
//! * `action` —— 对应的特权 RPC 动作（`None` 表示进程内处理，不经助手）
//! * `auth` —— 是否需要会话认证
//!
//! 注意 §5.2 的分组顺序与原文一致，便于人工逐条对照。

/// 是否需要认证。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Auth {
    /// 免认证可达（仅 `/api/health` 与 `/api/auth/login`）。
    Public,
    /// 需要会话认证。
    Required,
}

/// 一条路由的契约声明。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteSpec {
    pub method: &'static str,
    pub path: &'static str,
    /// 特权 RPC 动作；`None` 表示由 Web 进程自身处理。
    pub action: Option<&'static str>,
    pub auth: Auth,
}

const fn r(
    method: &'static str,
    path: &'static str,
    action: Option<&'static str>,
    auth: Auth,
) -> RouteSpec {
    RouteSpec {
        method,
        path,
        action,
        auth,
    }
}

use Auth::{Public, Required};

/// 全部路由。
///
/// 顺序按规格书 §5.2 的分组排列。
pub const ROUTES: &[RouteSpec] = &[
    // ── 认证与会话 ──
    r("POST", "/api/auth/login", None, Public),
    r("POST", "/api/auth/logout", None, Required),
    r("GET", "/api/auth/session", None, Required),
    r("GET", "/api/auth/sessions", None, Required),
    r("POST", "/api/auth/sessions/revoke", None, Required),
    r("DELETE", "/api/auth/sessions", None, Required),
    r("GET", "/api/health", None, Public),
    // ── 管理员与 2FA ──
    r("GET", "/api/admin", Some("admin.get"), Required),
    r("POST", "/api/admin", Some("admin.set"), Required),
    r("GET", "/api/admin/2fa", None, Required),
    r(
        "POST",
        "/api/admin/2fa/begin",
        Some("admin.totp.begin"),
        Required,
    ),
    r(
        "POST",
        "/api/admin/2fa/enable",
        Some("admin.totp.enable"),
        Required,
    ),
    r(
        "POST",
        "/api/admin/2fa/disable",
        Some("admin.totp.disable"),
        Required,
    ),
    // ── 资源管理 ──
    r("GET", "/api/snapshot", Some("snapshot"), Required),
    r("GET", "/api/status", Some("snapshot"), Required),
    r("GET", "/api/domains", Some("domains.list"), Required),
    r("POST", "/api/domains", Some("domains.add"), Required),
    r(
        "DELETE",
        "/api/domains/:id",
        Some("domains.delete"),
        Required,
    ),
    r("POST", "/api/users", Some("users.add"), Required),
    r("POST", "/api/users/status", Some("users.status"), Required),
    r(
        "POST",
        "/api/users/password",
        Some("users.password"),
        Required,
    ),
    r("DELETE", "/api/users/:id", Some("users.delete"), Required),
    r("POST", "/api/aliases", Some("aliases.add"), Required),
    r(
        "DELETE",
        "/api/aliases/:id",
        Some("aliases.delete"),
        Required,
    ),
    r("POST", "/api/queue/action", Some("queue.action"), Required),
    r(
        "POST",
        "/api/services/action",
        Some("services.action"),
        Required,
    ),
    r("GET", "/api/logs", Some("logs.list"), Required),
    r("GET", "/api/settings", Some("settings.get"), Required),
    r("POST", "/api/settings", Some("settings.set"), Required),
    r("GET", "/api/certificates", Some("certs.list"), Required),
    r(
        "POST",
        "/api/certificates/renew",
        Some("certs.renew"),
        Required,
    ),
    r("POST", "/api/dkim/rotate", Some("dkim.rotate"), Required),
    r(
        "POST",
        "/api/mail/test-loopback",
        Some("mail.test_loopback"),
        Required,
    ),
    r("GET", "/api/doctor", Some("system.doctor"), Required),
    r("GET", "/api/system/doctor", Some("system.doctor"), Required),
    r(
        "POST",
        "/api/network/check-port",
        Some("network.check_port"),
        Required,
    ),
    r(
        "POST",
        "/api/security/scan",
        Some("security.scan"),
        Required,
    ),
    r("POST", "/api/security/ban", Some("security.ban"), Required),
    r(
        "POST",
        "/api/security/unban",
        Some("security.unban"),
        Required,
    ),
    // ── 初始化流程 ──
    r("GET", "/api/setup/status", Some("setup.status"), Required),
    r(
        "POST",
        "/api/setup/identity",
        Some("setup.identity.apply"),
        Required,
    ),
    r(
        "POST",
        "/api/setup/dns/verify",
        Some("setup.dns.verify"),
        Required,
    ),
    r(
        "POST",
        "/api/setup/relay/test",
        Some("setup.relay.test"),
        Required,
    ),
    r(
        "POST",
        "/api/setup/relay/apply",
        Some("setup.relay.apply"),
        Required,
    ),
    r(
        "POST",
        "/api/setup/cert/issue",
        Some("setup.cert.issue"),
        Required,
    ),
    r(
        "POST",
        "/api/setup/mail/test",
        Some("setup.mail.test"),
        Required,
    ),
    // ── 备份 ──
    r("GET", "/api/backups", Some("backup.list"), Required),
    r("POST", "/api/backups", Some("backup.create"), Required),
    r(
        "POST",
        "/api/backups/restore",
        Some("backup.restore"),
        Required,
    ),
    r(
        "DELETE",
        "/api/backups/:name",
        Some("backup.delete"),
        Required,
    ),
    // ── 指标与遥测 ──
    //
    // 基线的 Node 进程自己读 `/proc`；Rust 版把同一件事交给助手侧已注册的
    // `metrics.realtime` 动作，避免在 web 与 priv 各写一份 `/proc` 解析。
    // 对外契约（路径与方法）不变。
    r(
        "GET",
        "/api/metrics/realtime",
        Some("metrics.realtime"),
        Required,
    ),
    r("GET", "/api/metrics/telemetry", None, Required),
    // ── AI 子系统 ──
    r("GET", "/api/ai/config", Some("ai.config.get"), Required),
    r("POST", "/api/ai/config", Some("ai.config.set"), Required),
    r("POST", "/api/ai/models", Some("ai.models.list"), Required),
    r("POST", "/api/ai/test", Some("ai.test"), Required),
    r("POST", "/api/ai/chat", Some("ai.chat"), Required),
    r("POST", "/api/ai/dns-chat", Some("ai.chat"), Required),
    r("POST", "/api/ai/diagnose", Some("ai.diagnose"), Required),
    r(
        "POST",
        "/api/ai/diagnose-dns",
        Some("ai.diagnose"),
        Required,
    ),
    r("POST", "/api/ai/parse", Some("ai.parse"), Required),
    r("POST", "/api/ai/parse-dns-raw", Some("ai.parse"), Required),
];

/// 合法的遥测时间窗（非法值回落 `1h`）。
pub const TELEMETRY_RANGES: &[&str] = &["1m", "5m", "30m", "1h", "6h", "24h", "3d"];

/// 遥测时间窗默认值。
pub const TELEMETRY_RANGE_DEFAULT: &str = "1h";

/// AI 路由的独立限流（20 次/分/IP）。
pub const AI_RATE_LIMIT_PER_MINUTE: u32 = 20;

/// 归一化遥测时间窗；非法值回落默认。
pub fn normalize_telemetry_range(range: Option<&str>) -> &'static str {
    match range {
        Some(v) => TELEMETRY_RANGES
            .iter()
            .find(|candidate| **candidate == v)
            .copied()
            .unwrap_or(TELEMETRY_RANGE_DEFAULT),
        None => TELEMETRY_RANGE_DEFAULT,
    }
}

/// 某条路径是否为 AI 路由（需要独立限流）。
pub fn is_ai_path(path: &str) -> bool {
    path.starts_with("/api/ai/")
}

/// 该路由是否免认证。
pub fn is_public(method: &str, path: &str) -> bool {
    ROUTES
        .iter()
        .any(|s| s.method == method && s.path == path && s.auth == Public)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn every_route_is_unique() {
        let mut seen = HashSet::new();
        for spec in ROUTES {
            let key = format!("{} {}", spec.method, spec.path);
            assert!(seen.insert(key.clone()), "重复路由: {key}");
        }
    }

    #[test]
    fn every_route_is_under_api_prefix() {
        for spec in ROUTES {
            assert!(
                spec.path.starts_with("/api/"),
                "路由必须以 /api/ 开头: {} {}",
                spec.method,
                spec.path
            );
        }
    }

    #[test]
    fn only_health_and_login_are_public() {
        // 除 /api/health 与 /api/auth/login 外，一律需要认证。
        // 这条断言防的是「某个新路由忘记加 auth」这类回归。
        let public: Vec<String> = ROUTES
            .iter()
            .filter(|s| s.auth == Public)
            .map(|s| format!("{} {}", s.method, s.path))
            .collect();
        let mut sorted = public.clone();
        sorted.sort();
        assert_eq!(
            sorted,
            vec![
                "GET /api/health".to_string(),
                "POST /api/auth/login".to_string()
            ]
        );
    }

    #[test]
    fn health_is_public_and_login_is_public() {
        assert!(is_public("GET", "/api/health"));
        assert!(is_public("POST", "/api/auth/login"));
        assert!(!is_public("GET", "/api/snapshot"));
    }

    #[test]
    fn resource_routes_map_to_allowlisted_actions() {
        // 每条声明了 action 的路由，其动作都必须在特权白名单内，
        // 否则线上会得到 500，而不是在编译期/测试期暴露。
        for spec in ROUTES {
            if let Some(action) = spec.action {
                assert!(
                    mailstack_core::actions::is_allowed(action),
                    "{} {} 映射到未登记动作 {action}",
                    spec.method,
                    spec.path
                );
            }
        }
    }

    #[test]
    fn destructive_routes_are_the_three_confirmed_ones() {
        let destructive: Vec<&str> = ROUTES
            .iter()
            .filter(|s| {
                s.action
                    .map(mailstack_core::actions::is_destructive)
                    .unwrap_or(false)
            })
            .map(|s| s.action.unwrap())
            .collect();
        let mut sorted = destructive.clone();
        sorted.sort_unstable();
        assert_eq!(
            sorted,
            vec!["backup.delete", "domains.delete", "users.delete"],
            "破坏性路由集合与 §5.4.1 的 DESTRUCTIVE 集必须一致"
        );
    }

    #[test]
    fn ai_routes_are_detected_for_separate_rate_limiting() {
        assert!(is_ai_path("/api/ai/chat"));
        assert!(is_ai_path("/api/ai/config"));
        assert!(!is_ai_path("/api/admin/get"));
        assert!(!is_ai_path("/api/ai")); // 无尾斜杠，不匹配
    }

    #[test]
    fn telemetry_range_normalization() {
        for valid in TELEMETRY_RANGES {
            assert_eq!(normalize_telemetry_range(Some(valid)), *valid);
        }
        // 非法值回落 1h。
        assert_eq!(normalize_telemetry_range(Some("bogus")), "1h");
        assert_eq!(normalize_telemetry_range(Some("")), "1h");
        assert_eq!(normalize_telemetry_range(None), "1h");
    }

    #[test]
    fn telemetry_ranges_match_baseline_set() {
        assert_eq!(
            TELEMETRY_RANGES,
            &["1m", "5m", "30m", "1h", "6h", "24h", "3d"]
        );
    }

    #[test]
    fn wildcard_routes_are_exactly_the_four_expected() {
        let mut wildcards: Vec<&str> = ROUTES
            .iter()
            .filter(|s| s.path.contains(':'))
            .map(|s| s.path)
            .collect();
        wildcards.sort_unstable();
        wildcards.dedup();
        assert_eq!(
            wildcards,
            vec![
                "/api/aliases/:id",
                "/api/backups/:name",
                "/api/domains/:id",
                "/api/users/:id",
            ]
        );
    }

    #[test]
    fn route_count_is_stable() {
        // 数量变化必须是有意为之：契约是向后兼容承诺（§1.1 第 5 条）。
        assert_eq!(
            ROUTES.len(),
            62,
            "路由数量变化需同步更新契约与 fixtures（实际 {}）",
            ROUTES.len()
        );
    }
}
