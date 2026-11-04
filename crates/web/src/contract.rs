#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Auth {
    Public,

    Required,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteSpec {
    pub method: &'static str,
    pub path: &'static str,

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

pub const ROUTES: &[RouteSpec] = &[
    r("POST", "/api/auth/login", None, Public),
    r("POST", "/api/auth/logout", None, Required),
    r("GET", "/api/auth/session", None, Required),
    r("GET", "/api/auth/sessions", None, Required),
    r("POST", "/api/auth/sessions/revoke", None, Required),
    r("DELETE", "/api/auth/sessions", None, Required),
    r("GET", "/api/health", None, Public),
    r("POST", "/api/rpc", None, Required),
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
    r("GET", "/api/users", Some("users.list"), Required),
    r("POST", "/api/users", Some("users.add"), Required),
    r("POST", "/api/users/status", Some("users.status"), Required),
    r(
        "POST",
        "/api/users/password",
        Some("users.password"),
        Required,
    ),
    r("DELETE", "/api/users/:id", Some("users.delete"), Required),
    r("GET", "/api/aliases", Some("aliases.list"), Required),
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
    r("GET", "/api/queue", Some("queue.list"), Required),
    r("GET", "/api/services", Some("services.list"), Required),
    r("GET", "/api/dkim/keys", Some("dkim.keys"), Required),
    r("GET", "/api/dns/records", Some("dns.records"), Required),
    r(
        "GET",
        "/api/metrics/system",
        Some("metrics.system"),
        Required,
    ),
    r("GET", "/api/activity", Some("activity.list"), Required),
    r("GET", "/api/setup/status", Some("setup.status"), Required),
    r(
        "POST",
        "/api/setup/wizard/complete",
        Some("setup.wizard.complete"),
        Required,
    ),
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
    r(
        "GET",
        "/api/metrics/realtime",
        Some("metrics.realtime"),
        Required,
    ),
    r("GET", "/api/metrics/telemetry", None, Required),
];

pub const TELEMETRY_RANGES: &[&str] = &["1m", "5m", "30m", "1h", "6h", "24h", "3d"];

pub const TELEMETRY_RANGE_DEFAULT: &str = "1h";

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

pub fn is_public(method: &str, path: &str) -> bool {
    ROUTES
        .iter()
        .any(|s| s.method == method && s.path == path && s.auth == Public)
}

pub fn is_exposed_action(action: &str) -> bool {
    ROUTES.iter().any(|spec| spec.action == Some(action))
}

pub const SESSION_REVOKING_ACTIONS: &[&str] =
    &["admin.set", "admin.totp.enable", "admin.totp.disable"];

pub fn revokes_sessions(action: &str) -> bool {
    SESSION_REVOKING_ACTIONS.contains(&action)
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
    fn destructive_routes_mirror_the_destructive_action_set() {
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
        let mut expected = mailstack_core::actions::DESTRUCTIVE_ACTIONS.to_vec();
        expected.sort_unstable();
        assert_eq!(
            sorted, expected,
            "破坏性路由集合必须与 DESTRUCTIVE_ACTIONS 一致（规格书 §5.4.1）"
        );

        assert_eq!(
            sorted,
            vec![
                "admin.totp.disable",
                "backup.delete",
                "domains.delete",
                "users.delete",
            ],
            "破坏性动作集合已变化，请同步更新本断言与 ci.yml 的不变量名单"
        );
    }

    #[test]
    fn telemetry_range_normalization() {
        for valid in TELEMETRY_RANGES {
            assert_eq!(normalize_telemetry_range(Some(valid)), *valid);
        }

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
        assert_eq!(
            ROUTES.len(),
            62,
            "路由数量变化需同步更新契约与 fixtures（实际 {}）",
            ROUTES.len()
        );
    }

    #[test]
    fn the_rpc_bridge_only_exposes_actions_that_already_have_a_route() {
        for action in ["admin.totp.verify", "admin.totp.consume_recovery"] {
            assert!(
                mailstack_core::actions::is_allowed(action),
                "前提：该动作确实在助手白名单里 —— 否则这条断言没有意义"
            );
            assert!(
                !is_exposed_action(action),
                "{action} 没有对外路由，不得被 RPC 桥暴露"
            );
        }

        for spec in ROUTES {
            if let Some(action) = spec.action {
                assert!(is_exposed_action(action), "{action} 应可过桥");
            }
        }
    }

    #[test]
    fn the_session_revoking_set_covers_every_credential_changing_route() {
        for action in SESSION_REVOKING_ACTIONS {
            assert!(
                is_exposed_action(action),
                "{action} 声明了「成功后吊销会话」，却没有对外路由：这段收尾永远不会执行"
            );
            assert!(
                mailstack_core::actions::is_allowed(action),
                "{action} 必须在助手动作白名单内"
            );
            assert!(revokes_sessions(action));
        }

        for (method, path, action) in [
            ("POST", "/api/admin", "admin.set"),
            ("POST", "/api/admin/2fa/enable", "admin.totp.enable"),
            ("POST", "/api/admin/2fa/disable", "admin.totp.disable"),
        ] {
            let spec = ROUTES
                .iter()
                .find(|spec| spec.path == path && spec.method == method)
                .unwrap_or_else(|| panic!("{method} {path} 必须在契约表里"));
            assert_eq!(spec.action, Some(action), "{path} 的动作名被改动了");
            assert!(
                revokes_sessions(action),
                "{path} 的动作 {action} 必须触发会话吊销"
            );
        }

        for action in SESSION_REVOKING_ACTIONS {
            assert!(
                !matches!(*action, "admin.get" | "admin.totp.begin"),
                "{action} 不该吊销会话（begin 只是把 secret 交给用户，2FA 尚未生效）"
            );
        }
        assert!(!revokes_sessions("users.password"));
        assert!(!revokes_sessions("admin.get"));
        assert!(!revokes_sessions(""));
    }
}
