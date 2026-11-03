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
    // RPC 桥：动作名在**请求体**里（`{"action":..,"data":..}`），由 Web 进程转发给
    // 助手。`action` 为 `None` —— 它按请求体分派，没有单一固定动作。
    // 允许集见 [`is_exposed_action`]：必须严于助手白名单。
    r("POST", "/api/rpc", None, Required),
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
    // `GET /api/users` 与 `POST /api/users` 同层级共存（静态段 + 方法区分）：
    // 前端把「列用户」与「建用户」都挂在同一个路径上。
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
    // 与 `/api/users` 同理：前端在同一个路径上分别用 GET / POST 取列表与新建。
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
    // ── 为管理前端新增的只读列表端点（基线 62 条契约里没有） ──
    //
    // 新前端（mailstack-admin-frontend）把每个列表页的数据源都做成一个独立动作。
    // 单列这 6 条而不是让前端走 RPC 桥，是因为契约表是**路由的唯一真相源**：
    // 桥的允许集由本表推导（见 [`is_exposed_action`]），不在这里声明就等于不可达。
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
    // ── 初始化流程 ──
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
    // 模型列表会向外部发送已保存凭据，因此 GET/POST 都必须经特权动作路由。
    r("GET", "/api/ai/models", Some("ai.models.list"), Required),
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

/// RPC 桥（`POST /api/rpc`）允许的动作集合 —— [`ROUTES`] 里声明过的全部动作。
///
/// 为什么这样取：动作名在桥里是**请求体字段**（由前端传输层决定），所以允许集
/// 必须**严于** `mailstack_core::actions::ALLOWED_ACTIONS`。本集合是那个白名单的
/// 真子集 —— 它只含已有专门 HTTP 路由的动作，于是只被登录流程内部使用的
/// `admin.totp.verify` / `admin.totp.consume_recovery` 不会因为桥而暴露到 HTTP 面。
///
/// 破坏性动作的 `confirm: true` 仍由助手侧 `ActionGate` 强制，请求体绕不过去。
pub fn is_exposed_action(action: &str) -> bool {
    ROUTES.iter().any(|spec| spec.action == Some(action))
}

/// 成功后**必须吊销会话**的动作（改密 / 2FA 绑定与解绑）。
///
/// ## 为什么它是契约的一部分，而不是埋在三个处理器里
///
/// `POST /api/admin`、`/api/admin/2fa/enable`、`/api/admin/2fa/disable` 成功之后
/// 必须让**全部旧会话失效** —— 改密/改 2FA 是事故响应的第一步，如果旧会话还能用，
/// 「 attacker 被踢下线」这条链就不成立。
///
/// 但同一个动作还能从 `POST /api/rpc` 桥触达（桥是前端传输层的兜底路径，不是
/// 只有手工 curl 才走得到的旁门），而桥原先只做「查白名单 + 转发」，**完全不做**
/// 这段收尾。把「动作 → 收尾」抽到这里，REST 处理器与桥共用同一份判定，
/// 才不会再出现「专用路由记得踢人、桥忘了踢」这种绕过。
///
/// 守卫见 [`tests::the_session_revoking_set_covers_every_credential_changing_route`]：
/// 三个动作必须各自有路由，且不允许出现「路由在、集合里没写」的动作。
pub const SESSION_REVOKING_ACTIONS: &[&str] =
    &["admin.set", "admin.totp.enable", "admin.totp.disable"];

/// 该动作成功后是否需要吊销该管理员的全部会话。
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
    fn destructive_routes_mirror_the_destructive_action_set() {
        // 这条断言的价值在于「两处**同步**」：`DESTRUCTIVE_ACTIONS` 加了动作而
        // 这里没跟上（或反之），就会有一边不要求 `confirm: true`。
        // 历史上有过 3 个（删域名/删用户/删备份），加入 `admin.totp.disable`
        // 后是 4 个 —— 拆 2FA 同样不可逆且削弱安全性。
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
        // 显式钉住当前集合，避免有人同时改两边而断言仍然通过。
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
        // 62 → 72：为管理前端新增 10 条 —— RPC 桥 `POST /api/rpc`、
        // 三条它硬编码了方法与路径的只读端点（GET /api/users、GET /api/aliases、
        // GET /api/ai/models），以及六条新的只读列表端点
        // （GET /api/queue、/api/services、/api/dkim/keys、/api/dns/records、
        // /api/metrics/system、/api/activity）。
        // 十条都是**新增**，没有改动或删除任何既有条目。
        // 72 → 73：新增 `POST /api/setup/wizard/complete`（向导收尾，
        // 置位 setup.json 的 wizardCompleted；RW 动作，幂等）。
        assert_eq!(
            ROUTES.len(),
            73,
            "路由数量变化需同步更新契约与 fixtures（实际 {}）",
            ROUTES.len()
        );
    }

    #[test]
    fn the_rpc_bridge_only_exposes_actions_that_already_have_a_route() {
        // 桥的允许集是白名单的真子集：只被登录流程内部使用的
        // `admin.totp.verify` / `admin.totp.consume_recovery` 不得从 HTTP 面可达。
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
        // 反向：已有路由的动作必须都能过桥，否则前端 fallback 传输会 403。
        for spec in ROUTES {
            if let Some(action) = spec.action {
                assert!(is_exposed_action(action), "{action} 应可过桥");
            }
        }
    }

    /// `admin.set` / `admin.totp.enable` / `admin.totp.disable` 成功后必须吊销
    /// 会话 —— 这份集合是 REST 路由与 RPC 桥**共用**的收尾判定。
    ///
    /// 守卫是双向的：集合里写了的动作必须有路由（否则永远没人能触发它）；
    /// 反过来，这三个动作**只能**通过这三条路由出现，且必须在集合里。
    #[test]
    fn the_session_revoking_set_covers_every_credential_changing_route() {
        // 集合里的每个动作都必须有对外路由。
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

        // 反向：任何映射到这三个动作的路由，动作名必须与集合一致（不允许改名漂移）。
        // 必须带 method 一起匹配：`/api/admin` 同时有 GET（admin.get）与 POST
        // （admin.set），只按 path 找到的是第一条（GET），会把正确实现判红。
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

        // 集合里不允许混进无需吊销的动作（否则会误踢全部会话）。
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
