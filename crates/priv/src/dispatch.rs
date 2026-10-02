//! 动作分派门（规格书 §5.4.1、§5.4.2、§5.4.4）。
//!
//! 门控在**执行之前**完成，任何拒绝都不产生副作用（INV-2）。
//!
//! 三条判定依次进行：
//!
//! 1. 动作必须命中白名单并属于本通道允许的集合 → 否则拒绝
//! 2. 破坏性动作必须携带 `confirm: true` → 否则拒绝
//! 3. AI 出站动作必须通过出站总闸 → 否则拒绝（INV-10）

use mailstack_core::actions::{self, Channel};
use mailstack_core::mode;
use mailstack_core::paths::Paths;

/// 门控判决。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateDecision {
    /// 放行。
    Allow,
    /// 拒绝，附对外错误语义。
    Deny(DenyReason),
}

/// 拒绝原因。`code` 直接映射到 HTTP 错误码，`message` 可给运维看。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DenyReason {
    pub code: &'static str,
    pub message: String,
}

impl DenyReason {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

/// 动作分派门。
pub struct ActionGate {
    paths: Paths,
    /// 若为 `Some`，则覆盖 AI 出站判定（测试注入用）。
    ai_outbound_override: Option<bool>,
}

impl ActionGate {
    pub fn new(paths: Paths) -> Self {
        Self {
            paths,
            ai_outbound_override: None,
        }
    }

    /// 注入 AI 出站判定结果，避免测试触碰进程环境变量。
    pub fn with_ai_outbound(paths: Paths, enabled: bool) -> Self {
        Self {
            paths,
            ai_outbound_override: Some(enabled),
        }
    }

    fn ai_outbound_enabled(&self) -> bool {
        match self.ai_outbound_override {
            Some(v) => v,
            None => mode::ai_outbound_enabled(&self.paths),
        }
    }

    /// 判定某个动作在本通道上是否可执行。
    ///
    /// `channel` 是该请求**到达的通道**（RO socket 或 RW 包装器）。
    /// 关键约束：RO 通道**不得**执行任何 RW 动作——否则只读面被悄悄拓宽，
    /// 正是 INV-24 要防的事。
    pub fn evaluate(
        &self,
        channel: Channel,
        action: &str,
        data: &serde_json::Value,
    ) -> GateDecision {
        // 1) 白名单：未登记的动作一律拒绝。
        if !actions::is_allowed(action) {
            return GateDecision::Deny(DenyReason::new(
                "UNKNOWN_ACTION",
                format!("unknown action: {action}"),
            ));
        }

        // 2) 通道一致性：RO 面不得执行变更动作。
        let required = actions::classify(action);
        if required == Channel::Rw && channel == Channel::Ro {
            return GateDecision::Deny(DenyReason::new(
                "ACTION_REQUIRES_PRIVILEGE",
                format!(
                    "{action} is a mutating action and is not available on the read-only surface"
                ),
            ));
        }

        // 3) 破坏性动作必须显式确认。
        if actions::is_destructive(action) {
            let confirmed = data
                .get("confirm")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if !confirmed {
                return GateDecision::Deny(DenyReason::new(
                    "CONFIRMATION_REQUIRED",
                    format!("{action} requires confirm: true"),
                ));
            }
        }

        // 4) AI 出站总闸。
        if is_ai_outbound_action(action) && !self.ai_outbound_enabled() {
            return GateDecision::Deny(DenyReason::new(
                "AI_OUTBOUND_DISABLED",
                "AI outbound calls are disabled by deployment policy".to_string(),
            ));
        }

        GateDecision::Allow
    }
}

/// 受出站总闸门控的动作集合（`dispatcher.py` 的 AI 出站闸）。
///
/// 注意 `ai.config.get` / `ai.models.list` 的归属：
/// `ai.config.get` 是纯读配置，不在出站闸内；
/// `ai.models.list` 会向供应商发起出站请求，故受门控。
pub fn is_ai_outbound_action(action: &str) -> bool {
    matches!(
        action,
        "ai.test" | "ai.chat" | "ai.diagnose" | "ai.parse" | "ai.models.list"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;

    struct Fixture {
        root: std::path::PathBuf,
        paths: Paths,
    }

    impl Fixture {
        fn new(tag: &str) -> Self {
            let mut root = std::env::temp_dir();
            root.push(format!(
                "mailstack-gate-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir_all(&root).unwrap();
            let paths = Paths::rooted(&root);
            Self { root, paths }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn assert_allowed(decision: GateDecision) {
        assert_eq!(decision, GateDecision::Allow);
    }

    fn assert_denied(decision: GateDecision, code: &str) {
        match decision {
            GateDecision::Deny(reason) => assert_eq!(reason.code, code, "实际: {reason:?}"),
            GateDecision::Allow => panic!("预期被拒绝({code})，但放行了"),
        }
    }

    #[test]
    fn unknown_action_is_always_denied() {
        // INV-3：白名单外的动作一律拒绝。
        let f = Fixture::new("unknown");
        let gate = ActionGate::with_ai_outbound(f.paths.clone(), true);
        assert_denied(
            gate.evaluate(Channel::Ro, "rm.rf", &json!({})),
            "UNKNOWN_ACTION",
        );
        assert_denied(
            gate.evaluate(Channel::Rw, "rm.rf", &json!({"confirm": true})),
            "UNKNOWN_ACTION",
        );
    }

    #[test]
    fn read_only_channel_allows_ro_actions() {
        let f = Fixture::new("ro");
        let gate = ActionGate::with_ai_outbound(f.paths.clone(), true);
        assert_allowed(gate.evaluate(Channel::Ro, "domains.list", &json!({})));
        assert_allowed(gate.evaluate(Channel::Ro, "snapshot", &json!({})));
        assert_allowed(gate.evaluate(Channel::Ro, "admin.get", &json!({})));
    }

    #[test]
    fn read_only_channel_refuses_mutating_actions() {
        // 这是 INV-24 的核心：只读面不得被悄悄拓宽成变更面。
        let f = Fixture::new("ro-widen");
        let gate = ActionGate::with_ai_outbound(f.paths.clone(), true);
        assert_denied(
            gate.evaluate(Channel::Ro, "domains.add", &json!({})),
            "ACTION_REQUIRES_PRIVILEGE",
        );
        assert_denied(
            gate.evaluate(Channel::Ro, "settings.set", &json!({})),
            "ACTION_REQUIRES_PRIVILEGE",
        );
        assert_denied(
            gate.evaluate(Channel::Ro, "admin.set", &json!({})),
            "ACTION_REQUIRES_PRIVILEGE",
        );
        assert_denied(
            gate.evaluate(Channel::Ro, "admin.totp.verify", &json!({})),
            "ACTION_REQUIRES_PRIVILEGE",
        );
    }

    #[test]
    fn rw_channel_allows_both_ro_and_rw_actions() {
        let f = Fixture::new("rw");
        let gate = ActionGate::with_ai_outbound(f.paths.clone(), true);
        assert_allowed(gate.evaluate(Channel::Rw, "domains.list", &json!({})));
        assert_allowed(gate.evaluate(Channel::Rw, "domains.add", &json!({})));
        assert_allowed(gate.evaluate(Channel::Rw, "queue.action", &json!({})));
    }

    #[test]
    fn destructive_action_requires_explicit_confirmation() {
        // INV-2：缺少 confirm 时拒绝，且不产生任何副作用。
        let f = Fixture::new("confirm");
        let gate = ActionGate::with_ai_outbound(f.paths.clone(), true);

        for action in ["domains.delete", "users.delete", "backup.delete"] {
            assert_denied(
                gate.evaluate(Channel::Rw, action, &json!({})),
                "CONFIRMATION_REQUIRED",
            );
            assert_denied(
                gate.evaluate(Channel::Rw, action, &json!({"confirm": false})),
                "CONFIRMATION_REQUIRED",
            );
            assert_allowed(gate.evaluate(Channel::Rw, action, &json!({"confirm": true})));
        }
    }

    #[test]
    fn non_destructive_action_does_not_need_confirmation() {
        let f = Fixture::new("noconfirm");
        let gate = ActionGate::with_ai_outbound(f.paths.clone(), true);
        assert_allowed(gate.evaluate(Channel::Rw, "aliases.delete", &json!({})));
        assert_allowed(gate.evaluate(Channel::Rw, "domains.add", &json!({})));
    }

    #[test]
    fn confirm_must_be_a_real_boolean_not_a_truthy_value() {
        let f = Fixture::new("confirmtype");
        let gate = ActionGate::with_ai_outbound(f.paths.clone(), true);
        // 字符串 "true" 不是 `true`，必须被拒绝。
        assert_denied(
            gate.evaluate(Channel::Rw, "domains.delete", &json!({"confirm": "true"})),
            "CONFIRMATION_REQUIRED",
        );
        assert_denied(
            gate.evaluate(Channel::Rw, "domains.delete", &json!({"confirm": 1})),
            "CONFIRMATION_REQUIRED",
        );
        assert_denied(
            gate.evaluate(Channel::Rw, "domains.delete", &json!({"confirm": null})),
            "CONFIRMATION_REQUIRED",
        );
    }

    #[test]
    fn ai_outbound_actions_are_gated_when_disabled() {
        // INV-10：关闭时一律拒绝。
        let f = Fixture::new("aioff");
        let gate = ActionGate::with_ai_outbound(f.paths.clone(), false);
        for action in [
            "ai.test",
            "ai.chat",
            "ai.diagnose",
            "ai.parse",
            "ai.models.list",
        ] {
            assert_denied(
                gate.evaluate(Channel::Rw, action, &json!({})),
                "AI_OUTBOUND_DISABLED",
            );
        }
    }

    #[test]
    fn ai_outbound_actions_pass_when_enabled() {
        let f = Fixture::new("aion");
        let gate = ActionGate::with_ai_outbound(f.paths.clone(), true);
        assert_allowed(gate.evaluate(Channel::Rw, "ai.chat", &json!({})));
        assert_allowed(gate.evaluate(Channel::Rw, "ai.test", &json!({})));
    }

    #[test]
    fn ai_config_get_is_not_gated_by_outbound_switch() {
        // ai.config.get 只读本地配置，不出网，故不受总闸门控。
        let f = Fixture::new("aiconf");
        let gate = ActionGate::with_ai_outbound(f.paths.clone(), false);
        assert_allowed(gate.evaluate(Channel::Ro, "ai.config.get", &json!({})));
        assert!(!is_ai_outbound_action("ai.config.get"));
        assert!(!is_ai_outbound_action("ai.config.set"));
    }

    #[test]
    fn outbound_gate_is_evaluated_after_whitelist_and_confirmation() {
        // 顺序断言：未登记动作报 UNKNOWN_ACTION，而不是报总闸错误。
        let f = Fixture::new("order");
        let gate = ActionGate::with_ai_outbound(f.paths.clone(), false);
        assert_denied(
            gate.evaluate(Channel::Rw, "ai.nonexistent", &json!({})),
            "UNKNOWN_ACTION",
        );
    }
}
