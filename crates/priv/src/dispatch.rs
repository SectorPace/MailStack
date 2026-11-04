use mailstack_core::actions::{self, Channel};
use mailstack_core::paths::Paths;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateDecision {
    Allow,

    Deny(DenyReason),
}

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

pub struct ActionGate {
    #[allow(dead_code)]
    paths: Paths,
}

impl ActionGate {
    pub fn new(paths: Paths) -> Self {
        Self { paths }
    }

    pub fn evaluate(
        &self,
        channel: Channel,
        action: &str,
        data: &serde_json::Value,
    ) -> GateDecision {
        if !actions::is_allowed(action) {
            return GateDecision::Deny(DenyReason::new(
                "UNKNOWN_ACTION",
                format!("unknown action: {action}"),
            ));
        }

        let required = actions::classify(action);
        if required == Channel::Rw && channel == Channel::Ro {
            return GateDecision::Deny(DenyReason::new(
                "ACTION_REQUIRES_PRIVILEGE",
                format!(
                    "{action} is a mutating action and is not available on the read-only surface"
                ),
            ));
        }

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

        GateDecision::Allow
    }
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
        let f = Fixture::new("unknown");
        let gate = ActionGate::new(f.paths.clone());
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
        let gate = ActionGate::new(f.paths.clone());
        assert_allowed(gate.evaluate(Channel::Ro, "domains.list", &json!({})));
        assert_allowed(gate.evaluate(Channel::Ro, "snapshot", &json!({})));
        assert_allowed(gate.evaluate(Channel::Ro, "admin.get", &json!({})));
    }

    #[test]
    fn read_only_channel_refuses_mutating_actions() {
        let f = Fixture::new("ro-widen");
        let gate = ActionGate::new(f.paths.clone());
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
        let gate = ActionGate::new(f.paths.clone());
        assert_allowed(gate.evaluate(Channel::Rw, "domains.list", &json!({})));
        assert_allowed(gate.evaluate(Channel::Rw, "domains.add", &json!({})));
        assert_allowed(gate.evaluate(Channel::Rw, "queue.action", &json!({})));
    }

    #[test]
    fn destructive_action_requires_explicit_confirmation() {
        let f = Fixture::new("confirm");
        let gate = ActionGate::new(f.paths.clone());

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
        let gate = ActionGate::new(f.paths.clone());
        assert_allowed(gate.evaluate(Channel::Rw, "aliases.delete", &json!({})));
        assert_allowed(gate.evaluate(Channel::Rw, "domains.add", &json!({})));
    }

    #[test]
    fn confirm_must_be_a_real_boolean_not_a_truthy_value() {
        let f = Fixture::new("confirmtype");
        let gate = ActionGate::new(f.paths.clone());

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
}
