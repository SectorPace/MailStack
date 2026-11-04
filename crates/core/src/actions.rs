use std::collections::HashSet;
use std::sync::LazyLock;

pub const ALLOWED_ACTIONS_RO: &[&str] = &[
    "snapshot",
    "system.doctor",
    "setup.status",
    "logs.list",
    "metrics.realtime",
    "domains.list",
    "certs.list",
    "settings.get",
    "security.scan",
    "backup.list",
    "admin.get",
    "network.check_port",
    "users.list",
    "aliases.list",
    "queue.list",
    "services.list",
    "dkim.keys",
    "dns.records",
    "metrics.system",
    "activity.list",
];

pub const ALLOWED_ACTIONS_RW: &[&str] = &[
    "setup.identity.apply",
    "setup.dns.verify",
    "setup.relay.test",
    "setup.relay.apply",
    "setup.cert.issue",
    "setup.mail.test",
    "setup.wizard.complete",
    "mail.test_loopback",
    "domains.add",
    "domains.delete",
    "users.add",
    "users.delete",
    "users.status",
    "users.password",
    "aliases.add",
    "aliases.delete",
    "queue.action",
    "services.action",
    "security.unban",
    "security.ban",
    "certs.renew",
    "dkim.rotate",
    "settings.set",
    "backup.create",
    "backup.restore",
    "backup.delete",
    "admin.set",
    "admin.totp.begin",
    "admin.totp.enable",
    "admin.totp.disable",
    "admin.totp.consume_recovery",
    "admin.totp.verify",
];

pub const DESTRUCTIVE_ACTIONS: &[&str] = &[
    "domains.delete",
    "users.delete",
    "backup.delete",
    "admin.totp.disable",
];

static RO_SET: LazyLock<HashSet<&'static str>> =
    LazyLock::new(|| ALLOWED_ACTIONS_RO.iter().copied().collect());
static RW_SET: LazyLock<HashSet<&'static str>> =
    LazyLock::new(|| ALLOWED_ACTIONS_RW.iter().copied().collect());
static DESTRUCTIVE_SET: LazyLock<HashSet<&'static str>> =
    LazyLock::new(|| DESTRUCTIVE_ACTIONS.iter().copied().collect());

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    Ro,

    Rw,
}

pub fn is_ro(action: &str) -> bool {
    RO_SET.contains(action)
}

pub fn is_rw(action: &str) -> bool {
    RW_SET.contains(action)
}

pub fn is_allowed(action: &str) -> bool {
    is_ro(action) || is_rw(action)
}

pub fn is_destructive(action: &str) -> bool {
    DESTRUCTIVE_SET.contains(action)
}

pub fn classify(action: &str) -> Channel {
    if is_rw(action) {
        Channel::Rw
    } else {
        Channel::Ro
    }
}

pub fn all_allowed_actions() -> Vec<&'static str> {
    let mut v: Vec<&'static str> = RO_SET
        .iter()
        .copied()
        .chain(RW_SET.iter().copied())
        .collect();
    v.sort_unstable();
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ro_and_rw_are_disjoint() {
        let overlap: Vec<_> = ALLOWED_ACTIONS_RO
            .iter()
            .filter(|a| RW_SET.contains(**a))
            .collect();
        assert!(overlap.is_empty(), "RO 与 RW 不得有交集: {overlap:?}");
    }

    #[test]
    fn no_duplicate_entries_in_either_set() {
        for (name, set) in [
            ("RO", ALLOWED_ACTIONS_RO),
            ("RW", ALLOWED_ACTIONS_RW),
            ("DESTRUCTIVE", DESTRUCTIVE_ACTIONS),
        ] {
            let unique: HashSet<_> = set.iter().collect();
            assert_eq!(unique.len(), set.len(), "{name} 集合存在重复项");
        }
    }

    #[test]
    fn destructive_actions_are_subset_of_rw() {
        for action in DESTRUCTIVE_ACTIONS {
            assert!(is_rw(action), "破坏性动作 {action} 必须同时属于 RW");
        }
    }

    #[test]
    fn unknown_action_defaults_to_read_only_surface() {
        assert_eq!(classify("totally.unknown.action"), Channel::Ro);
        assert_eq!(classify(""), Channel::Ro);
        assert!(!is_allowed("totally.unknown.action"));
    }

    #[test]
    fn known_actions_classify_to_expected_channel() {
        assert_eq!(classify("domains.list"), Channel::Ro);
        assert_eq!(classify("domains.add"), Channel::Rw);
        assert_eq!(classify("admin.get"), Channel::Ro);
        assert_eq!(classify("admin.set"), Channel::Rw);
    }

    #[test]
    fn read_only_set_has_twenty_actions() {
        assert_eq!(ALLOWED_ACTIONS_RO.len(), 20);
    }

    #[test]
    fn every_added_list_action_is_pure_read() {
        for action in [
            "users.list",
            "aliases.list",
            "queue.list",
            "services.list",
            "dkim.keys",
            "dns.records",
            "metrics.system",
            "activity.list",
        ] {
            assert!(is_ro(action), "{action} 必须是只读");
            assert!(!is_rw(action), "{action} 不得落在变更面");
            assert!(!is_destructive(action), "{action} 不得是破坏性动作");
        }
    }

    #[test]
    fn destructive_set_is_exactly_three_plus_totp_disable() {
        let mut got = DESTRUCTIVE_ACTIONS.to_vec();
        got.sort_unstable();
        assert_eq!(
            got,
            vec![
                "admin.totp.disable",
                "backup.delete",
                "domains.delete",
                "users.delete",
            ]
        );
    }

    #[test]
    fn disabling_two_factor_needs_confirmation() {
        assert!(is_destructive("admin.totp.disable"));
        assert!(is_rw("admin.totp.disable"), "它仍是变更动作");
        assert!(!is_ro("admin.totp.disable"));
    }

    #[test]
    fn every_setup_action_is_rw() {
        for action in ALLOWED_ACTIONS_RW
            .iter()
            .filter(|a| a.starts_with("setup."))
        {
            assert_eq!(classify(action), Channel::Rw, "{action} 必须走变更面");
        }
    }

    #[test]
    fn totp_lifecycle_is_entirely_rw() {
        for action in [
            "admin.totp.begin",
            "admin.totp.enable",
            "admin.totp.disable",
            "admin.totp.verify",
            "admin.totp.consume_recovery",
        ] {
            assert!(is_rw(action), "{action} 必须归 RW");
        }
    }

    #[test]
    fn all_allowed_actions_is_sorted_and_complete() {
        let all = all_allowed_actions();
        let mut sorted = all.clone();
        sorted.sort_unstable();
        assert_eq!(all, sorted, "输出必须已排序");
        assert_eq!(
            all.len(),
            ALLOWED_ACTIONS_RO.len() + ALLOWED_ACTIONS_RW.len()
        );
    }
}
