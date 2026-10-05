//! 特权动作三集与通道推导（规格书 §5.4.1、INV-24）。
//!
//! 归类纪律（`core.py:94-96` 原文）：纯读者入 RO；凡「写文件 / 改服务状态 /
//! 发信 / 锁账号 / 消费 TOTP 恢复码」者入 RW；**「拿不准」一律归 RW**。
//!
//! **未知 action 默认走只读面**——这是静默提权防护，不得改为默认走 RW。

use std::collections::HashSet;
use std::sync::LazyLock;

/// 只读动作（21 项）。这些动作可直连 `/run/mailstack/helper-ro.sock`。
pub const ALLOWED_ACTIONS_RO: &[&str] = &[
    // 纯读聚合：status() 汇总 domains/users/aliases/queue/certs/logs 的只读列表。
    "snapshot",
    // 诊断只读：仅读配置 + 对 TEST-NET-1(192.0.2.1) 做 ban/unban 往返探针，不落持久状态。
    "system.doctor",
    // 读 setup.json 与服务活性。
    "setup.status",
    // 读 journal / 日志文件。
    "logs.list",
    // 读 /proc + 服务状态。
    "metrics.realtime",
    // 读域名表。
    "domains.list",
    // 读证书文件。
    "certs.list",
    // 读 settings.json + 配置回读。
    "settings.get",
    // 只读扫描：无需副作用的配置与权限检查。
    "security.scan",
    // 列出备份归档。
    "backup.list",
    // 读 admin.json 的公开字段（绝不含 secret）。
    "admin.get",
    // 读 ai-provider.json 的公开配置。
    "ai.config.get",
    // 仅出站 TCP 端口探测，不写本机状态。
    "network.check_port",
    // ── 以下 8 项为管理前端（mailstack-admin-frontend）新增 ──
    // 基线 50 条白名单里**没有**这些动作，是为了支持前端的列表页而扩展的。
    // 全部是纯读：不写文件、不改服务状态、不发信，故按归类纪律（「纯读者入 RO」）入 RO。
    // 读两份用户注册表（managed-users.json / managed-mailboxes.json）。
    "users.list",
    // 读别名表。
    "aliases.list",
    // 读本机邮件队列。
    "queue.list",
    // 读 postfix/dovecot 等服务活性。
    "services.list",
    // 列举 opendkim 密钥目录（只读 stat，不导出私钥）。
    "dkim.keys",
    // 出站解析 A/MX/TXT，不写本机状态。
    "dns.records",
    // 读 /proc 的资源占用快照。
    "metrics.system",
    // 读审计日志尾部（只读）。
    "activity.list",
];

/// 变更动作。恒经 sudo 包装器下发，Web 进程无法直连变更 socket。
pub const ALLOWED_ACTIONS_RW: &[&str] = &[
    // setup 流程：写配置、签发证书、发测试信。dns.verify / relay.test 虽以出站查询为主，
    // 但不在只读白名单内且属 setup 流程，按纪律保守归 RW。
    "setup.identity.apply",
    "setup.dns.verify",
    "setup.relay.test",
    "setup.relay.apply",
    "setup.cert.issue",
    "setup.mail.test",
    // 发信（本机投递副作用）。
    "mail.test_loopback",
    // 域名 / 邮箱 / 别名 / 队列变更。users.status 会锁解账号，属 RW。
    "domains.add",
    "domains.delete",
    "users.add",
    "users.delete",
    "users.status",
    "users.password",
    "aliases.add",
    "aliases.delete",
    "queue.action",
    // 服务启停重载。
    "services.action",
    // 封禁 / 解封。
    "security.unban",
    "security.ban",
    // 证书续期 / DKIM 轮换（写密钥与配置）。
    "certs.renew",
    "dkim.rotate",
    // 写 settings.json。
    "settings.set",
    // 备份创建 / 恢复 / 删除。
    "backup.create",
    "backup.restore",
    "backup.delete",
    // 管理员凭证变更。
    "admin.set",
    // TOTP 全生命周期：begin/enable/disable 写信封，consume_recovery 消费恢复码，
    // verify 在迁移路径会重新封装 admin.json（有写副作用），故全归 RW。
    "admin.totp.begin",
    "admin.totp.enable",
    "admin.totp.disable",
    "admin.totp.consume_recovery",
    "admin.totp.verify",
    // AI 配置写入、出站对话 / 诊断 / 解析与模型枚举（出站携带受保护凭据）。
    "ai.config.set",
    "ai.test",
    "ai.chat",
    "ai.models.list",
    "ai.diagnose",
    "ai.parse",
];

/// 破坏性动作：必须携带 `confirm: true`，否则助手直接拒绝且不产生任何副作用（INV-2）。
///
/// `admin.totp.disable` 在此名单里：它把账号的第二个因子整个作废（secret 与
/// 恢复码一并丢弃），属不可逆且**削弱**安全性的动作。基线曾把它排除在外，
/// 理由是「2FA 已经不在了，确认没有意义」—— 但恰恰相反，会话被劫持时攻击者
/// 拿到的是**已认证会话**，不是第二个因子；此时唯一还能证明「你是你」的东西
/// 就是这个因子，把它无验证地关掉正是最需要确认的一步。
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

/// 调用通道。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    /// 直连只读 socket。
    Ro,
    /// 经 sudo 到特权二进制的变更面。
    Rw,
}

pub fn is_ro(action: &str) -> bool {
    RO_SET.contains(action)
}

pub fn is_rw(action: &str) -> bool {
    RW_SET.contains(action)
}

/// 白名单并集判定（对应 `ALLOWED_ACTIONS`）。
pub fn is_allowed(action: &str) -> bool {
    is_ro(action) || is_rw(action)
}

pub fn is_destructive(action: &str) -> bool {
    DESTRUCTIVE_SET.contains(action)
}

/// 推导通道：**未登记的 action 一律默认只读**，由 daemon 拒绝。
///
/// 原文注释："a read-only surface cannot widen silently"。
pub fn classify(action: &str) -> Channel {
    if is_rw(action) {
        Channel::Rw
    } else {
        Channel::Ro
    }
}

/// 全量白名单（RO ∪ RW），按字典序去重，供契约与门禁比对。
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
        // INV-24：静默提权防护。这条断言是安全门禁，不得删除。
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
    fn read_only_set_has_twenty_one_actions_after_moving_models_to_rw() {
        // 规格书 §5.4.1 明示 RO 为 14 项；数量漂移意味着归类纪律被破坏。
        // 管理前端增加了 8 个纯读列表动作，随后 `ai.models.list` 因携带 API key
        // 的出站请求从 RO 移到 RW；因此当前只读集合长度为 21 项。
        assert_eq!(ALLOWED_ACTIONS_RO.len(), 21);
    }

    #[test]
    fn model_listing_is_confined_to_the_privileged_channel() {
        assert!(!is_ro("ai.models.list"));
        assert!(is_rw("ai.models.list"));
        assert_eq!(classify("ai.models.list"), Channel::Rw);
    }

    #[test]
    fn every_added_list_action_is_pure_read() {
        // 这 8 项是规格外扩展，必须逐个确认没有被误归到变更面 ——
        // 一旦落进 RW，Web 进程就得经 sudo 下发，等于给只读列表开了特权通道。
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
        // 3 → 4：新增 `admin.totp.disable`。拆 2FA 不可逆且削弱安全性，
        // 必须与删域名 / 删用户 / 删备份一样先要 `confirm: true`。
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
        // 回归守卫：`admin.totp.disable` 一旦被移出破坏性名单，劫持来的会话
        // 就能静默拆掉 2FA，而这条断言会变红。
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
        // admin.totp.verify 在迁移路径会重新封装 admin.json（有写副作用）。
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
