//! 文件系统契约（规格书 §2.5）。
//!
//! **磁盘布局不得改变**：运维脚本与既有用户数据依赖这些路径。全部路径以
//! [`Paths`] 注入，生产默认值与 `core.py` 逐字一致，测试用临时目录覆盖。

use std::path::{Path, PathBuf};

/// 生产环境路径集合。
#[derive(Debug, Clone)]
pub struct Paths {
    /// `/etc/mailstack`
    pub etc: PathBuf,
    /// `/etc/postfix`
    pub postfix: PathBuf,
    /// `/etc/postfix/mailstack_domains` —— 虚拟域名表
    pub domains: PathBuf,
    /// `/etc/postfix/mailstack_aliases` —— 别名表
    pub aliases: PathBuf,
    /// `/etc/mailstack/admin.json`
    pub admin_config: PathBuf,
    /// `/etc/mailstack/mailbox-passwords.json` —— 邮箱口令记录库（PBKDF2，INV-37）
    ///
    /// IMAP/POP3（`mailstack-imap`）的**唯一**口令来源。此前该职责由 Dovecot 的
    /// PAM passdb 承担；换成自研协议面后，口令记录必须由 MailStack 自己持有，
    /// 否则协议面只能去解析 `/etc/shadow` 的 crypt 格式（yescrypt/$6$ 多套算法，
    /// 且与 INV-37 的「PBKDF2-SHA256 唯一真相源」冲突）。
    ///
    /// 文件为 `0600 root:root`（含可离线爆破的口令哈希），内容见
    /// [`crate::mailbox_passwords`]。
    pub mailbox_passwords: PathBuf,
    /// `/etc/mailstack/settings.json`
    pub settings_config: PathBuf,
    /// `/etc/mailstack/setup.json`
    pub setup_config: PathBuf,
    /// `/etc/mailstack/ai-provider.json`（机密）
    pub ai_config: PathBuf,
    /// `/etc/mailstack/ai.conf` —— AI 出站总闸
    pub ai_outbound_conf: PathBuf,
    /// `/etc/mailstack/install-args.conf` —— 含 `ACCESS_MODE`
    pub install_args_conf: PathBuf,
    /// `/etc/mailstack/totp.key` —— TOTP 主密钥（0600 root:root）
    pub totp_key: PathBuf,
    /// `/etc/mailstack/relay.json` —— 中继凭证（§5.9.6 迁移目标）
    pub relay_config: PathBuf,
    /// `/var/log/mailstack-rpc-audit.log`
    pub audit_log: PathBuf,
    /// `/var/vmail`
    pub vmail: PathBuf,
    /// `/var/lib/mailstack`
    pub var_lib: PathBuf,
    /// `/var/lib/mailstack/manual-bans.json` —— 管理台手工封禁（0600 root:root）
    pub manual_bans: PathBuf,
    /// `/etc/mailstack/managed-users.json` —— 受管 unix 账号名（JSON 数组，0640）
    pub managed_users: PathBuf,
    /// `/var/lib/mailstack/managed-mailboxes.json` —— 邮箱→unix账号注册表（0640 root:mailstack-webmail）
    ///
    /// 放在世界可遍历目录而非 `/etc/mailstack`：webmail 进程不在 mailstack-admin 组，
    /// 放 `/etc/mailstack` 会让每次 webmail 登录都 fail-closed。该文件不含机密
    /// （只有地址与账号名），故 `root:mailstack-webmail` 可读。
    pub managed_mailboxes: PathBuf,
    /// `/var/lib/mailstack/webmail-session-epoch.json` —— webmail 会话纪元（改密/锁定即 bump）
    pub webmail_session_epoch: PathBuf,
    /// `/var/backups/mailstack`
    pub backups_dir: PathBuf,
    /// `/run/mailstack`
    pub run_dir: PathBuf,
    /// `/etc/opendkim`
    pub opendkim: PathBuf,
    /// `/etc/letsencrypt`
    pub letsencrypt: PathBuf,
}

impl Default for Paths {
    fn default() -> Self {
        Self::production()
    }
}

impl Paths {
    /// 生产布局，逐字对齐 `core.py` / `backup.py` / `totp.py` 的常量。
    pub fn production() -> Self {
        let etc = PathBuf::from("/etc/mailstack");
        let postfix = PathBuf::from("/etc/postfix");
        Self {
            domains: postfix.join("mailstack_domains"),
            aliases: postfix.join("mailstack_aliases"),
            admin_config: etc.join("admin.json"),
            mailbox_passwords: etc.join("mailbox-passwords.json"),
            settings_config: etc.join("settings.json"),
            setup_config: etc.join("setup.json"),
            ai_config: etc.join("ai-provider.json"),
            ai_outbound_conf: etc.join("ai.conf"),
            install_args_conf: etc.join("install-args.conf"),
            totp_key: etc.join("totp.key"),
            relay_config: etc.join("relay.json"),
            audit_log: PathBuf::from("/var/log/mailstack-rpc-audit.log"),
            vmail: PathBuf::from("/var/vmail"),
            var_lib: PathBuf::from("/var/lib/mailstack"),
            manual_bans: PathBuf::from("/var/lib/mailstack/manual-bans.json"),
            managed_users: etc.join("managed-users.json"),
            managed_mailboxes: PathBuf::from("/var/lib/mailstack/managed-mailboxes.json"),
            webmail_session_epoch: PathBuf::from("/var/lib/mailstack/webmail-session-epoch.json"),
            backups_dir: PathBuf::from("/var/backups/mailstack"),
            run_dir: PathBuf::from("/run/mailstack"),
            opendkim: PathBuf::from("/etc/opendkim"),
            letsencrypt: PathBuf::from("/etc/letsencrypt"),
            etc,
            postfix,
        }
    }

    /// 全部路径挂到 `root` 下的等价布局，仅供测试使用。
    pub fn rooted(root: impl AsRef<Path>) -> Self {
        let root = root.as_ref();
        let join = |p: &str| root.join(p.trim_start_matches('/'));
        let etc = join("/etc/mailstack");
        let postfix = join("/etc/postfix");
        Self {
            domains: postfix.join("mailstack_domains"),
            aliases: postfix.join("mailstack_aliases"),
            admin_config: etc.join("admin.json"),
            mailbox_passwords: etc.join("mailbox-passwords.json"),
            settings_config: etc.join("settings.json"),
            setup_config: etc.join("setup.json"),
            ai_config: etc.join("ai-provider.json"),
            ai_outbound_conf: etc.join("ai.conf"),
            install_args_conf: etc.join("install-args.conf"),
            totp_key: etc.join("totp.key"),
            relay_config: etc.join("relay.json"),
            audit_log: join("/var/log/mailstack-rpc-audit.log"),
            vmail: join("/var/vmail"),
            var_lib: join("/var/lib/mailstack"),
            manual_bans: join("/var/lib/mailstack/manual-bans.json"),
            managed_users: join("/etc/mailstack/managed-users.json"),
            managed_mailboxes: join("/var/lib/mailstack/managed-mailboxes.json"),
            webmail_session_epoch: join("/var/lib/mailstack/webmail-session-epoch.json"),
            backups_dir: join("/var/backups/mailstack"),
            run_dir: join("/run/mailstack"),
            opendkim: join("/etc/opendkim"),
            letsencrypt: join("/etc/letsencrypt"),
            etc,
            postfix,
        }
    }
}
