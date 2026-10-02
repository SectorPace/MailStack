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
            backups_dir: join("/var/backups/mailstack"),
            run_dir: join("/run/mailstack"),
            opendkim: join("/etc/opendkim"),
            letsencrypt: join("/etc/letsencrypt"),
            etc,
            postfix,
        }
    }
}
