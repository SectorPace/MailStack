use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Paths {
    pub etc: PathBuf,

    pub postfix: PathBuf,

    pub domains: PathBuf,

    pub aliases: PathBuf,

    pub admin_config: PathBuf,

    pub mailbox_passwords: PathBuf,

    pub settings_config: PathBuf,

    pub setup_config: PathBuf,

    pub install_args_conf: PathBuf,

    pub totp_key: PathBuf,

    pub relay_config: PathBuf,

    pub audit_log: PathBuf,

    pub vmail: PathBuf,

    pub var_lib: PathBuf,

    pub manual_bans: PathBuf,

    pub managed_users: PathBuf,

    pub managed_mailboxes: PathBuf,

    pub webmail_session_epoch: PathBuf,

    pub backups_dir: PathBuf,

    pub run_dir: PathBuf,

    pub opendkim: PathBuf,

    pub letsencrypt: PathBuf,
}

impl Default for Paths {
    fn default() -> Self {
        Self::production()
    }
}

impl Paths {
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
