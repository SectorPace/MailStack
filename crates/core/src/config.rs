//! `/etc/mailstack/*.json` 的 schema 与写入白名单（规格书 §2.6；INV-30、INV-43）。
//!
//! 读取语义：文件缺失或解析失败时**回落到全默认值**（不报错），但仍通过
//! [`crate::warn`] 写一次 stderr —— 否则「一个损坏的配置文件」会静默降级成
//! 「未配置」，且没有任何地方说明文件无法解析。

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::atomic::atomic_as;
use crate::error::{CoreError, CoreResult};
use crate::password::PasswordRecord;
use crate::paths::Paths;

/// 管理台设置。字段与默认值逐条对齐 `telemetry.py:101-126`。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub transparency: u32,
    #[serde(rename = "backdropBlur")]
    pub backdrop_blur: u32,
    #[serde(rename = "reducedMotion")]
    pub reduced_motion: bool,
    #[serde(rename = "autoUpdate")]
    pub auto_update: bool,
    pub version: String,
    pub hostname: String,
    #[serde(rename = "adminEmail")]
    pub admin_email: String,
    pub timezone: String,
    #[serde(rename = "maxMessageSizeMb")]
    pub max_message_size_mb: u32,
    #[serde(rename = "relayConcurrency")]
    pub relay_concurrency: u32,
    #[serde(rename = "rateLimitPerHour")]
    pub rate_limit_per_hour: u32,
    #[serde(rename = "spamThreshold")]
    pub spam_threshold: u32,
    /// 默认 `blue`（systemBlue）。§4.5 明确要求由 `cyan` 翻转。
    #[serde(rename = "colorTheme")]
    pub color_theme: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            transparency: 70,
            backdrop_blur: 16,
            reduced_motion: false,
            auto_update: false,
            version: crate::VERSION.to_string(),
            hostname: default_hostname(),
            admin_email: String::new(),
            timezone: default_timezone(),
            max_message_size_mb: 50,
            relay_concurrency: 20,
            rate_limit_per_hour: 500,
            spam_threshold: 6,
            color_theme: "blue".to_string(),
        }
    }
}

fn default_hostname() -> String {
    // 避免为了一个 fqdn 引入整条依赖链；读取 /etc/hostname 已足够。
    std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "localhost".to_string())
}

fn default_timezone() -> String {
    std::env::var("TZ")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "UTC".to_string())
}

/// 写入白名单（`telemetry.py:130`）。
///
/// 只有这 11 个键可被 `settings.set` 写入，**其余键一律丢弃**（INV-43）。
/// 不得演变成任意键写入。
pub const SETTINGS_WRITE_WHITELIST: &[&str] = &[
    "transparency",
    "backdropBlur",
    "reducedMotion",
    "autoUpdate",
    "adminEmail",
    "maxMessageSizeMb",
    "rateLimitPerHour",
    "spamThreshold",
    "colorTheme",
    "hostname",
    "timezone",
];

/// 应用一次局部更新，丢弃白名单外的键。
///
/// 返回被应用的键名列表，便于审计与测试。
pub fn apply_settings_patch(
    settings: &mut Settings,
    patch: &serde_json::Map<String, serde_json::Value>,
) -> Vec<String> {
    let mut applied = Vec::new();
    let mut current = serde_json::to_value(&*settings).unwrap_or(serde_json::Value::Null);
    let Some(obj) = current.as_object_mut() else {
        return applied;
    };
    for (key, value) in patch {
        if !SETTINGS_WRITE_WHITELIST.contains(&key.as_str()) {
            continue;
        }
        obj.insert(key.clone(), value.clone());
        applied.push(key.clone());
    }
    if let Ok(updated) = serde_json::from_value::<Settings>(current) {
        *settings = updated;
    }
    applied
}

/// 读取设置；文件缺失或损坏时回落默认值并 `warn` 一次。
pub fn read_settings(paths: &Paths) -> Settings {
    read_settings_at(&paths.settings_config)
}

/// 指定路径的读取，便于测试与 `mailstackctl --settings-file` 场景。
pub fn read_settings_at(path: &Path) -> Settings {
    match std::fs::read_to_string(path) {
        Ok(text) => match serde_json::from_str::<Settings>(&text) {
            Ok(mut s) => {
                // 缺失的字段由 serde default 补齐；这里保证 version 反映真实版本。
                if s.version.is_empty() {
                    s.version = crate::VERSION.to_string();
                }
                s
            }
            Err(e) => {
                crate::warn::warn_with_error(&format!("parse settings {}", path.display()), &e);
                Settings::default()
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Settings::default(),
        Err(e) => {
            crate::warn::warn_with_error(&format!("read settings {}", path.display()), &e);
            Settings::default()
        }
    }
}

/// 原子写入设置（0640）。
pub fn write_settings(paths: &Paths, settings: &Settings) -> CoreResult<()> {
    let data = format!("{}\n", serde_json::to_string_pretty(settings)?);
    atomic_as(&paths.settings_config, data.as_bytes(), 0o640, None)
}

/// `admin.json` —— 凭证记录 + 2FA 信封（`core.py:480-556`）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdminConfig {
    pub username: String,
    pub algorithm: String,
    pub iterations: u32,
    pub salt: String,
    pub hash: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
    /// 2FA 块。**改密码不得覆盖此块**（INV-30）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<serde_json::Value>,
}

impl AdminConfig {
    /// 转为 [`PasswordRecord`] 以便复用常量时间校验。
    pub fn password_record(&self) -> PasswordRecord {
        PasswordRecord {
            username: self.username.clone(),
            algorithm: self.algorithm.clone(),
            iterations: self.iterations,
            salt: self.salt.clone(),
            hash: self.hash.clone(),
            updated_at: self.updated_at.clone(),
        }
    }
}

/// 管理员的**公开**字段（`admin_public`）。**绝不含 secret**（INV-1）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdminPublic {
    pub username: String,
    #[serde(rename = "passwordConfigured")]
    pub password_configured: bool,
    #[serde(rename = "twoFactorEnabled")]
    pub two_factor_enabled: bool,
    #[serde(rename = "recoveryCodesRemaining")]
    pub recovery_codes_remaining: usize,
}

impl Default for AdminPublic {
    fn default() -> Self {
        Self {
            username: "admin".to_string(),
            password_configured: false,
            two_factor_enabled: false,
            recovery_codes_remaining: 0,
        }
    }
}

/// 读取 `admin.json`；缺失返回 `None`（合法：从未配置）。
pub fn read_admin_config(paths: &Paths) -> Option<AdminConfig> {
    read_admin_config_at(&paths.admin_config)
}

/// 指定路径读取。损坏时报 `warn` 并返回 `None`。
pub fn read_admin_config_at(path: &Path) -> Option<AdminConfig> {
    match std::fs::read_to_string(path) {
        Ok(text) => match serde_json::from_str::<AdminConfig>(&text) {
            Ok(c) => Some(c),
            Err(e) => {
                crate::warn::warn_with_error(&format!("parse admin config {}", path.display()), &e);
                None
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            crate::warn::warn_with_error(&format!("read admin config {}", path.display()), &e);
            None
        }
    }
}

/// 管理员的公开视图（绝不返回 secret）。
pub fn admin_public(paths: &Paths) -> AdminPublic {
    let Some(config) = read_admin_config(paths) else {
        return AdminPublic::default();
    };
    let totp = config.totp.as_ref().and_then(|v| v.as_object());
    let enabled = totp
        .and_then(|t| t.get("enabled"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let recovery_len = totp
        .and_then(|t| t.get("recovery"))
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);

    AdminPublic {
        username: config.username.clone(),
        password_configured: !config.hash.is_empty(),
        two_factor_enabled: enabled,
        recovery_codes_remaining: recovery_len,
    }
}

/// 修改管理员凭证（对应 `admin_set`）。
///
/// **两条不可动摇的语义**：
/// * 只改用户名时保留既有 `totp` 块
/// * 改密码时同样保留既有 `totp` 块（旧实现曾导致每次普通改密静默关闭 2FA，INV-30）
pub fn admin_set(paths: &Paths, username: &str, password: &str) -> CoreResult<AdminPublic> {
    let username = username.trim();
    let path = &paths.admin_config;

    crate::atomic::locked(path, || {
        let old = read_admin_config_at(path);

        if password.is_empty() {
            // 仅改用户名：必须已有配置，且名字合法。
            let Some(mut config) = old else {
                return Err(CoreError::invalid("password is required for initial setup"));
            };
            if !crate::validate::ADMIN_RE.is_match(username) {
                return Err(CoreError::invalid("invalid administrator name"));
            }
            config.username = username.to_string();
            write_admin_config(path, &config)?;
            return Ok(admin_public(paths));
        }

        let record = crate::password::password_record(username, password)?;
        let mut config = AdminConfig {
            username: record.username,
            algorithm: record.algorithm,
            iterations: record.iterations,
            salt: record.salt,
            hash: record.hash,
            updated_at: record.updated_at,
            // INV-30：改密不得清空 2FA。
            totp: old.and_then(|c| c.totp),
        };
        // 规范化：确保 2FA 块在序列化时保留。
        if config.totp.is_none() {
            config.totp = None;
        }
        write_admin_config(path, &config)?;
        Ok(admin_public(paths))
    })
}

/// 在 `locked()` 临界区内对 `admin.json` 做**完整的读-改-写**（INV-32）。
///
/// 存在的理由：`write_admin_config` 自身的原子性只覆盖最终写入那一瞬，
/// 一次 `read → 改 → write` 仍会丢更新。两次并发的恢复码消费会各自基于
/// 「码还在」的同一份快照写回，于是同一张恢复码被用掉两次（double spend）。
/// 因此**所有**对 `admin.json` 的修改都必须经由本函数，而不是各自 read 后 write。
///
/// 配置不存在时返回错误而不是凭空创建：2FA 只能在已有管理员凭证之上启用。
pub(crate) fn update_admin_config<T>(
    path: &Path,
    f: impl FnOnce(&AdminConfig) -> CoreResult<(AdminConfig, T)>,
) -> CoreResult<T> {
    crate::atomic::locked(path, || {
        let current = read_admin_config_at(path)
            .ok_or_else(|| CoreError::invalid("administrator credentials are not configured"))?;
        let (next, out) = f(&current)?;
        write_admin_config(path, &next)?;
        Ok(out)
    })
}

fn write_admin_config(path: &Path, config: &AdminConfig) -> CoreResult<()> {
    let data = format!("{}\n", serde_json::to_string_pretty(config)?);
    atomic_as(
        path,
        data.as_bytes(),
        0o640,
        Some(crate::atomic::ADMIN_GROUP),
    )
}

/// `setup.json` —— 初始化身份信息（`network.py:138`，0600）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SetupConfig {
    pub domain: String,
    #[serde(rename = "mailHost")]
    pub mail_host: String,
    #[serde(rename = "serverIp")]
    pub server_ip: String,
    #[serde(rename = "dkimSelector")]
    pub dkim_selector: String,
    #[serde(
        rename = "expectedSpf",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub expected_spf: Option<String>,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
}

/// 校验 setup 身份：`mailHost` 必须是 `domain` 的子域。
pub fn validate_setup_identity(
    domain: &str,
    mail_host: &str,
    dkim_selector: &str,
) -> CoreResult<()> {
    if !crate::validate::DOMAIN_RE.is_match(domain) {
        return Err(CoreError::invalid("invalid domain"));
    }
    if !crate::validate::DOMAIN_RE.is_match(mail_host) {
        return Err(CoreError::invalid("invalid mail host"));
    }
    if !mail_host.ends_with(&format!(".{domain}")) {
        return Err(CoreError::invalid(
            "mail host must be a subdomain of the domain",
        ));
    }
    if !crate::validate::DKIM_SELECTOR_RE.is_match(dkim_selector) {
        return Err(CoreError::invalid("invalid DKIM selector"));
    }
    Ok(())
}

/// 读取 `setup.json`（缺失或损坏返回 `None`）。
pub fn read_setup_config(paths: &Paths) -> Option<SetupConfig> {
    read_setup_config_at(&paths.setup_config)
}

pub fn read_setup_config_at(path: &Path) -> Option<SetupConfig> {
    match std::fs::read_to_string(path) {
        Ok(text) => match serde_json::from_str(&text) {
            Ok(c) => Some(c),
            Err(e) => {
                crate::warn::warn_with_error(&format!("parse setup config {}", path.display()), &e);
                None
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            crate::warn::warn_with_error(&format!("read setup config {}", path.display()), &e);
            None
        }
    }
}

/// 原子写入 `setup.json`（0600）。
pub fn write_setup_config(paths: &Paths, config: &SetupConfig) -> CoreResult<()> {
    let data = format!("{}\n", serde_json::to_string_pretty(config)?);
    atomic_as(&paths.setup_config, data.as_bytes(), 0o600, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    struct Fixture {
        root: PathBuf,
        paths: Paths,
    }

    impl Fixture {
        fn new(tag: &str) -> Self {
            let mut root = std::env::temp_dir();
            root.push(format!(
                "mailstack-config-{tag}-{}-{}",
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

    #[test]
    fn default_settings_match_baseline_values() {
        let s = Settings::default();
        assert_eq!(s.transparency, 70);
        assert_eq!(s.backdrop_blur, 16);
        assert!(!s.reduced_motion);
        assert!(!s.auto_update);
        assert_eq!(s.max_message_size_mb, 50);
        assert_eq!(s.relay_concurrency, 20);
        assert_eq!(s.rate_limit_per_hour, 500);
        assert_eq!(s.spam_threshold, 6);
        // §4.5：由 cyan 翻转为 blue（systemBlue）。
        assert_eq!(s.color_theme, "blue");
        assert_eq!(s.version, crate::VERSION);
    }

    #[test]
    fn missing_settings_file_falls_back_to_defaults_without_error() {
        let f = Fixture::new("missing");
        let s = read_settings(&f.paths);
        assert_eq!(s, Settings::default());
    }

    #[test]
    fn corrupt_settings_file_falls_back_to_defaults() {
        let f = Fixture::new("corrupt");
        fs::create_dir_all(&f.paths.etc).unwrap();
        fs::write(&f.paths.settings_config, "{not json").unwrap();
        let s = read_settings(&f.paths);
        assert_eq!(s, Settings::default());
    }

    #[test]
    fn partial_settings_file_is_completed_by_defaults() {
        let f = Fixture::new("partial");
        fs::create_dir_all(&f.paths.etc).unwrap();
        fs::write(&f.paths.settings_config, "{\"transparency\":42}\n").unwrap();
        let s = read_settings(&f.paths);
        assert_eq!(s.transparency, 42);
        assert_eq!(s.backdrop_blur, 16, "缺失字段应回落默认值");
    }

    #[test]
    fn settings_round_trip_preserves_camel_case_keys() {
        let f = Fixture::new("roundtrip");
        let s = Settings {
            max_message_size_mb: 100,
            color_theme: "purple".into(),
            ..Settings::default()
        };
        write_settings(&f.paths, &s).unwrap();

        let raw = fs::read_to_string(&f.paths.settings_config).unwrap();
        assert!(raw.contains("\"maxMessageSizeMb\""), "必须写 camelCase 键");
        assert!(raw.contains("\"colorTheme\""));
        let back = read_settings(&f.paths);
        assert_eq!(back.max_message_size_mb, 100);
        assert_eq!(back.color_theme, "purple");
    }

    #[test]
    fn settings_write_whitelist_rejects_unknown_keys() {
        // INV-43 核心断言。
        let mut s = Settings::default();
        let patch: serde_json::Map<String, serde_json::Value> = serde_json::from_str(
            r#"{
                "transparency": 33,
                "colorTheme": "green",
                "version": "9.9.9",
                "evilKey": true,
                "hash": "injected"
            }"#,
        )
        .unwrap();
        let applied = apply_settings_patch(&mut s, &patch);

        assert_eq!(s.transparency, 33);
        assert_eq!(s.color_theme, "green");
        assert!(
            !applied.contains(&"version".to_string()),
            "version 不在白名单内"
        );
        assert!(!applied.contains(&"evilKey".to_string()));
        assert!(!applied.contains(&"hash".to_string()));
        assert_eq!(s.version, crate::VERSION, "version 必须保持不变");
    }

    #[test]
    fn settings_write_whitelist_has_exactly_eleven_keys() {
        assert_eq!(SETTINGS_WRITE_WHITELIST.len(), 11);
    }

    #[test]
    fn admin_public_never_exposes_secret_fields() {
        let f = Fixture::new("adminpublic");
        admin_set(&f.paths, "admin", "Tr0ubadour9x").unwrap();
        let public = admin_public(&f.paths);
        assert_eq!(public.username, "admin");
        assert!(public.password_configured);
        assert!(!public.two_factor_enabled);

        // 序列化后的 JSON 里不得出现 salt/hash。
        let json = serde_json::to_string(&public).unwrap();
        assert!(!json.contains("salt"));
        assert!(!json.contains("hash"));
        assert!(!json.contains("Tr0ubadour9x"));
    }

    #[test]
    fn admin_defaults_when_never_configured() {
        let f = Fixture::new("admindefault");
        let public = admin_public(&f.paths);
        assert_eq!(public, AdminPublic::default());
        assert!(!public.password_configured);
    }

    #[test]
    fn admin_set_requires_password_for_initial_setup() {
        let f = Fixture::new("admininit");
        let err = admin_set(&f.paths, "admin", "").unwrap_err();
        assert_eq!(err.to_string(), "password is required for initial setup");
    }

    #[test]
    fn admin_password_change_preserves_totp_block() {
        // INV-30：旧实现曾导致每次普通改密静默关闭 2FA。
        let f = Fixture::new("admin2fa");
        admin_set(&f.paths, "admin", "Tr0ubadour9x").unwrap();

        // 手工注入一个 2FA 块，模拟已启用 2FA 的账号。
        let text = fs::read_to_string(&f.paths.admin_config).unwrap();
        let mut value: serde_json::Value = serde_json::from_str(&text).unwrap();
        value["totp"] = serde_json::json!({
            "enabled": true,
            "recovery": ["aaaaaaaa", "bbbbbbbb"],
            "enc": "ZmFrZQ==",
            "nonce": "bm9uY2U=",
            "tag": "dGFn"
        });
        fs::write(
            &f.paths.admin_config,
            serde_json::to_string_pretty(&value).unwrap(),
        )
        .unwrap();

        // 改密码。
        admin_set(&f.paths, "admin", "An0therGood1").unwrap();

        let public = admin_public(&f.paths);
        assert!(public.two_factor_enabled, "INV-30: 改密码不得关闭 2FA");
        assert_eq!(public.recovery_codes_remaining, 2, "恢复码不得被清空");

        let after: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&f.paths.admin_config).unwrap()).unwrap();
        assert_eq!(after["totp"]["enc"], "ZmFrZQ==", "信封必须原样保留");
    }

    #[test]
    fn admin_rename_only_preserves_password_hash() {
        let f = Fixture::new("adminrename");
        admin_set(&f.paths, "admin", "Tr0ubadour9x").unwrap();
        let before: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&f.paths.admin_config).unwrap()).unwrap();

        admin_set(&f.paths, "supervisor", "").unwrap();
        let after: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&f.paths.admin_config).unwrap()).unwrap();

        assert_eq!(after["username"], "supervisor");
        assert_eq!(after["hash"], before["hash"], "仅改名不得改口令哈希");
        assert_eq!(after["salt"], before["salt"]);
    }

    #[test]
    fn admin_rename_rejects_invalid_name() {
        let f = Fixture::new("adminbadname");
        admin_set(&f.paths, "admin", "Tr0ubadour9x").unwrap();
        let err = admin_set(&f.paths, "ab", "").unwrap_err();
        assert_eq!(err.to_string(), "invalid administrator name");
    }

    #[test]
    fn admin_config_is_never_written_with_plaintext_password() {
        let f = Fixture::new("adminplain");
        admin_set(&f.paths, "admin", "Tr0ubadour9x").unwrap();
        let raw = fs::read_to_string(&f.paths.admin_config).unwrap();
        assert!(!raw.contains("Tr0ubadour9x"), "明文口令绝不落盘");
        assert!(raw.contains("pbkdf2-sha256"));
    }

    #[cfg(unix)]
    #[test]
    fn admin_config_is_written_0640() {
        use std::os::unix::fs::PermissionsExt;
        let f = Fixture::new("adminmode");
        admin_set(&f.paths, "admin", "Tr0ubadour9x").unwrap();
        let mode = fs::metadata(&f.paths.admin_config)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o640, "admin.json 必须为 0640");
    }

    #[test]
    fn setup_identity_requires_subdomain_mail_host() {
        validate_setup_identity("example.com", "mail.example.com", "mail").unwrap();
        assert!(validate_setup_identity("example.com", "example.com", "mail").is_err());
        assert!(validate_setup_identity("example.com", "mail.other.com", "mail").is_err());
        assert!(validate_setup_identity("bad domain", "mail.bad domain", "mail").is_err());
        assert!(
            validate_setup_identity("example.com", "mail.example.com", "bad selector!").is_err()
        );
    }

    #[test]
    fn setup_config_round_trip_at_0600() {
        let f = Fixture::new("setup");
        let config = SetupConfig {
            domain: "example.com".into(),
            mail_host: "mail.example.com".into(),
            server_ip: "203.0.113.10".into(),
            dkim_selector: "mail".into(),
            expected_spf: Some("v=spf1 mx -all".into()),
            updated_at: crate::now_iso8601_utc(),
        };
        write_setup_config(&f.paths, &config).unwrap();
        let back = read_setup_config(&f.paths).unwrap();
        assert_eq!(back, config);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&f.paths.setup_config)
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "setup.json 必须为 0600");
        }
    }

    #[test]
    fn setup_config_omits_optional_spf_when_absent() {
        let config = SetupConfig {
            domain: "example.com".into(),
            mail_host: "mail.example.com".into(),
            server_ip: "203.0.113.10".into(),
            dkim_selector: "mail".into(),
            expected_spf: None,
            updated_at: crate::now_iso8601_utc(),
        };
        let json = serde_json::to_string(&config).unwrap();
        assert!(!json.contains("expectedSpf"));
    }
}
