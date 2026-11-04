use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::atomic::atomic_as;
use crate::error::{CoreError, CoreResult};
use crate::password::PasswordRecord;
use crate::paths::Paths;

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

fn clamp_settings(settings: &mut Settings) {
    settings.transparency = settings.transparency.clamp(0, 100);
    settings.backdrop_blur = settings.backdrop_blur.clamp(0, 100);
    settings.spam_threshold = settings.spam_threshold.clamp(0, 100);

    settings.max_message_size_mb = settings.max_message_size_mb.clamp(1, 1024);

    settings.rate_limit_per_hour = settings.rate_limit_per_hour.clamp(1, 1_000_000);
}

const SETTING_VALUE_RANGES: &[(&str, f64, f64)] = &[
    ("transparency", 0.0, 100.0),
    ("backdropBlur", 0.0, 100.0),
    ("spamThreshold", 0.0, 100.0),
    ("maxMessageSizeMb", 1.0, 1024.0),
    ("rateLimitPerHour", 1.0, 1_000_000.0),
];

pub fn apply_settings_patch(
    settings: &mut Settings,
    patch: &serde_json::Map<String, serde_json::Value>,
) -> Vec<String> {
    let mut current = serde_json::to_value(&*settings).unwrap_or(serde_json::Value::Null);
    let Some(obj) = current.as_object_mut() else {
        return Vec::new();
    };
    let mut accepted = Vec::new();
    for (key, value) in patch {
        if !SETTINGS_WRITE_WHITELIST.contains(&key.as_str()) {
            continue;
        }
        let mut value = value.clone();

        if value.is_number() {
            if let Some((_, min, max)) = SETTING_VALUE_RANGES
                .iter()
                .find(|(range_key, _, _)| range_key == key)
            {
                if let Some(number) = value.as_f64() {
                    let clamped = number.round().clamp(*min, *max) as u32;
                    value = serde_json::Value::from(clamped);
                }
            }
        }
        obj.insert(key.clone(), value);
        accepted.push(key.clone());
    }

    let mut updated = match serde_json::from_value::<Settings>(current) {
        Ok(updated) => updated,
        Err(error) => {
            crate::warn::warn(&format!(
                "settings patch rejected (no key was applied): {error}"
            ));
            return Vec::new();
        }
    };
    clamp_settings(&mut updated);
    *settings = updated;
    accepted
}

pub fn read_settings(paths: &Paths) -> Settings {
    read_settings_at(&paths.settings_config)
}

pub fn read_settings_at(path: &Path) -> Settings {
    match std::fs::read_to_string(path) {
        Ok(text) => match serde_json::from_str::<Settings>(&text) {
            Ok(mut s) => {
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

pub fn write_settings(paths: &Paths, settings: &Settings) -> CoreResult<()> {
    let data = format!("{}\n", serde_json::to_string_pretty(settings)?);
    atomic_as(&paths.settings_config, data.as_bytes(), 0o640, None)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdminConfig {
    pub username: String,
    pub algorithm: String,
    pub iterations: u32,
    pub salt: String,
    pub hash: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<serde_json::Value>,
}

impl AdminConfig {
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

pub fn read_admin_config(paths: &Paths) -> Option<AdminConfig> {
    read_admin_config_at(&paths.admin_config)
}

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

pub fn admin_set(paths: &Paths, username: &str, password: &str) -> CoreResult<AdminPublic> {
    let username = username.trim();
    let path = &paths.admin_config;

    crate::atomic::locked(path, || {
        let old = read_admin_config_at(path);

        let degraded = old.is_none()
            && std::fs::metadata(path)
                .map(|meta| meta.len() > 0)
                .unwrap_or(false);

        if password.is_empty() {
            let Some(mut config) = old else {
                return Err(CoreError::invalid("password is required for initial setup"));
            };
            if !crate::validate::ADMIN_RE.is_match(username) {
                return Err(CoreError::invalid("invalid administrator name"));
            }
            config.username = username.to_string();
            write_admin_config(path, &config)?;
            audit_admin_config_recovery(paths, path, degraded)?;
            return Ok(admin_public(paths));
        }

        let record = crate::password::password_record(username, password)?;
        let config = AdminConfig {
            username: record.username,
            algorithm: record.algorithm,
            iterations: record.iterations,
            salt: record.salt,
            hash: record.hash,
            updated_at: record.updated_at,

            totp: old.and_then(|c| c.totp),
        };
        write_admin_config(path, &config)?;
        audit_admin_config_recovery(paths, path, degraded)?;
        Ok(admin_public(paths))
    })
}

fn audit_admin_config_recovery(paths: &Paths, path: &Path, degraded: bool) -> CoreResult<()> {
    if !degraded {
        return Ok(());
    }
    crate::audit::audit(
        &paths.audit_log,
        "admin.config.recovered",
        true,
        "",
        &format!(
            "{} (previous file existed but was corrupt/unreadable; overwritten with a fresh config)",
            path.display()
        ),
    )?;
    Ok(())
}

pub(crate) fn update_admin_config<T>(
    path: &Path,
    f: impl FnOnce(&AdminConfig) -> CoreResult<(AdminConfig, T)>,
) -> CoreResult<T> {
    crate::atomic::locked(path, || {
        let current = read_admin_config_at(path)
            .ok_or_else(|| CoreError::invalid("administrator credentials are not configured"))?;
        let (next, out) = f(&current)?;
        if next != current {
            write_admin_config(path, &next)?;
        }
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

    #[serde(rename = "wizardCompleted", default)]
    pub wizard_completed: bool,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
}

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

pub fn write_setup_config(paths: &Paths, config: &SetupConfig) -> CoreResult<()> {
    let data = format!("{}\n", serde_json::to_string_pretty(config)?);
    crate::atomic::locked(&paths.setup_config, || {
        atomic_as(&paths.setup_config, data.as_bytes(), 0o600, None)
    })
}

pub fn mark_setup_wizard_complete(paths: &Paths) -> CoreResult<()> {
    mark_setup_wizard_complete_at(&paths.setup_config)
}

pub fn mark_setup_wizard_complete_at(path: &Path) -> CoreResult<()> {
    crate::atomic::locked(path, || {
        let Some(mut config) = read_setup_config_at(path) else {
            return Err(CoreError::invalid(
                "setup identity is not configured; complete the identity step first",
            ));
        };
        if config.wizard_completed {
            return Ok(());
        }
        config.wizard_completed = true;
        let data = format!("{}\n", serde_json::to_string_pretty(&config)?);
        atomic_as(path, data.as_bytes(), 0o600, None)
    })
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
    fn a_rejected_settings_patch_reports_no_applied_keys() {
        let mut s = Settings::default();
        let before = s.clone();
        let patch: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(r#"{ "transparency": "not-a-number", "colorTheme": "green" }"#)
                .unwrap();

        let applied = apply_settings_patch(&mut s, &patch);

        assert!(
            applied.is_empty(),
            "反序列化失败时不得回报任何已应用键，实际：{applied:?}"
        );
        assert_eq!(s, before, "被拒绝的 patch 不得改动任何设置");
    }

    #[test]
    fn a_valid_settings_patch_still_reports_its_keys() {
        let mut s = Settings::default();
        let patch: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(r#"{ "transparency": 42 }"#).unwrap();
        let applied = apply_settings_patch(&mut s, &patch);
        assert_eq!(applied, vec!["transparency".to_string()]);
        assert_eq!(s.transparency, 42);
    }

    #[test]
    fn update_admin_config_skips_the_write_when_the_closure_changed_nothing() {
        let f = Fixture::new("nowrite");
        admin_set(&f.paths, "admin", "Tr0ubadour9x").unwrap();
        let before = fs::metadata(&f.paths.admin_config)
            .unwrap()
            .modified()
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));

        let outcome: () =
            update_admin_config(&f.paths.admin_config, |current| Ok((current.clone(), ())))
                .unwrap();

        let after = fs::metadata(&f.paths.admin_config)
            .unwrap()
            .modified()
            .unwrap();
        assert_eq!(outcome, ());
        assert_eq!(before, after, "闭包没有改动的 update_admin_config 不得写盘");
    }

    #[test]
    fn update_admin_config_still_writes_when_the_closure_changes_something() {
        let f = Fixture::new("dowrite");
        admin_set(&f.paths, "admin", "Tr0ubadour9x").unwrap();
        let before = fs::metadata(&f.paths.admin_config)
            .unwrap()
            .modified()
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));

        update_admin_config(&f.paths.admin_config, |current| {
            let mut next = current.clone();
            next.username = "supervisor".to_string();
            Ok((next, ()))
        })
        .unwrap();

        let after = fs::metadata(&f.paths.admin_config)
            .unwrap()
            .modified()
            .unwrap();
        assert_ne!(before, after, "有真实改动时必须写盘");
        let public = admin_public(&f.paths);
        assert_eq!(public.username, "supervisor");
    }

    #[test]
    fn settings_patch_values_are_clamped_to_sane_ranges() {
        let mut s = Settings::default();
        let patch: serde_json::Map<String, serde_json::Value> = serde_json::from_str(
            r#"{
                "transparency": 4000000000,
                "backdropBlur": 999,
                "maxMessageSizeMb": 0,
                "rateLimitPerHour": 99999999999,
                "spamThreshold": 5000
            }"#,
        )
        .unwrap();

        let applied = apply_settings_patch(&mut s, &patch);

        assert_eq!(applied.len(), 5, "五个键都在白名单内，应被接受");
        assert_eq!(s.transparency, 100, "百分比上限 100");
        assert_eq!(s.backdrop_blur, 100);
        assert_eq!(s.max_message_size_mb, 1, "邮件上限至少 1 MB");
        assert_eq!(s.rate_limit_per_hour, 1_000_000);
        assert_eq!(s.spam_threshold, 100);
    }

    #[test]
    fn settings_patch_leaves_in_range_values_untouched() {
        let mut s = Settings::default();
        let patch: serde_json::Map<String, serde_json::Value> = serde_json::from_str(
            r#"{ "transparency": 30, "maxMessageSizeMb": 25, "rateLimitPerHour": 500 }"#,
        )
        .unwrap();
        apply_settings_patch(&mut s, &patch);
        assert_eq!(s.transparency, 30);
        assert_eq!(s.max_message_size_mb, 25);
        assert_eq!(s.rate_limit_per_hour, 500);
    }

    #[test]
    fn admin_public_never_exposes_secret_fields() {
        let f = Fixture::new("adminpublic");
        admin_set(&f.paths, "admin", "Tr0ubadour9x").unwrap();
        let public = admin_public(&f.paths);
        assert_eq!(public.username, "admin");
        assert!(public.password_configured);
        assert!(!public.two_factor_enabled);

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
        let f = Fixture::new("admin2fa");
        admin_set(&f.paths, "admin", "Tr0ubadour9x").unwrap();

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

    #[test]
    fn a_corrupt_admin_file_recovery_is_audited() {
        let f = Fixture::new("adminrecovery");
        fs::create_dir_all(&f.paths.etc).unwrap();
        fs::write(&f.paths.admin_config, "{corrupt json").unwrap();

        admin_set(&f.paths, "admin", "Tr0ubadour9x").unwrap();

        let log = fs::read_to_string(&f.paths.audit_log).unwrap();
        assert!(
            log.contains("admin.config.recovered"),
            "退化恢复必须进审计链：{log}"
        );

        assert!(admin_public(&f.paths).password_configured);
    }

    #[test]
    fn a_first_boot_admin_set_writes_no_recovery_record() {
        let f = Fixture::new("adminfirstboot");
        admin_set(&f.paths, "admin", "Tr0ubadour9x").unwrap();
        match fs::read_to_string(&f.paths.audit_log) {
            Ok(log) => assert!(
                !log.contains("admin.config.recovered"),
                "首次配置不得记为退化恢复：{log}"
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => panic!("{e}"),
        }
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
            wizard_completed: true,
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
            wizard_completed: false,
            updated_at: crate::now_iso8601_utc(),
        };
        let json = serde_json::to_string(&config).unwrap();
        assert!(!json.contains("expectedSpf"));
    }

    #[test]
    fn wizard_completion_falls_back_to_false_for_old_files_and_marks_idempotently() {
        let f = Fixture::new("wizardcomplete");

        fs::create_dir_all(f.paths.setup_config.parent().unwrap()).unwrap();
        fs::write(
            &f.paths.setup_config,
            r#"{
  "domain": "example.com",
  "mailHost": "mail.example.com",
  "serverIp": "203.0.113.10",
  "dkimSelector": "mail",
  "updatedAt": "2026-10-01T00:00:00Z"
}"#,
        )
        .unwrap();
        assert!(
            !read_setup_config(&f.paths).unwrap().wizard_completed,
            "旧文件必须回落 false"
        );

        mark_setup_wizard_complete(&f.paths).unwrap();
        let marked = read_setup_config(&f.paths).unwrap();
        assert!(marked.wizard_completed);
        assert_eq!(marked.domain, "example.com", "置位不得改动其余字段");
        let raw_first = fs::read_to_string(&f.paths.setup_config).unwrap();

        mark_setup_wizard_complete(&f.paths).unwrap();
        assert!(read_setup_config(&f.paths).unwrap().wizard_completed);
        assert_eq!(
            fs::read_to_string(&f.paths.setup_config).unwrap(),
            raw_first,
            "重复置位不得重写文件"
        );
    }

    #[test]
    fn wizard_completion_is_refused_without_an_identity() {
        let f = Fixture::new("wizardnoidentity");
        let error = mark_setup_wizard_complete(&f.paths).unwrap_err();
        assert!(
            error.to_string().contains("not configured"),
            "身份未配置必须拒绝：{error}"
        );
        assert!(
            !f.paths.setup_config.exists(),
            "被拒的置位不得凭空造出 setup.json"
        );
    }
}
