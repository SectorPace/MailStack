//! 部署模式判定与 AI 出站总闸（规格书 §5.2 末、§5.4、INV-10）。
//!
//! **所有调用方必须走 [`is_public_mode`] / [`ai_outbound_enabled`] 单一入口**，
//! 不得自行解析 `install-args.conf` 或环境变量。

use crate::paths::Paths;

/// 读取 `ACCESS_MODE`。文件或键缺失时返回 `local`。
///
/// `install.sh` 以 `printf 'ACCESS_MODE=%q\n'` 写入，故值可能带 shell 引号，
/// 必须剥离。
pub fn read_access_mode(paths: &Paths) -> String {
    let Ok(text) = std::fs::read_to_string(&paths.install_args_conf) else {
        return "local".to_string();
    };
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("ACCESS_MODE=") {
            let value = rest.trim().trim_matches(|c| c == '\'' || c == '"');
            return if value.is_empty() {
                "local".to_string()
            } else {
                value.to_string()
            };
        }
    }
    "local".to_string()
}

/// 是否面向公网（`caddy`/`direct`）或显式高安全档。
pub fn is_public_mode(paths: &Paths) -> bool {
    if matches!(read_access_mode(paths).as_str(), "caddy" | "direct") {
        return true;
    }
    std::env::var("MAILSTACK_SECURITY_PROFILE")
        .map(|v| v.trim().to_lowercase() == "high")
        .unwrap_or(false)
}

/// 指定环境变量值的出站判定（供测试注入，避免依赖进程环境）。
pub fn is_public_mode_with(paths: &Paths, security_profile: Option<&str>) -> bool {
    if matches!(read_access_mode(paths).as_str(), "caddy" | "direct") {
        return true;
    }
    security_profile
        .map(|v| v.trim().to_lowercase() == "high")
        .unwrap_or(false)
}

/// AI 出站总闸（`core.py:63-86` 语义必须完整保留）。
///
/// * 环境变量 `MAILSTACK_AI_OUTBOUND` 非空 → 以其为准（`0`/`false`/`no`/`off` 视为关）
/// * 非公网模式 → 恒 `true`（历史行为）
/// * 公网模式 → 读 `ai.conf` 的 `enabled=` 行
/// * 文件缺失或未开启 → **`false`（fail-closed）**
pub fn ai_outbound_enabled(paths: &Paths) -> bool {
    ai_outbound_enabled_with(
        paths,
        std::env::var("MAILSTACK_AI_OUTBOUND").ok().as_deref(),
    )
}

/// 可注入环境变量的版本，便于测试（不触碰进程全局状态）。
pub fn ai_outbound_enabled_with(paths: &Paths, env_flag: Option<&str>) -> bool {
    let flag = env_flag.unwrap_or("").trim().to_lowercase();
    if !flag.is_empty() {
        return !matches!(flag.as_str(), "0" | "false" | "no" | "off");
    }
    if !is_public_mode(paths) {
        return true;
    }
    let Ok(text) = std::fs::read_to_string(&paths.ai_outbound_conf) else {
        return false;
    };
    for line in text.lines() {
        let line = line.trim();
        // 6.13：键名必须**整串**等于 `enabled`。
        //
        // 原先是 `line.starts_with("enabled") && line.contains('=')` ——
        // 前缀匹配意味着 `enabledx=1`、`enabled_backup=yes` 之类也会被当成
        // 出站开关。配置文件是运维可编辑的，任何同前缀的注释性条目都可能
        // 意外把 AI 出站打开（而这是一个应当 fail-closed 的开关）。
        let Some((key, raw_value)) = line.split_once('=') else {
            continue;
        };
        if key.trim() != "enabled" {
            continue;
        }
        let value = raw_value
            .trim()
            .trim_matches(|c| c == '\'' || c == '"')
            .to_lowercase();
        return matches!(value.as_str(), "1" | "true" | "yes" | "on");
    }
    false
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
        fn new() -> Self {
            let mut root = std::env::temp_dir();
            root.push(format!("mailstack-mode-{}", uuid_like()));
            fs::create_dir_all(&root).unwrap();
            let paths = Paths::rooted(&root);
            Self { root, paths }
        }

        fn write(&self, path: &std::path::Path, content: &str) {
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, content).unwrap();
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn uuid_like() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        format!(
            "{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )
    }

    #[test]
    fn missing_install_args_defaults_to_local() {
        let f = Fixture::new();
        assert_eq!(read_access_mode(&f.paths), "local");
        assert!(!is_public_mode_with(&f.paths, None));
    }

    #[test]
    fn access_mode_survives_shell_quoting() {
        let f = Fixture::new();
        f.write(&f.paths.install_args_conf, "ACCESS_MODE='caddy'\n");
        assert_eq!(read_access_mode(&f.paths), "caddy");
        assert!(is_public_mode_with(&f.paths, None));

        f.write(&f.paths.install_args_conf, "ACCESS_MODE=\"direct\"\n");
        assert!(is_public_mode_with(&f.paths, None));
    }

    #[test]
    fn empty_access_mode_falls_back_to_local() {
        let f = Fixture::new();
        f.write(&f.paths.install_args_conf, "ACCESS_MODE=\n");
        assert_eq!(read_access_mode(&f.paths), "local");
    }

    #[test]
    fn security_profile_high_forces_public_mode() {
        let f = Fixture::new();
        assert!(is_public_mode_with(&f.paths, Some("high")));
        assert!(is_public_mode_with(&f.paths, Some("HIGH")));
        assert!(!is_public_mode_with(&f.paths, Some("low")));
    }

    #[test]
    fn ai_outbound_is_always_on_in_local_mode() {
        let f = Fixture::new();
        assert!(ai_outbound_enabled_with(&f.paths, None));
    }

    #[test]
    fn ai_outbound_is_fail_closed_in_public_mode_without_conf() {
        let f = Fixture::new();
        f.write(&f.paths.install_args_conf, "ACCESS_MODE=direct\n");
        // 文件缺失 → false（fail-closed），不是「回落到开启」。
        assert!(!ai_outbound_enabled_with(&f.paths, None));
    }

    #[test]
    fn ai_outbound_reads_enabled_flag_only_when_public() {
        let f = Fixture::new();
        f.write(&f.paths.install_args_conf, "ACCESS_MODE=caddy\n");
        f.write(&f.paths.ai_outbound_conf, "enabled=true\n");
        assert!(ai_outbound_enabled_with(&f.paths, None));

        f.write(&f.paths.ai_outbound_conf, "enabled=no\n");
        assert!(!ai_outbound_enabled_with(&f.paths, None));

        // 注释行与其它键不得误判为开启。
        f.write(&f.paths.ai_outbound_conf, "# enabled=true\nother=1\n");
        assert!(!ai_outbound_enabled_with(&f.paths, None));
    }

    #[test]
    fn env_flag_overrides_file_in_both_directions() {
        let f = Fixture::new();
        f.write(&f.paths.install_args_conf, "ACCESS_MODE=direct\n");
        f.write(&f.paths.ai_outbound_conf, "enabled=true\n");
        // 环境变量一旦设置即以其为准，含显式关闭。
        assert!(!ai_outbound_enabled_with(&f.paths, Some("0")));
        assert!(!ai_outbound_enabled_with(&f.paths, Some("false")));
        assert!(!ai_outbound_enabled_with(&f.paths, Some("OFF")));
        assert!(ai_outbound_enabled_with(&f.paths, Some("1")));
        assert!(ai_outbound_enabled_with(&f.paths, Some("yes")));
    }

    /// 6.13：键名必须**整串**等于 `enabled`，不能前缀匹配。
    ///
    /// 原实现 `line.starts_with("enabled")` 会让 `enabledx=1`、
    /// `enabled_backup=yes` 之类同前缀的条目把 AI 出站打开 ——
    /// 而这本该是 fail-closed 的开关。
    #[test]
    fn only_an_exact_enabled_key_turns_ai_outbound_on() {
        let f = Fixture::new();
        f.write(&f.paths.install_args_conf, "ACCESS_MODE=direct\n");

        for decoy in [
            "enabledx=1\n",
            "enabled_backup=yes\n",
            "ai_enabled=1\n",
            "enabled-extra=on\n",
        ] {
            f.write(&f.paths.ai_outbound_conf, decoy);
            assert!(
                !ai_outbound_enabled_with(&f.paths, None),
                "同前缀键 {decoy:?} 不得打开 AI 出站"
            );
        }

        // 真正的键仍然生效（含空白与引号）。
        f.write(&f.paths.ai_outbound_conf, "  enabled = \"yes\"  \n");
        assert!(ai_outbound_enabled_with(&f.paths, None));
    }
}
