//! 部署模式判定与 AI 出站总闸（规格书 §5.2 末、§5.4、INV-10）。
//!
//! **所有调用方必须走 [`is_public_mode`] / [`ai_outbound_enabled`] 单一入口**，
//! 不得自行解析 `install-args.conf` 或环境变量。

use crate::paths::Paths;

/// 读取 `ACCESS_MODE`。
///
/// 三态语义（fail-closed）：
///
/// * 配置文件**不存在**（首次启动）→ `local`（文档化的默认值）；
/// * 文件存在且**恰好一个**合法值（`local` / `caddy` / `direct`，大小写与 shell
///   引号归一后比较）→ 该值；
/// * 文件存在但**读不出来**（权限 / I/O 错误）、`ACCESS_MODE` 缺失、值为空、
///   未知值（如 `public` 这类别名）、或出现**多个** `ACCESS_MODE` 行（歧义）
///   → warn + `direct`（最严的公网档）。
///
/// 原实现只对「读不出来」fail-closed，其余一律回落 `local`（最宽松档）。部署模式
/// 决定的是安全等级（AI 出站总闸、明文备份是否允许、会话 Cookie 的 `Secure`、
/// 中继是否放行私网），所以「文件存在但内容不可解释」必须与「读不出来」同等
/// 对待：`install.sh` 半写、手工改坏、大小写不符都会静默把一台公网主机降级成
/// 本地档。
///
/// `install.sh` 以 `printf 'ACCESS_MODE=%q\n'` 写入，故值可能带 shell 引号，
/// 必须剥离。
pub fn read_access_mode(paths: &Paths) -> String {
    match std::fs::read_to_string(&paths.install_args_conf) {
        Ok(text) => parse_access_mode(&text, &paths.install_args_conf),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => "local".to_string(),
        Err(e) => {
            crate::warn::warn_with_error(
                &format!(
                    "read access mode {} (failing closed to direct)",
                    paths.install_args_conf.display()
                ),
                &e,
            );
            "direct".to_string()
        }
    }
}

/// 解析 `install-args.conf` 的 `ACCESS_MODE`（文件**已**成功读取）。
///
/// 抽出来是为了让三态判定可以在不碰文件系统的前提下被穷举测试，也为了让
/// 「文件缺失 → local」与「文件存在但没有可解释的值 → direct」这两条路径
/// 不会在同一个函数里互相掩盖。
fn parse_access_mode(text: &str, path: &std::path::Path) -> String {
    let mut found: Option<String> = None;
    for line in text.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("ACCESS_MODE=") else {
            continue;
        };
        let value = rest
            .trim()
            .trim_matches(|c| c == '\'' || c == '"')
            .trim()
            .to_ascii_lowercase();
        if !matches!(value.as_str(), "local" | "caddy" | "direct") {
            crate::warn::warn_with_detail(
                &format!("read access mode {}", path.display()),
                &format!("ACCESS_MODE 值非法（{value:?}），按 direct 处理"),
            );
            return "direct".to_string();
        }
        if found.is_some() {
            // 两行不同值 = 无法确定部署模式（install.sh 半写 / 手工拼接）。
            // 先到先得会让文件末尾那一行被静默忽略，方向也不可控。
            crate::warn::warn_with_detail(
                &format!("read access mode {}", path.display()),
                "ACCESS_MODE 出现多次，按 direct 处理",
            );
            return "direct".to_string();
        }
        found = Some(value);
    }
    match found {
        Some(value) => value,
        None => {
            // 文件存在却没有该键：不是「首次启动」，是内容不可解释。
            crate::warn::warn_with_detail(
                &format!("read access mode {}", path.display()),
                "缺少 ACCESS_MODE 行，按 direct 处理",
            );
            "direct".to_string()
        }
    }
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

    /// fail-closed 守卫：文件存在但 `ACCESS_MODE` 为空 ⇒ 按最严档处理。
    ///
    /// 旧测试（`empty_access_mode_falls_back_to_local`）把 fail-open 钉成了期望
    /// 行为：`install.sh` 半写出来的 `ACCESS_MODE=` 会在公网主机上静默降级成
    /// `local`（AI 出站总闸失效、允许明文备份、Cookie 不再强制 Secure）。
    #[test]
    fn empty_access_mode_fails_closed_to_direct() {
        let f = Fixture::new();
        f.write(&f.paths.install_args_conf, "ACCESS_MODE=\n");
        assert_eq!(read_access_mode(&f.paths), "direct");
        assert!(
            is_public_mode_with(&f.paths, None),
            "空值必须按公网档处理，而不是本地档"
        );
    }

    /// fail-closed 守卫：未知值 / 别名 / 大小写异常都不得静默降级。
    #[test]
    fn unknown_access_mode_values_fail_closed_to_direct() {
        for content in [
            "ACCESS_MODE=public\n",
            "ACCESS_MODE=lan\n",
            "ACCESS_MODE=1\n",
            "enabled=1\n",           // 没有任何 ACCESS_MODE 行
            "# ACCESS_MODE=local\n", // 注释行不是配置
            "ACCESS_MODE=local extra\n",
        ] {
            let f = Fixture::new();
            f.write(&f.paths.install_args_conf, content);
            let mode = read_access_mode(&f.paths);
            assert_eq!(
                mode, "direct",
                "内容 {content:?} 不可解释时不得回落到最宽松档"
            );
            assert!(is_public_mode_with(&f.paths, None), "内容 {content:?}");
        }
    }

    /// 歧义：两行 `ACCESS_MODE` 必须按最严档处理（先到先得会让末尾行被静默忽略）。
    #[test]
    fn conflicting_access_mode_lines_fail_closed_to_direct() {
        let f = Fixture::new();
        f.write(
            &f.paths.install_args_conf,
            "ACCESS_MODE=direct\nACCESS_MODE=local\n",
        );
        assert_eq!(read_access_mode(&f.paths), "direct");

        let f = Fixture::new();
        f.write(
            &f.paths.install_args_conf,
            "ACCESS_MODE=local\nACCESS_MODE=local\n",
        );
        // 重复但一致：仍是无法唯一确定来源的写坏形态，按最严档处理。
        assert_eq!(read_access_mode(&f.paths), "direct");
    }

    /// 大小写归一后仍是**合法**值：不能把 `DIRECT` 判成未知（那会误伤正常安装）。
    #[test]
    fn access_mode_values_are_normalised_before_comparison() {
        for (content, expected) in [
            ("ACCESS_MODE=DIRECT\n", "direct"),
            ("ACCESS_MODE=Caddy\n", "caddy"),
            ("ACCESS_MODE= Local \n", "local"),
            ("ACCESS_MODE=\"local\"\n", "local"),
        ] {
            let f = Fixture::new();
            f.write(&f.paths.install_args_conf, content);
            assert_eq!(read_access_mode(&f.paths), expected, "内容 {content:?}");
        }
    }

    /// fail-closed 守卫：文件存在但**读不出来**（权限/I-O 错误）时，
    /// 不得回落到最宽松的 `local`，而要按最严的公网档 `direct` 处理并告警。
    ///
    /// 用一个**目录**冒充配置文件触发读错误：`read_to_string` 对目录报
    /// EISDIR，与运行身份无关 —— 以 root 跑测试时 chmod 000 挡不住 root。
    #[test]
    fn an_unreadable_install_args_conf_fails_closed_to_the_restrictive_mode() {
        let f = Fixture::new();
        fs::create_dir_all(&f.paths.install_args_conf).unwrap();

        assert_eq!(read_access_mode(&f.paths), "direct");
        assert!(
            is_public_mode_with(&f.paths, None),
            "读不出部署模式必须按公网档（更严）处理"
        );
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
