use crate::paths::Paths;

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
            crate::warn::warn_with_detail(
                &format!("read access mode {}", path.display()),
                "缺少 ACCESS_MODE 行，按 direct 处理",
            );
            "direct".to_string()
        }
    }
}

pub fn is_public_mode(paths: &Paths) -> bool {
    if matches!(read_access_mode(paths).as_str(), "caddy" | "direct") {
        return true;
    }
    std::env::var("MAILSTACK_SECURITY_PROFILE")
        .map(|v| v.trim().to_lowercase() == "high")
        .unwrap_or(false)
}

pub fn is_public_mode_with(paths: &Paths, security_profile: Option<&str>) -> bool {
    if matches!(read_access_mode(paths).as_str(), "caddy" | "direct") {
        return true;
    }
    security_profile
        .map(|v| v.trim().to_lowercase() == "high")
        .unwrap_or(false)
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
    fn empty_access_mode_fails_closed_to_direct() {
        let f = Fixture::new();
        f.write(&f.paths.install_args_conf, "ACCESS_MODE=\n");
        assert_eq!(read_access_mode(&f.paths), "direct");
        assert!(
            is_public_mode_with(&f.paths, None),
            "空值必须按公网档处理，而不是本地档"
        );
    }

    #[test]
    fn unknown_access_mode_values_fail_closed_to_direct() {
        for content in [
            "ACCESS_MODE=public\n",
            "ACCESS_MODE=lan\n",
            "ACCESS_MODE=1\n",
            "enabled=1\n",
            "# ACCESS_MODE=local\n",
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

        assert_eq!(read_access_mode(&f.paths), "direct");
    }

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
}
