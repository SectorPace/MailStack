//! 敏感文件的权限体检（对应基线的 `telemetry.key_permission_scan`）。
//!
//! **只读**：只 `stat`，不改任何东西。它要回答的是「有没有哪一份机密现在能被
//! 不该看到它的进程读到」—— 这类问题不会自己暴露，等到暴露时密文早就被读走了。
//!
//! ## 判定策略的来历
//!
//! 每一项的 `max_mode` 都取自**本仓库写入该文件时实际使用的权限**
//! （`config.rs` / `totp.rs` / `auth::keys` / `smtp::relay_store` / `queue::store`），
//! 不是另拍一个数。这样「扫描器说违规」与「写入方说合规」不可能各说各话。
//!
//! ## 每个文件最多报一条
//!
//! 一个 `0644` 的机密文件既是「world 可读」也是「超出策略」，两条都报只是噪音 ——
//! 修的时候都是改 mode 一个动作。这里按严重度取最先命中的一条，并在 `detail`
//! 里带上实际模式与允许模式，信息量并不少。

use std::path::PathBuf;

/// 一条敏感路径及其允许的最宽权限。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensitivePath {
    pub path: PathBuf,
    /// 允许的最宽权限位（任何超出该掩码的位都算违规）。
    pub max_mode: u32,
    /// 是否真的含机密。决定「world 可读」是 High 还是 Medium。
    pub holds_secret: bool,
    /// 这是给人看的一行说明，会原样出现在体检结果里。
    pub note: &'static str,
}

impl SensitivePath {
    pub fn new(
        path: impl Into<PathBuf>,
        max_mode: u32,
        holds_secret: bool,
        note: &'static str,
    ) -> Self {
        Self {
            path: path.into(),
            max_mode,
            holds_secret,
            note,
        }
    }
}

/// 严重级别。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Medium,
    High,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Medium => "medium",
            Severity::High => "high",
        }
    }
}

/// 违规类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Issue {
    /// 任何人可写 —— 攻击者可以直接替换内容（比可读更严重）。
    WorldWritable,
    /// 任何人可读。
    WorldReadable,
    /// 同组可写。
    GroupWritable,
    /// 权限位超出了该文件允许的最宽掩码。
    TooPermissive,
    /// 不是普通文件（符号链接、设备文件……）。
    NotARegularFile,
}

impl Issue {
    pub fn as_str(self) -> &'static str {
        match self {
            Issue::WorldWritable => "world_writable",
            Issue::WorldReadable => "world_readable",
            Issue::GroupWritable => "group_writable",
            Issue::TooPermissive => "too_permissive",
            Issue::NotARegularFile => "not_a_regular_file",
        }
    }
}

/// 一条体检结论。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub path: PathBuf,
    pub severity: Severity,
    pub issue: Issue,
    /// 实际模式（八进制字符串），读不到时为 `None`。
    pub mode: Option<String>,
    pub max_mode: String,
    pub note: String,
    pub detail: String,
}

/// 一次体检的结果。
///
/// `absent` 单列而不是省略：运维需要区分「查过了、没问题」与「这台机器上根本没有
/// 这个文件」，而这两者在只列 `findings` 的输出里长得一模一样。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanReport {
    pub scanned: usize,
    pub absent: Vec<PathBuf>,
    pub findings: Vec<Finding>,
}

impl ScanReport {
    pub fn highest_severity(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }
}

/// 体检一组路径。
///
/// 不存在的路径计入 `absent`（不是问题：中继未配置、证书未签发都是正常状态）。
/// 目录也可以放进清单 —— 只要求「不得被非属主访问」的目录（如 `/etc/mailstack`）。
pub fn scan(paths: &[SensitivePath]) -> ScanReport {
    let mut report = ScanReport::default();

    for entry in paths {
        let Ok(metadata) = std::fs::symlink_metadata(&entry.path) else {
            report.absent.push(entry.path.clone());
            continue;
        };

        // 符号链接本身不是「文件内容」，跟着它走会把这个体检变成对任意路径的探测。
        let file_type = metadata.file_type();
        if !file_type.is_file() && !file_type.is_dir() {
            report.scanned += 1;
            report.findings.push(Finding {
                path: entry.path.clone(),
                severity: Severity::Medium,
                issue: Issue::NotARegularFile,
                mode: mode_of(&metadata).map(|m| format!("{m:o}")),
                max_mode: format!("{:o}", entry.max_mode),
                note: entry.note.to_string(),
                detail: "path is neither a regular file nor a directory".to_string(),
            });
            continue;
        }

        report.scanned += 1;
        let mode = mode_of(&metadata);
        let Some(mode) = mode else {
            continue;
        };

        if let Some((issue, severity)) = classify(mode, entry.max_mode, entry.holds_secret) {
            report.findings.push(Finding {
                path: entry.path.clone(),
                severity,
                issue,
                mode: Some(format!("{mode:o}")),
                max_mode: format!("{:o}", entry.max_mode),
                note: entry.note.to_string(),
                detail: detail_for(issue, mode, entry.max_mode),
            });
        }
    }

    // 严重的排前面：运维最先看到的那条应该是最该修的那条。
    report
        .findings
        .sort_by(|a, b| b.severity.cmp(&a.severity).then(a.path.cmp(&b.path)));
    report.absent.sort();
    report
}

/// 取出权限位（非 Unix 目标返回 `None`）。
#[cfg(unix)]
fn mode_of(metadata: &std::fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    Some(metadata.permissions().mode() & 0o777)
}

#[cfg(not(unix))]
fn mode_of(_metadata: &std::fs::Metadata) -> Option<u32> {
    None
}

/// 判定一条路径最该被报出来的那个问题（严重度优先，取一条）。
///
/// 关键点：**只报「超出该文件策略」的那些位**。`0644` 对域名表（上限就是 0644）
/// 完全正常，对 `totp.key` 才是 world 可读。若先无条件判 world 位再比策略，
/// 就会出现「表文件天天报 world_readable」这种噪音，噪音一多就没人看了。
fn classify(mode: u32, max_mode: u32, holds_secret: bool) -> Option<(Issue, Severity)> {
    let beyond = mode & !max_mode;
    if beyond == 0 {
        return None;
    }
    if beyond & 0o002 != 0 {
        // 可写比可读严重：攻击者不必读走机密就能篡改内容。
        return Some((Issue::WorldWritable, Severity::High));
    }
    if beyond & 0o004 != 0 {
        return Some((
            Issue::WorldReadable,
            if holds_secret {
                Severity::High
            } else {
                Severity::Medium
            },
        ));
    }
    if beyond & 0o020 != 0 {
        return Some((
            Issue::GroupWritable,
            if holds_secret {
                Severity::High
            } else {
                Severity::Medium
            },
        ));
    }
    // 剩下的组合（如机密的 0640 对上限 0600）只是「比该有的宽」，不是对外可读。
    Some((
        Issue::TooPermissive,
        if holds_secret {
            Severity::Medium
        } else {
            Severity::Info
        },
    ))
}

fn detail_for(issue: Issue, mode: u32, max_mode: u32) -> String {
    match issue {
        Issue::WorldWritable => format!("{mode:o} is writable by any user"),
        Issue::WorldReadable => format!("{mode:o} is readable by any user"),
        Issue::GroupWritable => format!("{mode:o} is writable by the owning group"),
        Issue::TooPermissive => format!("{mode:o} exceeds the allowed {max_mode:o}"),
        Issue::NotARegularFile => "not a regular file".to_string(),
    }
}

/// 该路径是否在清单里被声明为「含机密」。
#[cfg(test)]
fn is_declared_secret(paths: &[SensitivePath], path: &std::path::Path) -> bool {
    paths
        .iter()
        .any(|entry| entry.path == path && entry.holds_secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new(tag: &str) -> Self {
            let mut root = std::env::temp_dir();
            root.push(format!(
                "mailstack-secscan-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir_all(&root).unwrap();
            Self { root }
        }

        #[cfg(unix)]
        fn write(&self, name: &str, mode: u32) -> PathBuf {
            use std::os::unix::fs::PermissionsExt;
            let path = self.root.join(name);
            fs::write(&path, b"secret").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            path
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[cfg(unix)]
    fn entry(path: &Path, max_mode: u32, holds_secret: bool) -> SensitivePath {
        SensitivePath::new(path, max_mode, holds_secret, "test entry")
    }

    #[cfg(unix)]
    #[test]
    fn a_tight_permission_is_reported_as_clean() {
        let f = Fixture::new("clean");
        let path = f.write("totp.key", 0o600);
        let report = scan(&[entry(&path, 0o600, true)]);
        assert_eq!(report.scanned, 1);
        assert!(report.findings.is_empty(), "{:?}", report.findings);
        assert!(report.absent.is_empty());
        assert_eq!(report.highest_severity(), None);
    }

    #[cfg(unix)]
    #[test]
    fn a_world_readable_secret_is_high_severity() {
        let f = Fixture::new("worldread");
        let path = f.write("totp.key", 0o644);
        let report = scan(&[entry(&path, 0o600, true)]);
        assert_eq!(report.findings.len(), 1);
        let finding = &report.findings[0];
        assert_eq!(finding.issue, Issue::WorldReadable);
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.mode.as_deref(), Some("644"));
        assert_eq!(finding.max_mode, "600");
        assert!(finding.detail.contains("readable by any user"));
    }

    #[cfg(unix)]
    #[test]
    fn a_world_writable_file_outranks_being_world_readable() {
        // 可写比可读严重：攻击者不必读走机密就能篡改内容。
        let f = Fixture::new("worldwrite");
        let path = f.write("relay.json", 0o666);
        let report = scan(&[entry(&path, 0o600, true)]);
        assert_eq!(report.findings.len(), 1, "每个文件最多报一条");
        assert_eq!(report.findings[0].issue, Issue::WorldWritable);
        assert_eq!(report.findings[0].severity, Severity::High);
    }

    #[cfg(unix)]
    #[test]
    fn a_file_that_stays_within_its_policy_is_clean() {
        // `domains` 表本来就是 0644（Postfix 要读它）。策略上限写 0644 就应当无问题 ——
        // 「world 可读」本身不是罪，超出**这份文件该有的**权限才是。
        let f = Fixture::new("inpolicy");
        let path = f.write("mailstack_domains", 0o644);
        let report = scan(&[entry(&path, 0o644, false)]);
        assert!(report.findings.is_empty(), "{:?}", report.findings);
    }

    #[cfg(unix)]
    #[test]
    fn a_non_secret_exceeding_its_policy_is_only_informational() {
        let f = Fixture::new("nonblocking");
        let path = f.write("mailstack_aliases", 0o640);
        let report = scan(&[entry(&path, 0o600, false)]);
        assert_eq!(report.findings[0].issue, Issue::TooPermissive);
        assert_eq!(report.findings[0].severity, Severity::Info);
    }

    #[cfg(unix)]
    #[test]
    fn group_readable_is_reported_when_it_exceeds_the_policy() {
        // `totp.key` 连组都不可读（只有特权进程该读到它）。
        let f = Fixture::new("groupread");
        let path = f.write("totp.key", 0o640);
        let report = scan(&[entry(&path, 0o600, true)]);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].issue, Issue::TooPermissive);
        assert_eq!(report.findings[0].severity, Severity::Medium);
        assert!(report.findings[0]
            .detail
            .contains("exceeds the allowed 600"));
    }

    #[cfg(unix)]
    #[test]
    fn group_writable_is_reported_explicitly() {
        let f = Fixture::new("groupwrite");
        let path = f.write("admin.json", 0o660);
        let report = scan(&[entry(&path, 0o640, true)]);
        assert_eq!(report.findings[0].issue, Issue::GroupWritable);
        assert_eq!(report.findings[0].severity, Severity::High);
    }

    #[cfg(unix)]
    #[test]
    fn a_missing_path_is_listed_as_absent_not_as_a_finding() {
        // 未配置中继 / 未签发证书都是**正常状态**，不该报成问题。
        let f = Fixture::new("absent");
        let missing = f.root.join("nope.json");
        let present = f.write("admin.json", 0o640);
        let report = scan(&[entry(&missing, 0o600, true), entry(&present, 0o640, true)]);

        assert_eq!(report.scanned, 1);
        assert_eq!(report.absent, vec![missing]);
        assert!(report.findings.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn a_directory_can_be_checked_too() {
        use std::os::unix::fs::PermissionsExt;
        let f = Fixture::new("dir");
        let dir = f.root.join("etc");
        fs::create_dir_all(&dir).unwrap();
        // 上限 0750 已经含了属主与同组的全部读/执行位，因此目录上能多出来的
        // 只可能是「写」位 —— 这里多的是同组可写。
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o760)).unwrap();

        let report = scan(&[entry(&dir, 0o750, false)]);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].issue, Issue::GroupWritable);
        assert_eq!(report.findings[0].severity, Severity::Medium);
    }

    #[cfg(unix)]
    #[test]
    fn a_world_readable_directory_is_reported_against_its_own_policy() {
        use std::os::unix::fs::PermissionsExt;
        let f = Fixture::new("dirworld");
        let dir = f.root.join("etc");
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();

        let report = scan(&[entry(&dir, 0o750, false)]);
        assert_eq!(report.findings[0].issue, Issue::WorldReadable);
        assert_eq!(report.findings[0].severity, Severity::Medium);
    }

    #[cfg(unix)]
    #[test]
    fn findings_are_ordered_most_severe_first() {
        let f = Fixture::new("order");
        let clean = f.write("settings.json", 0o640);
        let medium = f.write("setup.json", 0o604);
        let high = f.write("totp.key", 0o644);

        let report = scan(&[
            entry(&clean, 0o640, true),
            entry(&medium, 0o600, false),
            entry(&high, 0o600, true),
        ]);
        assert_eq!(report.findings.len(), 2);
        assert_eq!(report.findings[0].path, high, "High 必须排在最前");
        assert_eq!(report.findings[0].severity, Severity::High);
        assert_eq!(report.findings[1].path, medium);
        assert_eq!(report.highest_severity(), Some(Severity::High));
    }

    #[test]
    fn severity_ordering_is_high_then_medium_then_info() {
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Info);
        assert_eq!(Severity::High.as_str(), "high");
        assert_eq!(Issue::WorldWritable.as_str(), "world_writable");
    }

    #[cfg(unix)]
    #[test]
    fn secret_flag_is_queryable_for_callers_building_reports() {
        let f = Fixture::new("secretflag");
        let secret = f.write("totp.key", 0o600);
        let plain = f.write("mailstack_domains", 0o644);
        let list = vec![entry(&secret, 0o600, true), entry(&plain, 0o644, false)];
        assert!(is_declared_secret(&list, &secret));
        assert!(!is_declared_secret(&list, &plain));
        assert!(!is_declared_secret(&list, Path::new("/nope")));
    }
}
