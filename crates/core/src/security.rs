use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensitivePath {
    pub path: PathBuf,

    pub max_mode: u32,

    pub holds_secret: bool,

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Issue {
    WorldWritable,

    WorldReadable,

    GroupWritable,

    TooPermissive,

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub path: PathBuf,
    pub severity: Severity,
    pub issue: Issue,

    pub mode: Option<String>,
    pub max_mode: String,
    pub note: String,
    pub detail: String,
}

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

pub fn scan(paths: &[SensitivePath]) -> ScanReport {
    let mut report = ScanReport::default();

    for entry in paths {
        let Ok(metadata) = std::fs::symlink_metadata(&entry.path) else {
            report.absent.push(entry.path.clone());
            continue;
        };

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

    report
        .findings
        .sort_by(|a, b| b.severity.cmp(&a.severity).then(a.path.cmp(&b.path)));
    report.absent.sort();
    report
}

#[cfg(unix)]
fn mode_of(metadata: &std::fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    Some(metadata.permissions().mode() & 0o777)
}

#[cfg(not(unix))]
fn mode_of(_metadata: &std::fs::Metadata) -> Option<u32> {
    None
}

fn classify(mode: u32, max_mode: u32, holds_secret: bool) -> Option<(Issue, Severity)> {
    let beyond = mode & !max_mode;
    if beyond == 0 {
        return None;
    }
    if beyond & 0o002 != 0 {
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
