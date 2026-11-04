use std::path::{Path, PathBuf};
use std::sync::Arc;

use mailstack_core::atomic::{atomic_as, locked_with, rows};
use mailstack_core::exec::{
    postmap_and_reload, CommandRunner, PostmapOutcome, ServiceEnv, SystemCommandRunner,
    SystemServiceEnv,
};
use mailstack_core::validate::{ADDRESS_RE, DOMAIN_RE, USER_RE};
use mailstack_core::Paths;

use crate::error::{StoreError, StoreResult};

const TABLE_FILE_MODE: u32 = 0o644;

pub const MAX_ALIAS_DESTINATIONS: usize = 50;

pub type TableRow = Vec<String>;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AliasEntry {
    pub source: String,
    pub destinations: Vec<String>,
}

#[derive(Clone)]
pub struct TableStore {
    paths: Paths,
    runner: Arc<dyn CommandRunner>,
    env: Arc<dyn ServiceEnv>,
}

impl std::fmt::Debug for TableStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TableStore")
            .field("domains", &self.paths.domains)
            .field("aliases", &self.paths.aliases)
            .finish_non_exhaustive()
    }
}

#[cfg(all(test, unix))]
fn assert_waits_for_table_lock<T: Send + 'static>(
    table_path: &Path,
    operation: impl FnOnce() -> T + Send + 'static,
) -> T {
    use std::sync::mpsc;
    use std::time::Duration;

    let table_path = table_path.to_path_buf();
    let (locked_tx, locked_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let holder = std::thread::spawn(move || {
        mailstack_core::atomic::locked(&table_path, || {
            locked_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            Ok(())
        })
    });
    locked_rx.recv().unwrap();

    let (finished_tx, finished_rx) = mpsc::channel();
    let writer = std::thread::spawn(move || {
        let result = operation();
        let _ = finished_tx.send(());
        result
    });
    let finished_while_locked = match finished_rx.recv_timeout(Duration::from_millis(250)) {
        Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => true,
        Err(mpsc::RecvTimeoutError::Timeout) => false,
    };

    release_tx.send(()).unwrap();
    holder.join().unwrap().unwrap();
    let result = writer.join().unwrap();
    assert!(
        !finished_while_locked,
        "表的读改写必须等待已持有的 sidecar 锁"
    );
    result
}

impl TableStore {
    pub fn new(paths: Paths) -> Self {
        Self {
            paths,
            runner: Arc::new(SystemCommandRunner),
            env: Arc::new(SystemServiceEnv),
        }
    }

    pub fn with_parts(
        paths: Paths,
        runner: Arc<dyn CommandRunner>,
        env: Arc<dyn ServiceEnv>,
    ) -> Self {
        Self { paths, runner, env }
    }

    pub fn domains_path(&self) -> &Path {
        &self.paths.domains
    }

    pub fn aliases_path(&self) -> &Path {
        &self.paths.aliases
    }

    pub fn domains(&self) -> Vec<String> {
        read_rows(&self.paths.domains)
            .into_iter()
            .filter_map(|row| row.into_iter().next())
            .collect()
    }

    pub fn add_domain(&self, name: &str) -> StoreResult<Vec<String>> {
        let domain = validated_domain(name)?;
        let path = self.paths.domains.clone();
        locked_with(&path, || {
            let mut table = read_rows_for_update(&path)?;
            table.retain(|row| row.first() != Some(&domain));

            table.push(vec![domain, "OK".to_string()]);
            require_postfix_sync(self.write_rows(&path, &table)?)?;
            Ok(self.domains())
        })
    }

    pub fn delete_domain(&self, name: &str) -> StoreResult<Vec<String>> {
        let domain = validated_domain(name)?;
        let domains_path = self.paths.domains.clone();
        let aliases_path = self.paths.aliases.clone();
        let suffix = format!("@{domain}");
        locked_with(&domains_path, || {
            locked_with(&aliases_path, || {
                let mut domains = read_rows_for_update(&domains_path)?;
                let mut aliases = read_rows_for_update(&aliases_path)?;
                domains.retain(|row| row.first() != Some(&domain));
                aliases.retain(|row| {
                    !row.first()
                        .map(|source| source.ends_with(&suffix))
                        .unwrap_or(false)
                });

                require_postfix_sync(self.write_rows(&aliases_path, &aliases)?)?;
                require_postfix_sync(self.write_rows(&domains_path, &domains)?)?;
                Ok(self.domains())
            })
        })
    }

    pub fn aliases(&self) -> Vec<AliasEntry> {
        read_rows(&self.paths.aliases)
            .into_iter()
            .filter(|row| row.len() > 1)
            .map(|row| AliasEntry {
                source: row[0].clone(),
                destinations: row[1..].to_vec(),
            })
            .collect()
    }

    pub fn add_alias(&self, source: &str, destinations: &[String]) -> StoreResult<Vec<AliasEntry>> {
        let source = source.trim().to_ascii_lowercase();
        if !is_valid_address(&source) {
            return Err(StoreError::invalid("invalid alias"));
        }
        let domain = source
            .rsplit_once('@')
            .map(|(_, domain)| domain)
            .unwrap_or("");
        if !is_valid_domain(domain) {
            return Err(StoreError::invalid("invalid alias domain"));
        }

        if destinations.is_empty() {
            return Err(StoreError::invalid(
                "invalid alias: at least one destination is required",
            ));
        }

        let mut normalised = Vec::with_capacity(destinations.len());
        for destination in destinations {
            let destination = destination.trim().to_ascii_lowercase();

            if !has_no_whitespace_or_control(&destination)
                || !(USER_RE.is_match(&destination) || ADDRESS_RE.is_match(&destination))
            {
                return Err(StoreError::invalid("invalid alias destination"));
            }
            normalised.push(destination);
        }

        if normalised.len() > MAX_ALIAS_DESTINATIONS {
            return Err(StoreError::invalid("invalid alias: too many destinations"));
        }

        let path = self.paths.aliases.clone();
        locked_with(&path, || {
            let mut table = read_rows_for_update(&path)?;
            table.retain(|row| row.first() != Some(&source));
            let mut row = vec![source];
            row.extend(normalised);
            table.push(row);
            require_postfix_sync(self.write_rows(&path, &table)?)?;
            Ok(self.aliases())
        })
    }

    pub fn delete_alias(&self, source: &str) -> StoreResult<Vec<AliasEntry>> {
        let source = source.trim().to_ascii_lowercase();
        if !is_valid_address(&source) {
            return Err(StoreError::invalid("invalid alias"));
        }
        let domain = source
            .rsplit_once('@')
            .map(|(_, domain)| domain)
            .unwrap_or("");
        if !is_valid_domain(domain) {
            return Err(StoreError::invalid("invalid alias"));
        }

        let path = self.paths.aliases.clone();
        locked_with(&path, || {
            let mut table = read_rows_for_update(&path)?;
            table.retain(|row| row.first() != Some(&source));
            require_postfix_sync(self.write_rows(&path, &table)?)?;
            Ok(self.aliases())
        })
    }

    fn write_rows(&self, path: &Path, table: &[TableRow]) -> StoreResult<PostmapOutcome> {
        let mut text = String::new();
        for row in table {
            text.push_str(&row.join(" "));
            text.push('\n');
        }
        atomic_as(path, text.as_bytes(), TABLE_FILE_MODE, None)?;
        Ok(postmap_and_reload(
            self.env.as_ref(),
            self.runner.as_ref(),
            path,
        ))
    }
}

fn require_postfix_sync(outcome: PostmapOutcome) -> StoreResult<()> {
    let mut failed: Vec<&'static str> = Vec::new();
    if !outcome.postmap_ok {
        failed.push("postmap");
    }
    if !outcome.check_ok {
        failed.push("postfix check");
    }
    if !outcome.reload_ok {
        failed.push("postfix reload");
    }
    if failed.is_empty() {
        return Ok(());
    }
    Err(StoreError::Postmap(format!(
        "table file written, but Postfix update failed at: {}",
        failed.join(", ")
    )))
}

pub fn read_rows(path: &Path) -> Vec<TableRow> {
    rows(path)
}

fn read_rows_for_update(path: &Path) -> StoreResult<Vec<TableRow>> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(StoreError::io(path, error)),
    }
    let text = std::fs::read_to_string(path).map_err(|error| StoreError::io(path, error))?;
    Ok(rows_from_text(&text))
}

pub fn rows_from_text(text: &str) -> Vec<TableRow> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            Some(line.split_whitespace().map(str::to_string).collect())
        })
        .collect()
}

pub fn validated_domain(input: &str) -> StoreResult<String> {
    let domain = input.trim().to_ascii_lowercase();
    if !is_valid_domain(&domain) {
        return Err(StoreError::invalid("invalid domain"));
    }
    Ok(domain)
}

fn is_valid_domain(domain: &str) -> bool {
    has_no_whitespace_or_control(domain) && DOMAIN_RE.is_match(domain)
}

fn is_valid_address(address: &str) -> bool {
    has_no_whitespace_or_control(address) && ADDRESS_RE.is_match(address)
}

fn has_no_whitespace_or_control(value: &str) -> bool {
    !value.is_empty() && !value.chars().any(|c| c.is_whitespace() || c.is_control())
}

pub fn hash_db_path(table: &Path) -> PathBuf {
    mailstack_core::exec::hash_db_path(table)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mailstack_core::exec::CommandOutput;
    use std::sync::Mutex;

    struct RecordingRunner {
        calls: Mutex<Vec<(String, Vec<String>)>>,
    }

    impl RecordingRunner {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                calls: Mutex::new(Vec::new()),
            })
        }

        fn calls(&self) -> Vec<(String, Vec<String>)> {
            self.calls.lock().unwrap().clone()
        }

        fn programs(&self) -> Vec<String> {
            self.calls().into_iter().map(|(p, _)| p).collect()
        }
    }

    impl CommandRunner for RecordingRunner {
        fn run(&self, program: &str, args: &[&str]) -> mailstack_core::CoreResult<CommandOutput> {
            self.calls.lock().unwrap().push((
                program.to_string(),
                args.iter().map(|a| a.to_string()).collect(),
            ));
            Ok(CommandOutput {
                status: 0,
                stdout: String::new(),
                stderr: String::new(),
            })
        }

        fn run_with_timeout(
            &self,
            program: &str,
            args: &[&str],
            _timeout: std::time::Duration,
        ) -> mailstack_core::CoreResult<CommandOutput> {
            self.run(program, args)
        }
    }

    struct FixedEnv;

    impl mailstack_core::exec::ServiceEnv for FixedEnv {
        fn program_available(&self, program: &str) -> bool {
            program == "postfix"
        }

        fn path_exists(&self, _path: &Path) -> bool {
            false
        }
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        store: TableStore,
        runner: Arc<RecordingRunner>,
        paths: Paths,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let paths = Paths::rooted(dir.path());
            std::fs::create_dir_all(&paths.postfix).unwrap();
            let runner = RecordingRunner::new();
            let store = TableStore::with_parts(paths.clone(), runner.clone(), Arc::new(FixedEnv));
            Self {
                _dir: dir,
                store,
                runner,
                paths,
            }
        }

        fn read(&self, path: &Path) -> String {
            std::fs::read_to_string(path).unwrap_or_default()
        }
    }

    #[test]
    fn domains_list_skips_comments_and_blank_lines() {
        let f = Fixture::new();
        std::fs::write(
            &f.paths.domains,
            "# managed domains\nexample.com\tOK\n   \nfoo.test OK\n",
        )
        .unwrap();
        assert_eq!(f.store.domains(), vec!["example.com", "foo.test"]);
    }

    #[test]
    fn missing_tables_read_as_empty_not_an_error() {
        let f = Fixture::new();
        assert!(f.store.domains().is_empty());
        assert!(f.store.aliases().is_empty());
    }

    #[test]
    fn domain_add_writes_the_postfix_hash_format_and_runs_postmap() {
        let f = Fixture::new();
        f.store.add_domain("example.com").unwrap();

        assert_eq!(f.read(&f.paths.domains), "example.com OK\n");

        assert_eq!(f.runner.programs(), vec!["postmap", "postfix", "postfix"]);
        assert_eq!(
            f.runner.calls()[0].1,
            vec![f.paths.domains.to_string_lossy().to_string()]
        );
    }

    #[test]
    fn domain_add_normalises_case_and_whitespace() {
        let f = Fixture::new();
        f.store.add_domain("  Example.COM  ").unwrap();
        assert_eq!(f.store.domains(), vec!["example.com"]);
    }

    #[test]
    fn domain_add_replaces_an_existing_entry_instead_of_duplicating() {
        let f = Fixture::new();
        f.store.add_domain("example.com").unwrap();
        f.store.add_domain("example.com").unwrap();
        assert_eq!(f.store.domains(), vec!["example.com"], "不得重复追加");
    }

    #[test]
    fn domain_add_preserves_unrelated_rows_including_their_columns() {
        let f = Fixture::new();
        std::fs::write(&f.paths.domains, "keep.test OK extra\n").unwrap();
        f.store.add_domain("example.com").unwrap();

        let rows = read_rows(&f.paths.domains);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0], vec!["keep.test", "OK", "extra"], "不得丢列");
        assert_eq!(rows[1][0], "example.com");
    }

    #[test]
    fn domain_add_rejects_invalid_input_with_the_documented_message() {
        let f = Fixture::new();
        for bad in ["example", "-bad.com", "bad-.com", "", "   "] {
            let err = f.store.add_domain(bad).unwrap_err();
            assert_eq!(err.kind(), "InvalidInput");
            assert_eq!(err.to_string(), "invalid domain", "{bad:?} 的文案是契约");
        }
    }

    #[test]
    fn domain_add_rejects_newline_injection() {
        let f = Fixture::new();
        let err = f
            .store
            .add_domain("evil.test\nattacker.test OK")
            .unwrap_err();
        assert_eq!(err.to_string(), "invalid domain");
        assert_eq!(f.read(&f.paths.domains), "", "不得写入任何内容");
    }

    #[test]
    fn delete_domain_also_removes_its_aliases() {
        let f = Fixture::new();
        f.store.add_domain("example.com").unwrap();
        f.store.add_domain("other.test").unwrap();
        f.store
            .add_alias("sales@example.com", &["alice".to_string()])
            .unwrap();
        f.store
            .add_alias("info@other.test", &["bob".to_string()])
            .unwrap();

        f.store.delete_domain("example.com").unwrap();

        assert_eq!(f.store.domains(), vec!["other.test"]);
        let aliases = f.store.aliases();
        assert_eq!(aliases.len(), 1);
        assert_eq!(aliases[0].source, "info@other.test");
    }

    #[test]
    fn delete_domain_validates_the_same_way_as_add() {
        let f = Fixture::new();
        assert_eq!(
            f.store.delete_domain("../etc").unwrap_err().to_string(),
            "invalid domain"
        );
    }

    #[test]
    fn aliases_skip_rows_without_destinations() {
        let f = Fixture::new();
        std::fs::write(
            &f.paths.aliases,
            "lonely@example.com\nsales@example.com alice bob@remote.test\n",
        )
        .unwrap();
        let aliases = f.store.aliases();
        assert_eq!(aliases.len(), 1, "单列行没有映射意义，不应暴露");
        assert_eq!(aliases[0].source, "sales@example.com");
        assert_eq!(
            aliases[0].destinations,
            vec!["alice".to_string(), "bob@remote.test".to_string()]
        );
    }

    #[test]
    fn alias_add_accepts_local_users_and_full_addresses() {
        let f = Fixture::new();
        let aliases = f
            .store
            .add_alias(
                "sales@example.com",
                &["alice".to_string(), "bob@remote.test".to_string()],
            )
            .unwrap();
        assert_eq!(aliases.len(), 1);
        assert_eq!(
            aliases[0].destinations,
            vec!["alice".to_string(), "bob@remote.test".to_string()]
        );

        assert_eq!(
            f.read(&f.paths.aliases),
            "sales@example.com alice bob@remote.test\n"
        );
    }

    #[test]
    fn alias_add_rejects_newline_injection_into_the_table() {
        let f = Fixture::new();
        let err = f
            .store
            .add_alias(
                "sales@example.com",
                &["alice\nattacker@evil.test".to_string()],
            )
            .unwrap_err();
        assert_eq!(err.to_string(), "invalid alias destination");
        assert_eq!(f.read(&f.paths.aliases), "", "不得写入任何内容");
    }

    #[test]
    fn alias_add_rejects_space_separated_injection() {
        let f = Fixture::new();
        let err = f
            .store
            .add_alias("sales@example.com", &["alice boss@evil.test".to_string()])
            .unwrap_err();
        assert_eq!(err.to_string(), "invalid alias destination");
        assert_eq!(f.read(&f.paths.aliases), "");
    }

    #[test]
    fn alias_add_rejects_injection_through_the_source() {
        let f = Fixture::new();
        for bad in [
            "sales@example.com\nattacker@evil.test",
            "not-an-address",
            "a b@example.com",
        ] {
            let err = f.store.add_alias(bad, &["alice".to_string()]).unwrap_err();
            assert_eq!(err.to_string(), "invalid alias", "{bad:?} 应被拒绝");
            assert_eq!(f.read(&f.paths.aliases), "");
        }
    }

    #[test]
    fn alias_source_domain_is_validated_separately() {
        let f = Fixture::new();
        let err = f
            .store
            .add_alias("sales@bad..domain", &["alice".to_string()])
            .unwrap_err();
        assert_eq!(err.to_string(), "invalid alias domain");
    }

    #[test]
    fn alias_add_requires_at_least_one_destination() {
        let f = Fixture::new();
        let err = f.store.add_alias("sales@example.com", &[]).unwrap_err();
        assert_eq!(
            err.to_string(),
            "invalid alias: at least one destination is required"
        );
    }

    #[test]
    fn alias_add_caps_the_destination_count() {
        let f = Fixture::new();
        let too_many: Vec<String> = (0..MAX_ALIAS_DESTINATIONS + 1)
            .map(|i| format!("user{i}"))
            .collect();
        let err = f
            .store
            .add_alias("sales@example.com", &too_many)
            .unwrap_err();
        assert_eq!(err.to_string(), "invalid alias: too many destinations");

        let at_limit: Vec<String> = (0..MAX_ALIAS_DESTINATIONS)
            .map(|i| format!("user{i}"))
            .collect();
        assert!(f.store.add_alias("sales@example.com", &at_limit).is_ok());
    }

    #[test]
    fn alias_add_overwrites_the_same_source() {
        let f = Fixture::new();
        f.store
            .add_alias("sales@example.com", &["alice".to_string()])
            .unwrap();
        let aliases = f
            .store
            .add_alias("sales@example.com", &["bob".to_string()])
            .unwrap();
        assert_eq!(aliases.len(), 1);
        assert_eq!(aliases[0].destinations, vec!["bob".to_string()]);
    }

    #[test]
    fn delete_alias_validates_the_id_before_writing() {
        let f = Fixture::new();
        f.store
            .add_alias("sales@example.com", &["alice".to_string()])
            .unwrap();
        let before = f.read(&f.paths.aliases);

        let err = f
            .store
            .delete_alias("sales@example.com\nattacker@evil.test")
            .unwrap_err();
        assert_eq!(err.to_string(), "invalid alias");
        assert_eq!(f.read(&f.paths.aliases), before, "表文件不得被改动");
    }

    #[test]
    fn delete_alias_removes_only_the_targeted_row() {
        let f = Fixture::new();
        f.store
            .add_alias("a@example.com", &["alice".to_string()])
            .unwrap();
        f.store
            .add_alias("b@example.com", &["bob".to_string()])
            .unwrap();

        let aliases = f.store.delete_alias("a@example.com").unwrap();
        assert_eq!(aliases.len(), 1);
        assert_eq!(aliases[0].source, "b@example.com");
    }

    #[cfg(unix)]
    #[test]
    fn table_mutations_wait_for_their_read_modify_write_locks() {
        let f = Fixture::new();

        let store = f.store.clone();
        assert_waits_for_table_lock(&f.paths.domains, move || store.add_domain("example.com"))
            .unwrap();

        let store = f.store.clone();
        assert_waits_for_table_lock(&f.paths.domains, move || store.delete_domain("example.com"))
            .unwrap();

        let store = f.store.clone();
        assert_waits_for_table_lock(&f.paths.aliases, move || store.delete_domain("example.com"))
            .unwrap();

        let store = f.store.clone();
        assert_waits_for_table_lock(&f.paths.aliases, move || {
            store.add_alias("sales@example.com", &["alice".to_string()])
        })
        .unwrap();

        let store = f.store.clone();
        assert_waits_for_table_lock(&f.paths.aliases, move || {
            store.delete_alias("sales@example.com")
        })
        .unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn add_domain_refuses_to_replace_a_table_when_reading_it_fails() {
        use std::os::unix::fs::symlink;

        let f = Fixture::new();
        let target = f.paths.postfix.join("domains-target");
        std::fs::create_dir(&target).unwrap();
        symlink(&target, &f.paths.domains).unwrap();

        let error = f.store.add_domain("example.com").unwrap_err();

        assert!(matches!(error, StoreError::Io { .. }));
        assert!(std::fs::symlink_metadata(&f.paths.domains)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[cfg(unix)]
    #[test]
    fn delete_domain_does_not_modify_either_table_when_alias_read_fails() {
        use std::os::unix::fs::symlink;

        let f = Fixture::new();
        std::fs::write(&f.paths.domains, "example.com OK\n").unwrap();
        let target = f.paths.postfix.join("aliases-target");
        std::fs::create_dir(&target).unwrap();
        symlink(&target, &f.paths.aliases).unwrap();

        let error = f.store.delete_domain("example.com").unwrap_err();

        assert!(matches!(error, StoreError::Io { .. }));
        assert_eq!(f.read(&f.paths.domains), "example.com OK\n");
        assert!(std::fs::symlink_metadata(&f.paths.aliases)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[test]
    fn every_write_triggers_postmap() {
        let f = Fixture::new();
        f.store.add_domain("example.com").unwrap();
        let after_add = f.runner.calls().len();
        assert!(after_add >= 3, "写入后必须编译 hash 表并重载");

        f.runner.calls.lock().unwrap().clear();
        f.store
            .add_alias("sales@example.com", &["alice".to_string()])
            .unwrap();
        assert_eq!(f.runner.programs(), vec!["postmap", "postfix", "postfix"]);
    }

    struct FailingRunner;

    impl CommandRunner for FailingRunner {
        fn run(&self, _program: &str, _args: &[&str]) -> mailstack_core::CoreResult<CommandOutput> {
            Ok(CommandOutput {
                status: 1,
                stdout: String::new(),
                stderr: "simulated failure".to_string(),
            })
        }

        fn run_with_timeout(
            &self,
            program: &str,
            args: &[&str],
            _timeout: std::time::Duration,
        ) -> mailstack_core::CoreResult<CommandOutput> {
            self.run(program, args)
        }
    }

    #[test]
    fn a_failed_postmap_is_surfaced_as_an_error_not_swallowed() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::rooted(dir.path());
        std::fs::create_dir_all(&paths.postfix).unwrap();
        let store =
            TableStore::with_parts(paths.clone(), Arc::new(FailingRunner), Arc::new(FixedEnv));

        let error = store.add_domain("example.com").unwrap_err();
        assert_eq!(error.kind(), "PostmapError");
        assert!(
            error.to_string().contains("postmap"),
            "错误应指明失败在哪一步：{error}"
        );

        assert_eq!(store.domains(), vec!["example.com".to_string()]);
    }

    struct NoPostfixRunner;

    impl CommandRunner for NoPostfixRunner {
        fn run(&self, program: &str, _args: &[&str]) -> mailstack_core::CoreResult<CommandOutput> {
            Err(mailstack_core::CoreError::NotFound(PathBuf::from(program)))
        }

        fn run_with_timeout(
            &self,
            program: &str,
            args: &[&str],
            _timeout: std::time::Duration,
        ) -> mailstack_core::CoreResult<CommandOutput> {
            self.run(program, args)
        }
    }

    #[test]
    fn a_host_without_postfix_accepts_table_writes() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::rooted(dir.path());
        std::fs::create_dir_all(&paths.postfix).unwrap();
        let store =
            TableStore::with_parts(paths.clone(), Arc::new(NoPostfixRunner), Arc::new(FixedEnv));

        store.add_domain("example.com").unwrap();
        store
            .add_alias("sales@example.com", &["alice".to_string()])
            .unwrap();

        assert_eq!(store.domains(), vec!["example.com".to_string()]);
        assert_eq!(store.aliases().len(), 1);
    }

    #[test]
    fn delete_domain_writes_the_aliases_table_before_the_domains_table() {
        let f = Fixture::new();
        f.store.add_domain("example.com").unwrap();
        f.store
            .add_alias("sales@example.com", &["alice".to_string()])
            .unwrap();
        f.runner.calls.lock().unwrap().clear();

        f.store.delete_domain("example.com").unwrap();

        let postmap_targets: Vec<String> = f
            .runner
            .calls()
            .iter()
            .filter(|(program, _)| program == "postmap")
            .map(|(_, args)| args[0].clone())
            .collect();
        assert_eq!(postmap_targets.len(), 2);
        assert_eq!(
            postmap_targets[0],
            f.paths.aliases.to_string_lossy().to_string(),
            "别名表（引用域的一方）必须先写"
        );
        assert_eq!(
            postmap_targets[1],
            f.paths.domains.to_string_lossy().to_string()
        );
    }

    #[test]
    fn table_files_are_world_readable_like_the_installer_creates_them() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let f = Fixture::new();
            f.store.add_domain("example.com").unwrap();
            let mode = std::fs::metadata(&f.paths.domains)
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o644, "实际权限：{mode:o}");
        }
    }

    #[test]
    fn validation_helpers_reject_every_whitespace_variant() {
        for bad in ["a b", "a\tb", "a\nb", "a\rb", "a\0b", ""] {
            assert!(
                !has_no_whitespace_or_control(bad),
                "{bad:?} 必须被判为含空白/控制字符"
            );
        }
        assert!(has_no_whitespace_or_control("alice@example.com"));
    }

    #[test]
    fn hash_db_path_matches_postmap_output() {
        assert_eq!(
            hash_db_path(Path::new("/etc/postfix/mailstack_domains")),
            PathBuf::from("/etc/postfix/mailstack_domains.db")
        );
    }
}
