//! Postfix 表文件读写：虚拟域名表与别名表（规格书 §2.5、§3.3）。
//!
//! 两个文件是**对外契约**：
//!
//! ```text
//! virtual_alias_domains = hash:/etc/postfix/mailstack_domains
//! virtual_alias_maps    = hash:/etc/postfix/mailstack_aliases
//! ```
//!
//! 因此格式必须与 Postfix 的 `hash:` 表兼容（每行 `<key> [value...]`，`#` 注释），
//! 且每次写入后必须 `postmap` 重新编译 `.db` —— 否则 Postfix 读到的仍是旧表。
//!
//! ## 两条注入防护（Python 基线的注释明确点名）
//!
//! 表文件是**按空白分词**的：一个值里混入空格或换行，就不再是「一个值」，而是
//! 「多列 / 多行」——等于往 Postfix 的路由表里塞进任意条目。因此：
//!
//! * 别名的**每个目标**都必须是合法用户名或完整地址（`USER_RE` / `ADDRESS_RE`），
//!   这两条正则都不含空白字符；
//! * 别名的**删除**同样要校验 id —— 未校验的 id 会被直接写进表文件，
//!   一个换行不是「删掉一行」而是「注入几行」。
//!
//! 两条都在 [`has_no_whitespace_or_control`] 上再加了一层显式拒绝：正则表达式的
//! 语义若被改坏，这里仍拦得住。

use std::path::{Path, PathBuf};
use std::sync::Arc;

use mailstack_core::atomic::{atomic_as, rows};
use mailstack_core::exec::{
    postmap_and_reload, CommandRunner, PostmapOutcome, ServiceEnv, SystemCommandRunner,
    SystemServiceEnv,
};
use mailstack_core::validate::{ADDRESS_RE, DOMAIN_RE, USER_RE};
use mailstack_core::Paths;

use crate::error::{StoreError, StoreResult};

/// 表文件权限：`0644 root:root`。
///
/// 与安装脚本 `install -m 0644 /etc/postfix/mailstack_{domains,aliases}` 一致。
/// 刻意**不**用 `atomic()` 的默认 `0640`（`core.py` 的默认值）：这两张表由非特权的
/// Postfix 进程读取，且内容只是路由信息、不含机密；`0640 root:root` 会把它挡在门外。
/// 顺带也不 chown 到 `mailstack-admin` 组（属主保持当前用户，生产下即 root）。
const TABLE_FILE_MODE: u32 = 0o644;

/// 单个别名的最大目标数（`mail.py` 的上限）。
pub const MAX_ALIAS_DESTINATIONS: usize = 50;

/// 表文件的一行：按空白分词后的各列。
pub type TableRow = Vec<String>;

/// 别名表的一行。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AliasEntry {
    pub source: String,
    pub destinations: Vec<String>,
}

/// Postfix 表文件的读写入口。
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

impl TableStore {
    /// 生产构造：真实命令运行器 + 真实环境探测。
    pub fn new(paths: Paths) -> Self {
        Self {
            paths,
            runner: Arc::new(SystemCommandRunner),
            env: Arc::new(SystemServiceEnv),
        }
    }

    /// 注入运行器与环境探测（让表文件逻辑能在没有 Postfix 的机器上测试）。
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

    // ───────────────────────────── 域名表 ─────────────────────────────

    /// 虚拟域名表的第一列（`mail.py: domain_list`）。
    pub fn domains(&self) -> Vec<String> {
        read_rows(&self.paths.domains)
            .into_iter()
            .filter_map(|row| row.into_iter().next())
            .collect()
    }

    /// 添加域名（`domain_add`）：校验 → 去重写入 → `postmap` → 返回新列表。
    pub fn add_domain(&self, name: &str) -> StoreResult<Vec<String>> {
        let domain = validated_domain(name)?;
        let mut table: Vec<TableRow> = read_rows(&self.paths.domains)
            .into_iter()
            .filter(|row| row.first() != Some(&domain))
            .collect();
        // Postfix 的 virtual_alias_domains 只关心 key；`OK` 是基线的占位值，
        // 保持逐字一致以免 .db 内容与历史部署出现差异。
        table.push(vec![domain, "OK".to_string()]);
        self.write_rows(&self.paths.domains, &table)?;
        Ok(self.domains())
    }

    /// 删除域名（`domain_delete`）：**同时删除该域下的所有别名行**。
    ///
    /// 不删别名会留下指向已删除域的孤儿映射，Postfix 会照旧接受它们 —— 等于
    /// 「删了域名但收信路由没变」。
    pub fn delete_domain(&self, name: &str) -> StoreResult<Vec<String>> {
        let domain = validated_domain(name)?;

        let domains: Vec<TableRow> = read_rows(&self.paths.domains)
            .into_iter()
            .filter(|row| row.first() != Some(&domain))
            .collect();
        self.write_rows(&self.paths.domains, &domains)?;

        let suffix = format!("@{domain}");
        let aliases: Vec<TableRow> = read_rows(&self.paths.aliases)
            .into_iter()
            .filter(|row| {
                !row.first()
                    .map(|source| source.ends_with(&suffix))
                    .unwrap_or(false)
            })
            .collect();
        self.write_rows(&self.paths.aliases, &aliases)?;

        Ok(self.domains())
    }

    // ───────────────────────────── 别名表 ─────────────────────────────

    /// 别名表（`aliases`）：只返回真正有目标的行（单列行没有意义）。
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

    /// 添加/覆盖别名（`alias_add`）。
    ///
    /// 目标必须成组提供：基线里 `destinations` 若被当成裸字符串，会**逐字符**迭代，
    /// 于是 `"ab"` 静默变成两个目标 `a` 与 `b`。Rust 侧用 `&[String]` 从类型上
    /// 排除这种误用。
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
            // 这一条同时挡住空格与换行注入：两者都不被 USER_RE / ADDRESS_RE 接受。
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

        let mut table: Vec<TableRow> = read_rows(&self.paths.aliases)
            .into_iter()
            .filter(|row| row.first() != Some(&source))
            .collect();
        let mut row = vec![source];
        row.extend(normalised);
        table.push(row);
        self.write_rows(&self.paths.aliases, &table)?;
        Ok(self.aliases())
    }

    /// 删除别名（`alias_del`）。id 同样要校验 —— 见模块文档的第二条注入防护。
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

        let table: Vec<TableRow> = read_rows(&self.paths.aliases)
            .into_iter()
            .filter(|row| row.first() != Some(&source))
            .collect();
        self.write_rows(&self.paths.aliases, &table)?;
        Ok(self.aliases())
    }

    /// 原子写入表文件并让 Postfix 重读（`postmap` + `postfix check` + `reload`）。
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

/// 读表文件（`rows`）：跳过空行与 `#` 注释、按空白分词；文件缺失视为空表。
pub fn read_rows(path: &Path) -> Vec<TableRow> {
    rows(path)
}

/// 表文件**文本** → 行：分词规则与 [`read_rows`] 完全一致。
///
/// 为什么要单独暴露：有些调用方需要**先自己 `read_to_string`** 才能区分
/// 「文件不存在（= 空表）」与「文件存在但读不了（权限/IO 错误）」——
/// 这两种情况在 [`read_rows`] 里被合并成空表，而调用方需要据此决定
/// fail-closed 还是 fail-open。抽出这一层是为了让它们与 [`read_rows`]
/// 共用**同一个**分词实现：两处各写一遍，语义迟早漂移。
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

/// 校验并归一化域名。
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

/// 显式的空白/控制字符拒绝（正则之外的纵深防护）。
fn has_no_whitespace_or_control(value: &str) -> bool {
    !value.is_empty() && !value.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// 表文件对应的 hash 数据库路径。
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
    }

    /// 确定性环境探测：只暴露 `postfix`，不带 systemd。
    ///
    /// 真实探测会看宿主机有没有 `systemctl` 与 `/run/systemd/system`，那样测试
    /// 结果就随机器而变。这里固定走 `postfix` 专用分支，断言才有意义。
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

    // ───────────────────────────── 域名表 ─────────────────────────────

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

        // 表文件格式：`<domain> OK`，行尾换行。
        assert_eq!(f.read(&f.paths.domains), "example.com OK\n");
        // 写完必须编译 hash 表，否则 Postfix 读到的还是旧表。
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
        // 域名里塞换行 = 往虚拟域名表里注入任意行。
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
        // 否则会留下指向已删除域的孤儿映射：删了域名但收信路由没变。
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

    // ───────────────────────────── 别名表 ─────────────────────────────

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
        // 写盘格式：一行、空格分隔。
        assert_eq!(
            f.read(&f.paths.aliases),
            "sales@example.com alice bob@remote.test\n"
        );
    }

    #[test]
    fn alias_add_rejects_newline_injection_into_the_table() {
        // 基线注释点名的第一条注入：目标里的换行会往表里塞进任意条目。
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
        // 空格会让「一个目标」变成「两个目标」，等于悄悄改了路由。
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
        // ADDRESS_RE 的域名部分允许 `..` 之类，必须再过一遍 DOMAIN_RE。
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
        // 基线注释点名的第二条注入：未校验的 id 写进表文件，换行不是「删一行」
        // 而是「注入几行」。
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

    #[test]
    fn table_files_are_world_readable_like_the_installer_creates_them() {
        // 非特权的 Postfix 进程要能读这两张表；它们不含机密。
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
