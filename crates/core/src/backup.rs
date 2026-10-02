//! 备份与恢复（`backup.create` / `backup.restore` / `backup.delete`）。
//!
//! ## 威胁模型：归档是**不可信输入**
//!
//! 恢复这个动作的实质是「把外部文件往系统目录里写」。攻击面有三个，每一个都必须
//! 在**落地之前**挡掉：
//!
//! 1. **路径穿越**：成员名里带 `..`、绝对路径或空分量，把内容写到允许清单之外。
//! 2. **链接攻击**：归档里先放一个指向 `/etc/shadow` 的符号链接，再让后续成员
//!    顺着它写进去。所以校验与落地必须是两个阶段，且后者用 `O_NOFOLLOW` 打开。
//! 3. **元数据攻击**：设备节点、FIFO、setuid 位。写一个设备节点进 `/dev` 等于
//!    开了一个可以在内核里做 I/O 的入口。
//!
//! ## 为什么在进程内读写 tar 而不是 shell 出 `tar -czf`
//!
//! 上面第 3 条要求逐个读出成员的**元数据**（类型位、权限位）。解析 `tar -tvzf`
//! 的人类可读输出做这件事，等于把一条安全边界建在文本格式上 —— 文件名里一个换行
//! 就能让解析结果与实际内容不一致。用 `tar` crate 直接读头部，判断的是归档里
//! 真实的字节。
//!
//! ## 加密：fail-closed，绝不静默降级
//!
//! 公网模式下明文归档是医生检查的 FAIL 项。因此：
//!
//! * 公网模式下**没有口令就拒绝创建**，而不是「这次先明文」；
//! * 加密失败时把明文归档一并删掉 —— 运维要求了加密，留下明文就是静默降级；
//! * 恢复时若元数据标了 `encrypted` 而没给口令，拒绝，而不是去猜一个。

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::atomic::atomic_as;
use crate::error::CoreError;
use crate::paths::Paths;

/// 归档文件名前缀 / 后缀。
pub const BACKUP_PREFIX: &str = "mailstack-backup-";
pub const BACKUP_SUFFIX: &str = ".tar.gz";

/// 列表最多回多少条（新的在前）。
pub const MAX_LISTED_BACKUPS: usize = 50;

/// 归档文件本体的上限。
pub const MAX_ARCHIVE_BYTES: u64 = 5 * 1024 * 1024 * 1024;
/// 成员数量上限。
pub const MAX_MEMBERS: usize = 100_000;
/// **解压后**的总体积上限。压缩包很小但解压出几百 GB 是经典的解压炸弹。
pub const MAX_EXPANDED_BYTES: u64 = 50 * 1024 * 1024 * 1024;

/// 归档本体的权限：里面有凭证与私钥。
pub const ARCHIVE_MODE: u32 = 0o600;
/// 元数据 sidecar 的权限。
pub const METADATA_MODE: u32 = 0o600;
/// 恢复时普通文件的权限。
pub const RESTORED_FILE_MODE: u32 = 0o640;
/// 恢复时机密文件的权限。
pub const RESTORED_SECRET_MODE: u32 = 0o600;
/// 恢复时 `admin.json` 的权限。
///
/// 它**必须**是 0640 而不是 0600：管理台进程不是 root，靠 `mailstack-admin` 组
/// 才读得到自己的凭证。用通用的「机密文件 0600」处理它，会把控制台锁在自己
/// 的凭证之外。
pub const RESTORED_ADMIN_MODE: u32 = 0o640;
/// 由 `mailstack-admin` 组读取的文件名。
pub const ADMIN_FILE_NAME: &str = "admin.json";
/// 恢复时按 0600 落盘的机密文件名（不含 `admin.json`，它单独处理）。
pub const RESTORED_SECRET_NAMES: &[&str] = &["sasl_passwd", "ai.json", "ai-provider.json"];

/// 允许被恢复覆盖的路径前缀（归档内的相对名字）。
pub const ALLOWED_PREFIXES: &[&str] = &[
    "etc/mailstack/",
    "etc/postfix/",
    "etc/dovecot/",
    "etc/opendkim/",
    "var/vmail/",
    "var/lib/mailstack/",
    "root/Maildir/",
    "home/",
];

/// 被排除在归档之外的机密文件（`includeSecrets = false` 时）。
///
/// 用**归档内相对名**而不是绝对路径：成员名本来就是相对 `/` 的，按同一个口径比较
/// 才能保证「排除」与「校验」说的是同一件事；测试也不必为了命中去伪造绝对路径。
pub const SECRET_EXCLUDES: &[&str] = &[
    "etc/mailstack/admin.json",
    "etc/mailstack/ai.json",
    "etc/mailstack/ai-provider.json",
    "etc/postfix/sasl_passwd",
    "etc/postfix/sasl_passwd.db",
];

/// 默认纳入归档的配置目录（**相对 root**，存在才纳入）。
pub const DEFAULT_SOURCE_DIRS: &[&str] = &[
    "etc/mailstack",
    "etc/postfix",
    "etc/dovecot",
    "etc/opendkim",
    "var/lib/mailstack",
];

/// 默认纳入的邮件存储目录（`includeMails = true` 且存在时，相对 root）。
pub const MAIL_SOURCE_DIR: &str = "var/vmail";

static FILENAME_RE: LazyLock<Regex> = LazyLock::new(|| {
    // `mailstack-backup-YYYYMMDD-HHMMSS[-suffix].tar.gz`。
    // 后缀是**可选**的：同一秒内两次创建会撞名，第二次带一个随机后缀；
    // 预恢复快照用 `-pre-restore`。两者都必须能通过解析，否则回滚点会解析不到。
    Regex::new(r"^mailstack-backup-\d{8}-\d{6}(?:-[a-z0-9_-]+)?\.tar\.gz$")
        .expect("备份文件名正则必须能编译")
});

/// 备份子系统的错误。
#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    /// 调用方输入非法（文件名、载荷）或归档内容不合规。
    #[error("{0}")]
    Invalid(String),
    #[error("io error on {}: {source}", .path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("归档处理失败：{0}")]
    Archive(String),
}

impl BackupError {
    fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }

    fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}

impl From<BackupError> for CoreError {
    fn from(error: BackupError) -> Self {
        match error {
            BackupError::Invalid(message) => CoreError::invalid(message),
            BackupError::Io { path, source } => CoreError::io(path, source),
            BackupError::Archive(detail) => CoreError::invalid(format!("归档处理失败：{detail}")),
        }
    }
}

/// 备份归档的元数据（与归档同名的 `.json` sidecar）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupMetadata {
    pub name: String,
    pub filename: String,
    pub path: String,
    pub size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "includeMails")]
    pub include_mails: bool,
    #[serde(rename = "includeSecrets", default)]
    pub include_secrets: bool,
    #[serde(default)]
    pub partial: bool,
    #[serde(default)]
    pub encrypted: bool,
    pub version: String,
    /// 元数据缺失时置位：界面必须能区分「这份备份没写元数据」与「它就是这么小」。
    #[serde(rename = "metadataMissing", default, skip_serializing_if = "is_false")]
    pub metadata_missing: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// 创建归档时的选项。
#[derive(Debug, Clone, Default)]
pub struct CreateOptions {
    pub include_mails: bool,
    pub include_secrets: bool,
    /// 单个文件读不到时继续（并在元数据里标 `partial`）。
    pub allow_partial: bool,
}

/// 一次创建的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateOutcome {
    pub metadata: BackupMetadata,
    /// 是否因为读不到个别文件而降级（`allow_partial` 时才可能为真）。
    pub partial: bool,
}

/// 备份目录。
///
/// 所有对外入口都先过 [`BackupStore::resolve`]，因此「文件名 → 路径」这一层
/// 只有一个实现：它同时保证名字合规、是真的本机备份、且不在目录之外。
#[derive(Debug, Clone)]
pub struct BackupStore {
    dir: PathBuf,
}

impl BackupStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn from_paths(paths: &Paths) -> Self {
        Self::new(paths.backups_dir.clone())
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// 归档 → 同名的 `.json` sidecar 路径。
    pub fn metadata_path(&self, archive: &Path) -> PathBuf {
        let name = archive.file_name().unwrap_or_default().to_string_lossy();
        archive.with_file_name(name.replace(BACKUP_SUFFIX, ".json"))
    }

    /// 解析一个**文件名**（不是路径）到本机备份路径。
    ///
    /// 三道判定，缺一不可：
    /// 1. 名字必须匹配 `mailstack-backup-*.tar.gz` —— 否则 `../../etc/passwd` 也能过；
    /// 2. 解析后的父目录必须**就是**备份目录（防 `..` 与符号链接绕道）；
    /// 3. 必须是普通文件（不是符号链接、不是目录）。
    pub fn resolve(&self, name: &str) -> Result<PathBuf, BackupError> {
        if Path::new(name).file_name().map(|f| f.to_string_lossy()) != Some(name.into())
            || !is_backup_filename(name)
        {
            return Err(BackupError::invalid(
                "Backup filename must identify a local MailStack backup",
            ));
        }
        let base = self.dir.canonicalize().map_err(|e| {
            BackupError::invalid(format!("备份目录不可用（{}）：{e}", self.dir.display()))
        })?;
        let target = base.join(name);
        let symlinked = std::fs::symlink_metadata(&target)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false);
        if symlinked {
            return Err(BackupError::invalid(
                "Backup archive was not found in the system backup directory",
            ));
        }
        let resolved = target.canonicalize().map_err(|_| {
            BackupError::invalid("Backup archive was not found in the system backup directory")
        })?;
        if resolved.parent() != Some(base.as_path()) || !resolved.is_file() {
            return Err(BackupError::invalid(
                "Backup archive was not found in the system backup directory",
            ));
        }
        let size = std::fs::metadata(&resolved)
            .map_err(|e| BackupError::io(&resolved, e))?
            .len();
        if size > MAX_ARCHIVE_BYTES {
            return Err(BackupError::invalid(
                "Backup archive exceeds the size limit",
            ));
        }
        Ok(resolved)
    }

    /// 列出本机备份，新的在前，最多 [`MAX_LISTED_BACKUPS`] 条。
    ///
    /// 从未匹配的文件名、符号链接一律跳过：它们不是本机备份，列出来只会让运维
    /// 去点一个点不动的条目。
    pub fn list(&self) -> Vec<BackupMetadata> {
        let read = match std::fs::read_dir(&self.dir) {
            Ok(read) => read,
            Err(_) => return Vec::new(),
        };
        let mut candidates: Vec<PathBuf> = read
            .flatten()
            .filter(|item| {
                let path = item.path();
                let name = item.file_name().to_string_lossy().to_string();
                is_backup_filename(&name)
                    && !path.extension().is_some_and(|e| e == "json")
                    && !std::fs::symlink_metadata(&path)
                        .map(|m| m.file_type().is_symlink())
                        .unwrap_or(true)
            })
            .map(|item| item.path())
            .collect();

        candidates.sort_by_key(|path| {
            std::cmp::Reverse(
                std::fs::metadata(path)
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
            )
        });

        candidates
            .into_iter()
            .take(MAX_LISTED_BACKUPS)
            .map(|archive| self.describe(&archive))
            .collect()
    }

    /// 读归档的元数据；缺失或损坏时给出一条「元数据缺失」的兜底条目。
    ///
    /// **不返回 `None`**：一个读不到元数据的归档仍然是一份真实存在的备份，
    /// 把它从列表里抹掉比标出来更危险。
    pub fn describe(&self, archive: &Path) -> BackupMetadata {
        let name = archive
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let metadata_path = self.metadata_path(archive);
        let readable = std::fs::symlink_metadata(&metadata_path)
            .map(|m| !m.file_type().is_symlink() && m.is_file())
            .unwrap_or(false);
        if readable {
            if let Ok(text) = std::fs::read_to_string(&metadata_path) {
                if let Ok(metadata) = serde_json::from_str::<BackupMetadata>(&text) {
                    return metadata;
                }
            }
        }
        let (size, modified) = std::fs::metadata(archive)
            .map(|m| {
                (
                    m.len(),
                    m.modified().ok().and_then(|t| {
                        t.duration_since(std::time::UNIX_EPOCH).ok().and_then(|d| {
                            time::OffsetDateTime::from_unix_timestamp(d.as_secs() as i64).ok()
                        })
                    }),
                )
            })
            .unwrap_or((0, None));
        BackupMetadata {
            name: name.clone(),
            filename: name,
            path: archive.display().to_string(),
            size,
            sha256: None,
            created_at: modified
                .map(crate::time_fmt::format_iso8601)
                .unwrap_or_default(),
            include_mails: false,
            include_secrets: false,
            partial: false,
            encrypted: false,
            version: crate::VERSION.to_string(),
            metadata_missing: true,
        }
    }

    /// 写入元数据 sidecar。
    pub fn write_metadata(&self, metadata: &BackupMetadata) -> Result<(), BackupError> {
        let archive = self.dir.join(&metadata.filename);
        let payload =
            serde_json::to_vec_pretty(metadata).map_err(|e| BackupError::Archive(e.to_string()))?;
        let mut payload = payload;
        payload.push(b'\n');
        let path = self.metadata_path(&archive);
        atomic_as(&path, &payload, METADATA_MODE, None)
            .map_err(|e| BackupError::io(&path, io_of(e)))
    }

    /// 删除归档及其元数据。
    pub fn delete(&self, name: &str) -> Result<(), BackupError> {
        let target = self.resolve(name)?;
        std::fs::remove_file(&target).map_err(|e| BackupError::io(&target, e))?;
        let metadata_path = self.metadata_path(&target);
        let is_regular = std::fs::symlink_metadata(&metadata_path)
            .map(|m| !m.file_type().is_symlink() && m.is_file())
            .unwrap_or(false);
        if is_regular {
            std::fs::remove_file(&metadata_path).map_err(|e| BackupError::io(&metadata_path, e))?;
        }
        Ok(())
    }
}

/// `CoreError` → `std::io::Error`：`atomic_as` 的失败原因需要保留在 I/O 错误里。
fn io_of(error: CoreError) -> std::io::Error {
    std::io::Error::other(error.to_string())
}

/// 名字是否是一份合规的本机备份。
pub fn is_backup_filename(name: &str) -> bool {
    FILENAME_RE.is_match(name)
}

/// 归档成员名是否合规：返回规范化后的相对路径。
///
/// `managed_home_users` 是**允许被恢复写入家目录**的账号集合。当前用户模型
/// （`users.*`）尚未移植，因此生产调用传的是空集合 —— 任何 `home/<user>/...`
/// 成员都会被拒绝。这是刻意的 fail-closed：我们无法证明某个家目录归 MailStack 管，
/// 就不该往里面写东西。等用户模型落地后把真实账号集合传进来即可。
pub fn normalize_member(
    raw: &str,
    managed_home_users: &BTreeSet<String>,
) -> Result<String, BackupError> {
    let trimmed = raw.trim().replace('\\', "/");
    let name = trimmed.trim_start_matches('/');
    let parts: Vec<&str> = name.split('/').collect();
    if name.is_empty()
        || parts
            .iter()
            .any(|p| p.is_empty() || *p == "." || *p == "..")
    {
        return Err(BackupError::invalid(format!(
            "Archive path traversal rejected: {raw}"
        )));
    }
    let normalized = parts.join("/");
    let exact = ALLOWED_PREFIXES
        .iter()
        .map(|prefix| prefix.trim_end_matches('/'));
    if !exact.clone().any(|candidate| candidate == normalized)
        && !ALLOWED_PREFIXES
            .iter()
            .any(|prefix| normalized.starts_with(prefix))
    {
        return Err(BackupError::invalid(format!(
            "Archive member is outside the restore allowlist: {raw}"
        )));
    }
    if let Some(rest) = normalized.strip_prefix("home/") {
        let owner = rest.split('/').next().unwrap_or("");
        if owner.is_empty() || !managed_home_users.contains(owner) {
            return Err(BackupError::invalid(format!(
                "Archive member targets a home directory MailStack does not manage: {raw}"
            )));
        }
    }
    Ok(normalized)
}

/// 逐个成员校验归档，返回规范化后的成员名（按归档内顺序）。
///
/// 只做**读**：不写任何目标路径。这是「校验与落地分离」的前一半。
pub fn validate_archive(
    archive: &Path,
    managed_home_users: &BTreeSet<String>,
) -> Result<Vec<String>, BackupError> {
    let metadata = std::fs::symlink_metadata(archive).map_err(|e| BackupError::io(archive, e))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(BackupError::invalid(
            "Backup archive must be a regular file",
        ));
    }
    if metadata.len() > MAX_ARCHIVE_BYTES {
        return Err(BackupError::invalid(
            "Backup archive exceeds the size limit",
        ));
    }

    let file = std::fs::File::open(archive).map_err(|e| BackupError::io(archive, e))?;
    let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(file));
    let mut inspected = Vec::new();
    let mut expanded: u64 = 0;

    let entries = tar
        .entries()
        .map_err(|e| BackupError::Archive(e.to_string()))?;
    for entry in entries {
        let entry = entry.map_err(|e| BackupError::Archive(e.to_string()))?;
        if inspected.len() >= MAX_MEMBERS {
            return Err(BackupError::invalid(
                "Backup archive contains too many entries",
            ));
        }
        let raw = entry
            .path()
            .map_err(|e| BackupError::Archive(e.to_string()))?
            .to_string_lossy()
            .to_string();
        let normalized = normalize_member(&raw, managed_home_users)?;

        let kind = entry.header().entry_type();
        // 只放行普通文件与目录。其余（符号链接 / 硬链接 / 块设备 / 字符设备 /
        // FIFO / 其它）都是**攻击载荷**而不是备份内容。
        if !(kind.is_file() || kind.is_dir()) {
            return Err(BackupError::invalid(format!(
                "Archive contains a device, link or special file: {raw}"
            )));
        }
        let mode = entry.header().mode().unwrap_or(0);
        if mode & 0o7000 != 0 {
            return Err(BackupError::invalid(format!(
                "Archive contains unsafe permission bits: {raw}"
            )));
        }
        expanded = expanded.saturating_add(entry.size());
        if expanded > MAX_EXPANDED_BYTES {
            return Err(BackupError::invalid(
                "Backup archive expands beyond the size limit",
            ));
        }
        inspected.push(normalized);
    }
    Ok(inspected)
}

/// 把归档恢复进 `dest_root`（生产是 `/`），返回落地的路径。
///
/// 两个阶段，**不可合并**：
/// 1. 在临时目录里把归档完整解出来 —— 此时还没有任何系统路径被触碰；
/// 2. 全部校验通过后，才逐个复制到目标目录，且每个目标都用 `O_NOFOLLOW` 打开。
///
/// 少了第 1 步，一次「写到一半才发现第 3 个成员是符号链接」的恢复会留下
/// 半个现场；少了 `O_NOFOLLOW`，校验与落地之间的时间差就足以让攻击者换掉目标。
pub fn extract_archive(
    archive: &Path,
    dest_root: &Path,
    managed_home_users: &BTreeSet<String>,
) -> Result<Vec<PathBuf>, BackupError> {
    let inspected = validate_archive(archive, managed_home_users)?;
    let dest_root = dest_root
        .canonicalize()
        .map_err(|e| BackupError::io(dest_root, e))?;

    let staging = StagingDir::create()?;
    let file = std::fs::File::open(archive).map_err(|e| BackupError::io(archive, e))?;
    let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(file));
    let entries = tar
        .entries()
        .map_err(|e| BackupError::Archive(e.to_string()))?;
    for (index, entry) in entries.enumerate() {
        let mut entry = entry.map_err(|e| BackupError::Archive(e.to_string()))?;
        let normalized = inspected
            .get(index)
            .ok_or_else(|| BackupError::Archive("归档成员数与校验结果不一致".to_string()))?
            .clone();

        let staged = staging.path().join(&normalized);
        if entry.header().entry_type().is_dir() {
            std::fs::create_dir_all(&staged).map_err(|e| BackupError::io(&staged, e))?;
            continue;
        }
        if let Some(parent) = staged.parent() {
            std::fs::create_dir_all(parent).map_err(|e| BackupError::io(parent, e))?;
        }
        let mut out = std::fs::File::create(&staged).map_err(|e| BackupError::io(&staged, e))?;
        std::io::copy(&mut entry, &mut out).map_err(|e| BackupError::io(&staged, e))?;
        out.flush().map_err(|e| BackupError::io(&staged, e))?;
    }

    let mut restored = Vec::new();
    for normalized in &inspected {
        let source = staging.path().join(normalized);
        if source.is_dir() {
            continue;
        }
        let parts: Vec<&str> = normalized.split('/').collect();
        let parent = make_safe_parent(&dest_root, &parts[..parts.len() - 1])?;
        let target = parent.join(parts[parts.len() - 1]);
        if std::fs::symlink_metadata(&target)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
        {
            return Err(BackupError::invalid(format!(
                "Restore target is a symbolic link: {}",
                target.display()
            )));
        }
        let existed = target.exists();
        if existed {
            let metadata =
                std::fs::symlink_metadata(&target).map_err(|e| BackupError::io(&target, e))?;
            if hard_link_count(&metadata) > 1 {
                return Err(BackupError::invalid(format!(
                    "Restore target has multiple hard links: {}",
                    target.display()
                )));
            }
        }
        let mode = restored_mode(parts[parts.len() - 1]);
        let mut output = open_no_follow(&target, mode)?;
        let mut input = std::fs::File::open(&source).map_err(|e| BackupError::io(&source, e))?;
        std::io::copy(&mut input, &mut output).map_err(|e| BackupError::io(&target, e))?;
        output.flush().map_err(|e| BackupError::io(&target, e))?;
        output.sync_all().map_err(|e| BackupError::io(&target, e))?;
        set_mode(&output, &target, mode)?;
        if parts[parts.len() - 1] == ADMIN_FILE_NAME {
            chown_admin_group(&output, &target);
        } else if !existed {
            chown_like_parent(&output, &parent);
        }
        restored.push(target);
    }
    Ok(restored)
}

/// 恢复时该用的权限位。
fn restored_mode(file_name: &str) -> u32 {
    if file_name == ADMIN_FILE_NAME {
        RESTORED_ADMIN_MODE
    } else if RESTORED_SECRET_NAMES.contains(&file_name) {
        RESTORED_SECRET_MODE
    } else {
        RESTORED_FILE_MODE
    }
}

/// 逐级创建目标父目录，**任何一级是符号链接即拒绝**。
///
/// 这是链接攻击的第二道闸：即便成员名完全合规，路径上也可能存在一个既有符号链接
/// 把它引向别处。
fn make_safe_parent(root: &Path, parts: &[&str]) -> Result<PathBuf, BackupError> {
    let mut parent = root.to_path_buf();
    for part in parts {
        let candidate = parent.join(part);
        if std::fs::symlink_metadata(&candidate)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
        {
            return Err(BackupError::invalid(format!(
                "Restore destination contains a symbolic link: {}",
                candidate.display()
            )));
        }
        if !candidate.exists() {
            std::fs::create_dir(&candidate).map_err(|e| BackupError::io(&candidate, e))?;
        } else if !candidate.is_dir() {
            return Err(BackupError::invalid(format!(
                "Restore destination parent is not a directory: {}",
                candidate.display()
            )));
        }
        parent = candidate;
    }
    Ok(parent)
}

/// 摘要一个文件的 SHA256（十六进制）。
pub fn file_sha256(path: &Path) -> Result<String, BackupError> {
    let mut file = std::fs::File::open(path).map_err(|e| BackupError::io(path, e))?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|e| BackupError::io(path, e))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex::encode(digest.finalize()))
}

/// 归档是否是 gzip。
///
/// 恢复时用它区分「没标加密但头不对」= **损坏**，与「标了加密」= 需要口令。
/// 把损坏当成加密，会让运维拿着口令去解一个只是丢了头部的文件。
pub fn is_gzip_file(path: &Path) -> bool {
    let mut magic = [0u8; 2];
    match std::fs::File::open(path).and_then(|mut f| f.read_exact(&mut magic)) {
        Ok(()) => magic == [0x1f, 0x8b],
        Err(_) => false,
    }
}

/// 把 `sources` 打包成 `target`。
///
/// `root` 是成员名的基准（生产就是 `/`，测试传一个临时根）：成员名一律是
/// 「相对 root 的路径」。这样归档里的名字与恢复侧的允许清单说的是同一套坐标系，
/// 而不是「谁恰好是绝对路径」。
///
/// 目录会被递归展开；**符号链接一律跳过**（归档里放链接是恢复期攻击的第一步，
/// 自家生成的归档没必要带链接）。`allow_partial` 为真时，单个文件读不到只记账，
/// 不中断整次备份。
pub fn create_archive(
    root: &Path,
    sources: &[PathBuf],
    target: &Path,
    excludes: &[&str],
    allow_partial: bool,
) -> Result<bool, BackupError> {
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent).map_err(|e| BackupError::io(parent, e))?;
    }
    let file = std::fs::File::create(target).map_err(|e| BackupError::io(target, e))?;
    let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
    let mut builder = tar::Builder::new(encoder);
    let mut partial = false;

    for source in sources {
        add_tree(
            &mut builder,
            root,
            source,
            excludes,
            allow_partial,
            &mut partial,
        )?;
    }

    let encoder = builder
        .into_inner()
        .map_err(|e| BackupError::Archive(e.to_string()))?;
    encoder.finish().map_err(|e| BackupError::io(target, e))?;
    // 归档里有凭证与私钥，权限必须显式收紧 —— `File::create` 会用进程 umask
    // （通常是 0644）落盘，等于把备份内容对整个系统可读。
    set_mode_path(target, ARCHIVE_MODE)?;
    Ok(partial)
}

fn add_tree(
    builder: &mut tar::Builder<flate2::write::GzEncoder<std::fs::File>>,
    root: &Path,
    path: &Path,
    excludes: &[&str],
    allow_partial: bool,
    partial: &mut bool,
) -> Result<(), BackupError> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => return tolerate(error, path, allow_partial, partial),
    };
    // 不跟随符号链接：归档里不该出现链接，否则恢复侧必须为它写一整套规则。
    if metadata.file_type().is_symlink() {
        return Ok(());
    }
    let name = archive_name(root, path);
    if excludes.contains(&name.as_str()) {
        return Ok(());
    }

    if metadata.is_dir() {
        append(builder, path, &name)?;
        let read = match std::fs::read_dir(path) {
            Ok(read) => read,
            Err(error) => return tolerate(error, path, allow_partial, partial),
        };
        for item in read {
            match item {
                Ok(item) => add_tree(
                    builder,
                    root,
                    &item.path(),
                    excludes,
                    allow_partial,
                    partial,
                )?,
                Err(error) => tolerate(error, path, allow_partial, partial)?,
            }
        }
        return Ok(());
    }
    append(builder, path, &name)
}

fn append(
    builder: &mut tar::Builder<flate2::write::GzEncoder<std::fs::File>>,
    path: &Path,
    name: &str,
) -> Result<(), BackupError> {
    builder
        .append_path_with_name(path, name)
        .map_err(|e| BackupError::io(path, e))
}

/// 「读不到」的处置：允许部分成功时记账并继续，否则原样报错。
fn tolerate(
    error: std::io::Error,
    path: &Path,
    allow_partial: bool,
    partial: &mut bool,
) -> Result<(), BackupError> {
    if allow_partial {
        *partial = true;
        crate::warn::warn_with_detail(
            "backup source unreadable",
            &format!("{}: {error}", path.display()),
        );
        return Ok(());
    }
    Err(BackupError::io(path, error))
}

/// 绝对路径 → 归档内的相对名字（相对 `root`，且不带前导 `/`）。
fn archive_name(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .trim_start_matches('/')
        .to_string()
}

/// 默认的待备份来源（**存在的**才纳入）。
///
/// `root` 是成员名的基准（生产是 `/`）。带上它，测试就能在一棵临时树上跑完整的
/// 创建流程，而不是去读生产主机的 `/etc`。
pub fn default_sources(root: &Path, include_mails: bool) -> Vec<PathBuf> {
    let mut sources: Vec<PathBuf> = DEFAULT_SOURCE_DIRS
        .iter()
        .map(|suffix| root.join(suffix))
        .filter(|path| path.exists())
        .collect();
    if include_mails {
        let mail = root.join(MAIL_SOURCE_DIR);
        if mail.is_dir() {
            sources.push(mail);
        }
    }
    sources
}

/// 恢复时用到的加密后端。
///
/// 抽成 trait 是必须的：口令**只能经 stdin** 传给 `gpg`（`--passphrase-fd 0`），
/// 走 argv 会让它出现在 `ps` 与审计日志里。`core::exec::CommandRunner` 不支持
/// stdin，因此这里自带一条最窄的通道，而不是把改动扩散到那个被广泛使用的 trait。
pub trait BackupCipher: Send + Sync {
    fn available(&self) -> bool;
    /// 就地加密：成功后 `input` 的密文写在 `output`。
    fn encrypt(&self, input: &Path, output: &Path, passphrase: &str) -> Result<(), BackupError>;
    fn decrypt(&self, input: &Path, output: &Path, passphrase: &str) -> Result<(), BackupError>;
}

/// 真实实现：调用系统 `gpg`，口令经 stdin 传入。
#[derive(Debug, Default)]
pub struct GpgCipher;

impl GpgCipher {
    fn spawn(&self, args: &[&str], passphrase: &str, context: &str) -> Result<(), BackupError> {
        use std::process::{Command, Stdio};
        let mut child = Command::new("gpg")
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| BackupError::Archive(format!("{context}: 无法启动 gpg：{e}")))?;
        if let Some(stdin) = child.stdin.as_mut() {
            stdin
                .write_all(passphrase.as_bytes())
                .map_err(|e| BackupError::Archive(format!("{context}: 写入口令失败：{e}")))?;
        }
        let output = child
            .wait_with_output()
            .map_err(|e| BackupError::Archive(format!("{context}: 等待 gpg 失败：{e}")))?;
        if !output.status.success() {
            return Err(BackupError::Archive(format!(
                "{context}: gpg 退出码 {}",
                output.status.code().unwrap_or(-1)
            )));
        }
        Ok(())
    }
}

impl BackupCipher for GpgCipher {
    fn available(&self) -> bool {
        std::env::var_os("PATH")
            .is_some_and(|path| std::env::split_paths(&path).any(|dir| dir.join("gpg").is_file()))
    }

    fn encrypt(&self, input: &Path, output: &Path, passphrase: &str) -> Result<(), BackupError> {
        self.spawn(
            &[
                "--batch",
                "--yes",
                "--pinentry-mode",
                "loopback",
                "--passphrase-fd",
                "0",
                "--symmetric",
                "--cipher-algo",
                "AES256",
                "-o",
                &output.to_string_lossy(),
                &input.to_string_lossy(),
            ],
            passphrase,
            "备份加密",
        )
    }

    fn decrypt(&self, input: &Path, output: &Path, passphrase: &str) -> Result<(), BackupError> {
        self.spawn(
            &[
                "--batch",
                "--yes",
                "--pinentry-mode",
                "loopback",
                "--passphrase-fd",
                "0",
                "--decrypt",
                "-o",
                &output.to_string_lossy(),
                &input.to_string_lossy(),
            ],
            passphrase,
            "备份解密",
        )
    }
}

/// 恢复时的选项。
#[derive(Debug, Clone, Default)]
pub struct RestoreOptions {
    pub passphrase: Option<String>,
    pub allow_partial_restore: bool,
    /// 只做校验与预览，不写任何目标路径。
    pub dry_run: bool,
}

/// 一次恢复的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreOutcome {
    pub dry_run: bool,
    pub files_count: usize,
    pub preview_files: Vec<String>,
    pub restored_files: Vec<PathBuf>,
    pub sha256: String,
}

/// 校验并恢复一份归档。
///
/// 顺序是刻意的：**先校验完整性，再解压，最后才落地**。任何一步失败都不留下
/// 半个现场。
pub fn restore_archive(
    store: &BackupStore,
    names_archive: &Path,
    dest_root: &Path,
    options: &RestoreOptions,
    managed_home_users: &BTreeSet<String>,
    cipher: &dyn BackupCipher,
) -> Result<RestoreOutcome, BackupError> {
    let metadata = store.describe(names_archive);
    if metadata.partial && !options.allow_partial_restore {
        return Err(BackupError::invalid(
            "Partial backups require allowPartialRestore=true",
        ));
    }
    let expected = metadata
        .sha256
        .as_deref()
        .unwrap_or("")
        .to_ascii_lowercase();
    if !is_sha256_hex(&expected) {
        return Err(BackupError::invalid(
            "Backup metadata does not contain a valid SHA256 checksum",
        ));
    }
    let actual = file_sha256(names_archive)?;
    if actual != expected {
        return Err(BackupError::invalid(
            "Backup archive SHA256 integrity verification failed",
        ));
    }

    // 加密与否**只看元数据标志**：未标加密而 gzip 头不对是损坏，不是加密 ——
    // 让运维拿着口令去解一个只是丢了头部的文件，会把人引到完全错误的方向。
    let passphrase = options.passphrase.clone().unwrap_or_default();
    let decrypted = if metadata.encrypted {
        if passphrase.is_empty() {
            return Err(BackupError::invalid(
                "This backup is encrypted; the passphrase is required to restore it",
            ));
        }
        if !cipher.available() {
            return Err(BackupError::invalid(
                "gpg is not installed; encrypted backups cannot be restored",
            ));
        }
        let staged = store
            .dir()
            .join(format!(".mailstack-restore-{}.tar", std::process::id()));
        cipher.decrypt(names_archive, &staged, &passphrase)?;
        Some(staged)
    } else {
        if !is_gzip_file(names_archive) {
            return Err(BackupError::invalid(
                "Backup archive is corrupted (not a gzip archive) and cannot be restored",
            ));
        }
        None
    };
    let source = decrypted.as_deref().unwrap_or(names_archive);
    let members = match validate_archive(source, managed_home_users) {
        Ok(members) => members,
        Err(error) => {
            if let Some(staged) = &decrypted {
                let _ = std::fs::remove_file(staged);
            }
            return Err(error);
        }
    };

    if options.dry_run {
        if let Some(staged) = &decrypted {
            let _ = std::fs::remove_file(staged);
        }
        return Ok(RestoreOutcome {
            dry_run: true,
            files_count: members.len(),
            preview_files: members.iter().take(20).cloned().collect(),
            restored_files: Vec::new(),
            sha256: actual,
        });
    }

    let restored = extract_archive(source, dest_root, managed_home_users);
    if let Some(staged) = &decrypted {
        let _ = std::fs::remove_file(staged);
    }
    let restored = restored?;
    Ok(RestoreOutcome {
        dry_run: false,
        files_count: restored.len(),
        preview_files: Vec::new(),
        restored_files: restored,
        sha256: actual,
    })
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

/// 加密归档（就地）。失败时**连明文一起删掉** —— 运维要求了加密，留下明文
/// 就是一次静默降级。
pub fn encrypt_in_place(
    archive: &Path,
    passphrase: &str,
    cipher: &dyn BackupCipher,
) -> Result<(), BackupError> {
    if !cipher.available() {
        let _ = std::fs::remove_file(archive);
        return Err(BackupError::invalid(
            "gpg is not installed; encrypted backups are unavailable (refusing to fall back to plaintext)",
        ));
    }
    let staged = archive.with_file_name(format!(
        "{}.enc",
        archive.file_name().unwrap_or_default().to_string_lossy()
    ));
    match cipher.encrypt(archive, &staged, passphrase) {
        Ok(()) => {
            set_mode_path(&staged, ARCHIVE_MODE)?;
            std::fs::rename(&staged, archive).map_err(|e| BackupError::io(archive, e))?;
            Ok(())
        }
        Err(error) => {
            let _ = std::fs::remove_file(&staged);
            let _ = std::fs::remove_file(archive);
            Err(error)
        }
    }
}

// ─────────────────────────── 平台细节 ───────────────────────────

/// 以 `O_NOFOLLOW` 打开目标：校验与落地之间的时间差里若有人把目标换成符号链接，
/// 这次打开会直接失败，而不是顺着链接写出去。
fn open_no_follow(path: &Path, mode: u32) -> Result<std::fs::File, BackupError> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(not(unix))]
    let _ = mode;
    options.open(path).map_err(|e| BackupError::io(path, e))
}

fn set_mode(file: &std::fs::File, path: &Path, mode: u32) -> Result<(), BackupError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(mode))
            .map_err(|e| BackupError::io(path, e))?;
    }
    #[cfg(not(unix))]
    let _ = (file, path, mode);
    Ok(())
}

fn set_mode_path(path: &Path, mode: u32) -> Result<(), BackupError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .map_err(|e| BackupError::io(path, e))?;
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
    Ok(())
}

#[cfg(unix)]
fn hard_link_count(metadata: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    metadata.nlink()
}

#[cfg(not(unix))]
fn hard_link_count(_metadata: &std::fs::Metadata) -> u64 {
    1
}

/// 把恢复出来的 `admin.json` 交给 `mailstack-admin` 组。
///
/// 管理台进程不是 root，靠这个组权限读自己的凭证。chown 失败只告警：文件已经
/// 落地且内容是完整的，把它丢掉反而更糟 —— 但必须让运维看见。
fn chown_admin_group(file: &std::fs::File, path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let Some(gid) = crate::atomic::gid_by_name(crate::atomic::ADMIN_GROUP) else {
            crate::warn::warn_with_detail(
                "chown restored admin.json to group mailstack-admin",
                &format!("{}: 组不存在，已被保留为 0640 但属组未变", path.display()),
            );
            return;
        };
        // SAFETY: `file` 是本函数内仍存活的打开句柄，fd 有效。
        let code = unsafe { libc::fchown(file.as_raw_fd(), 0, gid) };
        if code != 0 {
            crate::warn::warn_with_detail(
                "chown restored admin.json to group mailstack-admin",
                &format!("{}: {}", path.display(), std::io::Error::last_os_error()),
            );
        }
    }
    #[cfg(not(unix))]
    let _ = (file, path);
}

fn chown_like_parent(file: &std::fs::File, parent: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::io::AsRawFd;
        let Ok(metadata) = std::fs::metadata(parent) else {
            return;
        };
        // SAFETY: `file` 是本函数内仍存活的打开句柄，fd 有效。
        let _ = unsafe { libc::fchown(file.as_raw_fd(), metadata.uid(), metadata.gid()) };
    }
    #[cfg(not(unix))]
    let _ = (file, parent);
}

/// 解压用的临时目录，析构即清理。
struct StagingDir {
    path: PathBuf,
}

impl StagingDir {
    fn create() -> Result<Self, BackupError> {
        let mut base = std::env::temp_dir();
        base.push(format!(
            "ms_backup_extract_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&base).map_err(|e| BackupError::io(&base, e))?;
        Ok(Self { path: base })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for StagingDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// 备份列表的诚实性检查：`publicMode` 下的**未加密**归档。
///
/// 与 `security.scan` 的 FAIL 项共用同一份判定。元数据缺失或损坏一律按未加密算
/// （fail-closed）——把不清楚的一律当成安全的，正是要避免的事。
pub fn plaintext_archives(store: &BackupStore, public_mode: bool) -> Vec<String> {
    if !public_mode {
        return Vec::new();
    }
    store
        .list()
        .into_iter()
        .filter(|metadata| !metadata.encrypted)
        .map(|metadata| metadata.filename)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp_root(tag: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "mailstack-backup-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// 不依赖 gpg 的替身加密：把口令长度写在头部，便于断言「确实走了加密路径」。
    struct FakeCipher;

    impl BackupCipher for FakeCipher {
        fn available(&self) -> bool {
            true
        }
        fn encrypt(
            &self,
            input: &Path,
            output: &Path,
            passphrase: &str,
        ) -> Result<(), BackupError> {
            let body = std::fs::read(input).map_err(|e| BackupError::io(input, e))?;
            let mut file = std::fs::File::create(output).map_err(|e| BackupError::io(output, e))?;
            file.write_all(passphrase.as_bytes()).unwrap();
            file.write_all(&body).unwrap();
            Ok(())
        }
        fn decrypt(
            &self,
            input: &Path,
            output: &Path,
            passphrase: &str,
        ) -> Result<(), BackupError> {
            let body = std::fs::read(input).map_err(|e| BackupError::io(input, e))?;
            if !body.starts_with(passphrase.as_bytes()) {
                return Err(BackupError::invalid("口令不对"));
            }
            let mut file = std::fs::File::create(output).map_err(|e| BackupError::io(output, e))?;
            file.write_all(&body[passphrase.len()..]).unwrap();
            Ok(())
        }
    }

    struct NoCipher;

    impl BackupCipher for NoCipher {
        fn available(&self) -> bool {
            false
        }
        fn encrypt(&self, _i: &Path, _o: &Path, _p: &str) -> Result<(), BackupError> {
            Err(BackupError::invalid("unavailable"))
        }
        fn decrypt(&self, _i: &Path, _o: &Path, _p: &str) -> Result<(), BackupError> {
            Err(BackupError::invalid("unavailable"))
        }
    }

    fn write(path: &Path, body: &[u8]) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, body).unwrap();
    }

    // ───────────────────── 文件名与成员名 ─────────────────────

    #[test]
    fn only_well_formed_backup_filenames_are_accepted() {
        for good in [
            "mailstack-backup-20261002-120000.tar.gz",
            "mailstack-backup-20261002-120000-ab12.tar.gz",
            "mailstack-backup-20261002-120000-pre-restore.tar.gz",
        ] {
            assert!(is_backup_filename(good), "{good} 应当被接受");
        }
        for bad in [
            "../../etc/passwd",
            "mailstack-backup-20261002-120000.tar",
            "mailstack-backup-2026-10-02.tar.gz",
            "/var/backups/mailstack/mailstack-backup-20261002-120000.tar.gz",
            "mailstack-backup-20261002-120000.tar.gz/../x",
            "",
        ] {
            assert!(!is_backup_filename(bad), "{bad} 必须被拒绝");
        }
    }

    #[test]
    fn archive_members_outside_the_allowlist_are_rejected() {
        // 这是本模块最重要的一组断言：归档是不可信输入。
        let none = BTreeSet::new();
        for bad in [
            "../etc/passwd",
            "/etc/mailstack/../../etc/shadow",
            "etc/mailstack/../shadow",
            "etc/shadow",
            "usr/bin/whatever",
            "etc/postfix/./main.cf",
            "",
            "etc/mailstack/",
        ] {
            assert!(normalize_member(bad, &none).is_err(), "{bad:?} 必须被拒绝");
        }
    }

    #[test]
    fn archive_members_inside_the_allowlist_are_normalised() {
        let none = BTreeSet::new();
        for (raw, expected) in [
            ("/etc/mailstack/admin.json", "etc/mailstack/admin.json"),
            ("etc/dovecot/dovecot.conf", "etc/dovecot/dovecot.conf"),
            (
                "var/lib/mailstack/manual-bans.json",
                "var/lib/mailstack/manual-bans.json",
            ),
            (
                "var/vmail/example.com/u/Maildir/new/1",
                "var/vmail/example.com/u/Maildir/new/1",
            ),
            ("root/Maildir/cur/2", "root/Maildir/cur/2"),
        ] {
            assert_eq!(normalize_member(raw, &none).unwrap(), expected, "{raw}");
        }
    }

    #[test]
    fn home_members_are_rejected_until_a_user_model_exists() {
        // users.* 尚未移植，因此生产传入的是空集合 —— 任何家目录成员都必须被拒。
        // 这是 fail-closed：无法证明某个家目录归 MailStack 管，就不往里写。
        let none = BTreeSet::new();
        assert!(normalize_member("home/alice/Maildir/new/1", &none).is_err());

        let mut allowed = BTreeSet::new();
        allowed.insert("alice".to_string());
        assert!(normalize_member("home/alice/Maildir/new/1", &allowed).is_ok());
        assert!(
            normalize_member("home/bob/Maildir/new/1", &allowed).is_err(),
            "不在清单里的账号仍然要拒"
        );
    }

    // ───────────────────── 归档校验：链接 / 设备 / setuid ─────────────────────

    /// 造一个只含指定头部的 tar.gz，用于验证「非普通文件必须被拒」。
    fn craft(entries: Vec<tar::Header>) -> PathBuf {
        let dir = temp_root("craft");
        let path = dir.join("mailstack-backup-20261002-120000-crafted.tar.gz");
        let file = std::fs::File::create(&path).unwrap();
        let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        let mut builder = tar::Builder::new(encoder);
        for header in entries {
            builder.append(&header, std::io::empty()).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap();
        path
    }

    fn header(name: &str, kind: tar::EntryType, mode: u32) -> tar::Header {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(kind);
        header.set_mode(mode);
        header.set_size(0);
        header.set_path(name).unwrap();
        header.set_cksum();
        header
    }

    #[test]
    fn a_symbolic_link_inside_the_archive_is_refused() {
        let path = craft(vec![header(
            "etc/mailstack/evil",
            tar::EntryType::Symlink,
            0o777,
        )]);
        let error = validate_archive(&path, &BTreeSet::new()).expect_err("符号链接必须被拒");
        assert!(
            error.to_string().contains("device, link or special"),
            "{error}"
        );
    }

    #[test]
    fn a_character_device_inside_the_archive_is_refused() {
        let path = craft(vec![header(
            "etc/mailstack/dev",
            tar::EntryType::Char,
            0o600,
        )]);
        assert!(validate_archive(&path, &BTreeSet::new()).is_err());
    }

    #[test]
    fn a_member_with_a_setuid_bit_is_refused() {
        let path = craft(vec![header(
            "etc/mailstack/x",
            tar::EntryType::Regular,
            0o4755,
        )]);
        let error = validate_archive(&path, &BTreeSet::new()).expect_err("setuid 必须被拒");
        assert!(
            error.to_string().contains("unsafe permission bits"),
            "{error}"
        );
    }

    // ───────────────────── 创建 / 列表 / 删除 ─────────────────────

    /// 建一棵**生产形状**的源树：成员名是相对 `/` 的（`etc/mailstack/...`），
    /// 因此这里的「临时根」扮演的就是生产里的 `/`。
    fn source_tree(tag: &str) -> (PathBuf, Vec<PathBuf>) {
        let root = temp_root(tag);
        let staging = root.join("staging");
        write(&staging.join("etc/mailstack/settings.json"), b"{}");
        write(&staging.join("etc/mailstack/admin.json"), b"secret");
        write(
            &staging.join("etc/postfix/main.cf"),
            b"myhostname = mx.test\n",
        );
        write(&staging.join("var/lib/mailstack/manual-bans.json"), b"[]");
        let sources = ["etc/mailstack", "etc/postfix", "var/lib/mailstack"]
            .iter()
            .map(|suffix| staging.join(suffix))
            .collect();
        (staging, sources)
    }

    #[test]
    fn create_writes_the_archive_the_metadata_and_the_checksum() {
        let (staging, sources) = source_tree("create");
        let store = BackupStore::new(staging.parent().unwrap().join("backups"));
        let target = store.dir().join("mailstack-backup-20261002-120000.tar.gz");

        let partial = create_archive(&staging, &sources, &target, &[], false).unwrap();
        assert!(!partial);
        assert!(target.is_file());

        let metadata = BackupMetadata {
            name: "mailstack-backup-20261002-120000.tar.gz".into(),
            filename: "mailstack-backup-20261002-120000.tar.gz".into(),
            path: target.display().to_string(),
            size: std::fs::metadata(&target).unwrap().len(),
            sha256: Some(file_sha256(&target).unwrap()),
            created_at: "2026-10-02T12:00:00Z".into(),
            include_mails: false,
            include_secrets: true,
            partial: false,
            encrypted: false,
            version: crate::VERSION.to_string(),
            metadata_missing: false,
        };
        store.write_metadata(&metadata).unwrap();

        let listed = store.list();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].sha256.as_deref(), metadata.sha256.as_deref());
        assert!(!listed[0].metadata_missing);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "归档里有凭证，必须 0600");
        }
    }

    #[test]
    fn excluded_secrets_never_enter_the_archive() {
        let (staging, sources) = source_tree("exclude");
        let store = BackupStore::new(staging.parent().unwrap().join("backups"));
        let target = store.dir().join("mailstack-backup-20261002-120000.tar.gz");

        create_archive(&staging, &sources, &target, SECRET_EXCLUDES, false).unwrap();

        let file = std::fs::File::open(&target).unwrap();
        let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(file));
        let names: Vec<String> = tar
            .entries()
            .unwrap()
            .map(|e| e.unwrap().path().unwrap().to_string_lossy().to_string())
            .collect();
        assert!(
            !names.iter().any(|n| n.ends_with("admin.json")),
            "排除的机密不得进入归档：{names:?}"
        );
        assert!(
            names.iter().any(|n| n.ends_with("settings.json")),
            "{names:?}"
        );
    }

    #[test]
    fn a_missing_metadata_sidecar_is_flagged_rather_than_hidden() {
        let root = temp_root("nometa");
        let store = BackupStore::new(root.clone());
        let target = store.dir().join("mailstack-backup-20261002-120000.tar.gz");
        write(&target, b"not really a targz but present");

        let listed = store.list();
        assert_eq!(listed.len(), 1);
        assert!(
            listed[0].metadata_missing,
            "读不到元数据必须标出来，而不是把这份备份从列表里抹掉"
        );
    }

    #[test]
    fn resolve_refuses_names_that_escape_the_backup_directory() {
        let root = temp_root("resolve");
        let store = BackupStore::new(root.join("backups"));
        std::fs::create_dir_all(store.dir()).unwrap();
        for bad in [
            "../etc/passwd",
            "/etc/passwd",
            "sub/mailstack-backup-20261002-120000.tar.gz",
            "mailstack-backup-20261002-120000.tar",
        ] {
            assert!(store.resolve(bad).is_err(), "{bad:?} 必须被拒绝");
        }
        // 名字合规但不存在 → 也是错误（不能返回一个不存在的路径）。
        assert!(store
            .resolve("mailstack-backup-20261002-120000.tar.gz")
            .is_err());
    }

    #[test]
    fn delete_removes_both_the_archive_and_its_metadata() {
        let root = temp_root("delete");
        let store = BackupStore::new(root.join("backups"));
        let target = store.dir().join("mailstack-backup-20261002-120000.tar.gz");
        write(&target, b"x");
        write(&store.metadata_path(&target), b"{}");
        std::fs::remove_file(store.metadata_path(&target)).ok();
        store
            .write_metadata(&BackupMetadata {
                name: "mailstack-backup-20261002-120000.tar.gz".into(),
                filename: "mailstack-backup-20261002-120000.tar.gz".into(),
                path: target.display().to_string(),
                size: 1,
                sha256: None,
                created_at: "2026-10-02T12:00:00Z".into(),
                include_mails: false,
                include_secrets: false,
                partial: false,
                encrypted: false,
                version: crate::VERSION.to_string(),
                metadata_missing: false,
            })
            .unwrap();

        store
            .delete("mailstack-backup-20261002-120000.tar.gz")
            .unwrap();
        assert!(!target.exists());
        assert!(!store.metadata_path(&target).exists());
    }

    // ───────────────────── 恢复 ─────────────────────

    /// 造一份名字合规、校验和正确的归档（可选加密），并写好元数据。
    ///
    /// 返回归档路径。恢复侧的所有用例都从这里出发 —— 它们要验的是**恢复**的判定，
    /// 不该每个用例各写一遍打包与元数据。
    fn build_backup(
        store: &BackupStore,
        name: &str,
        files: &[(&str, &[u8])],
        encrypted: bool,
        cipher: &dyn BackupCipher,
    ) -> PathBuf {
        let root = store
            .dir()
            .parent()
            .expect("备份目录应有父目录")
            .join(format!("staging-{name}"));
        let mut sources = Vec::new();
        for (relative, body) in files {
            let path = root.join(relative);
            write(&path, body);
            sources.push(path);
        }
        let target = store.dir().join(name);
        create_archive(&root, &sources, &target, &[], false).unwrap();
        if encrypted {
            encrypt_in_place(&target, "hunter2", cipher).unwrap();
        }
        store
            .write_metadata(&BackupMetadata {
                name: name.to_string(),
                filename: name.to_string(),
                path: target.display().to_string(),
                size: std::fs::metadata(&target).unwrap().len(),
                sha256: Some(file_sha256(&target).unwrap()),
                created_at: "2026-10-02T12:00:00Z".into(),
                include_mails: false,
                include_secrets: true,
                partial: false,
                encrypted,
                version: crate::VERSION.to_string(),
                metadata_missing: false,
            })
            .unwrap();
        target
    }

    #[test]
    fn a_restore_round_trips_contents_and_applies_the_documented_modes() {
        let root = temp_root("roundtrip");
        let store = BackupStore::new(root.join("backups"));
        let name = "mailstack-backup-20261002-120000.tar.gz";
        let target = build_backup(
            &store,
            name,
            &[
                ("etc/mailstack/settings.json", b"{}"),
                ("etc/mailstack/admin.json", b"secret"),
                ("etc/mailstack/ai-provider.json", b"key"),
                ("etc/postfix/main.cf", b"x\n"),
            ],
            false,
            &NoCipher,
        );

        let restore_root = root.join("destroot");
        std::fs::create_dir_all(&restore_root).unwrap();
        let outcome = restore_archive(
            &store,
            &target,
            &restore_root,
            &RestoreOptions::default(),
            &BTreeSet::new(),
            &NoCipher,
        )
        .unwrap();

        assert_eq!(outcome.files_count, 4);
        assert_eq!(
            std::fs::read_to_string(restore_root.join("etc/mailstack/settings.json")).unwrap(),
            "{}"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &str| {
                std::fs::metadata(restore_root.join(p))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777
            };
            assert_eq!(
                mode("etc/mailstack/admin.json"),
                0o640,
                "管理台要靠组权限读它"
            );
            assert_eq!(mode("etc/mailstack/ai-provider.json"), 0o600, "机密");
            assert_eq!(mode("etc/postfix/main.cf"), 0o640, "普通配置");
        }
    }

    #[test]
    fn a_tampered_archive_fails_the_checksum_before_anything_lands() {
        let root = temp_root("tamper");
        let store = BackupStore::new(root.join("backups"));
        let target = build_backup(
            &store,
            "mailstack-backup-20261002-120000.tar.gz",
            &[("etc/mailstack/settings.json", b"{}")],
            false,
            &NoCipher,
        );

        // 篡改归档本体。
        let mut bytes = std::fs::read(&target).unwrap();
        bytes.extend_from_slice(b"junk");
        std::fs::write(&target, &bytes).unwrap();

        let dest = root.join("dest");
        std::fs::create_dir_all(&dest).unwrap();
        let error = restore_archive(
            &store,
            &target,
            &dest,
            &RestoreOptions::default(),
            &BTreeSet::new(),
            &NoCipher,
        )
        .expect_err("校验和不符必须拒绝");
        assert!(error.to_string().contains("SHA256"), "{error}");
        assert!(
            std::fs::read_dir(&dest).unwrap().next().is_none(),
            "校验失败时不得落地任何文件"
        );
    }

    #[test]
    fn a_dry_run_previews_without_writing_anything() {
        let root = temp_root("dryrun");
        let store = BackupStore::new(root.join("backups"));
        let target = build_backup(
            &store,
            "mailstack-backup-20261002-120000.tar.gz",
            &[("etc/mailstack/settings.json", b"{}")],
            false,
            &NoCipher,
        );

        let dest = root.join("dest");
        std::fs::create_dir_all(&dest).unwrap();
        let outcome = restore_archive(
            &store,
            &target,
            &dest,
            &RestoreOptions {
                dry_run: true,
                ..Default::default()
            },
            &BTreeSet::new(),
            &NoCipher,
        )
        .unwrap();

        assert!(outcome.dry_run);
        assert_eq!(outcome.preview_files.len(), outcome.files_count);
        assert!(
            std::fs::read_dir(&dest).unwrap().next().is_none(),
            "dryRun 不得写任何目标路径"
        );
    }

    #[test]
    fn an_encrypted_backup_requires_a_passphrase_and_an_available_cipher() {
        let root = temp_root("encrypted");
        let store = BackupStore::new(root.join("backups"));
        let target = build_backup(
            &store,
            "mailstack-backup-20261002-120000.tar.gz",
            &[("etc/mailstack/settings.json", b"{}")],
            true,
            &FakeCipher,
        );
        assert!(
            !is_gzip_file(&target),
            "加密之后不再是 gzip —— 恢复侧靠元数据标志区分加密与损坏"
        );
        let dest = root.join("dest");
        std::fs::create_dir_all(&dest).unwrap();

        // 没给口令 → 拒绝，且不得猜到「那大概是损坏」。
        let error = restore_archive(
            &store,
            &target,
            &dest,
            &RestoreOptions::default(),
            &BTreeSet::new(),
            &FakeCipher,
        )
        .expect_err("加密包缺口令必须拒绝");
        assert!(
            error.to_string().contains("passphrase is required"),
            "{error}"
        );

        // 给了口令但机器上没有 gpg → 也拒绝（fail-closed）。
        let error = restore_archive(
            &store,
            &target,
            &dest,
            &RestoreOptions {
                passphrase: Some("hunter2".into()),
                ..Default::default()
            },
            &BTreeSet::new(),
            &NoCipher,
        )
        .expect_err("没有 gpg 必须拒绝");
        assert!(
            error.to_string().contains("gpg is not installed"),
            "{error}"
        );

        // 口令 + 可用的后端 → 成功。
        let outcome = restore_archive(
            &store,
            &target,
            &dest,
            &RestoreOptions {
                passphrase: Some("hunter2".into()),
                ..Default::default()
            },
            &BTreeSet::new(),
            &FakeCipher,
        )
        .unwrap();
        assert_eq!(outcome.files_count, 1);
        assert_eq!(
            std::fs::read_to_string(dest.join("etc/mailstack/settings.json")).unwrap(),
            "{}"
        );
    }

    #[test]
    fn a_non_gzip_archive_that_is_not_marked_encrypted_is_reported_as_corrupt() {
        // 把它当成加密，会让运维拿着口令去解一个只是丢了头部的文件。
        let root = temp_root("corrupt");
        let store = BackupStore::new(root.join("backups"));
        let name = "mailstack-backup-20261002-120000.tar.gz";
        let target = store.dir().join(name);
        write(&target, b"not a gzip archive at all");
        store
            .write_metadata(&BackupMetadata {
                name: name.into(),
                filename: name.into(),
                path: target.display().to_string(),
                size: std::fs::metadata(&target).unwrap().len(),
                sha256: Some(file_sha256(&target).unwrap()),
                created_at: "2026-10-02T12:00:00Z".into(),
                include_mails: false,
                include_secrets: false,
                partial: false,
                encrypted: false,
                version: crate::VERSION.to_string(),
                metadata_missing: false,
            })
            .unwrap();

        let dest = root.join("dest");
        std::fs::create_dir_all(&dest).unwrap();
        let error = restore_archive(
            &store,
            &target,
            &dest,
            &RestoreOptions::default(),
            &BTreeSet::new(),
            &NoCipher,
        )
        .expect_err("损坏必须如实报出");
        assert!(error.to_string().contains("corrupted"), "{error}");
    }

    #[test]
    fn a_partial_backup_needs_an_explicit_opt_in_to_restore() {
        let root = temp_root("partial");
        let store = BackupStore::new(root.join("backups"));
        let name = "mailstack-backup-20261002-120000.tar.gz";
        let target = store.dir().join(name);
        write(&target, b"x");
        store
            .write_metadata(&BackupMetadata {
                name: name.into(),
                filename: name.into(),
                path: target.display().to_string(),
                size: 1,
                sha256: Some("0".repeat(64)),
                created_at: "2026-10-02T12:00:00Z".into(),
                include_mails: false,
                include_secrets: false,
                partial: true,
                encrypted: false,
                version: crate::VERSION.to_string(),
                metadata_missing: false,
            })
            .unwrap();
        let dest = root.join("dest");
        std::fs::create_dir_all(&dest).unwrap();

        let error = restore_archive(
            &store,
            &target,
            &dest,
            &RestoreOptions::default(),
            &BTreeSet::new(),
            &NoCipher,
        )
        .expect_err("部分备份必须显式确认");
        assert!(error.to_string().contains("allowPartialRestore"), "{error}");
    }

    #[test]
    fn metadata_without_a_valid_checksum_is_refused() {
        let root = temp_root("nohash");
        let store = BackupStore::new(root.join("backups"));
        let name = "mailstack-backup-20261002-120000.tar.gz";
        let target = store.dir().join(name);
        write(&target, b"x");
        for bad in [None, Some("short".to_string()), Some("z".repeat(64))] {
            store
                .write_metadata(&BackupMetadata {
                    name: name.into(),
                    filename: name.into(),
                    path: target.display().to_string(),
                    size: 1,
                    sha256: bad.clone(),
                    created_at: "2026-10-02T12:00:00Z".into(),
                    include_mails: false,
                    include_secrets: false,
                    partial: false,
                    encrypted: false,
                    version: crate::VERSION.to_string(),
                    metadata_missing: false,
                })
                .unwrap();
            let dest = root.join("dest");
            std::fs::create_dir_all(&dest).unwrap();
            let error = restore_archive(
                &store,
                &target,
                &dest,
                &RestoreOptions::default(),
                &BTreeSet::new(),
                &NoCipher,
            )
            .expect_err("没有合法校验和必须拒绝");
            assert!(error.to_string().contains("SHA256"), "{bad:?} → {error}");
        }
    }

    #[test]
    fn plaintext_archives_are_only_reported_in_public_mode() {
        let root = temp_root("plaintext");
        let store = BackupStore::new(root.join("backups"));
        let target = store.dir().join("mailstack-backup-20261002-120000.tar.gz");
        write(&target, b"x");
        store
            .write_metadata(&BackupMetadata {
                name: "mailstack-backup-20261002-120000.tar.gz".into(),
                filename: "mailstack-backup-20261002-120000.tar.gz".into(),
                path: target.display().to_string(),
                size: 1,
                sha256: None,
                created_at: "2026-10-02T12:00:00Z".into(),
                include_mails: false,
                include_secrets: false,
                partial: false,
                encrypted: false,
                version: crate::VERSION.to_string(),
                metadata_missing: false,
            })
            .unwrap();

        assert!(
            plaintext_archives(&store, false).is_empty(),
            "local 模式是合法的"
        );
        assert_eq!(
            plaintext_archives(&store, true),
            vec!["mailstack-backup-20261002-120000.tar.gz".to_string()],
            "公网模式下明文归档必须被点名"
        );
    }

    #[test]
    fn default_sources_only_include_what_exists_under_the_root() {
        // 带上 root 之后这条断言与主机上到底装了什么无关：建一棵临时树即可。
        let root = temp_root("sources");
        assert!(
            default_sources(&root, true).is_empty(),
            "空树里不该有任何来源"
        );
        std::fs::create_dir_all(root.join("etc/mailstack")).unwrap();
        std::fs::create_dir_all(root.join("var/vmail")).unwrap();
        let sources = default_sources(&root, true);
        assert_eq!(sources.len(), 2);
        assert!(sources.iter().all(|path| path.exists()));
        // 不含邮件时只剩配置目录。
        assert_eq!(default_sources(&root, false).len(), 1);
    }
}
