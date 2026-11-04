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

pub const BACKUP_PREFIX: &str = "mailstack-backup-";
pub const BACKUP_SUFFIX: &str = ".tar.gz";

pub const MAX_LISTED_BACKUPS: usize = 50;

pub const MAX_ARCHIVE_BYTES: u64 = 5 * 1024 * 1024 * 1024;

pub const MAX_MEMBERS: usize = 100_000;

pub const MAX_EXPANDED_BYTES: u64 = 50 * 1024 * 1024 * 1024;

pub const ARCHIVE_MODE: u32 = 0o600;

pub const METADATA_MODE: u32 = 0o600;

pub const RESTORED_FILE_MODE: u32 = 0o640;

pub const RESTORED_SECRET_MODE: u32 = 0o600;

pub const RESTORED_ADMIN_MODE: u32 = 0o640;

pub const ADMIN_FILE_NAME: &str = "admin.json";

pub const RESTORED_SECRET_NAMES: &[&str] = &["sasl_passwd", "totp.key"];

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

pub const SECRET_EXCLUDES: &[&str] = &[
    "etc/mailstack/admin.json",
    "etc/postfix/sasl_passwd",
    "etc/postfix/sasl_passwd.db",
];

pub const DEFAULT_SOURCE_DIRS: &[&str] = &[
    "etc/mailstack",
    "etc/postfix",
    "etc/dovecot",
    "etc/opendkim",
    "var/lib/mailstack",
];

pub const MAIL_DIR_NAME: &str = "Maildir";

pub const LEGACY_MAIL_SOURCE_DIR: &str = "var/vmail";

static FILENAME_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^mailstack-backup-\d{8}-\d{6}(?:-[a-z0-9_-]+)?\.tar\.gz$")
        .expect("备份文件名正则必须能编译")
});

#[derive(Debug, thiserror::Error)]
pub enum BackupError {
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

    #[serde(rename = "metadataMissing", default, skip_serializing_if = "is_false")]
    pub metadata_missing: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Debug, Clone, Default)]
pub struct CreateOptions {
    pub include_mails: bool,
    pub include_secrets: bool,

    pub allow_partial: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateOutcome {
    pub metadata: BackupMetadata,

    pub partial: bool,
}

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

    pub fn metadata_path(&self, archive: &Path) -> PathBuf {
        let name = archive.file_name().unwrap_or_default().to_string_lossy();
        archive.with_file_name(name.replace(BACKUP_SUFFIX, ".json"))
    }

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

fn io_of(error: CoreError) -> std::io::Error {
    std::io::Error::other(error.to_string())
}

pub fn is_backup_filename(name: &str) -> bool {
    FILENAME_RE.is_match(name)
}

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

        let mut out = create_mode_file(&staged, 0o600)?;
        std::io::copy(&mut entry, &mut out).map_err(|e| BackupError::io(&staged, e))?;
        out.flush().map_err(|e| BackupError::io(&staged, e))?;
    }

    let mut restored = Vec::new();

    let mut overwritten: Vec<(PathBuf, PathBuf, Option<u32>)> = Vec::new();
    let mut created: Vec<PathBuf> = Vec::new();

    let landing = (|| -> Result<(), BackupError> {
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
            let mode_before = if existed { file_mode(&target) } else { None };
            if existed {
                let metadata =
                    std::fs::symlink_metadata(&target).map_err(|e| BackupError::io(&target, e))?;
                if hard_link_count(&metadata) > 1 {
                    return Err(BackupError::invalid(format!(
                        "Restore target has multiple hard links: {}",
                        target.display()
                    )));
                }

                let backup = staging
                    .path()
                    .join(format!(".rollback-{}", unique_temp_tag()));
                backup_original(&target, &backup)?;
                overwritten.push((target.clone(), backup, mode_before));
            } else {
                created.push(target.clone());
            }
            let mode = restored_mode(parts[parts.len() - 1]);
            land_one(
                &source,
                &target,
                mode,
                parts[parts.len() - 1],
                existed,
                &parent,
            )?;
            restored.push(target);
        }
        Ok(())
    })();

    if let Err(error) = landing {
        rollback_landing(&overwritten, &created);
        return Err(error);
    }
    Ok(restored)
}

fn backup_original(target: &Path, backup: &Path) -> Result<(), BackupError> {
    let mut input = std::fs::File::open(target).map_err(|e| BackupError::io(target, e))?;
    let mut output = create_mode_file(backup, 0o600)?;
    std::io::copy(&mut input, &mut output).map_err(|e| BackupError::io(backup, e))?;
    output.flush().map_err(|e| BackupError::io(backup, e))?;
    output.sync_all().map_err(|e| BackupError::io(backup, e))?;
    Ok(())
}

fn land_one(
    source: &Path,
    target: &Path,
    mode: u32,
    file_name: &str,
    existed: bool,
    parent: &Path,
) -> Result<(), BackupError> {
    let mut output = open_no_follow(target, mode)?;
    let copy = (|| -> Result<(), BackupError> {
        let mut input = std::fs::File::open(source).map_err(|e| BackupError::io(source, e))?;
        std::io::copy(&mut input, &mut output).map_err(|e| BackupError::io(target, e))?;
        output.flush().map_err(|e| BackupError::io(target, e))?;
        output.sync_all().map_err(|e| BackupError::io(target, e))?;
        Ok(())
    })();
    copy?;
    set_mode(&output, target, mode)?;
    if file_name == ADMIN_FILE_NAME {
        chown_admin_group(&output, target);
    } else if !existed {
        chown_like_parent(&output, parent);
    }
    Ok(())
}

fn rollback_landing(overwritten: &[(PathBuf, PathBuf, Option<u32>)], created: &[PathBuf]) {
    for (target, backup, mode_before) in overwritten {
        let result = (|| -> Result<(), BackupError> {
            let mut output = open_no_follow(target, RESTORED_FILE_MODE)?;
            let mut input = std::fs::File::open(backup).map_err(|e| BackupError::io(backup, e))?;
            std::io::copy(&mut input, &mut output).map_err(|e| BackupError::io(target, e))?;
            output.flush().map_err(|e| BackupError::io(target, e))?;
            output.sync_all().map_err(|e| BackupError::io(target, e))?;
            if let Some(mode) = mode_before {
                set_mode(&output, target, *mode)?;
            }
            Ok(())
        })();
        if let Err(error) = result {
            crate::warn::warn_with_detail(
                "restore rollback",
                &format!("{}: {error}", target.display()),
            );
        }
        let _ = std::fs::remove_file(backup);
    }
    for target in created {
        match std::fs::remove_file(target) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => crate::warn::warn_with_detail(
                "restore rollback",
                &format!("remove {}: {e}", target.display()),
            ),
        }
    }
}

fn restored_mode(file_name: &str) -> u32 {
    if file_name == ADMIN_FILE_NAME {
        RESTORED_ADMIN_MODE
    } else if RESTORED_SECRET_NAMES.contains(&file_name) {
        RESTORED_SECRET_MODE
    } else {
        RESTORED_FILE_MODE
    }
}

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

pub fn is_gzip_file(path: &Path) -> bool {
    let mut magic = [0u8; 2];
    match std::fs::File::open(path).and_then(|mut f| f.read_exact(&mut magic)) {
        Ok(()) => magic == [0x1f, 0x8b],
        Err(_) => false,
    }
}

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
    let staged = unique_sibling_path(target);
    let write = (|| -> Result<bool, BackupError> {
        let file = create_mode_file(&staged, ARCHIVE_MODE)?;
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
        encoder.finish().map_err(|e| BackupError::io(&staged, e))?;
        Ok(partial)
    })();

    match write {
        Ok(partial) => {
            std::fs::rename(&staged, target).map_err(|e| BackupError::io(target, e))?;

            set_mode_path(target, ARCHIVE_MODE)?;
            Ok(partial)
        }
        Err(error) => {
            let _ = std::fs::remove_file(&staged);
            Err(error)
        }
    }
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

fn archive_name(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .trim_start_matches('/')
        .to_string()
}

pub fn mail_sources(root: &Path, mail_dirs: &[PathBuf]) -> Vec<PathBuf> {
    let mut sources: Vec<PathBuf> = mail_dirs
        .iter()
        .filter(|maildir| maildir.is_dir())
        .cloned()
        .collect();
    let legacy = root.join(LEGACY_MAIL_SOURCE_DIR);
    if legacy.is_dir() {
        sources.push(legacy);
    }
    sources
}

pub fn default_sources(root: &Path, include_mails: bool, mail_dirs: &[PathBuf]) -> Vec<PathBuf> {
    let mut sources: Vec<PathBuf> = DEFAULT_SOURCE_DIRS
        .iter()
        .map(|suffix| root.join(suffix))
        .filter(|path| path.exists())
        .collect();
    if include_mails {
        sources.extend(mail_sources(root, mail_dirs));
    }
    sources
}

pub trait BackupCipher: Send + Sync {
    fn available(&self) -> bool;

    fn encrypt(&self, input: &Path, output: &Path, passphrase: &str) -> Result<(), BackupError>;
    fn decrypt(&self, input: &Path, output: &Path, passphrase: &str) -> Result<(), BackupError>;
}

#[derive(Debug, Default)]
pub struct GpgCipher;

pub const GPG_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);

impl GpgCipher {
    fn resolve_program() -> Result<PathBuf, BackupError> {
        crate::exec::resolve_program_for_execution("gpg")
            .map(PathBuf::from)
            .map_err(|error| {
                BackupError::Archive(format!(
                    "拒绝执行不可信的 gpg（{error}）；备份口令不能交给未通过可信解析的程序"
                ))
            })
    }

    fn spawn(&self, args: &[&str], passphrase: &str, context: &str) -> Result<(), BackupError> {
        use std::process::{Command, Stdio};
        use std::time::Instant;

        let program = Self::resolve_program()?;
        let mut child = Command::new(&program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| BackupError::Archive(format!("{context}: 无法启动 gpg：{e}")))?;

        let write_result = match child.stdin.take() {
            Some(mut stdin) => stdin
                .write_all(passphrase.as_bytes())
                .map_err(|e| format!("{e}")),
            None => Ok(()),
        };
        if let Err(detail) = write_result {
            let _ = child.kill();
            let _ = child.wait();
            return Err(BackupError::Archive(format!(
                "{context}: 写入口令失败：{detail}"
            )));
        }

        let deadline = Instant::now() + GPG_TIMEOUT;
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) => {}
                Err(e) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(BackupError::Archive(format!(
                        "{context}: 等待 gpg 失败：{e}"
                    )));
                }
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(BackupError::Archive(format!(
                    "{context}: gpg 超过 {GPG_TIMEOUT:?} 未返回，已终止"
                )));
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
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
        Self::resolve_program().is_ok()
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

#[derive(Debug, Clone, Default)]
pub struct RestoreOptions {
    pub passphrase: Option<String>,
    pub allow_partial_restore: bool,

    pub dry_run: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreOutcome {
    pub dry_run: bool,
    pub files_count: usize,
    pub preview_files: Vec<String>,
    pub restored_files: Vec<PathBuf>,
    pub sha256: String,
}

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

    let passphrase = options.passphrase.clone().unwrap_or_default();

    let mut staging: Option<StagingDir> = None;
    let decrypted = if metadata.encrypted {
        if passphrase.is_empty() {
            return Err(BackupError::invalid(
                "This backup is encrypted; the passphrase is required to restore it",
            ));
        }
        if !cipher.available() {
            return Err(BackupError::invalid(
                "gpg is not installed (or does not resolve to a trusted executable); encrypted backups cannot be restored",
            ));
        }
        let dir = StagingDir::create()?;
        let staged = dir.path().join("restore.tar");
        cipher.decrypt(names_archive, &staged, &passphrase)?;
        staging = Some(dir);
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

    let members = validate_archive(source, managed_home_users)?;

    if options.dry_run {
        return Ok(RestoreOutcome {
            dry_run: true,
            files_count: members.len(),
            preview_files: members.iter().take(20).cloned().collect(),
            restored_files: Vec::new(),
            sha256: actual,
        });
    }

    let restored = extract_archive(source, dest_root, managed_home_users);

    drop(staging);
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

pub fn encrypt_in_place(
    archive: &Path,
    passphrase: &str,
    cipher: &dyn BackupCipher,
) -> Result<(), BackupError> {
    if !cipher.available() {
        let _ = std::fs::remove_file(archive);
        return Err(BackupError::invalid(
            "gpg is not installed (or does not resolve to a trusted executable); encrypted backups are unavailable (refusing to fall back to plaintext)",
        ));
    }

    let staged = unique_sibling_path(archive);
    let staged_file = create_mode_file(&staged, ARCHIVE_MODE)?;
    drop(staged_file);
    match cipher.encrypt(archive, &staged, passphrase) {
        Ok(()) => match (|| -> Result<(), BackupError> {
            set_mode_path(&staged, ARCHIVE_MODE)?;
            std::fs::rename(&staged, archive).map_err(|e| BackupError::io(archive, e))
        })() {
            Ok(()) => Ok(()),
            Err(error) => {
                let _ = std::fs::remove_file(&staged);
                let _ = std::fs::remove_file(archive);
                Err(error)
            }
        },
        Err(error) => {
            let _ = std::fs::remove_file(&staged);
            let _ = std::fs::remove_file(archive);
            Err(error)
        }
    }
}

fn unique_temp_tag() -> String {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{}.{}.{}", std::process::id(), seq, nanos)
}

fn unique_sibling_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    path.with_file_name(format!("{name}.tmp.{}", unique_temp_tag()))
}

fn create_mode_file(path: &Path, mode: u32) -> Result<std::fs::File, BackupError> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    options.open(path).map_err(|e| BackupError::io(path, e))
}

#[cfg(unix)]
fn file_mode(path: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .ok()
        .map(|m| m.permissions().mode() & 0o777)
}

#[cfg(not(unix))]
fn file_mode(_path: &Path) -> Option<u32> {
    None
}

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

        let _ = unsafe { libc::fchown(file.as_raw_fd(), metadata.uid(), metadata.gid()) };
    }
    #[cfg(not(unix))]
    let _ = (file, parent);
}

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
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&base)
                .map_err(|e| BackupError::io(&base, e))?;
        }
        #[cfg(not(unix))]
        {
            std::fs::create_dir_all(&base).map_err(|e| BackupError::io(&base, e))?;
        }
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
                ("etc/mailstack/totp.key", b"key"),
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
            assert_eq!(mode("etc/mailstack/totp.key"), 0o600, "机密");
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

    #[cfg(unix)]
    #[test]
    fn a_failed_landing_restores_overwritten_files_from_their_backups() {
        let root = temp_root("rollback");
        let store = BackupStore::new(root.join("backups"));
        let target = build_backup(
            &store,
            "mailstack-backup-20261002-120000.tar.gz",
            &[
                ("etc/mailstack/settings.json", b"new-settings"),
                ("etc/mailstack/evil.json", b"never-lands"),
            ],
            false,
            &NoCipher,
        );

        let dest = root.join("dest");
        write(
            &dest.join("etc/mailstack/settings.json"),
            b"original-settings",
        );
        std::os::unix::fs::symlink(
            dest.join("etc/mailstack/nowhere").as_path(),
            dest.join("etc/mailstack/evil.json").as_path(),
        )
        .unwrap();

        let error = restore_archive(
            &store,
            &target,
            &dest,
            &RestoreOptions::default(),
            &BTreeSet::new(),
            &NoCipher,
        )
        .expect_err("符号链接目标必须被拒");
        assert!(error.to_string().contains("symbolic link"), "{error}");

        assert_eq!(
            std::fs::read_to_string(dest.join("etc/mailstack/settings.json")).unwrap(),
            "original-settings",
            "落地失败必须把已覆盖的文件回滚为原件"
        );

        assert!(
            std::fs::symlink_metadata(dest.join("etc/mailstack/evil.json"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn create_archive_leaves_no_temporary_file_behind() {
        let (staging, sources) = source_tree("notmp");
        let store_dir = staging.parent().unwrap().join("backups");
        let target = store_dir.join("mailstack-backup-20261002-120000.tar.gz");

        create_archive(&staging, &sources, &target, &[], false).unwrap();

        let leftovers: Vec<String> = std::fs::read_dir(&store_dir)
            .unwrap()
            .filter_map(|item| item.ok())
            .map(|item| item.file_name().to_string_lossy().to_string())
            .filter(|name| name.contains(".tmp."))
            .collect();
        assert!(leftovers.is_empty(), "不得残留临时归档: {leftovers:?}");
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

    #[cfg(unix)]
    #[test]
    fn gpg_is_never_executed_from_an_untrusted_path_entry() {
        use std::os::unix::fs::PermissionsExt;

        static PATH_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _serial = PATH_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let dir = temp_root("gpg-path");
        let marker = dir.join("executed");

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        let fake = dir.join("gpg");
        std::fs::write(
            &fake,
            format!("#!/bin/sh\ntouch '{}'\nexit 0\n", marker.display()),
        )
        .unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();

        let input = dir.join("archive.tar.gz");
        std::fs::write(&input, b"plain").unwrap();
        let output = dir.join("archive.enc");

        let previous = std::env::var_os("PATH");
        std::env::set_var("PATH", &dir);
        let resolved = crate::exec::resolve_program_for_execution("gpg");
        let available = GpgCipher.available();
        let attempt = GpgCipher.encrypt(&input, &output, "hunter2");
        match previous {
            Some(value) => std::env::set_var("PATH", value),
            None => std::env::remove_var("PATH"),
        }

        match resolved {
            Ok(path) => assert_ne!(
                std::path::Path::new(&path),
                fake.as_path(),
                "不可信目录里的 gpg 不得被解析为可执行"
            ),
            Err(_) => {
                assert!(!available, "不可信的 gpg 不得被报告为可用");
                assert!(attempt.is_err(), "必须拒绝执行，而不是把口令交给它");
            }
        }
        assert!(
            !marker.exists(),
            "不可信目录里的 gpg 被实际执行了：root 助手可被本地用户劫持"
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_encryption_stage_file_is_private_and_not_predictable() {
        use std::os::unix::fs::PermissionsExt;
        use std::sync::Mutex;

        struct CheckingCipher {
            observed: Mutex<Option<(PathBuf, u32, bool)>>,
        }

        impl BackupCipher for CheckingCipher {
            fn available(&self) -> bool {
                true
            }
            fn encrypt(
                &self,
                input: &Path,
                output: &Path,
                passphrase: &str,
            ) -> Result<(), BackupError> {
                let metadata = std::fs::metadata(output)
                    .expect("暂存文件必须由 encrypt_in_place 预创建（O_EXCL + 0600）");
                let mode = metadata.permissions().mode() & 0o777;
                let predictable = output
                    .file_name()
                    .map(|name| name.to_string_lossy().ends_with(".enc"))
                    .unwrap_or(true);
                *self.observed.lock().unwrap() = Some((output.to_path_buf(), mode, predictable));

                let body = std::fs::read(input).map_err(|e| BackupError::io(input, e))?;
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .truncate(true)
                    .open(output)
                    .map_err(|e| BackupError::io(output, e))?;
                file.write_all(passphrase.as_bytes()).unwrap();
                file.write_all(&body).unwrap();
                Ok(())
            }
            fn decrypt(&self, _i: &Path, _o: &Path, _p: &str) -> Result<(), BackupError> {
                Err(BackupError::invalid("unavailable"))
            }
        }

        let dir = temp_root("enc-staging");
        let archive = dir.join("mailstack-backup-20261002-120000.tar.gz");
        std::fs::write(&archive, b"plaintext").unwrap();
        let cipher = CheckingCipher {
            observed: Mutex::new(None),
        };

        encrypt_in_place(&archive, "hunter2", &cipher).unwrap();

        let (staged, mode, predictable) = cipher
            .observed
            .lock()
            .unwrap()
            .clone()
            .expect("加密后端必须被调用");
        assert_eq!(mode, 0o600, "暂存密文必须从创建那一刻就是 0600");
        assert!(!predictable, "暂存名不得可预测（旧实现是 <archive>.enc）");
        assert_eq!(
            staged.parent(),
            archive.parent(),
            "必须同目录才能原子 rename"
        );
        assert!(!staged.exists(), "暂存文件应已 rename 为最终归档");
        assert_eq!(
            std::fs::metadata(&archive).unwrap().permissions().mode() & 0o777,
            ARCHIVE_MODE,
            "最终归档权限"
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_decrypted_archive_is_staged_in_a_private_directory() {
        use std::os::unix::fs::PermissionsExt;
        use std::sync::Mutex;

        struct ObservingCipher {
            observed: Mutex<Option<(PathBuf, u32)>>,
        }

        impl BackupCipher for ObservingCipher {
            fn available(&self) -> bool {
                true
            }
            fn encrypt(
                &self,
                input: &Path,
                output: &Path,
                passphrase: &str,
            ) -> Result<(), BackupError> {
                FakeCipher.encrypt(input, output, passphrase)
            }
            fn decrypt(
                &self,
                input: &Path,
                output: &Path,
                passphrase: &str,
            ) -> Result<(), BackupError> {
                let parent = output.parent().expect("解密产物应有父目录").to_path_buf();
                let mode = std::fs::metadata(&parent)
                    .expect("staging 目录必须已存在")
                    .permissions()
                    .mode()
                    & 0o777;
                *self.observed.lock().unwrap() = Some((parent, mode));
                FakeCipher.decrypt(input, output, passphrase)
            }
        }

        let root = temp_root("decrypt-staging");
        let store = BackupStore::new(root.join("backups"));
        let cipher = ObservingCipher {
            observed: Mutex::new(None),
        };
        let target = build_backup(
            &store,
            "mailstack-backup-20261002-120000.tar.gz",
            &[("etc/mailstack/settings.json", b"{}")],
            true,
            &cipher,
        );

        let dest = root.join("dest");
        std::fs::create_dir_all(&dest).unwrap();
        let outcome = restore_archive(
            &store,
            &target,
            &dest,
            &RestoreOptions {
                passphrase: Some("hunter2".into()),
                ..Default::default()
            },
            &BTreeSet::new(),
            &cipher,
        )
        .unwrap();
        assert_eq!(outcome.files_count, 1);

        let (parent, mode) = cipher
            .observed
            .lock()
            .unwrap()
            .clone()
            .expect("解密后端必须被调用");
        assert_eq!(mode, 0o700, "明文归档的 staging 目录必须是 0700");
        assert_ne!(parent.as_path(), store.dir(), "明文归档不得落在备份目录里");
        assert!(!parent.exists(), "staging 目录应在恢复完成后被清理");
    }

    #[test]
    fn a_non_gzip_archive_that_is_not_marked_encrypted_is_reported_as_corrupt() {
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
        let root = temp_root("sources");
        assert!(
            default_sources(&root, true, &[]).is_empty(),
            "空树里不该有任何来源"
        );
        std::fs::create_dir_all(root.join("etc/mailstack")).unwrap();
        let sources = default_sources(&root, true, &[]);
        assert_eq!(sources.len(), 1, "只有配置目录；var/vmail 本栈不创建");
        assert!(sources.iter().all(|path| path.exists()));

        assert_eq!(default_sources(&root, false, &[]).len(), 1);

        std::fs::create_dir_all(root.join("home/alice/Maildir/new")).unwrap();
        let maildir = root.join("home/alice/Maildir");
        let with_mail = default_sources(&root, true, std::slice::from_ref(&maildir));
        assert!(
            with_mail.contains(&maildir),
            "受管账号的 Maildir 必须成为邮件来源：{with_mail:?}"
        );

        let bob_maildir = root.join("home/bob/Maildir");
        std::fs::create_dir_all(root.join("home/bob")).unwrap();
        let only_alice = default_sources(&root, true, std::slice::from_ref(&bob_maildir));
        assert!(
            !only_alice.contains(&bob_maildir),
            "不存在的 Maildir 不该被纳入：{only_alice:?}"
        );

        std::fs::create_dir_all(root.join(LEGACY_MAIL_SOURCE_DIR)).unwrap();
        let with_legacy = default_sources(&root, true, &[]);
        assert!(with_legacy.contains(&root.join(LEGACY_MAIL_SOURCE_DIR)));
    }

    #[test]
    fn include_mails_archives_and_restores_the_authoritative_home_maildir() {
        let root = temp_root("homemaildir");
        write(&root.join("etc/mailstack/settings.json"), b"{}");
        let maildir = root.join("home/alice/Maildir");
        write(
            &maildir.join("new/1712000000.M1P1.test"),
            b"Subject: hi\r\n\r\nbody",
        );
        let homes = vec![root.join("home/alice/Maildir")];

        let store = BackupStore::new(root.join("backups"));
        let target = store.dir().join("mailstack-backup-20261002-120000.tar.gz");
        let sources = default_sources(&root, true, &homes);
        create_archive(&root, &sources, &target, &[], false).unwrap();

        let file = std::fs::File::open(&target).unwrap();
        let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(file));
        let names: Vec<String> = tar
            .entries()
            .unwrap()
            .map(|e| e.unwrap().path().unwrap().to_string_lossy().to_string())
            .collect();
        assert!(
            names
                .iter()
                .any(|name| name == "home/alice/Maildir/new/1712000000.M1P1.test"),
            "归档必须包含受管邮箱的邮件：{names:?}"
        );

        store
            .write_metadata(&BackupMetadata {
                name: "mailstack-backup-20261002-120000.tar.gz".into(),
                filename: "mailstack-backup-20261002-120000.tar.gz".into(),
                path: target.display().to_string(),
                size: std::fs::metadata(&target).unwrap().len(),
                sha256: Some(file_sha256(&target).unwrap()),
                created_at: "2026-10-02T12:00:00Z".into(),
                include_mails: true,
                include_secrets: false,
                partial: false,
                encrypted: false,
                version: crate::VERSION.to_string(),
                metadata_missing: false,
            })
            .unwrap();

        let dest = root.join("dest");
        std::fs::create_dir_all(&dest).unwrap();
        let mut allowed = BTreeSet::new();
        allowed.insert("alice".to_string());
        let outcome = restore_archive(
            &store,
            &target,
            &dest,
            &RestoreOptions::default(),
            &allowed,
            &NoCipher,
        )
        .unwrap();
        assert!(outcome.files_count >= 2, "{outcome:?}");
        assert_eq!(
            std::fs::read_to_string(dest.join("home/alice/Maildir/new/1712000000.M1P1.test"))
                .unwrap(),
            "Subject: hi\r\n\r\nbody",
            "受管邮箱的邮件必须被还原"
        );

        let other = root.join("dest-other");
        std::fs::create_dir_all(&other).unwrap();
        let error = restore_archive(
            &store,
            &target,
            &other,
            &RestoreOptions::default(),
            &BTreeSet::new(),
            &NoCipher,
        )
        .expect_err("非受管家目录必须被拒");
        assert!(error.to_string().contains("does not manage"), "{error}");
    }
}
