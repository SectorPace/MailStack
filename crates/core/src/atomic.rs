//! 文件写入原语（规格书 §5.7.1、§5.7.2、§5.7.4；INV-31 ~ INV-33）。
//!
//! 两把锁的 sidecar **必须不同名**，否则自死锁（INV-31）：
//!
//! | 原语 | sidecar | 覆盖范围 |
//! |---|---|---|
//! | [`atomic`] | `.<name>.lock` | 仅最终写入阶段 |
//! | [`locked`] | `<name>.lock` | 整个 read-modify-write 临界区 |
//!
//! [`locked`] 存在的理由：`atomic` 只串行化最后的写阶段，一个 load-modify-save
//! 序列仍会丢更新——两次并发的恢复码消费可能各自写回「码仍然存在」的文件
//! （"double spend"）。

use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};

use crate::error::{CoreError, CoreResult};

/// 写入 secret 时的默认组（`atomic` 会把临时文件 chown 到该组）。
pub const ADMIN_GROUP: &str = "mailstack-admin";

/// `atomic()` 使用的锁 sidecar 路径：`.<name>.lock`。
fn atomic_lock_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    path.with_file_name(format!(".{name}.lock"))
}

/// `locked()` 使用的锁 sidecar 路径：`<name>.lock`。
///
/// **刻意与 [`atomic_lock_path`] 不同**——同名会在「持 locked 时再调 atomic」的
/// 合法用法下自死锁（INV-31）。
fn locked_lock_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    path.with_file_name(format!("{name}.lock"))
}

/// 临时文件路径：同目录下 `<name>.tmp`。
///
/// 必须与目标同目录，`rename` 才是同文件系统内的原子操作。
fn temp_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    path.with_file_name(format!("{name}.tmp"))
}

/// 原子写入 `data` 到 `path`，权限 `mode` 在 **rename 之前**应用（INV-33）。
///
/// 步骤与 `core.py:621-662` 逐条对应：
/// 1. `mkdir -p` 目标目录
/// 2. 在 sidecar `.<name>.lock` 上取排他锁
/// 3. 写临时文件 → `flush` → `fsync`
/// 4. `chmod(tmp, mode)`（**在 rename 之前**，secret 不得以进程 umask 落盘）
/// 5. `chown(tmp, -1, mailstack-admin)`（尽力而为，失败仅 warn）
/// 6. `rename(tmp, path)`
pub fn atomic(path: &Path, data: &[u8], mode: u32) -> CoreResult<()> {
    atomic_as(path, data, mode, Some(ADMIN_GROUP))
}

/// 可指定目标组的 [`atomic`]，`group = None` 表示跳过 chown（测试用）。
pub fn atomic_as(path: &Path, data: &[u8], mode: u32, group: Option<&str>) -> CoreResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| CoreError::io(parent, e))?;
    }

    let lock_path = atomic_lock_path(path);
    let lock_handle = open_lock_sidecar(&lock_path);
    let _guard = lock_handle.as_ref().map(FileLock::acquire);

    let tmp = temp_path(path);
    {
        use std::io::Write;
        let mut f = File::create(&tmp).map_err(|e| CoreError::io(&tmp, e))?;
        f.write_all(data).map_err(|e| CoreError::io(&tmp, e))?;
        f.flush().map_err(|e| CoreError::io(&tmp, e))?;
        f.sync_all().map_err(|e| CoreError::io(&tmp, e))?;
    }

    set_mode(&tmp, mode)?;
    if let Some(group) = group {
        chown_group_best_effort(&tmp, group);
    }

    fs::rename(&tmp, path).map_err(|e| CoreError::io(path, e))?;
    Ok(())
}

/// 在整个 read-modify-write 临界区持排他锁（`core.py:664-724`）。
///
/// 锁 sidecar 为 `<name>.lock`，与 [`atomic`] 的 `.<name>.lock` 不同名。
/// 降级链：POSIX `flock` → Windows 字节锁 → 无锁（接口不变）。
pub fn locked<T, F>(path: &Path, f: F) -> CoreResult<T>
where
    F: FnOnce() -> CoreResult<T>,
{
    let lock_path = locked_lock_path(path);
    if let Some(parent) = lock_path.parent() {
        let _ = fs::create_dir_all(parent);
    }

    let handle = match open_lock_sidecar(&lock_path) {
        Some(h) => Some(h),
        None => {
            // 无法打开 sidecar 时降级为无锁，但保留同样的接口语义。
            crate::warn::warn(&format!("open lock sidecar {}", lock_path.display()));
            None
        }
    };
    let _guard = handle.as_ref().map(FileLock::acquire);

    f()
}

fn open_lock_sidecar(path: &Path) -> Option<File> {
    OpenOptions::new()
        .create(true)
        .read(true)
        .append(true)
        .open(path)
        .ok()
}

/// RAII 排他锁；析构时释放。
struct FileLock;

impl FileLock {
    fn acquire(file: &File) -> Self {
        // `fs2` 在 Unix 上走 flock(LOCK_EX)、Windows 上走 LockFileEx，
        // 语义与 `core.py` 的 fcntl.flock 降级链一致。
        if let Err(e) = fs2::FileExt::lock_exclusive(file) {
            crate::warn::warn_with_error("acquire file lock", &e);
        }
        Self
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        // 释放在句柄关闭时由内核完成（flock 随 fd 关闭释放），
        // 故此处无需持有 File 引用。
    }
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> CoreResult<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|e| CoreError::io(path, e))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> CoreResult<()> {
    // Windows 无 POSIX 权限位；生产目标是 Linux，此处仅为让测试可跑。
    Ok(())
}

/// 尝试把文件属组改为 `group`；失败仅 warn（`core.py` 同样只忽略异常）。
#[cfg(unix)]
fn chown_group_best_effort(path: &Path, group: &str) {
    let Some(gid) = gid_by_name(group) else {
        crate::warn::warn(&format!("resolve group {group}"));
        return;
    };
    if let Err(e) = std::os::unix::fs::chown(path, Some(u32::MAX), Some(gid)) {
        crate::warn::warn(&format!("chown {} to group {group}: {e}", path.display()));
    }
}

#[cfg(not(unix))]
fn chown_group_best_effort(_path: &Path, _group: &str) {}

/// 通过 NSS 解析组名到 gid（等价 `grp.getgrnam`）。
#[cfg(unix)]
pub fn gid_by_name(name: &str) -> Option<u32> {
    use std::ffi::CString;
    let cname = CString::new(name).ok()?;
    let mut grp: libc::group = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::group = std::ptr::null_mut();
    let mut buf = vec![0 as libc::c_char; 4096];
    let rc = unsafe {
        libc::getgrnam_r(
            cname.as_ptr(),
            &mut grp,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    if rc == 0 && !result.is_null() {
        Some(grp.gr_gid)
    } else {
        None
    }
}

/// 当前进程 uid（`os.getuid()`）；非 Unix 返回 0。
#[cfg(unix)]
pub fn current_uid() -> u32 {
    unsafe { libc::getuid() }
}

#[cfg(not(unix))]
pub fn current_uid() -> u32 {
    0
}

/// 文件快照，用于写入前保存、失败时回滚（`file_snapshot`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSnapshot {
    pub exists: bool,
    pub content: Vec<u8>,
    pub mode: Option<u32>,
}

/// 记录 `path` 的 `{exists, content, mode}`。
pub fn file_snapshot(path: &Path) -> CoreResult<FileSnapshot> {
    if !path.exists() {
        return Ok(FileSnapshot {
            exists: false,
            content: Vec::new(),
            mode: None,
        });
    }
    let content = fs::read(path).map_err(|e| CoreError::io(path, e))?;
    Ok(FileSnapshot {
        exists: true,
        content,
        mode: current_mode(path),
    })
}

/// 恢复快照：原本不存在则 `unlink`，否则写回内容并恢复 mode。
pub fn file_restore(path: &Path, snapshot: &FileSnapshot, mode: Option<u32>) -> CoreResult<()> {
    if !snapshot.exists {
        match fs::remove_file(path) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(CoreError::io(path, e)),
        }
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| CoreError::io(parent, e))?;
    }
    fs::write(path, &snapshot.content).map_err(|e| CoreError::io(path, e))?;
    let effective = mode.or(snapshot.mode).unwrap_or(0o640);
    set_mode(path, effective)
}

#[cfg(unix)]
fn current_mode(path: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path)
        .ok()
        .map(|m| m.permissions().mode() & 0o777)
}

#[cfg(not(unix))]
fn current_mode(_path: &Path) -> Option<u32> {
    None
}

/// 读表文件（`rows`）：跳过空行与 `#` 注释行，按空白分词。
pub fn rows(path: &Path) -> Vec<Vec<String>> {
    let Ok(text) = fs::read_to_string(path) else {
        return Vec::new();
    };
    text.lines()
        .filter(|line| {
            let t = line.trim();
            !t.is_empty() && !t.starts_with('#')
        })
        .map(|line| line.split_whitespace().map(str::to_string).collect())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "mailstack-atomic-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn atomic_writes_content_and_creates_parent_dirs() {
        let dir = temp_dir("write");
        let target = dir.join("nested/deep/secret.json");
        atomic_as(&target, b"{\"a\":1}\n", 0o640, None).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"{\"a\":1}\n");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn atomic_leaves_no_temp_file_behind() {
        let dir = temp_dir("notmp");
        let target = dir.join("f.txt");
        atomic_as(&target, b"hello", 0o600, None).unwrap();
        let leftovers: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "不得残留临时文件: {leftovers:?}");
        fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn atomic_applies_mode_before_rename() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("mode");
        let target = dir.join("secret.json");
        atomic_as(&target, b"topsecret", 0o600, None).unwrap();
        let mode = fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "INV-33: mode 必须在 rename 前生效");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn atomic_overwrites_existing_file() {
        let dir = temp_dir("overwrite");
        let target = dir.join("f.txt");
        atomic_as(&target, b"first", 0o640, None).unwrap();
        atomic_as(&target, b"second", 0o640, None).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"second");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn lock_sidecar_names_never_collide() {
        // INV-31：同名会自死锁，这条断言是安全门禁。
        let p = PathBuf::from("/etc/mailstack/admin.json");
        assert_ne!(atomic_lock_path(&p), locked_lock_path(&p));
        assert_eq!(
            atomic_lock_path(&p),
            PathBuf::from("/etc/mailstack/.admin.json.lock")
        );
        assert_eq!(
            locked_lock_path(&p),
            PathBuf::from("/etc/mailstack/admin.json.lock")
        );
    }

    #[test]
    fn locked_can_nest_atomic_without_deadlock() {
        // 这正是两把锁必须不同名的原因：持 locked 时调用 atomic 是合法用法。
        let dir = temp_dir("nest");
        let target = dir.join("admin.json");
        let result = locked(&target, || {
            atomic_as(&target, b"inner", 0o640, None)?;
            Ok(42)
        });
        assert_eq!(result.unwrap(), 42);
        assert_eq!(fs::read(&target).unwrap(), b"inner");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn locked_propagates_inner_error() {
        let dir = temp_dir("err");
        let target = dir.join("f");
        let result: CoreResult<()> = locked(&target, || Err(CoreError::invalid("boom")));
        assert!(result.is_err());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn file_snapshot_and_restore_round_trip() {
        let dir = temp_dir("snap");
        let target = dir.join("relay.conf");
        fs::write(&target, b"original").unwrap();
        let snap = file_snapshot(&target).unwrap();
        assert!(snap.exists);
        fs::write(&target, b"mutated").unwrap();
        file_restore(&target, &snap, None).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"original");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn file_restore_unlinks_when_originally_absent() {
        let dir = temp_dir("absent");
        let target = dir.join("new.conf");
        let snap = file_snapshot(&target).unwrap();
        assert!(!snap.exists);
        fs::write(&target, b"created").unwrap();
        file_restore(&target, &snap, None).unwrap();
        assert!(!target.exists(), "原本不存在则恢复应删除该文件");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rows_skips_blank_and_comment_lines() {
        let dir = temp_dir("rows");
        let target = dir.join("table");
        fs::write(
            &target,
            b"# comment\n\nexample.com  ok\n  \nfoo.test\tbar\n",
        )
        .unwrap();
        let got = rows(&target);
        assert_eq!(
            got,
            vec![
                vec!["example.com".to_string(), "ok".to_string()],
                vec!["foo.test".to_string(), "bar".to_string()],
            ]
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rows_of_missing_file_is_empty_not_an_error() {
        assert!(rows(Path::new("/nonexistent/mailstack/table")).is_empty());
    }
}
