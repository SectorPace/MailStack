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

/// 临时文件路径：同目录下 `<name>.tmp.<pid>.<seq>.<nanos>`。
///
/// ## 为什么带唯一后缀
///
/// 原实现是固定 `<name>.tmp`，有三个问题：
///
/// 1. **固定名会交错**：两个无锁写者（`locked()` 的降级路径）各自打开同一个
///    `<name>.tmp`，写的内容互相覆盖，最终 `rename` 出去的是**半写文件**。
/// 2. **跟随符号链接**：`File::create` 是 `O_CREAT|O_TRUNC`，**不**拒绝已存在的
///    符号链接。能在目标目录写文件的人可以预置一个指向自选路径的 `.tmp`，
///    于是密钥内容被引到那里（本地提权跳板）。
/// 3. **失败无清理**：`rename` 出错时 `.tmp` 就留在盘上，长期留一份机密副本。
///
/// 唯一后缀让「(2) 预置符号链接」不再可能（`create_new` 要求不存在），
/// 同时让「(1) 交错」的两个写者落在不同文件上。仍固定同目录，rename 才是
/// 同文件系统内的原子操作。
fn temp_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    // 进程内自增计数：同一进程内多次写同一目标也不会撞名
    // （时间戳在快速连续写入下可能相同）。
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    path.with_file_name(format!("{name}.tmp.{}.{seq}.{nanos}", std::process::id()))
}

/// 原子写入 `data` 到 `path`，权限 `mode` 在 **首字节落盘之前**就已确定（INV-33）。
///
/// 步骤与 `core.py:621-662` 逐条对应：
/// 1. `mkdir -p` 目标目录
/// 2. 在 sidecar `.<name>.lock` 上取排他锁
/// 3. 以 `O_CREAT|O_EXCL` + `mode(mode)` 创建**唯一**临时文件（权限此刻即生效）
/// 4. 写 → `flush` → `fsync`
/// 5. `chown(tmp, -1, mailstack-admin)`（尽力而为，失败仅 warn）
/// 6. `rename(tmp, path)`，随后 **fsync 父目录**
///
/// ## 为什么第 3 步就用 `mode`
///
/// 基线与本模块文档原本都写「`chmod` 在 rename 之前」—— 那只保证了 rename 时
/// 权限已收紧，却**没有覆盖真正的风险窗口**：临时文件从 `create` 到 `chmod`
/// 之间已经写入了完整机密，而这段时间它的权限是 `0666 & ~umask`（root ⇒ 0644）。
/// 用 inotify 守着目录即可稳定命中。真正要的是「首字节落盘之前就是 0600」。
pub fn atomic(path: &Path, data: &[u8], mode: u32) -> CoreResult<()> {
    atomic_as(path, data, mode, Some(ADMIN_GROUP))
}

/// 可指定目标组的 [`atomic`]，`group = None` 表示跳过 chown（测试用）。
pub fn atomic_as(path: &Path, data: &[u8], mode: u32, group: Option<&str>) -> CoreResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| CoreError::io(parent, e))?;
    }

    let lock_path = atomic_lock_path(path);
    let _guard = FileLock::acquire(open_lock_sidecar(&lock_path)?, &lock_path)?;

    let tmp = temp_path(path);
    // `OpenOptions` 而不是 `File::create`：三处差别都指向同一个不变量（INV-33）。
    //
    // * `mode(mode)` —— **在 create(2) 那一刻**就把权限定死。原实现用
    //   `File::create`（`0666 & ~umask`，root 常见 umask 022 ⇒ **0644**）写完
    //   完整内容、fsync 之后才 `set_mode`。于是 `admin.json`（口令哈希）、
    //   `totp.key`（AES 主密钥）、`tls/<domain>/privkey.pem`（TLS 私钥）、
    //   `ai-provider.json`（API Key）在「写完 → chmod」这段窗口里是
    //   **0644 明文**，目录 0755 可列、文件名可预测 ⇒ 用 inotify 守着目录就能
    //   稳定命中。这与本函数文档第 4 步写的「secret 不得以进程 umask 落盘」
    //   **直接相反**：文档承诺 chmod 在 rename 之前，但真正的风险窗口是
    //   「首字节落盘之前」，比 rename 早得多。
    // * `create_new(true)` —— `O_EXCL`，已存在（含符号链接）即失败。不加它，
    //   能在目标目录写文件的人可预置一个指向自选路径的同名临时文件，
    //   把密钥内容引过去（本地提权跳板）。
    // * 失败路径显式删除临时文件 —— 否则一次 rename 失败就在盘上留一份
    //   长期存在的机密副本。
    let write_result = (|| -> CoreResult<()> {
        use std::io::Write;
        // `.mode(..)` 是 `OpenOptionsExt`（Unix）的方法。生产目标是 Linux，
        // 与 `backup.rs` 里 `open_no_follow` 的做法一致；Windows 上没有「创建时
        // 指定权限」这回事，故只在 Unix 上挂载。
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt;

        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp)
            .map_err(|e| CoreError::io(&tmp, e))?;
        f.write_all(data).map_err(|e| CoreError::io(&tmp, e))?;
        f.flush().map_err(|e| CoreError::io(&tmp, e))?;
        f.sync_all().map_err(|e| CoreError::io(&tmp, e))?;
        Ok(())
    })();
    if let Err(err) = write_result {
        // 尽力清理：失败不是关键路径，不能让它掩盖真正的错误。
        let _ = fs::remove_file(&tmp);
        return Err(err);
    }

    if let Some(group) = group {
        chown_group_best_effort(&tmp, group);
    }

    if let Err(err) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(CoreError::io(path, err));
    }
    // `rename` 只保证「同一次挂起内可见」，**不保证已落盘**：掉电时目录项可能
    // 尚未写回。fsync 父目录才把这次重命名固化，否则「断电不丢件」只在
    // 不掉电时成立。
    if let Some(parent) = path.parent() {
        fsync_dir(parent);
    }
    Ok(())
}

/// fsync 目录本身（`rename` 落盘的持久化保证）。
///
/// 失败只 warn：某些文件系统（如某些网络/FUSE 挂载）不支持目录 fsync，
/// 那时它也不支持掉电持久化，不该让写入整体失败。
fn fsync_dir(dir: &Path) {
    match File::open(dir) {
        Ok(handle) => {
            if let Err(err) = handle.sync_all() {
                crate::warn::warn(&format!("fsync {}: {err}", dir.display()));
            }
        }
        Err(err) => crate::warn::warn(&format!("open dir {}: {err}", dir.display())),
    }
}

/// 在整个 read-modify-write 临界区持排他锁（`core.py:664-724`）。
///
/// 锁 sidecar 为 `<name>.lock`，与 [`atomic`] 的 `.<name>.lock` 不同名。
/// POSIX 使用 `flock`，Windows 使用字节锁；无法打开或取得锁时返回错误，不进入临界区。
pub fn locked<T, F>(path: &Path, f: F) -> CoreResult<T>
where
    F: FnOnce() -> CoreResult<T>,
{
    locked_with(path, f)
}

/// 在整个读改写临界区持锁，并把锁错误转换为调用方的错误类型。
pub fn locked_with<T, E, F>(path: &Path, f: F) -> Result<T, E>
where
    E: From<CoreError>,
    F: FnOnce() -> Result<T, E>,
{
    let lock_path = locked_lock_path(path);
    if let Some(parent) = lock_path.parent() {
        fs::create_dir_all(parent).map_err(|e| CoreError::io(parent, e))?;
    }

    let _guard = FileLock::acquire(open_lock_sidecar(&lock_path)?, &lock_path)?;

    f()
}

fn open_lock_sidecar(path: &Path) -> CoreResult<File> {
    OpenOptions::new()
        .create(true)
        .read(true)
        .append(true)
        .open(path)
        .map_err(|e| CoreError::io(path, e))
}

/// RAII 排他锁；句柄由 guard 持有，析构时关闭并释放内核锁。
struct FileLock {
    _file: File,
}

impl FileLock {
    fn acquire(file: File, path: &Path) -> CoreResult<Self> {
        // `fs2` 在 Unix 上走 flock(LOCK_EX)、Windows 上走 LockFileEx，
        // 语义与 `core.py` 的 fcntl.flock 降级链一致。
        fs2::FileExt::lock_exclusive(&file).map_err(|e| CoreError::io(path, e))?;
        Ok(Self { _file: file })
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
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(FileSnapshot {
                exists: false,
                content: Vec::new(),
                mode: None,
            });
        }
        Err(e) => return Err(CoreError::io(path, e)),
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
    fn locked_fails_closed_when_the_sidecar_cannot_be_opened() {
        let dir = temp_dir("lock-open-error");
        let target = dir.join("state");
        fs::create_dir(locked_lock_path(&target)).unwrap();
        let called = std::sync::atomic::AtomicBool::new(false);

        let result = locked(&target, || {
            called.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        });

        assert!(result.is_err(), "锁 sidecar 不能打开时必须拒绝操作");
        assert!(!called.load(std::sync::atomic::Ordering::SeqCst));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn atomic_fails_closed_when_the_sidecar_cannot_be_opened() {
        let dir = temp_dir("atomic-lock-open-error");
        let target = dir.join("secret");
        fs::create_dir(atomic_lock_path(&target)).unwrap();

        assert!(atomic_as(&target, b"secret", 0o600, None).is_err());
        assert!(!target.exists(), "无法取得锁时不能写入目标文件");
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
    fn file_snapshot_reports_metadata_errors_instead_of_treating_them_as_missing() {
        let dir = temp_dir("snapshot-metadata-error");
        let parent_file = dir.join("not-a-directory");
        fs::write(&parent_file, b"file").unwrap();
        let target = parent_file.join("state.json");

        let result = file_snapshot(&target);

        assert!(matches!(result, Err(CoreError::Io { .. })));
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
