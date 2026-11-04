use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};

use crate::error::{CoreError, CoreResult};

pub const ADMIN_GROUP: &str = "mailstack-admin";

fn atomic_lock_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    path.with_file_name(format!(".{name}.lock"))
}

fn locked_lock_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    path.with_file_name(format!("{name}.lock"))
}

fn temp_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    path.with_file_name(format!("{name}.tmp.{}.{seq}.{nanos}", std::process::id()))
}

#[cfg(test)]
type TempCreatedHook = Option<Box<dyn Fn(&Path)>>;

#[cfg(test)]
thread_local! {
    static ON_TEMP_CREATED: std::cell::RefCell<TempCreatedHook> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn notify_temp_created(path: &Path) {
    ON_TEMP_CREATED.with(|hook| {
        let borrowed = hook.borrow();
        if let Some(callback) = borrowed.as_ref() {
            callback(path);
        }
    });
}

#[cfg(not(test))]
fn notify_temp_created(_path: &Path) {}

pub fn atomic(path: &Path, data: &[u8], mode: u32) -> CoreResult<()> {
    atomic_as(path, data, mode, Some(ADMIN_GROUP))
}

pub fn atomic_as(path: &Path, data: &[u8], mode: u32, group: Option<&str>) -> CoreResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| CoreError::io(parent, e))?;
    }

    let lock_path = atomic_lock_path(path);
    let _guard = FileLock::acquire(open_lock_sidecar(&lock_path)?, &lock_path)?;

    let tmp = temp_path(path);

    let write_result = (|| -> CoreResult<()> {
        use std::io::Write;

        #[cfg(unix)]
        let mut f = {
            use std::os::unix::fs::OpenOptionsExt;
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(mode)
                .open(&tmp)
                .map_err(|e| CoreError::io(&tmp, e))?
        };
        #[cfg(not(unix))]
        let mut f = {
            let _ = mode;
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)
                .map_err(|e| CoreError::io(&tmp, e))?
        };

        notify_temp_created(&tmp);
        f.write_all(data).map_err(|e| CoreError::io(&tmp, e))?;
        f.flush().map_err(|e| CoreError::io(&tmp, e))?;
        f.sync_all().map_err(|e| CoreError::io(&tmp, e))?;
        Ok(())
    })();
    if let Err(err) = write_result {
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

    if let Some(parent) = path.parent() {
        fsync_dir(parent);
    }
    Ok(())
}

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

pub fn locked<T, F>(path: &Path, f: F) -> CoreResult<T>
where
    F: FnOnce() -> CoreResult<T>,
{
    locked_with(path, f)
}

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

struct FileLock {
    _file: File,
}

impl FileLock {
    fn acquire(file: File, path: &Path) -> CoreResult<Self> {
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
    Ok(())
}

#[cfg(unix)]
fn chown_group_best_effort(path: &Path, group: &str) {
    let Some(gid) = gid_by_name(group) else {
        crate::warn::warn(&format!("resolve group {group}"));
        return;
    };
    if let Err(e) = std::os::unix::fs::chown(path, None, Some(gid)) {
        crate::warn::warn(&format!("chown {} to group {group}: {e}", path.display()));
    }
}

#[cfg(not(unix))]
fn chown_group_best_effort(_path: &Path, _group: &str) {}

#[cfg(unix)]
pub fn gid_by_name(name: &str) -> Option<u32> {
    const MAX_BUFFER: usize = 1024 * 1024;

    use std::ffi::CString;
    let cname = CString::new(name).ok()?;
    let mut size = 4096usize;
    loop {
        let mut grp: libc::group = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::group = std::ptr::null_mut();
        let mut buf = vec![0 as libc::c_char; size];
        let rc = unsafe {
            libc::getgrnam_r(
                cname.as_ptr(),
                &mut grp,
                buf.as_mut_ptr(),
                buf.len(),
                &mut result,
            )
        };
        if rc == 0 {
            return (!result.is_null()).then_some(grp.gr_gid);
        }
        if rc == libc::ERANGE && size < MAX_BUFFER {
            size = (size * 2).min(MAX_BUFFER);
            continue;
        }
        return None;
    }
}

#[cfg(unix)]
pub fn current_uid() -> u32 {
    unsafe { libc::getuid() }
}

#[cfg(not(unix))]
pub fn current_uid() -> u32 {
    0
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSnapshot {
    pub exists: bool,
    pub content: Vec<u8>,
    pub mode: Option<u32>,
}

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

    let effective = mode.or(snapshot.mode).unwrap_or(0o640);
    atomic_as(path, &snapshot.content, effective, None)?;

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

pub fn rows(path: &Path) -> Vec<Vec<String>> {
    try_rows(path).unwrap_or_default()
}

pub fn try_rows(path: &Path) -> CoreResult<Vec<Vec<String>>> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(CoreError::io(path, error)),
    };
    Ok(text
        .lines()
        .filter(|line| {
            let t = line.trim();
            !t.is_empty() && !t.starts_with('#')
        })
        .map(|line| line.split_whitespace().map(str::to_string).collect())
        .collect())
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
            .filter(|n| n.contains(".tmp."))
            .collect();
        assert!(leftovers.is_empty(), "不得残留临时文件: {leftovers:?}");
        fs::remove_dir_all(&dir).ok();
    }

    #[cfg(test)]
    struct TempHookGuard;

    #[cfg(test)]
    impl Drop for TempHookGuard {
        fn drop(&mut self) {
            ON_TEMP_CREATED.with(|hook| *hook.borrow_mut() = None);
        }
    }

    #[cfg(test)]
    fn observe_temp_creation<F: Fn(&Path) + 'static>(callback: F) -> TempHookGuard {
        ON_TEMP_CREATED.with(|hook| *hook.borrow_mut() = Some(Box::new(callback)));
        TempHookGuard
    }

    #[cfg(unix)]
    #[test]
    fn atomic_applies_mode_before_the_first_byte_lands() {
        use std::cell::RefCell;
        use std::os::unix::fs::PermissionsExt;
        use std::rc::Rc;

        let dir = temp_dir("first-byte");
        let target = dir.join("admin.json");
        let observed: Rc<RefCell<Option<u32>>> = Rc::new(RefCell::new(None));
        let sink = Rc::clone(&observed);
        let calls = Rc::new(RefCell::new(0usize));
        let counter = Rc::clone(&calls);

        let _hook = observe_temp_creation(move |tmp: &Path| {
            *counter.borrow_mut() += 1;
            let mode = fs::metadata(tmp)
                .expect("回调触发时临时文件必须已经存在")
                .permissions()
                .mode()
                & 0o777;
            *sink.borrow_mut() = Some(mode);
        });

        atomic_as(&target, b"{\"password\":\"topsecret\"}", 0o600, None).unwrap();

        assert_eq!(*calls.borrow(), 1, "每次写入必须恰好观察到一个临时文件");
        assert_eq!(
            *observed.borrow(),
            Some(0o600),
            "INV-33：mode 必须在首字节落盘之前就是 0600；\
             读到 0644 说明实现退回了「先写后 chmod」"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_failed_rename_leaves_no_temp_file() {
        let dir = temp_dir("failed-rename");
        let target = dir.join("victim");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("blocker"), b"x").unwrap();

        let error =
            atomic_as(&target, b"topsecret", 0o600, None).expect_err("rename 到非空目录不可能成功");
        assert!(matches!(error, CoreError::Io { .. }), "{error:?}");

        let leftovers: Vec<String> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .filter(|name| name.starts_with("victim.tmp."))
            .collect();
        assert!(
            leftovers.is_empty(),
            "失败的写入不得在盘上留一份机密副本: {leftovers:?}"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn temp_paths_are_unique_per_call() {
        let target = PathBuf::from("/etc/mailstack/admin.json");
        let first = temp_path(&target);
        let second = temp_path(&target);

        assert_ne!(first, second, "同一目标的两次写入不得共用临时文件");
        assert_eq!(
            first.parent(),
            target.parent(),
            "临时文件必须与目标同目录 —— 跨文件系统的 rename 不是原子操作"
        );
        let name = first.file_name().unwrap().to_string_lossy().to_string();
        assert!(
            name.starts_with("admin.json.tmp."),
            "临时文件名应带目标名与唯一后缀，实际 {name}"
        );
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

    #[cfg(unix)]
    #[test]
    fn group_resolution_finds_existing_groups_and_reports_missing_ones() {
        assert!(gid_by_name("root").is_some(), "root 组必须能解析");
        assert!(
            gid_by_name("mailstack-definitely-missing-group").is_none(),
            "不存在的组必须返回 None"
        );
    }
}
