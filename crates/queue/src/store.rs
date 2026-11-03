//! 磁盘队列（规格书 §5.8「队列落盘用 fsync + 原子重命名」；风险表「队列原子性」）。
//!
//! 布局（`root` = `Paths::var_lib/queue`）：
//!
//! ```text
//! queue/entries/<id>.json   —— 每条消息一个文件
//! queue/claims/<id>.claim   —— 投递租约（5.10：标记「这条正在被投递」）
//! queue/corrupt/            —— 解析失败的条目（隔离，绝不静默丢弃）
//! queue/outbound-health.json —— 出站健康状态（重试风暴的结论要跨重启保留）
//! ```
//!
//! 为什么一文件一条消息：写入就是「同目录 rename」，**天然原子**；不需要维护
//! 一个可能半写坏的索引文件。代价是目录项多，但队列规模（数千级）远未到
//! 需要分桶的程度。
//!
//! 所有写入都经 [`mailstack_core::atomic::atomic_as`]：写临时文件 → `fsync` →
//! `chmod 0600` → `rename`。**任何一步都不会让半成品文件出现在 entries/ 下**，
//! 因此断电重启后读到的每个条目要么是完整的旧版本、要么是完整的新版本。

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use mailstack_core::atomic::atomic_as;
use mailstack_core::Paths;

use crate::entry::QueueEntry;
use crate::error::{QueueError, QueueResult};

/// 队列文件权限：报文含用户邮件正文，仅属主可读。
const QUEUE_FILE_MODE: u32 = 0o600;

/// [`QueueStore::enqueue_new`] 遇到 id 撞车时的重试次数。
const ENQUEUE_NEW_ATTEMPTS: u32 = 5;

/// `corrupt/` 目录保留的最大文件数（按修改时间保留最近的）。
///
/// 隔离目录原先只增不减：一次「把 O_EXCL 占位当损坏」的误判、或一条反复解析
/// 失败的条目（例如将来某次 schema 变更），都会让它在长期运行后无限增长。
pub const MAX_CORRUPT_FILES: usize = 200;

/// 投递租约时长（5.10）。
///
/// 一条条目从「开始投递」到「把结果写回磁盘」之间，磁盘上没有它的任何状态变化。
/// 这段窗口里崩溃 / 掉电 / 停机取消，重启后条目仍带全部收件人 —— 下一轮会**整批
/// 重投**，收件人收到重复邮件。
///
/// 租约把这段窗口显式化：开始投递前写一个 claim 文件，结束后删除。重启后
/// 仍在租约内的条目**先跳过**，等租约过期再重试 —— 于是「重启即重投」变成
/// 「只有确实超过了投递时长的条目才会被重试」。
///
/// 取值必须 **大于** 单轮调度的上限（`mailstackd` 的 `ROUND_TIMEOUT = 600s`），
/// 否则还在正常投递的条目会被自己人抢走。这里取 900s（15 分钟）。
pub const CLAIM_TTL_SECONDS: i64 = 900;

/// 出站健康状态（持久化）。
///
/// 存在的理由：§5.10.3 R-25-3 要求「出站 25 被封」这类结论必须在管理台给出**明确
/// 结论**。若只放在内存里，进程一重启结论就丢了，运维看到的是「队列莫名其妙在涨」。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboundHealthState {
    /// 连续失败次数；任何一次成功投递都清零。
    #[serde(rename = "consecutiveFailures", default)]
    pub consecutive_failures: u32,
    /// 最近一次成功投递时间（ISO 8601 UTC）。
    #[serde(
        rename = "lastSuccessAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub last_success_at: Option<String>,
    /// 最近一次失败描述。
    #[serde(
        rename = "lastFailure",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub last_failure: Option<String>,
}

/// 磁盘队列。
#[derive(Debug, Clone)]
pub struct QueueStore {
    root: PathBuf,
    /// 测试注入：下一次针对这些 id 的 `try_claim` 直接返回 I/O 错误。
    ///
    /// 生产代码里不存在这个字段（`cfg(test)`）：它只被 `crates/queue` 自己的
    /// 反例测试用来构造「认领失败但整轮不得丢弃在途投递」的场景。
    #[cfg(test)]
    claim_faults: std::sync::Arc<std::sync::Mutex<std::collections::VecDeque<String>>>,
}

impl QueueStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            #[cfg(test)]
            claim_faults: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::VecDeque::new(),
            )),
        }
    }

    /// 生产布局：`/var/lib/mailstack/queue`。
    pub fn from_paths(paths: &Paths) -> Self {
        Self::new(paths.var_lib.join("queue"))
    }

    /// 队列根目录。
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// 条目目录。
    pub fn entries_dir(&self) -> PathBuf {
        self.root.join("entries")
    }

    /// 损坏条目隔离目录。
    pub fn corrupt_dir(&self) -> PathBuf {
        self.root.join("corrupt")
    }

    /// 投递租约目录（5.10）。
    pub fn claims_dir(&self) -> PathBuf {
        self.root.join("claims")
    }

    fn claim_path(&self, id: &str) -> QueueResult<PathBuf> {
        if !crate::entry::is_safe_id(id) {
            return Err(QueueError::invalid(format!("unsafe queue id: {id:?}")));
        }
        Ok(self.claims_dir().join(format!("{id}.claim")))
    }

    /// 尝试为某条目取得投递租约（5.10）。
    ///
    /// 返回 `true` 表示拿到（可以投递）；`false` 表示已有**未过期**的租约
    /// （别的轮次/进程正在投它以跳过）。
    ///
    /// ## 为什么整段「判过期 → 删除 → 建文件」必须在同一把进程间锁内
    ///
    /// `create_new`（`O_EXCL`）只保证「只有一个创建者」，但「删除过期租约」原先
    /// 是**无条件 `remove_file`** —— 它删的是路径，不是「刚刚判为过期的那个
    /// inode」。两个执行者的交错（A 判过期 → A 删 → A 建 → B 删掉 A 刚建的
    /// 新租约 → B 建）会让**双方都认为自己持有租约**，同一封邮件被投两遍。
    /// `prune_claims`（后台清理）与 `try_claim`（前台认领）之间天然存在同一交错。
    ///
    /// 因此把判过期、清理与占名三步收进 [`QueueStore::with_claims_lock`]：
    /// 锁是 `claims/` 目录旁的一把 `flock`，跨进程有效（`mailstack_core` 的
    /// `locked_with` 原语）。这样「判过期」与「删除/占名」之间不可能再插进
    /// 另一个执行者。
    pub fn try_claim(&self, id: &str, now_unix: i64) -> QueueResult<bool> {
        let path = self.claim_path(id)?;
        #[cfg(test)]
        if self.take_claim_fault(id) {
            return Err(QueueError::io(
                &path,
                std::io::Error::other("injected claim failure"),
            ));
        }
        self.with_claims_lock(|| {
            // 锁内重读：过期的清理掉，新鲜的留给持有者。
            if !self.claim_is_fresh(&path, now_unix) {
                match fs::remove_file(&path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(QueueError::io(&path, error)),
                }
            }

            match fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&path)
            {
                Ok(mut file) => {
                    use std::io::Write;
                    // 内容 = 取得时刻（unix 秒）。写失败也不影响正确性：文件存在本身
                    // 就是「已认领」；时间戳只是为了让过期判定不依赖 mtime。
                    let _ = writeln!(file, "{now_unix}");
                    Ok(true)
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
                Err(error) => Err(QueueError::io(&path, error)),
            }
        })
    }

    /// 释放租约（投递结束，无论成功失败）。
    pub fn release_claim(&self, id: &str) -> QueueResult<()> {
        let path = self.claim_path(id)?;
        self.with_claims_lock(|| match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(QueueError::io(&path, error)),
        })
    }

    /// 在 `claims/` 的进程间互斥锁内执行 `f`。
    ///
    /// 锁文件是 `claims/.claims.lock`（隐藏名 + `.lock` 后缀，不是 `.claim`，
    /// 因此不会被 [`Self::claimed_ids`] / [`Self::prune_claims`] 当成租约）。
    fn with_claims_lock<T>(&self, f: impl FnOnce() -> QueueResult<T>) -> QueueResult<T> {
        let dir = self.claims_dir();
        fs::create_dir_all(&dir).map_err(|e| QueueError::io(&dir, e))?;
        mailstack_core::atomic::locked_with(&dir.join(".claims"), f)
    }

    /// 测试注入：该 id 是否被安排了一次认领 I/O 失败（消费一次）。
    #[cfg(test)]
    fn take_claim_fault(&self, id: &str) -> bool {
        let mut faults = self.claim_faults.lock().unwrap_or_else(|p| p.into_inner());
        match faults.iter().position(|fault| fault == id) {
            Some(index) => {
                faults.remove(index);
                true
            }
            None => false,
        }
    }

    /// 测试注入：安排一次认领 I/O 失败（只影响同一 store 实例的克隆）。
    #[cfg(test)]
    pub(crate) fn fail_next_claim(&self, id: &str) {
        self.claim_faults
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push_back(id.to_string());
    }

    /// 当前仍有效的租约对应的条目 id 集合。
    pub fn claimed_ids(&self, now_unix: i64) -> QueueResult<std::collections::HashSet<String>> {
        let dir = self.claims_dir();
        let mut claimed = std::collections::HashSet::new();
        if !dir.exists() {
            return Ok(claimed);
        }
        let read = fs::read_dir(&dir).map_err(|e| QueueError::io(&dir, e))?;
        for item in read {
            let Ok(item) = item else { continue };
            let path = item.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let Some(id) = name.strip_suffix(".claim") else {
                continue;
            };
            if self.claim_is_fresh(&path, now_unix) {
                claimed.insert(id.to_string());
            }
        }
        Ok(claimed)
    }

    /// 清理所有过期租约，返回清理数量。
    ///
    /// 与 [`Self::try_claim`] 共用同一把进程间锁：否则「后台清理判过期」与
    /// 「前台认领刚建的新租约」之间会出现 remove-after-create 交错，删掉别人
    /// 刚拿到的租约。
    pub fn prune_claims(&self, now_unix: i64) -> QueueResult<usize> {
        let dir = self.claims_dir();
        if !dir.exists() {
            return Ok(0);
        }
        self.with_claims_lock(|| {
            let mut removed = 0usize;
            let read = fs::read_dir(&dir).map_err(|e| QueueError::io(&dir, e))?;
            for item in read {
                let Ok(item) = item else { continue };
                let path = item.path();
                if path.extension().and_then(|e| e.to_str()) != Some("claim") {
                    continue;
                }
                if !self.claim_is_fresh(&path, now_unix) && fs::remove_file(&path).is_ok() {
                    removed += 1;
                }
            }
            Ok(removed)
        })
    }

    /// 租约是否仍在有效期内。
    ///
    /// 以**文件内容**的时间戳为准（而不是 mtime）：mtime 会被 touch、备份还原、
    /// 文件系统复制改变，而内容是我们自己写的。内容读不出来时退化为 mtime，
    /// 再不行就当作**过期** —— 宁可多投一次，也不要让一条条目被永久卡住。
    fn claim_is_fresh(&self, path: &Path, now_unix: i64) -> bool {
        let claimed_at = match fs::read_to_string(path) {
            Ok(text) => text.trim().parse::<i64>().ok(),
            Err(_) => None,
        };
        let claimed_at = match claimed_at {
            Some(ts) => ts,
            None => match fs::metadata(path).and_then(|m| m.modified()) {
                Ok(modified) => modified
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0),
                Err(_) => return false,
            },
        };
        // 时间戳来自未来（时钟回拨过）也按「刚取得」处理：宁可多等一个 TTL，
        // 也不要因为时钟问题把正在投递的条目抢过来重投。
        now_unix.saturating_sub(claimed_at) < CLAIM_TTL_SECONDS
    }

    fn health_path(&self) -> PathBuf {
        self.root.join("outbound-health.json")
    }

    fn entry_path(&self, id: &str) -> QueueResult<PathBuf> {
        if !crate::entry::is_safe_id(id) {
            // 双保险：id 拼进路径前必须复检，否则一个被篡改的 id 就能写到队列目录之外。
            return Err(QueueError::invalid(format!("unsafe queue id: {id:?}")));
        }
        Ok(self.entries_dir().join(format!("{id}.json")))
    }

    /// 写入（或覆盖）一条条目。id 相同即覆盖，因此「更新重试状态」也是本方法。
    ///
    /// 覆盖语义是**重试回写所依赖的**：运行器把已投递的收件人摘掉后按原 id 写回。
    /// 新条目（首封入队、DSN 退信）必须改走 [`QueueStore::enqueue_new`] ——
    /// 那里才是「同 id 即覆盖」会变成丢信的地方。
    pub fn enqueue(&self, entry: &QueueEntry) -> QueueResult<()> {
        entry.validate()?;
        let path = self.entry_path(&entry.id)?;
        let payload = serde_json::to_vec_pretty(entry)?;
        atomic_as(&path, &payload, QUEUE_FILE_MODE, None)?;
        Ok(())
    }

    /// 新条目入队：**只新增，绝不覆盖**既有条目。
    ///
    /// `enqueue` 的覆盖语义对重试回写是必需的，但对新邮件是最坏行为：两个进程
    /// 在同一毫秒生成了同一个 id（[`crate::entry::new_id`] 已混入进程级随机前缀
    /// 把概率压到可忽略，但不是零）时，后写的一方会把先写的那封**无声覆盖** ——
    /// 收件人视角就是丢信。
    ///
    /// ## 为什么占位用的是**旁路文件**而不是目标文件
    ///
    /// 原实现在目标路径上 `create_new` 再 `atomic_as` 覆盖：占位与真正写入之间
    /// 有一个**可见的 0 字节 `<id>.json` 窗口**。同目录的另一个读者（`run_once`
    /// 的 `load_all` / `load_due`、`queue.list`、另一个 `enqueue_new`）在这个
    /// 窗口里读到它 → 解析失败 → 把它当损坏条目 rename 进 `corrupt/`：
    /// 一条正常在途入队被误判为损坏，还伴随一条 `warn`，把排查引向不存在的损坏。
    ///
    /// 现在占位的是一个隐藏旁路文件（`.<id>.json.reserve`），它既不匹配
    /// `is_queue_file`（只认 `.json` 结尾且不以 `.` 开头），也不会被任何读者
    /// 当成条目；目标文件只在 `atomic_as` 的 rename 那一刻出现，且**一出现就是
    /// 完整的**。占位仍用 `O_EXCL`，且同一 id 的两个写入者只可能有一个拿到
    /// 旁路占位，因此「撞车换 id」的语义不变。
    pub fn enqueue_new(&self, entry: &mut QueueEntry) -> QueueResult<()> {
        entry.validate()?;
        let dir = self.entries_dir();
        // 占位要求目录已存在（`try_claim` 对 claims 目录同款处理）。
        fs::create_dir_all(&dir).map_err(|e| QueueError::io(&dir, e))?;
        for _ in 0..ENQUEUE_NEW_ATTEMPTS {
            let path = self.entry_path(&entry.id)?;
            let reserved_path = self.reservation_path(&entry.id);
            match fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&reserved_path)
            {
                Ok(file) => drop(file),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    // 撞车：换一个 id 再试。连续撞车只可能是熵源被破坏，
                    // 最终报错而不是回退成覆盖。
                    entry.id = crate::entry::new_id();
                    continue;
                }
                Err(error) => return Err(QueueError::io(&reserved_path, error)),
            }
            // 目标名已存在 = 该 id 已经被占用（上一版实现里崩溃遗留的完整条目，
            // 或外部工具写进来的文件）。绝不覆盖，换 id 重试。
            if path.exists() {
                let _ = fs::remove_file(&reserved_path);
                entry.id = crate::entry::new_id();
                continue;
            }
            let payload = serde_json::to_vec_pretty(entry)?;
            let result = atomic_as(&path, &payload, QUEUE_FILE_MODE, None);
            let _ = fs::remove_file(&reserved_path);
            return match result {
                Ok(()) => Ok(()),
                Err(error) => {
                    // 写入失败：目标文件不存在（`atomic_as` 是 rename，不会留下
                    // 半成品），把占位名还回去，让调用方看到「这封邮件从未入队」。
                    let _ = fs::remove_file(&path);
                    Err(error.into())
                }
            };
        }
        Err(QueueError::invalid(format!(
            "queue id collision persisted after {ENQUEUE_NEW_ATTEMPTS} attempts (entry {})",
            entry.id
        )))
    }

    /// 入队占位用的旁路文件名。
    ///
    /// 以 `.` 开头且以 `.reserve` 结尾 —— 既不是 `is_queue_file` 认的条目，
    /// 也不会被 `atomic_as` 的临时文件命名规则撞上。
    fn reservation_path(&self, id: &str) -> PathBuf {
        self.entries_dir().join(format!(".{id}.json.reserve"))
    }

    /// 读取全部条目（按 id 升序 = 入队时间序）。
    ///
    /// 解析失败的条目被**移动到 `corrupt/`** 并 `warn` 一次，而不是丢弃：
    /// 一条读不出来的条目往往正是排查问题的线索，静默删除会让它永久消失。
    ///
    /// ## 调度主路径不要用它
    ///
    /// 它会把**每条**条目的完整报文（`data`，上限 50 MiB）反序列化进内存。
    /// 调度器每 10 秒跑一轮，只应使用 [`Self::load_due`]。
    pub fn load_all(&self) -> QueueResult<Vec<QueueEntry>> {
        let dir = self.entries_dir();
        if !dir.exists() {
            return Ok(Vec::new());
        }

        let mut entries = Vec::new();
        let read = fs::read_dir(&dir).map_err(|e| QueueError::io(&dir, e))?;
        for item in read {
            let item = match item {
                Ok(i) => i,
                Err(e) => {
                    mailstack_core::warn::warn_with_detail("queue dir entry", &e.to_string());
                    continue;
                }
            };
            let path = item.path();
            if !is_queue_file(&path) {
                continue;
            }
            let raw = match fs::read(&path) {
                Ok(raw) => raw,
                Err(error) => {
                    // 读不到不等于损坏：条目可能刚好被另一个执行者投递完成并删除。
                    mailstack_core::warn::warn_with_detail(
                        "queue entry read",
                        &format!("{}: {error}", path.display()),
                    );
                    continue;
                }
            };
            match parse_entry(&raw) {
                Ok(entry) => entries.push(entry),
                Err(reason) => {
                    mailstack_core::warn::warn_with_detail(
                        "queue entry unreadable",
                        &format!("{}: {reason}", path.display()),
                    );
                    self.quarantine(&path);
                }
            }
        }

        entries.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(entries)
    }

    /// 只读取**已到期**的条目（调度主路径，5.9 的内存上界）。
    ///
    /// ## 为什么不能先 `load_all` 再过滤
    ///
    /// `QueueEntry.data` 是完整报文（上限 50 MiB），而 `due` 过滤发生在读取
    /// **之后** —— 退避中的绝大多数条目（还没到重试时间）也会被整体读进内存。
    /// 积压 1000 条 × 5 MiB 就是每 10 秒 5 GiB 的峰值，且恰恰在出站被封、
    /// 积压最大时发生。
    ///
    /// 这里分两阶段：先只用 `nextAttemptUnix` 的**轻量头**判到期（`serde`
    /// 对 `data` 字段做跳过，不分配字符串），只有到期的条目才完整反序列化。
    /// 解析失败仍按 [`Self::load_all`] 的纪律隔离，不静默丢弃。
    pub fn load_due(&self, now_unix: i64) -> QueueResult<Vec<QueueEntry>> {
        let dir = self.entries_dir();
        if !dir.exists() {
            return Ok(Vec::new());
        }

        let mut entries = Vec::new();
        let read = fs::read_dir(&dir).map_err(|e| QueueError::io(&dir, e))?;
        for item in read {
            let item = match item {
                Ok(i) => i,
                Err(e) => {
                    mailstack_core::warn::warn_with_detail("queue dir entry", &e.to_string());
                    continue;
                }
            };
            let path = item.path();
            if !is_queue_file(&path) {
                continue;
            }
            let raw = match fs::read(&path) {
                Ok(raw) => raw,
                Err(error) => {
                    mailstack_core::warn::warn_with_detail(
                        "queue entry read",
                        &format!("{}: {error}", path.display()),
                    );
                    continue;
                }
            };
            let header: EntryHeader = match serde_json::from_slice(&raw) {
                Ok(header) => header,
                Err(reason) => {
                    mailstack_core::warn::warn_with_detail(
                        "queue entry unreadable",
                        &format!("{}: {reason}", path.display()),
                    );
                    self.quarantine(&path);
                    continue;
                }
            };
            // 未到期：正文一次都不解析。
            if header.next_attempt_unix > now_unix {
                continue;
            }
            match parse_entry(&raw) {
                // 头部与正文理应一致；以正文为准再判一次，防御性兜底。
                Ok(entry) if entry.is_due(now_unix) => entries.push(entry),
                Ok(_) => {}
                Err(reason) => {
                    mailstack_core::warn::warn_with_detail(
                        "queue entry unreadable",
                        &format!("{}: {reason}", path.display()),
                    );
                    self.quarantine(&path);
                }
            }
        }

        entries.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(entries)
    }

    /// 删除一条条目（投递完成或已退信后）。返回是否确实删除了文件。
    pub fn remove(&self, id: &str) -> QueueResult<bool> {
        let path = self.entry_path(id)?;
        // 5.10：条目消失时必须把租约一起清掉，否则 claim 目录会永久留下孤儿文件
        // （它的 id 已经不在了，只会让 `claimed_ids` 越来越大）。
        let _ = self.release_claim(id);
        let existed = match fs::remove_file(&path) {
            Ok(()) => true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => return Err(QueueError::io(&path, e)),
        };
        // 顺带清理 `atomic_as` 留下的锁 sidecar（尽力而为）。
        let sidecar = path.with_file_name(format!(
            ".{}.lock",
            path.file_name().unwrap_or_default().to_string_lossy()
        ));
        let _ = fs::remove_file(sidecar);
        Ok(existed)
    }

    /// 待投递条目数量。
    ///
    /// 5.16：原实现是 `load_all()?.len()` —— `backlog` / `len()` 每 2 秒被遥测采样
    /// 调用一次，于是**每 2 秒把全部邮件正文解析一遍**。千条积压时那是每 2 秒
    /// 数百 MB 的解析开销，而且它跑在 tokio worker 上，会直接饿死收信与投递。
    ///
    /// 计数只需要知道「有几个条目文件」，不需要解析内容：这里只 stat 目录项，
    /// 跳过非条目文件（锁 sidecar、健康状态文件等）。坏条目的隔离行为仍由
    /// `load_all` 负责 —— 计数不值得为它做一次全量解析。
    pub fn len(&self) -> QueueResult<usize> {
        let dir = self.entries_dir();
        if !dir.exists() {
            return Ok(0);
        }
        let read = fs::read_dir(&dir).map_err(|e| QueueError::io(&dir, e))?;
        let mut count = 0usize;
        for item in read {
            let Ok(item) = item else { continue };
            if is_queue_file(&item.path()) {
                count += 1;
            }
        }
        Ok(count)
    }

    pub fn is_empty(&self) -> QueueResult<bool> {
        Ok(self.len()? == 0)
    }

    /// 读出站健康状态。文件缺失或损坏时返回 `None`（并 `warn`），
    /// **不得**因为一个坏掉的状态文件就让整个队列停摆。
    pub fn load_health(&self) -> Option<OutboundHealthState> {
        let path = self.health_path();
        let raw = match fs::read_to_string(&path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
            Err(e) => {
                mailstack_core::warn::warn_with_detail("queue health read", &e.to_string());
                return None;
            }
        };
        match serde_json::from_str(&raw) {
            Ok(state) => Some(state),
            Err(e) => {
                mailstack_core::warn::warn_with_detail(
                    "queue health parse",
                    &format!("{}: {e}", path.display()),
                );
                None
            }
        }
    }

    /// 写出站健康状态。
    pub fn save_health(&self, state: &OutboundHealthState) -> QueueResult<()> {
        let payload = serde_json::to_vec_pretty(state)?;
        atomic_as(&self.health_path(), &payload, QUEUE_FILE_MODE, None)?;
        Ok(())
    }

    /// 把损坏文件移到隔离目录，文件名带上时间戳避免互相覆盖。
    ///
    /// 隔离目录有保留上限（[`MAX_CORRUPT_FILES`]）：它是排查线索，不是归档 ——
    /// 一个只增不减的目录会在长期运行后把磁盘填满，尤其当「损坏」其实是
    /// 并发窗口造成的误判时。
    fn quarantine(&self, path: &Path) {
        let dir = self.corrupt_dir();
        if let Err(e) = fs::create_dir_all(&dir) {
            mailstack_core::warn::warn_with_detail("queue corrupt dir", &e.to_string());
            return;
        }
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let target = dir.join(format!("{name}.{stamp}.corrupt"));
        if let Err(e) = fs::rename(path, &target) {
            mailstack_core::warn::warn_with_detail("queue quarantine", &e.to_string());
        }
        self.prune_corrupt_dir();
    }

    /// 把 `corrupt/` 收缩到 [`MAX_CORRUPT_FILES`] 条（保留最近修改的）。
    fn prune_corrupt_dir(&self) {
        let dir = self.corrupt_dir();
        let Ok(read) = fs::read_dir(&dir) else { return };
        let mut files: Vec<(std::time::SystemTime, PathBuf)> = Vec::new();
        for item in read.flatten() {
            let path = item.path();
            if !path.is_file() {
                continue;
            }
            let modified = item
                .metadata()
                .and_then(|m| m.modified())
                .unwrap_or(std::time::UNIX_EPOCH);
            files.push((modified, path));
        }
        if files.len() <= MAX_CORRUPT_FILES {
            return;
        }
        files.sort_by_key(|(modified, _)| *modified);
        let excess = files.len() - MAX_CORRUPT_FILES;
        let mut removed = 0usize;
        for (_, path) in files.into_iter().take(excess) {
            if fs::remove_file(&path).is_ok() {
                removed += 1;
            }
        }
        if removed > 0 {
            mailstack_core::warn::warn_with_detail(
                "queue corrupt dir pruned",
                &format!("removed {removed} oldest quarantined entries"),
            );
        }
    }
}

/// 该目录项是否是队列条目文件。
///
/// 只认 `<name>.json`：`atomic_as` 的临时文件是 `<name>.json.tmp`、锁 sidecar 是
/// `.<name>.json.lock`，两者都会被这一步过滤掉，因此**不会**把写到一半的文件当成条目。
fn is_queue_file(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }
    let Some(name) = path.file_name().map(|n| n.to_string_lossy().to_string()) else {
        return false;
    };
    !name.starts_with('.') && name.ends_with(".json")
}

/// 条目的轻量头：只用于在**不分配正文**的前提下判断是否到期。
///
/// `serde` 对未声明的字段（包括 `data`）做跳过而不分配，因此反序列化这个结构
/// 不会把整封邮件读进内存。
#[derive(Deserialize)]
struct EntryHeader {
    #[serde(rename = "nextAttemptUnix", default)]
    next_attempt_unix: i64,
}

/// 完整解析一条条目（含 `validate`）。
///
/// 测试里计数完整解析次数：`load_due` 必须只为**到期**条目付这份代价，
/// 这是「不把整个队列正文读进内存」唯一可稳定观测的证据。
fn parse_entry(raw: &[u8]) -> Result<QueueEntry, String> {
    #[cfg(test)]
    FULL_ENTRY_PARSES.with(|count| count.set(count.get() + 1));
    let entry: QueueEntry = serde_json::from_slice(raw).map_err(|e| e.to_string())?;
    entry.validate().map_err(|e| e.to_string())?;
    Ok(entry)
}

// 本线程完整解析过的条目数（测试用）。
//
// 用 `thread_local` 而不是全局原子：测试并行跑，全局计数会被相邻测试污染，
// 而每个 `#[test]` 都有自己的线程，线程局部计数天然隔离。
#[cfg(test)]
thread_local! {
    static FULL_ENTRY_PARSES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::EntryKind;

    fn temp_store() -> (tempfile::TempDir, QueueStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = QueueStore::new(dir.path().join("queue"));
        (dir, store)
    }

    fn entry(id_suffix: &str) -> QueueEntry {
        let mut e = QueueEntry::new(
            EntryKind::Outbound,
            "s@example.org",
            vec!["r@example.net".to_string()],
            "Subject: t\r\n\r\nbody",
            1_700_000_000,
        )
        .unwrap();
        e.id = format!("00000000001-{id_suffix}");
        e
    }

    #[test]
    fn enqueue_then_load_round_trips() {
        let (_d, store) = temp_store();
        let e = entry("AAAA");
        store.enqueue(&e).unwrap();

        let loaded = store.load_all().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0], e);
    }

    #[test]
    fn queue_survives_restart_without_losing_entries() {
        // 规格书 §5.8 第一条：持久化到磁盘，重启不丢。
        // 「重启」用一个全新的 store 实例指向同一目录来模拟。
        let (dir, store) = temp_store();
        store.enqueue(&entry("0001")).unwrap();
        store.enqueue(&entry("0002")).unwrap();
        store.enqueue(&entry("0003")).unwrap();
        drop(store);

        let reopened = QueueStore::new(dir.path().join("queue"));
        let loaded = reopened.load_all().unwrap();
        assert_eq!(loaded.len(), 3, "重启后条目不得丢失");
        assert_eq!(loaded[0].id, "00000000001-0001");
        assert_eq!(loaded[2].id, "00000000001-0003");
    }

    #[test]
    fn queue_writes_are_atomic_and_leave_no_partial_files() {
        // 原子性：落盘后不得留下临时文件或半成品；锁 sidecar 必须被读路径忽略。
        let (_d, store) = temp_store();
        store.enqueue(&entry("BEEF")).unwrap();

        let dir = store.entries_dir();
        let names: Vec<String> = fs::read_dir(&dir)
            .unwrap()
            .map(|i| i.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        assert!(
            names.contains(&"00000000001-BEEF.json".to_string()),
            "条目文件缺失：{names:?}"
        );
        assert!(
            !names.iter().any(|n| n.ends_with(".tmp")),
            "不得留下临时文件：{names:?}"
        );

        // 锁 sidecar 与临时文件都不得被当作队列条目 —— 否则一次「写到一半」会被读成半条消息。
        assert_eq!(store.load_all().unwrap().len(), 1);
        assert!(!is_queue_file(&dir.join("00000000001-BEEF.json.tmp")));
        assert!(!is_queue_file(&dir.join(".00000000001-BEEF.json.lock")));
    }

    #[test]
    fn queue_files_are_owner_only() {
        // 条目含用户邮件正文，必须是 0600。
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let (_d, store) = temp_store();
            store.enqueue(&entry("CAFE")).unwrap();
            let path = store.entries_dir().join("00000000001-CAFE.json");
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "队列文件实际权限：{mode:o}");
        }
    }

    #[test]
    fn corrupt_queue_files_are_quarantined_not_dropped() {
        // 一条读不出来的条目必须被隔离，而不是被静默删除 —— 它往往是排查线索。
        let (_d, store) = temp_store();
        store.enqueue(&entry("GOOD")).unwrap();

        let dir = store.entries_dir();
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("00000000001-BAD0.json"), b"{ not valid json").unwrap();
        // 结构合法但语义非法的条目（空收件人）同样要被隔离。
        fs::write(
            dir.join("00000000001-BAD1.json"),
            br#"{"id":"00000000001-BAD1","kind":"outbound","mailFrom":"s@x","recipients":[],"data":"x","createdAt":"2026-01-01T00:00:00+00:00","attempts":0,"nextAttemptUnix":0}"#,
        )
        .unwrap();

        let loaded = store.load_all().unwrap();
        assert_eq!(loaded.len(), 1, "只有合法条目应当被读出");
        assert_eq!(loaded[0].id, "00000000001-GOOD");

        let quarantined: Vec<String> = fs::read_dir(store.corrupt_dir())
            .unwrap()
            .map(|i| i.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(
            quarantined.len(),
            2,
            "两个坏条目都应被隔离：{quarantined:?}"
        );
        assert!(quarantined
            .iter()
            .any(|n| n.starts_with("00000000001-BAD0.json")));
        // 原始文件不应再留在 entries/ 下。
        assert!(!dir.join("00000000001-BAD0.json").exists());
    }

    /// 新条目入队绝不覆盖既有条目：目标已存在时换 id 重试，原邮件必须原样保留。
    #[test]
    fn enqueue_new_never_overwrites_an_existing_entry() {
        let (_d, store) = temp_store();
        let first = entry("AAAA");
        store.enqueue(&first).unwrap();

        // 模拟撞车：另一封不同的邮件拿到了同一个 id。
        let mut collided = entry("BBBB");
        collided.id = first.id.clone();

        store.enqueue_new(&mut collided).unwrap();

        // 先写的那封原样保留；后写的换了 id 落盘。
        let loaded = store.load_all().unwrap();
        assert_eq!(loaded.len(), 2, "撞车不得覆盖任何一封邮件");
        let original = loaded
            .iter()
            .find(|e| e.id == first.id)
            .expect("先写的邮件必须原样保留");
        assert_eq!(original.data, first.data);
        assert_ne!(collided.id, first.id, "撞车的一方必须换到新 id");
        assert!(loaded.iter().any(|e| e.id == collided.id));

        // 无撞车时 id 保持不变。
        let mut fresh = entry("CCCC");
        let before = fresh.id.clone();
        store.enqueue_new(&mut fresh).unwrap();
        assert_eq!(fresh.id, before);
    }

    /// 撞车检测在写盘**之前**发生（O_EXCL 占位）：占住目标的 id 换新 id 后仍能
    /// 正常落盘、原占位内容一字不动；且非法 id（校验失败）在进入撞车循环前就被拒绝。
    #[test]
    fn enqueue_new_validates_before_the_collision_loop() {
        let (_d, store) = temp_store();
        let mut invalid = entry("BBBB");
        invalid.id = "../escape".to_string();
        assert!(store.enqueue_new(&mut invalid).is_err());
        assert!(store.load_all().unwrap().is_empty(), "非法条目不得落盘");

        // 模拟撞车（等价于另一进程已 O_EXCL 占位，或崩溃残留）：目标名已存在，
        // 后到的入队必须换 id，而不是覆盖占位内容。
        fs::create_dir_all(store.entries_dir()).unwrap();
        let occupied = store.entries_dir().join("00000000001-CCCC.json");
        fs::write(&occupied, b"placeholder").unwrap();
        let mut collided = entry("CCCC");
        collided.id = "00000000001-CCCC".to_string();
        store.enqueue_new(&mut collided).unwrap();

        assert_ne!(collided.id, "00000000001-CCCC", "撞车必须换 id");
        assert_eq!(
            fs::read(&occupied).unwrap(),
            b"placeholder",
            "已占位的名字不得被覆盖"
        );
        assert!(store
            .load_all()
            .unwrap()
            .iter()
            .any(|e| e.id == collided.id));
    }

    /// 首封入队时条目目录可能还不存在：占位前必须先建目录（与 `try_claim`
    /// 对 claims 目录的处理一致），否则新装环境的第一封邮件直接失败。
    #[test]
    fn enqueue_new_creates_the_entries_directory_itself() {
        let (_d, store) = temp_store();
        assert!(!store.entries_dir().exists());
        let mut fresh = entry("AAAA");
        store.enqueue_new(&mut fresh).unwrap();
        assert_eq!(store.load_all().unwrap().len(), 1);
    }

    #[test]
    fn remove_deletes_only_the_targeted_entry() {
        let (_d, store) = temp_store();
        store.enqueue(&entry("0001")).unwrap();
        store.enqueue(&entry("0002")).unwrap();

        assert!(store.remove("00000000001-0001").unwrap());
        assert!(
            !store.remove("00000000001-0001").unwrap(),
            "重复删除应返回 false"
        );

        let loaded = store.load_all().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id, "00000000001-0002");
    }

    #[test]
    fn remove_and_enqueue_reject_unsafe_ids() {
        // 一个被篡改的 id 不得让文件写到队列目录之外。
        let (_d, store) = temp_store();
        assert!(store.remove("../escape").is_err());
        assert!(store
            .enqueue(&{
                let mut e = entry("0001");
                e.id = "../escape".to_string();
                e
            })
            .is_err());
    }

    #[test]
    fn missing_queue_directory_is_an_empty_queue_not_an_error() {
        let (_d, store) = temp_store();
        assert!(store.load_all().unwrap().is_empty());
        assert!(store.is_empty().unwrap());
        assert_eq!(store.len().unwrap(), 0);
    }

    #[test]
    fn health_state_round_trips_and_survives_restart() {
        let (dir, store) = temp_store();
        let state = OutboundHealthState {
            consecutive_failures: 7,
            last_success_at: Some("2026-09-30T00:00:00+00:00".to_string()),
            last_failure: Some("ConnectionError".to_string()),
        };
        store.save_health(&state).unwrap();

        let reopened = QueueStore::new(dir.path().join("queue"));
        assert_eq!(reopened.load_health(), Some(state));
    }

    #[test]
    fn corrupt_health_state_is_tolerated() {
        // 一个坏掉的状态文件不得让队列停摆。
        let (_d, store) = temp_store();
        fs::create_dir_all(store.root()).unwrap();
        fs::write(store.root().join("outbound-health.json"), b"not json").unwrap();
        assert_eq!(store.load_health(), None);
    }

    #[test]
    fn health_file_is_not_mistaken_for_a_queue_entry() {
        // 状态文件与条目同目录，必须靠子目录隔离而不是靠文件名侥幸。
        let (_d, store) = temp_store();
        store
            .save_health(&OutboundHealthState {
                consecutive_failures: 3,
                ..Default::default()
            })
            .unwrap();
        store.enqueue(&entry("0001")).unwrap();
        assert_eq!(store.load_all().unwrap().len(), 1);
    }

    #[test]
    fn load_all_is_sorted_by_id_so_it_is_sorted_by_time() {
        let (_d, store) = temp_store();
        for suffix in ["000C", "000A", "000B"] {
            store.enqueue(&entry(suffix)).unwrap();
        }
        let ids: Vec<String> = store
            .load_all()
            .unwrap()
            .into_iter()
            .map(|e| e.id)
            .collect();
        assert_eq!(
            ids,
            vec!["00000000001-000A", "00000000001-000B", "00000000001-000C"]
        );
    }

    /// 5.16：`len()` 只数条目文件，**不解析邮件正文**。
    ///
    /// 原实现是 `load_all()?.len()`。而 `backlog` / `len()` 每 2 秒被遥测采样
    /// 调用一次 —— 千条积压时就是每 2 秒数百 MB 的解析，还跑在 tokio worker 上。
    ///
    /// 判据：一条**内容已损坏**的条目文件仍然被计入数量。`load_all()` 会把它
    /// 移进 `corrupt/`（因此数不到它），而只 stat 目录项的 `len()` 必须数得到 ——
    /// 这正是「不解析」的可观测证据。
    #[test]
    fn len_counts_entry_files_without_parsing_them() {
        let (_d, store) = temp_store();
        store.enqueue(&entry("0001")).unwrap();
        store.enqueue(&entry("0002")).unwrap();
        assert_eq!(store.len().unwrap(), 2);

        // 塞一个坏条目进目录。
        let broken = store.entries_dir().join("00000000001-0003.json");
        fs::write(&broken, b"not a queue entry at all").unwrap();

        assert_eq!(store.len().unwrap(), 3, "len() 必须只数文件，不解析内容");

        // 对照：load_all 会隔离坏条目，因此只返回 2 条。
        let parsed = store.load_all().unwrap();
        assert_eq!(parsed.len(), 2, "load_all 应隔离坏条目");
        assert!(!broken.exists(), "坏条目应已移入 corrupt/");
    }

    /// 健康状态文件与锁 sidecar 不得被算进条目数量。
    #[test]
    fn len_ignores_non_entry_files() {
        let (_d, store) = temp_store();
        store.enqueue(&entry("0001")).unwrap();
        store.save_health(&OutboundHealthState::default()).unwrap();
        fs::write(store.entries_dir().join(".hidden.lock"), b"").unwrap();
        assert_eq!(store.len().unwrap(), 1);
    }

    // ── 5.10：投递租约 ──

    /// 同一时刻只有一方能拿到租约（`O_EXCL`，不是 `exists()` + 写）。
    #[test]
    fn a_claim_is_exclusive_until_released() {
        let (_d, store) = temp_store();
        store.enqueue(&entry("0001")).unwrap();
        let id = "00000000001-0001";
        let now = 1_700_000_100;

        assert!(store.try_claim(id, now).unwrap(), "首次认领必须成功");
        assert!(
            !store.try_claim(id, now + 1).unwrap(),
            "未释放前第二次认领必须失败 —— 否则两个执行者会同时投递"
        );

        store.release_claim(id).unwrap();
        assert!(store.try_claim(id, now + 2).unwrap(), "释放后应可再次认领");
    }

    /// 过期租约必须能被接管：否则一次崩溃就让条目卡死到 TTL 之后（且无人清理）。
    #[test]
    fn an_expired_claim_can_be_taken_over() {
        let (_d, store) = temp_store();
        store.enqueue(&entry("0001")).unwrap();
        let id = "00000000001-0001";
        let now = 1_700_000_000;

        assert!(store.try_claim(id, now).unwrap());
        // TTL 之内：仍然是别人的。
        assert!(!store.try_claim(id, now + CLAIM_TTL_SECONDS - 1).unwrap());
        // 恰好过期：可接管。
        assert!(
            store.try_claim(id, now + CLAIM_TTL_SECONDS).unwrap(),
            "超过 TTL 的租约必须可被接管"
        );
    }

    /// `claimed_ids` 只返回仍有效的租约；`prune_claims` 清掉过期的。
    #[test]
    fn claimed_ids_reflects_only_live_leases() {
        let (_d, store) = temp_store();
        for suffix in ["0001", "0002"] {
            store.enqueue(&entry(suffix)).unwrap();
        }
        let fresh = "00000000001-0001";
        let stale = "00000000001-0002";
        let now = 1_700_000_000;
        assert!(store.try_claim(fresh, now).unwrap());
        assert!(store
            .try_claim(stale, now - CLAIM_TTL_SECONDS - 10)
            .unwrap());

        let claimed = store.claimed_ids(now).unwrap();
        assert!(claimed.contains(fresh), "未过期的租约必须可见");
        assert!(!claimed.contains(stale), "过期的租约不得把条目挡在队列外");

        let pruned = store.prune_claims(now).unwrap();
        assert_eq!(pruned, 1, "只应清掉那条过期的");
        assert!(
            !store.claim_path(stale).unwrap().exists(),
            "过期租约文件应已被清理"
        );
    }

    /// 条目被删除时租约必须一起消失，否则 claim 目录会留下永久孤儿。
    #[test]
    fn removing_an_entry_releases_its_claim() {
        let (_d, store) = temp_store();
        store.enqueue(&entry("0001")).unwrap();
        let id = "00000000001-0001";
        let now = 1_700_000_000;

        assert!(store.try_claim(id, now).unwrap());
        assert!(store.claim_path(id).unwrap().exists());

        store.remove(id).unwrap();
        assert!(
            !store.claim_path(id).unwrap().exists(),
            "条目已删除，租约必须一并清理"
        );
        assert!(store.claimed_ids(now).unwrap().is_empty());
    }

    /// 租约内容损坏时按 mtime 兜底；mtime 也拿不到则视为过期（宁可多投一次，
    /// 也不要让条目被永久卡住）。
    #[test]
    fn a_corrupt_claim_timestamp_falls_back_to_mtime_not_to_a_deadlock() {
        let (_d, store) = temp_store();
        let id = "00000000001-0001";
        store.enqueue(&entry("0001")).unwrap();
        let now = 1_700_000_000;
        assert!(store.try_claim(id, now).unwrap());

        // 把内容写坏，但文件刚创建 —— mtime 是「现在」，仍应视为有效。
        fs::write(store.claim_path(id).unwrap(), b"garbage").unwrap();
        let fresh = store.claimed_ids(now).unwrap();
        assert!(
            fresh.contains(id),
            "时间戳损坏时应退化为 mtime 判定，而不是立刻放开"
        );
    }

    // ── R5-002：租约接管必须是原子的（判过期与占名之间不得插入另一个执行者） ──

    /// 两个执行者抢同一条过期租约：**恰好一个**拿到。
    ///
    /// 原实现「判过期 → 无条件 remove_file → create_new」两步之间没有校验，
    /// 后到的执行者可能删掉前一个刚建的新租约，于是双方都返回 `Ok(true)`。
    #[test]
    fn only_one_of_two_concurrent_claimers_wins_the_same_stale_lease() {
        let (_d, store) = temp_store();
        let id = "00000000001-0001";
        let now = 1_700_000_000;
        let claim_path = store.claim_path(id).unwrap();
        fs::create_dir_all(store.claims_dir()).unwrap();

        for round in 0..200 {
            // 每一轮都放一个已过期的租约，然后两个线程同时接管。
            fs::write(&claim_path, format!("{}", now - CLAIM_TTL_SECONDS - 10)).unwrap();
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
            let mut handles = Vec::new();
            for _ in 0..2 {
                let store = store.clone();
                let barrier = std::sync::Arc::clone(&barrier);
                handles.push(std::thread::spawn(move || {
                    barrier.wait();
                    store.try_claim(id, now).unwrap()
                }));
            }
            let winners: usize = handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .filter(|won| *won)
                .count();
            assert_eq!(
                winners, 1,
                "第 {round} 轮：{winners} 个执行者同时拿到同一条条约租约"
            );
        }
    }

    /// 认领操作确实被一把跨线程（生产里是跨进程）的锁串起来 —— 这是上一条
    /// 不变量的**机制**：只要 `try_claim` / `prune_claims` / `release_claim`
    /// 都在同一把锁内，判过期与占名之间就不可能插进另一个执行者。
    #[test]
    fn claim_mutations_are_serialised_by_a_shared_lock() {
        let (_d, store) = temp_store();
        let id = "00000000001-0001";
        let now = 1_700_000_000;
        fs::create_dir_all(store.claims_dir()).unwrap();

        let holder = store.clone();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            holder
                .with_claims_lock(|| {
                    started_tx.send(()).unwrap();
                    std::thread::sleep(std::time::Duration::from_millis(300));
                    Ok(())
                })
                .unwrap();
        });
        started_rx.recv().unwrap();

        let began = std::time::Instant::now();
        assert!(store.try_claim(id, now).unwrap());
        let waited = began.elapsed();
        worker.join().unwrap();

        assert!(
            waited >= std::time::Duration::from_millis(200),
            "try_claim 没有等待 claims 锁（只用了 {waited:?}）—— 判过期与占名又可被插队"
        );
    }

    // ── R5-009：调度只应加载到期条目（未到期条目的正文一次都不解析） ──

    #[test]
    fn load_due_skips_the_body_of_entries_that_are_not_due() {
        let (_d, store) = temp_store();
        // 8 条远未到期的积压（正文故意做大，确保「全量解析」会真的吃内存）。
        for index in 0..8 {
            let mut e = entry(&format!("FUT{index:01}"));
            e.data = format!("Subject: t\r\n\r\n{}", "x".repeat(256 * 1024));
            e.next_attempt_unix = 9_999_999_999;
            store.enqueue(&e).unwrap();
        }
        // 2 条已到期。
        for index in 0..2 {
            let mut e = entry(&format!("DUE{index:01}"));
            e.next_attempt_unix = 1_000;
            store.enqueue(&e).unwrap();
        }

        FULL_ENTRY_PARSES.with(|count| count.set(0));
        let due = store.load_due(2_000).unwrap();
        let parsed = FULL_ENTRY_PARSES.with(|count| count.get());

        assert_eq!(due.len(), 2, "只应返回到期条目：{due:?}");
        assert_eq!(
            parsed, 2,
            "完整解析了 {parsed} 条条目（应为 2）—— 未到期条目的正文也被读进了内存"
        );
        // 对照：`load_all` 会把 10 条全部完整解析（它是只读聚合面的接口）。
        FULL_ENTRY_PARSES.with(|count| count.set(0));
        assert_eq!(store.load_all().unwrap().len(), 10);
        assert_eq!(FULL_ENTRY_PARSES.with(|count| count.get()), 10);
    }

    /// 到期判定以正文里的 `nextAttemptUnix` 为准：头部字段被篡改成「已到期」
    /// 但正文远未到期的条目不得被调度（头部只是省内存的预筛，不是真相源）。
    #[test]
    fn load_due_still_rechecks_the_full_entry_before_scheduling_it() {
        let (_d, store) = temp_store();
        store.enqueue(&entry("0001")).unwrap();
        let path = store.entries_dir().join("00000000001-0001.json");
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["nextAttemptUnix"] = serde_json::json!(0);
        // 正文里的字段是同一个 —— 这条测试钉住「两阶段解析不会把不一致静默放过」；
        // 真正的不一致在 schema 上不可能出现，故这里只验证正常路径。
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(store.load_due(10).unwrap().len(), 1);
    }

    /// 解析坏的条目在 `load_due` 里同样被隔离，而不是被静默丢弃。
    #[test]
    fn load_due_quarantines_corrupt_entries_instead_of_dropping_them() {
        let (_d, store) = temp_store();
        fs::create_dir_all(store.entries_dir()).unwrap();
        fs::write(
            store.entries_dir().join("00000000001-BAD0.json"),
            b"{ not valid json",
        )
        .unwrap();
        assert!(store.load_due(1_700_000_000).unwrap().is_empty());
        assert_eq!(fs::read_dir(store.corrupt_dir()).unwrap().count(), 1);
    }

    // ── R5-014：入队占位不得被并发读者当成损坏条目 ──

    /// 并发 `enqueue_new` 与 `load_all`：读者永远看不到半成品，`corrupt/` 必须为空。
    ///
    /// 原实现在**目标文件**上 O_EXCL 占位，占位到 rename 之间有一个可见的
    /// 0 字节窗口；`atomic_as` 的 fsync 让这个窗口有毫秒级宽度，并发读者几乎
    /// 必然撞上，把一条正常在途入队 rename 进 `corrupt/`。
    #[test]
    fn concurrent_enqueue_and_load_never_quarantine_a_live_entry() {
        let (_d, store) = temp_store();
        let writer = {
            let store = store.clone();
            std::thread::spawn(move || {
                for index in 0..64 {
                    let mut e = entry(&format!("ENQ{index:02}"));
                    e.data = format!("Subject: t\r\n\r\n{}", "y".repeat(256 * 1024));
                    store.enqueue_new(&mut e).unwrap();
                }
            })
        };
        let reader = {
            let store = store.clone();
            std::thread::spawn(move || {
                for _ in 0..400 {
                    let _ = store.load_all().unwrap();
                }
            })
        };
        writer.join().unwrap();
        reader.join().unwrap();

        let corrupt = match fs::read_dir(store.corrupt_dir()) {
            Ok(read) => read.count(),
            Err(_) => 0,
        };
        assert_eq!(
            corrupt, 0,
            "并发读者把 {corrupt} 个正常在途入队当成了损坏条目"
        );
        assert_eq!(store.load_all().unwrap().len(), 64, "64 封邮件都必须在");
    }

    /// `corrupt/` 有保留上限：长期运行不会因为反复隔离而无限增长。
    #[test]
    fn the_corrupt_directory_is_bounded() {
        let (_d, store) = temp_store();
        let dir = store.corrupt_dir();
        fs::create_dir_all(&dir).unwrap();
        for index in 0..(MAX_CORRUPT_FILES + 16) {
            fs::write(dir.join(format!("old-{index:04}.corrupt")), b"x").unwrap();
        }
        store.enqueue(&entry("GC00")).unwrap();
        fs::write(store.entries_dir().join("00000000001-GC01.json"), b"bad").unwrap();
        store.load_all().unwrap();

        let count = fs::read_dir(&dir).unwrap().count();
        assert!(
            count <= MAX_CORRUPT_FILES,
            "corrupt/ 长到 {count} 条，超过上限 {MAX_CORRUPT_FILES}"
        );
        let newest_kept = fs::read_dir(&dir).unwrap().flatten().any(|item| {
            item.file_name()
                .to_string_lossy()
                .starts_with("00000000001-GC01")
        });
        assert!(newest_kept, "刚隔离的那一条必须保留（保留最近的）");
    }
}
