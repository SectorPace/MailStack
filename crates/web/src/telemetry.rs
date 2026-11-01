//! 系统时序遥测（`GET /api/metrics/telemetry`）—— 等价移植基线的
//! `SystemMetricsCollector`（`backend/server.production.ts`）。
//!
//! **为什么由 Web 进程自己采样，而不是走特权助手**：契约里这条路由的 `action`
//! 是 `None`（进程内应答），而动作白名单已冻结为 50 条 —— 不能为它新增一个动作。
//! 因此采样只能在本进程内完成。
//!
//! 与基线一致的四点语义（都是有意保留的，不是巧合）：
//!
//! 1. **7 档时间窗各一个环形缓冲**，采样间隔与容量见 [`RANGES`]。
//! 2. **CPU 是差分采样**：由两次 `/proc/stat` 快照相减得出。因此 `sample()`
//!    连续调用两次，第二次测到的是两次调用之间的空档（接近 0）——
//!    每个上报周期只能消费一次。
//! 3. **读不到的守护进程显示为 `STOPPED`，而不是从列表里消失**：界面据此区分
//!    「没在跑」与「没读到」。`mailstack-webmail` 恒为 `STOPPED`（基线把 `node`
//!    这个 comm 归为「无法安全归属」而刻意排除）。
//! 4. `points` 为空时 `samplingCount` 就是 0：此时响应用一次**即时采样**填充
//!    `current`，但**不**把它塞进 `points` —— 否则前端会看到一个只含单点的曲线，
//!    误以为历史只有一段。
//!
//! **为什么不复用 `mailstack_core::sysinfo::read_meminfo`**：那个函数的契约是
//! 「缺 `MemAvailable` 就回 `None`」（fail-loud，服务 `/api/status`）。而遥测这条
//! 路由的基线契约允许在缺 `MemAvailable` 时退到 `MemFree` 并给出一个数字。两者
//! 语义不同，**不把两种纪律揉进同一个函数**，故这里单独解析 `/proc/meminfo`。

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mailstack_core::exec::{CommandOutput, CommandRunner, SystemCommandRunner};
use serde_json::{json, Value};

/// 毫秒时钟。注入是为了让「环形缓冲是否到期」这类断言不随真实时间漂移。
pub type MillisClock = Arc<dyn Fn() -> i64 + Send + Sync>;

/// 7 档时间窗：`(范围, 采样间隔 ms, 容量)`。顺序即契约顺序。
pub const RANGES: &[(&str, i64, usize)] = &[
    ("1m", 2_000, 30),
    ("5m", 5_000, 60),
    ("30m", 30_000, 60),
    ("1h", 60_000, 60),
    ("6h", 300_000, 72),
    ("24h", 900_000, 96),
    ("3d", 3_600_000, 72),
];

/// 1h 档在 [`RANGES`] 中的下标（也是默认档）。非法 `range` 回落到它。
const DEFAULT_RANGE_INDEX: usize = 3;

/// 每隔多少个采样周期做一次全量 `/proc` 扫描。
///
/// 全量扫描每个进程要读两次文件；守护进程的 comm 一旦确定就不会变，因此
/// 只对「缓存里已有的 pid」与「从未见过的新 pid」重读。磁盘每 60 秒刷新一次。
const FULL_SCAN_EVERY_CYCLES: u32 = 30;

/// `/proc/<pid>/statm` 的页大小。基线硬编码 4096，本项目的构建目标
/// （`x86_64-unknown-linux-gnu`）也是 4 KiB 页。
const PAGE_SIZE_BYTES: u64 = 4096;

/// 磁盘用量刷新间隔（与基线的 60 秒定时器一致）。
const DISK_REFRESH_MS: i64 = 60_000;

/// `df` / `postqueue` 的最长等待时长。
///
/// 子进程卡死时按「读不到」处理：宁可丢一个读数，不可让一次挂起的
/// `postqueue` 把采样（连同它持有的内部缓存锁）无限期占住。
const SUBPROCESS_TIMEOUT: Duration = Duration::from_secs(5);

/// 守护进程展示顺序（即基线对象字面量的插入顺序）。
const DAEMON_ORDER: &[&str] = &[
    "postfix",
    "dovecot",
    "opendkim",
    "mailstack-web",
    "mailstack-webmail",
    "fail2ban",
];

/// 进程 `comm` → 守护进程 id。
///
/// 刻意排除过于通用、无法安全归属的名字：Dovecot 的 `config` / `log` / `stats`，
/// 以及 webmail 的 `node`（它与任意其它 Node 进程无法由名字区分）。
const COMM_TO_DAEMON: &[(&str, &str)] = &[
    // Postfix
    ("master", "postfix"),
    ("pickup", "postfix"),
    ("qmgr", "postfix"),
    ("cleanup", "postfix"),
    ("smtpd", "postfix"),
    ("smtp", "postfix"),
    ("showq", "postfix"),
    ("flush", "postfix"),
    ("local", "postfix"),
    ("virtual", "postfix"),
    ("pipe", "postfix"),
    ("bounce", "postfix"),
    ("defer", "postfix"),
    ("trace", "postfix"),
    ("verify", "postfix"),
    ("scache", "postfix"),
    ("proxymap", "postfix"),
    ("tlsmgr", "postfix"),
    ("postscreen", "postfix"),
    ("dnsblog", "postfix"),
    ("trivial-rewrite", "postfix"),
    // Dovecot
    ("dovecot", "dovecot"),
    ("doveadm", "dovecot"),
    ("dsync", "dovecot"),
    ("director", "dovecot"),
    ("anvil", "dovecot"),
    ("auth", "dovecot"),
    ("imap", "dovecot"),
    ("imap-login", "dovecot"),
    ("pop3", "dovecot"),
    ("pop3-login", "dovecot"),
    ("managesieve", "dovecot"),
    ("managesieve-login", "dovecot"),
    // OpenDKIM
    ("opendkim", "opendkim"),
    // fail2ban
    ("fail2ban", "fail2ban"),
    ("fail2ban-server", "fail2ban"),
];

/// 一次 `/proc/stat` 的 CPU 计数器。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CpuTimes {
    idle: u64,
    total: u64,
}

/// 内存读数（MB）。
#[derive(Debug, Clone, Copy, PartialEq)]
struct MemDetail {
    total_mb: f64,
    used_mb: f64,
    percent: f64,
}

/// 根分区用量。
#[derive(Debug, Clone, Copy, PartialEq)]
struct DiskInfo {
    total_gb: f64,
    used_gb: f64,
    percent: f64,
}

/// 队列读数。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct QueueMetrics {
    total: u64,
    deferred: u64,
}

/// 某个守护进程的即时读数。
#[derive(Debug, Clone, PartialEq)]
struct DaemonStat {
    id: &'static str,
    pid: u32,
    memory_mb: f64,
    cpu_percent: f64,
    status: &'static str,
}

/// 一个采样点。
#[derive(Debug, Clone, PartialEq)]
struct Point {
    ts_ms: i64,
    cpu_percent: f64,
    /// 守护进程内存合计（MB）。
    memory_mb: f64,
    sys_mem_percent: f64,
    sys_mem_used_mb: f64,
    sys_mem_total_mb: f64,
    load1: f64,
    load5: f64,
    load15: f64,
    queue_total: u64,
    queue_deferred: u64,
    daemons: Vec<DaemonStat>,
}

/// 一档时间窗的环形缓冲。
struct Ring {
    interval_ms: i64,
    cap: usize,
    points: VecDeque<Point>,
}

struct Inner {
    rings: Vec<Ring>,
    prev_cpu: Vec<CpuTimes>,
    pid_cache: HashMap<u32, &'static str>,
    seen_pids: HashSet<u32>,
    cycles_since_full_scan: u32,
    disk: DiskInfo,
    /// 上次刷新磁盘用量的时刻；`None` 表示还没刷过。
    disk_updated_ms: Option<i64>,
}

/// 时序遥测采集器。
pub struct TelemetryCollector {
    inner: Mutex<Inner>,
    proc_root: PathBuf,
    runner: Arc<dyn CommandRunner>,
    clock: MillisClock,
    /// 本进程 pid（用于 `mailstack-web` 那一行）。
    web_pid: u32,
}

impl TelemetryCollector {
    /// 生产构造：真实 `/proc`、真实 `df` / `postqueue`、真实时钟。
    pub fn system() -> Self {
        Self::new(
            mailstack_core::sysinfo::system_proc_root(),
            Arc::new(SystemCommandRunner),
            Arc::new(|| time::OffsetDateTime::now_utc().unix_timestamp_nanos() as i64 / 1_000_000),
            std::process::id(),
        )
    }

    /// 注入构造（测试用）。
    pub fn new(
        proc_root: PathBuf,
        runner: Arc<dyn CommandRunner>,
        clock: MillisClock,
        web_pid: u32,
    ) -> Self {
        let prev_cpu = read_cpu_times(&proc_root);
        Self {
            inner: Mutex::new(Inner {
                rings: RANGES
                    .iter()
                    .map(|(_, interval_ms, cap)| Ring {
                        interval_ms: *interval_ms,
                        cap: *cap,
                        points: VecDeque::new(),
                    })
                    .collect(),
                prev_cpu,
                pid_cache: HashMap::new(),
                seen_pids: HashSet::new(),
                cycles_since_full_scan: FULL_SCAN_EVERY_CYCLES,
                disk: DiskInfo {
                    total_gb: 0.0,
                    used_gb: 0.0,
                    percent: 0.0,
                },
                disk_updated_ms: None,
            }),
            proc_root,
            runner,
            clock,
            web_pid,
        }
    }

    /// 采一个样并推入各档环形缓冲。
    fn sample(&self) -> Point {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        self.sample_locked(&mut inner)
    }

    /// 启动后台采样任务（2 秒一次）。返回句柄，调用方可据此停机。
    ///
    /// 直到 Web 服务入口落地前，这个任务没有宿主进程 —— 端点依赖
    /// [`TelemetryCollector::telemetry`] 的「按需采样」兜底仍然可用。
    pub fn start_sampling(self: &Arc<Self>, interval: Duration) -> tokio::task::JoinHandle<()> {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                // 采样持锁做 /proc 遍历并跑子进程 —— 必须搬进阻塞线程池，
                // 否则一个挂起的 `postqueue` 就把 async worker 整个占住。
                let sampler = Arc::clone(&this);
                let _ = tokio::task::spawn_blocking(move || sampler.sample()).await;
            }
        })
    }

    /// 组装 `GET /api/metrics/telemetry` 的响应体。
    pub fn telemetry(&self, range: Option<&str>) -> Value {
        let timeframe = crate::contract::normalize_telemetry_range(range);
        let index = RANGES
            .iter()
            .position(|(name, _, _)| *name == timeframe)
            .unwrap_or(DEFAULT_RANGE_INDEX);
        let interval_ms = RANGES[index].1;

        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());

        // `points` 取的是**本轮采样之前**的快照：环里本来没有点时，
        // `samplingCount` 就该是 0（基线同样如此），即时采样只填 `current`。
        let points: Vec<Point> = inner.rings[index].points.iter().cloned().collect();
        let latest = match points.last() {
            Some(point) => point.clone(),
            None => self.sample_locked(&mut inner),
        };

        let mem = self.read_mem();
        let (total_daemon_mb, daemons) = self.daemons_locked(&mut inner);
        let disk = self.disk_locked(&mut inner);
        let load = mailstack_core::sysinfo::read_loadavg(&self.proc_root);
        let uptime = mailstack_core::sysinfo::read_uptime_secs(&self.proc_root);
        let cores = inner.prev_cpu.len();
        let hostname = read_hostname(&self.proc_root);

        let (avg_cpu, max_cpu, avg_mem, max_mem, avg_sys_mem, max_sys_mem) = summarize(&points);
        let loads = load.map(|l| [l.one, l.five, l.fifteen]).unwrap_or([0.0; 3]);

        json!({
            "timeframe": timeframe,
            "intervalMs": interval_ms,
            "samplingCount": points.len(),
            "current": {
                "cpuPercent": latest.cpu_percent,
                "totalDaemonMemoryMb": total_daemon_mb,
                "systemMemoryUsedMb": mem.used_mb,
                "systemMemoryTotalMb": mem.total_mb,
                "systemMemoryPercent": mem.percent,
                "loadAvg": loads,
                "uptimeSec": uptime.unwrap_or(0),
                "daemons": daemons.iter().map(daemon_metric_json).collect::<Vec<_>>(),
                "cores": cores,
                "hostname": hostname,
                "diskTotalGb": disk.total_gb,
                "diskUsedGb": disk.used_gb,
                "diskUsagePercent": disk.percent,
            },
            "summary": {
                "avgCpu": avg_cpu,
                "maxCpu": max_cpu,
                "currentCpu": latest.cpu_percent,
                "avgMemoryMb": avg_mem,
                "maxMemoryMb": max_mem,
                "currentMemoryMb": total_daemon_mb,
                "avgSystemMemPercent": avg_sys_mem,
                "maxSystemMemPercent": max_sys_mem,
                "currentSystemMemPercent": mem.percent,
                "currentLoad": loads,
            },
            "points": points.iter().map(point_json).collect::<Vec<_>>(),
        })
    }

    // ── 内部实现 ──

    fn sample_locked(&self, inner: &mut Inner) -> Point {
        let now = (self.clock)();
        let cpu = self.sample_cpu_locked(inner);
        let mem = self.read_mem();
        let (total_daemon_mb, daemons) = self.daemons_locked(inner);
        let queue = self.queue_metrics();
        let load = mailstack_core::sysinfo::read_loadavg(&self.proc_root);
        let loads = load.map(|l| [l.one, l.five, l.fifteen]).unwrap_or([0.0; 3]);

        let point = Point {
            ts_ms: now,
            cpu_percent: cpu,
            memory_mb: total_daemon_mb,
            sys_mem_percent: mem.percent,
            sys_mem_used_mb: mem.used_mb,
            sys_mem_total_mb: mem.total_mb,
            load1: loads[0],
            load5: loads[1],
            load15: loads[2],
            queue_total: queue.total,
            queue_deferred: queue.deferred,
            daemons,
        };

        for (i, ring) in inner.rings.iter_mut().enumerate() {
            // 1m 档每个周期都进点；其余各档按各自的间隔节流。
            let due = i == 0
                || ring
                    .points
                    .back()
                    .map(|last| now - last.ts_ms >= ring.interval_ms)
                    .unwrap_or(true);
            if due {
                ring.points.push_back(point.clone());
                while ring.points.len() > ring.cap {
                    ring.points.pop_front();
                }
            }
        }
        point
    }

    /// 差分 CPU 百分比（0..=100，保留 1 位小数）。
    fn sample_cpu_locked(&self, inner: &mut Inner) -> f64 {
        let now = read_cpu_times(&self.proc_root);
        if now.is_empty() {
            return 0.0;
        }
        // 核心数可能变化（CPU 热插拔 / cgroup 调整）：长度不一致时退化成
        // 「零增量基线」，而不是越界读旧数组。
        let prev = if inner.prev_cpu.len() == now.len() {
            inner.prev_cpu.clone()
        } else {
            now.clone()
        };
        inner.prev_cpu = now.clone();

        let sum = |v: &[CpuTimes]| -> (u64, u64) {
            v.iter().fold((0u64, 0u64), |(idle, total), c| {
                (idle + c.idle, total + c.total)
            })
        };
        let (idle, total) = sum(&now);
        let (old_idle, old_total) = sum(&prev);
        usage(total, idle, old_total, old_idle)
    }

    /// `/proc/meminfo`。缺 `MemAvailable` 时退到 `MemFree`（基线即如此）。
    fn read_mem(&self) -> MemDetail {
        let Ok(text) = std::fs::read_to_string(self.proc_root.join("meminfo")) else {
            return MemDetail {
                total_mb: 0.0,
                used_mb: 0.0,
                percent: 0.0,
            };
        };
        let mut total_kib = 0u64;
        let mut available_kib = None;
        let mut free_kib = 0u64;
        for line in text.lines() {
            let Some((key, rest)) = line.split_once(':') else {
                continue;
            };
            let value: u64 = rest
                .split_whitespace()
                .next()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            match key {
                "MemTotal" => total_kib = value,
                "MemAvailable" => available_kib = Some(value),
                "MemFree" => free_kib = value,
                _ => {}
            }
        }
        let free = available_kib.unwrap_or(free_kib);
        let total_mb = round1(total_kib as f64 / 1024.0);
        let free_mb = round1(free as f64 / 1024.0);
        let used_mb = (total_mb - free_mb).max(0.0);
        MemDetail {
            total_mb,
            used_mb,
            percent: if total_mb > 0.0 {
                round1(used_mb / total_mb * 100.0)
            } else {
                0.0
            },
        }
    }

    /// 遍历各守护进程的内存与存活状态。
    ///
    /// 返回 `(守护进程内存合计 MB, 有序列表)`。
    fn daemons_locked(&self, inner: &mut Inner) -> (f64, Vec<DaemonStat>) {
        let mut stats: Vec<DaemonStat> = DAEMON_ORDER
            .iter()
            .map(|id| DaemonStat {
                id,
                pid: 0,
                memory_mb: 0.0,
                cpu_percent: 0.0,
                status: "STOPPED",
            })
            .collect();

        // 本进程那一行：恒为 ACTIVE，内存取自自身 RSS。
        if let Some(entry) = stats.iter_mut().find(|s| s.id == "mailstack-web") {
            entry.pid = self.web_pid;
            entry.memory_mb = read_process_rss_mb(&self.proc_root, self.web_pid);
            entry.status = "ACTIVE";
        }

        let all_pids = read_numeric_pids(&self.proc_root);
        let full_scan = inner.cycles_since_full_scan >= FULL_SCAN_EVERY_CYCLES;
        let candidates: Vec<u32> = all_pids
            .iter()
            .copied()
            .filter(|pid| {
                full_scan || inner.pid_cache.contains_key(pid) || !inner.seen_pids.contains(pid)
            })
            .collect();

        for pid in candidates {
            let Some(comm) = read_trimmed(&self.proc_root.join(pid.to_string()).join("comm"))
            else {
                inner.pid_cache.remove(&pid);
                continue;
            };
            let comm = comm.to_lowercase();
            let Some(key) = COMM_TO_DAEMON
                .iter()
                .find(|(name, _)| *name == comm)
                .map(|(_, daemon)| *daemon)
            else {
                inner.pid_cache.remove(&pid);
                continue;
            };
            let Some(statm) = read_trimmed(&self.proc_root.join(pid.to_string()).join("statm"))
            else {
                inner.pid_cache.remove(&pid);
                continue;
            };
            let rss_pages: u64 = statm
                .split_whitespace()
                .nth(1)
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            let rss_mb = round1(rss_pages as f64 * PAGE_SIZE_BYTES as f64 / 1_048_576.0);

            inner.pid_cache.insert(pid, key);
            if let Some(entry) = stats.iter_mut().find(|s| s.id == key) {
                // 同一守护进程常有多个进程（Postfix 尤甚）：内存相加，
                // pid 取第一个被看到的。
                entry.memory_mb = round1(entry.memory_mb + rss_mb);
                entry.status = "ACTIVE";
                if entry.pid == 0 {
                    entry.pid = pid;
                }
            }
        }

        // 已经消失的 pid 从缓存剔除，避免缓存随进程生命周期无限增长。
        inner.pid_cache.retain(|pid, _| all_pids.contains(pid));
        inner.seen_pids = all_pids;
        inner.cycles_since_full_scan = if full_scan {
            1
        } else {
            inner.cycles_since_full_scan.saturating_add(1)
        };

        let total = round1(stats.iter().map(|s| s.memory_mb).sum());
        (total, stats)
    }

    /// `df -k /`（每 60 秒刷新一次，其余时间返回缓存）。
    fn disk_locked(&self, inner: &mut Inner) -> DiskInfo {
        let now = (self.clock)();
        let stale = inner
            .disk_updated_ms
            .map(|last| now - last >= DISK_REFRESH_MS)
            .unwrap_or(true);
        if stale {
            if let Some(disk) = self.read_disk() {
                inner.disk = disk;
            }
            // 读失败也要更新时间戳：否则每个上报周期都会重跑一次 `df`。
            inner.disk_updated_ms = Some(now);
        }
        inner.disk
    }

    /// `df -kP /`：`-P`（POSIX 输出）强制**一行一个文件系统**。
    /// 基线用的 `df -k /` 在设备名过长时会把记录折成两行，只认 `lines[1]`
    /// 会解析到残缺行；换成 `-P` 后列序与含义都不变，但不再折行。
    fn read_disk(&self) -> Option<DiskInfo> {
        let output = self.run_subprocess("df", &["-kP", "/"])?;
        if output.status != 0 {
            return None;
        }
        parse_df_k(output.stdout.as_str())
    }

    /// 跑一个外部采样命令，带超时；超时/失败按「读不到」处理（`None`）。
    ///
    /// 优先用 runner 自带的 `run_with_timeout`（真实现会 kill 超时子进程并
    /// 回收）；只实现 `run` 的测试 runner，其默认 `run_with_timeout` 会显式
    /// 报错 —— 此时退回本地镜像：临时线程里跑 `run`，超过时限就**放弃等待**
    /// （读数按缺省处理；被放弃的子进程自身是只读短命命令，自行结束）。
    /// 与 `mailstack_core::exec` 的纪律一致：不可让调用方无限期挂住。
    fn run_subprocess(&self, program: &str, args: &[&str]) -> Option<CommandOutput> {
        if let Ok(output) = self
            .runner
            .run_with_timeout(program, args, SUBPROCESS_TIMEOUT)
        {
            return Some(output);
        }
        let runner = Arc::clone(&self.runner);
        let program = program.to_string();
        let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            // CommandRunner::run 收 `&[&str]`：引用视图在闭包内构造，
            // 借用被移动进来的 args —— 生命周期整个落在闭包里，不逃逸。
            let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
            let _ = tx.send(runner.run(&program, &arg_refs).ok());
        });
        rx.recv_timeout(SUBPROCESS_TIMEOUT).ok().flatten()
    }

    /// `postqueue -j`：逐行 JSON 统计总数与延迟数。
    fn queue_metrics(&self) -> QueueMetrics {
        let Some(output) = self.run_subprocess("postqueue", &["-j"]) else {
            return QueueMetrics::default();
        };
        if output.status != 0 {
            return QueueMetrics::default();
        }
        let mut metrics = QueueMetrics::default();
        for line in output.stdout.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let Ok(item) = serde_json::from_str::<Value>(line) else {
                continue;
            };
            metrics.total += 1;
            let deferred = item
                .get("recipients")
                .and_then(Value::as_array)
                .map(|recipients| {
                    recipients
                        .iter()
                        .any(|r| r.get("delay_reason").map(|v| !v.is_null()).unwrap_or(false))
                })
                .unwrap_or(false);
            if deferred {
                metrics.deferred += 1;
            }
        }
        metrics
    }
}

/// 差分 CPU 百分比。
///
/// 总量按 Linux 口径取 `user..steal` 八项之和，`idle` 只取 `idle` 一项。
/// 基线的 Node 用 `os.cpus().times`（不含 iowait），两者只在 iowait/softirq/steal
/// 这几项上有别；这里取 Linux 通行口径（「非 idle 即忙」），语义更直白。
fn usage(total: u64, idle: u64, old_total: u64, old_idle: u64) -> f64 {
    let diff_total = total.saturating_sub(old_total);
    let diff_idle = idle.saturating_sub(old_idle);
    if diff_total == 0 {
        return 0.0;
    }
    let ratio = (diff_total - diff_idle.min(diff_total)) as f64 / diff_total as f64;
    round1((ratio * 100.0).clamp(0.0, 100.0))
}

/// 读 `/proc/stat` 的**每核** CPU 计数器（不含汇总的 `cpu ` 行）。
fn read_cpu_times(proc_root: &Path) -> Vec<CpuTimes> {
    let Ok(text) = std::fs::read_to_string(proc_root.join("stat")) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for line in text.lines() {
        let Some(rest) = line.strip_prefix("cpu") else {
            continue;
        };
        // 汇总行是 `cpu `（紧跟空格），每核行是 `cpu0` / `cpu1`。
        let Some(first) = rest.chars().next() else {
            continue;
        };
        if !first.is_ascii_digit() {
            continue;
        }
        // 先剥掉核心序号（`cpu0` 的 `0`），剩下的才是计数器；
        // 不剥的话它会占掉 `user` 的位置，整列都会错位一格。
        let counters = rest.trim_start_matches(|c: char| c.is_ascii_digit());
        let fields: Vec<u64> = counters
            .split_whitespace()
            .filter_map(|v| v.parse().ok())
            .collect();
        if fields.len() < 8 {
            continue;
        }
        // user nice system idle iowait irq softirq steal guest guest_nice
        out.push(CpuTimes {
            idle: fields[3],
            total: fields[..8].iter().sum(),
        });
    }
    out
}

/// 解析 `df -kP /` 的输出。
///
/// 要求字段数 ≥ 6（POSIX 列：Filesystem 1024-blocks Used Available Capacity
/// Mounted-on）且第 2/3 列是数字 —— 表头行（`1K-blocks` / `1024-blocks`）
/// 正因为不是数字而被跳过。解析不出来就回 `None`，**不拿残缺行凑一个数字**。
fn parse_df_k(stdout: &str) -> Option<DiskInfo> {
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 6 {
            continue;
        }
        let (Ok(total_kb), Ok(used_kb)) = (parts[1].parse::<u64>(), parts[2].parse::<u64>()) else {
            continue;
        };
        if total_kb == 0 {
            continue;
        }
        return Some(DiskInfo {
            total_gb: round1(total_kb as f64 / 1_048_576.0),
            used_gb: round1(used_kb as f64 / 1_048_576.0),
            percent: round1(used_kb as f64 / total_kb as f64 * 100.0),
        });
    }
    None
}

/// `/proc` 下的数字目录名（pid）。
fn read_numeric_pids(proc_root: &Path) -> HashSet<u32> {
    let Ok(entries) = std::fs::read_dir(proc_root) else {
        return HashSet::new();
    };
    entries
        .flatten()
        .filter_map(|e| e.file_name().to_str().and_then(|n| n.parse::<u32>().ok()))
        .collect()
}

fn read_trimmed(path: &Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
}

/// 进程常驻内存（MB），取自 `/proc/<pid>/statm` 的 RSS 页数。
fn read_process_rss_mb(proc_root: &Path, pid: u32) -> f64 {
    let Some(statm) = read_trimmed(&proc_root.join(pid.to_string()).join("statm")) else {
        return 0.0;
    };
    let rss_pages: u64 = statm
        .split_whitespace()
        .nth(1)
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    round1(rss_pages as f64 * PAGE_SIZE_BYTES as f64 / 1_048_576.0)
}

fn read_hostname(proc_root: &Path) -> String {
    read_trimmed(&proc_root.join("sys/kernel/hostname")).unwrap_or_else(|| "unknown".to_string())
}

/// 汇总一组采样点的均值与峰值（都保留 1 位小数）。
fn summarize(points: &[Point]) -> (f64, f64, f64, f64, f64, f64) {
    let count = points.len().max(1);
    let mut sum_cpu = 0.0;
    let mut max_cpu: f64 = 0.0;
    let mut sum_mem = 0.0;
    let mut max_mem: f64 = 0.0;
    let mut sum_sys_mem = 0.0;
    let mut max_sys_mem: f64 = 0.0;
    for point in points {
        sum_cpu += point.cpu_percent;
        max_cpu = max_cpu.max(point.cpu_percent);
        sum_mem += point.memory_mb;
        max_mem = max_mem.max(point.memory_mb);
        sum_sys_mem += point.sys_mem_percent;
        max_sys_mem = max_sys_mem.max(point.sys_mem_percent);
    }
    (
        round1(sum_cpu / count as f64),
        round1(max_cpu),
        round1(sum_mem / count as f64),
        round1(max_mem),
        round1(sum_sys_mem / count as f64),
        round1(max_sys_mem),
    )
}

fn point_json(point: &Point) -> Value {
    let mut daemons = serde_json::Map::new();
    for daemon in &point.daemons {
        daemons.insert(
            daemon.id.to_string(),
            json!({
                "memoryMb": daemon.memory_mb,
                "cpuPercent": daemon.cpu_percent,
                "status": daemon.status,
            }),
        );
    }
    json!({
        "timestamp": ms_to_iso(point.ts_ms),
        "cpuPercent": point.cpu_percent,
        "memoryMb": point.memory_mb,
        "systemMemoryPercent": point.sys_mem_percent,
        "systemMemoryUsedMb": point.sys_mem_used_mb,
        "systemMemoryTotalMb": point.sys_mem_total_mb,
        "load1": point.load1,
        "load5": point.load5,
        "load15": point.load15,
        "queueTotal": point.queue_total,
        "queueDeferred": point.queue_deferred,
        "daemons": Value::Object(daemons),
    })
}

fn daemon_metric_json(daemon: &DaemonStat) -> Value {
    json!({
        "id": daemon.id,
        "name": daemon.id,
        "pid": daemon.pid,
        "memoryMb": daemon.memory_mb,
        "cpuPercent": daemon.cpu_percent,
        "status": daemon.status,
    })
}

/// 毫秒时间戳 → ISO 8601。与其它接口共用 `core` 的格式串，
/// 因此带 `+00:00` 偏移与微秒位（JS 的 `new Date()` 两者都能解析）。
fn ms_to_iso(ms: i64) -> String {
    let seconds = ms.div_euclid(1000);
    let sub_ms = ms.rem_euclid(1000) as u32;
    let dt = time::OffsetDateTime::from_unix_timestamp(seconds)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH)
        .replace_nanosecond(sub_ms * 1_000_000)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    mailstack_core::time_fmt::format_iso8601(dt)
}

/// 四舍五入到 1 位小数（基线的 `Math.round(x * 10) / 10`）。
fn round1(value: f64) -> f64 {
    if !value.is_finite() {
        return 0.0;
    }
    (value * 10.0).round() / 10.0
}

/// 构造一个**不碰真实系统**的采集器：既不读 `/proc`，也不跑外部命令。
///
/// 供其它模块的测试使用 —— 那些测试关心的是「路由是否接线、认证是否正确」，
/// 不该顺手在开发机上跑一次 `df` / `postqueue`。
#[cfg(test)]
pub(crate) fn inert_collector(proc_root: PathBuf) -> TelemetryCollector {
    struct NoProbe;

    impl CommandRunner for NoProbe {
        fn run(
            &self,
            program: &str,
            _args: &[&str],
        ) -> mailstack_core::CoreResult<mailstack_core::exec::CommandOutput> {
            Ok(mailstack_core::exec::CommandOutput {
                status: 127,
                stdout: String::new(),
                stderr: format!("{program}: not available in tests"),
            })
        }
    }

    TelemetryCollector::new(proc_root, Arc::new(NoProbe), Arc::new(|| 0), 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mailstack_core::exec::CommandOutput;
    use mailstack_core::CoreResult;
    use std::sync::atomic::{AtomicI64, Ordering};

    /// 记账用的假命令运行器：测试**绝不**真的去跑 `df` / `postqueue`。
    struct FakeRunner {
        calls: Mutex<Vec<String>>,
        df: String,
        postqueue: String,
    }

    impl FakeRunner {
        fn new(df: &str, postqueue: &str) -> Arc<Self> {
            Arc::new(Self {
                calls: Mutex::new(Vec::new()),
                df: df.to_string(),
                postqueue: postqueue.to_string(),
            })
        }

        fn df_calls(&self) -> usize {
            self.calls
                .lock()
                .unwrap()
                .iter()
                .filter(|p| *p == "df")
                .count()
        }
    }

    impl CommandRunner for FakeRunner {
        fn run(&self, program: &str, _args: &[&str]) -> CoreResult<CommandOutput> {
            self.calls.lock().unwrap().push(program.to_string());
            match program {
                "df" => Ok(CommandOutput {
                    status: 0,
                    stdout: self.df.clone(),
                    stderr: String::new(),
                }),
                "postqueue" => Ok(CommandOutput {
                    status: 0,
                    stdout: self.postqueue.clone(),
                    stderr: String::new(),
                }),
                other => Ok(CommandOutput {
                    status: 127,
                    stdout: String::new(),
                    stderr: format!("{other}: not found"),
                }),
            }
        }
    }

    /// 一个临时 `/proc` 夹具。
    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new(tag: &str) -> Self {
            let mut root = std::env::temp_dir();
            root.push(format!(
                "mailstack-telemetry-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&root).unwrap();
            Self { root }
        }

        fn write(&self, rel: &str, body: &str) {
            let path = self.root.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, body).unwrap();
        }

        fn path(&self) -> PathBuf {
            self.root.clone()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.root).ok();
        }
    }

    /// 两个核的初始快照；`CPU_B` 是它之后的一次快照（idle +200、总量 +400）。
    const CPU_A: &str = "cpu  200 0 100 2000 0 0 0 0 0 0\n\
                         cpu0 100 0 50 1000 0 0 0 0 0 0\n\
                         cpu1 100 0 50 1000 0 0 0 0 0 0\n";
    const CPU_B: &str = "cpu  500 0 200 2400 0 0 0 0 0 0\n\
                         cpu0 250 0 100 1200 0 0 0 0 0 0\n\
                         cpu1 250 0 100 1200 0 0 0 0 0 0\n";

    const DF_OK: &str = "Filesystem  1024-blocks      Used Available Capacity Mounted on\n\
                         /dev/sda1    104857600  26214400  78643200      25% /\n";

    fn base_proc(f: &Fixture) {
        f.write("stat", CPU_A);
        f.write(
            "meminfo",
            "MemTotal:       16384000 kB\n\
             MemFree:         2000000 kB\n\
             MemAvailable:   12000000 kB\n\
             Cached:          3000000 kB\n",
        );
        f.write("loadavg", "0.52 0.58 0.59 2/1234 56789\n");
        f.write("uptime", "12345.67 8901.23\n");
        f.write("sys/kernel/hostname", "mail.example.test\n");
    }

    fn clock(start_ms: i64) -> (Arc<AtomicI64>, MillisClock) {
        let handle = Arc::new(AtomicI64::new(start_ms));
        let clock: MillisClock = {
            let handle = Arc::clone(&handle);
            Arc::new(move || handle.load(Ordering::SeqCst))
        };
        (handle, clock)
    }

    fn collector(f: &Fixture, runner: Arc<FakeRunner>, clock: MillisClock) -> TelemetryCollector {
        TelemetryCollector::new(f.path(), runner, clock, 4242)
    }

    #[test]
    fn telemetry_uses_the_baseline_intervals_and_falls_back_to_one_hour() {
        let f = Fixture::new("intervals");
        base_proc(&f);
        let c = collector(&f, FakeRunner::new("", ""), clock(0).1);

        for (range, interval_ms, _) in RANGES {
            let body = c.telemetry(Some(range));
            assert_eq!(body["timeframe"], *range, "档位应原样回显");
            assert_eq!(body["intervalMs"], *interval_ms, "{range} 的采样间隔");
        }

        // 非法 range 不得被透传（因而也无从注入），一律回落 1h。
        let bogus = c.telemetry(Some("../../etc/passwd"));
        assert_eq!(bogus["timeframe"], "1h");
        assert_eq!(bogus["intervalMs"], 60_000);
        assert_eq!(c.telemetry(None)["timeframe"], "1h");
    }

    #[test]
    fn cpu_is_differential_so_the_first_sample_has_nothing_to_compare_against() {
        let f = Fixture::new("cpu");
        base_proc(&f);
        let c = collector(&f, FakeRunner::new("", ""), clock(0).1);

        // 构造时把基线设成当前快照 ⇒ 第一次差分是 0（基线的构造函数亦然）。
        assert_eq!(c.sample().cpu_percent, 0.0);

        // idle +200、总量 +400 ⇒ 一半忙。
        f.write("stat", CPU_B);
        assert_eq!(c.sample().cpu_percent, 50.0);
    }

    #[test]
    fn daemons_come_from_proc_comm_and_an_absent_one_stays_stopped() {
        let f = Fixture::new("daemons");
        base_proc(&f);
        f.write("100/comm", "qmgr\n");
        f.write("100/statm", "500 100 0 0 0 0 0\n"); // 100 页 → 0.4 MB
        f.write("101/comm", "dovecot\n");
        f.write("101/statm", "500 256 0 0 0 0 0\n"); // 1.0 MB
        f.write("102/comm", "bash\n"); // 不是守护进程
        f.write("103/comm", "node\n"); // 基线刻意排除的通用名
        f.write("4242/statm", "1 512 0 0 0 0 0\n"); // 本进程 → 2.0 MB

        let c = collector(&f, FakeRunner::new("", ""), clock(0).1);
        let body = c.telemetry(None);
        let daemons = body["current"]["daemons"].as_array().unwrap();
        assert_eq!(daemons.len(), 6, "六个槽位恒在，缺席的也不许消失");

        let by_id = |id: &str| {
            daemons
                .iter()
                .find(|d| d["id"] == id)
                .unwrap_or_else(|| panic!("缺少守护进程 {id}"))
                .clone()
        };
        assert_eq!(by_id("postfix")["status"], "ACTIVE");
        assert_eq!(by_id("postfix")["pid"], 100);
        assert_eq!(by_id("postfix")["memoryMb"], 0.4);
        assert_eq!(by_id("dovecot")["status"], "ACTIVE");
        assert_eq!(by_id("dovecot")["pid"], 101);
        assert_eq!(by_id("opendkim")["status"], "STOPPED");
        assert_eq!(by_id("opendkim")["pid"], 0);
        assert_eq!(by_id("mailstack-web")["status"], "ACTIVE");
        assert_eq!(by_id("mailstack-web")["pid"], 4242);
        assert_eq!(by_id("mailstack-web")["memoryMb"], 2.0);
        assert_eq!(by_id("mailstack-webmail")["status"], "STOPPED");
        assert_eq!(by_id("fail2ban")["status"], "STOPPED");
        // 守护进程的 CPU 份额基线从不计算，保持 0（不是「读不到」）。
        assert_eq!(by_id("postfix")["cpuPercent"], 0.0);
        assert_eq!(body["current"]["totalDaemonMemoryMb"], 3.4);
    }

    #[test]
    fn several_processes_of_one_daemon_are_summed() {
        let f = Fixture::new("summing");
        base_proc(&f);
        f.write("100/comm", "qmgr\n");
        f.write("100/statm", "500 100 0 0 0 0 0\n"); // 0.4 MB
        f.write("104/comm", "pickup\n");
        f.write("104/statm", "500 256 0 0 0 0 0\n"); // 1.0 MB

        let c = collector(&f, FakeRunner::new("", ""), clock(0).1);
        let body = c.telemetry(None);
        let postfix = body["current"]["daemons"]
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["id"] == "postfix")
            .unwrap()
            .clone();
        assert_eq!(postfix["memoryMb"], 1.4, "同一守护进程的多个进程要相加");
        assert_ne!(
            postfix["pid"], 0,
            "pid 取第一个被看到的进程（顺序不定，但必须有）"
        );
    }

    #[test]
    fn queue_totals_come_from_postqueue_and_deferred_needs_a_delay_reason() {
        let f = Fixture::new("queue");
        base_proc(&f);
        let postqueue = concat!(
            "{\"queue_id\":\"A\",\"recipients\":[{\"address\":\"a@example.test\",\"delay_reason\":\"connect timeout\"}]}\n",
            "{\"queue_id\":\"B\",\"recipients\":[{\"address\":\"c@example.test\"}]}\n",
            "\n",
            "not json at all\n"
        );
        let c = collector(&f, FakeRunner::new(DF_OK, postqueue), clock(0).1);
        let point = c.sample();
        assert_eq!(point.queue_total, 2, "非 JSON 行不算队列条目");
        assert_eq!(
            point.queue_deferred, 1,
            "只有带 delay_reason 的收件人算延迟"
        );
    }

    #[test]
    fn disk_usage_is_parsed_from_df_and_refreshed_at_most_once_a_minute() {
        let f = Fixture::new("disk");
        base_proc(&f);
        let (now, clock) = clock(1_000);
        let runner = FakeRunner::new(DF_OK, "");
        let c = collector(&f, Arc::clone(&runner), clock);

        let first = c.telemetry(None);
        assert_eq!(first["current"]["diskTotalGb"], 100.0);
        assert_eq!(first["current"]["diskUsedGb"], 25.0);
        assert_eq!(first["current"]["diskUsagePercent"], 25.0);
        assert_eq!(runner.df_calls(), 1);

        // 一分钟之内不重跑：磁盘用量不是每 2 秒就会变的东西。
        c.telemetry(None);
        assert_eq!(runner.df_calls(), 1);

        now.store(1_000 + DISK_REFRESH_MS, Ordering::SeqCst);
        c.telemetry(None);
        assert_eq!(runner.df_calls(), 2);
    }

    #[test]
    fn an_unparseable_df_leaves_disk_at_zero_rather_than_guessing() {
        let f = Fixture::new("dfbad");
        base_proc(&f);
        let c = collector(
            &f,
            FakeRunner::new(
                "Filesystem 1024-blocks Used Available Capacity Mounted on\n",
                "",
            ),
            clock(0).1,
        );
        let body = c.telemetry(None);
        assert_eq!(body["current"]["diskTotalGb"], 0.0);
        assert_eq!(body["current"]["diskUsagePercent"], 0.0);
    }

    #[test]
    fn the_one_minute_ring_takes_every_cycle_and_the_others_are_time_gated() {
        let f = Fixture::new("rings");
        base_proc(&f);
        let (now, clock) = clock(0);
        let c = collector(&f, FakeRunner::new("", ""), clock);

        c.sample(); // t = 0：所有档都进第一个点
        now.store(1_000, Ordering::SeqCst);
        c.sample(); // t = 1s：只有 1m 档到期
        assert_eq!(c.telemetry(Some("1m"))["samplingCount"], 2);
        assert_eq!(c.telemetry(Some("1h"))["samplingCount"], 1);

        now.store(3_600_000, Ordering::SeqCst);
        c.sample(); // t = 1h：所有档都到期
        assert_eq!(c.telemetry(Some("1m"))["samplingCount"], 3);
        assert_eq!(c.telemetry(Some("1h"))["samplingCount"], 2);
        assert_eq!(c.telemetry(Some("3d"))["samplingCount"], 2);
    }

    #[test]
    fn an_unsampled_collector_reports_zero_points_but_still_fills_current() {
        let f = Fixture::new("empty");
        base_proc(&f);
        let c = collector(&f, FakeRunner::new(DF_OK, ""), clock(0).1);

        let body = c.telemetry(Some("1m"));
        assert_eq!(body["samplingCount"], 0, "没采过样就该是 0，而不是 1");
        assert_eq!(body["points"].as_array().unwrap().len(), 0);
        // 即时采样只填 `current`，不进 `points` —— 否则前端会以为历史只有一段。
        assert_eq!(body["current"]["cores"], 2);
        assert_eq!(body["current"]["hostname"], "mail.example.test");
        assert_eq!(body["current"]["uptimeSec"], 12345);
        assert_eq!(body["summary"]["currentLoad"][0], 0.52);
        assert_eq!(body["summary"]["avgCpu"], 0.0);
    }

    #[test]
    fn missing_mem_available_falls_back_to_mem_free_instead_of_reporting_nothing() {
        // 与 `core::sysinfo::read_meminfo` 的 fail-loud 契约不同：遥测这条路由的
        // 形状里没有「读不到」的位置，基线也是退到 MemFree。
        let f = Fixture::new("memfallback");
        base_proc(&f);
        f.write(
            "meminfo",
            "MemTotal:       16384000 kB\nMemFree:         2000000 kB\n",
        );
        let c = collector(&f, FakeRunner::new("", ""), clock(0).1);
        let body = c.telemetry(None);
        assert_eq!(body["current"]["systemMemoryTotalMb"], 16000.0);
        assert_eq!(body["current"]["systemMemoryUsedMb"], 14046.9);
        assert_eq!(body["current"]["systemMemoryPercent"], 87.8);
    }

    #[test]
    fn the_response_carries_every_field_the_frontend_type_declares() {
        let f = Fixture::new("shape");
        base_proc(&f);
        let c = collector(&f, FakeRunner::new(DF_OK, ""), clock(0).1);
        c.sample();
        let body = c.telemetry(None);

        for key in [
            "timeframe",
            "intervalMs",
            "samplingCount",
            "current",
            "summary",
            "points",
        ] {
            assert!(body.get(key).is_some(), "顶层缺字段 {key}");
        }
        for key in [
            "cpuPercent",
            "totalDaemonMemoryMb",
            "systemMemoryUsedMb",
            "systemMemoryTotalMb",
            "systemMemoryPercent",
            "loadAvg",
            "uptimeSec",
            "daemons",
            "cores",
            "hostname",
            "diskTotalGb",
            "diskUsedGb",
            "diskUsagePercent",
        ] {
            assert!(body["current"].get(key).is_some(), "current 缺字段 {key}");
        }
        for key in [
            "avgCpu",
            "maxCpu",
            "currentCpu",
            "avgMemoryMb",
            "maxMemoryMb",
            "currentMemoryMb",
            "avgSystemMemPercent",
            "maxSystemMemPercent",
            "currentSystemMemPercent",
            "currentLoad",
        ] {
            assert!(body["summary"].get(key).is_some(), "summary 缺字段 {key}");
        }
        let point = &body["points"][0];
        for key in [
            "timestamp",
            "cpuPercent",
            "memoryMb",
            "systemMemoryPercent",
            "systemMemoryUsedMb",
            "systemMemoryTotalMb",
            "load1",
            "load5",
            "load15",
            "queueTotal",
            "queueDeferred",
            "daemons",
        ] {
            assert!(point.get(key).is_some(), "point 缺字段 {key}");
        }
        // 时间戳必须是前端 `new Date()` 能解析的 ISO 8601。
        let timestamp = point["timestamp"].as_str().unwrap();
        assert!(
            timestamp.contains('T') && (timestamp.ends_with("+00:00") || timestamp.ends_with('Z')),
            "非法时间戳 {timestamp}"
        );
    }
}
