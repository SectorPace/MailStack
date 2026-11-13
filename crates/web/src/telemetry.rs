use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mailstack_core::exec::{CommandOutput, CommandRunner, SystemCommandRunner};
use serde_json::{json, Value};

pub type MillisClock = Arc<dyn Fn() -> i64 + Send + Sync>;

pub const RANGES: &[(&str, i64, usize)] = &[
    ("1m", 2_000, 30),
    ("5m", 5_000, 60),
    ("30m", 30_000, 60),
    ("1h", 60_000, 60),
    ("6h", 300_000, 72),
    ("24h", 900_000, 96),
    ("3d", 3_600_000, 72),
];

const DEFAULT_RANGE_INDEX: usize = 3;

const FULL_SCAN_EVERY_CYCLES: u32 = 30;

const PAGE_SIZE_BYTES: u64 = 4096;

const DISK_REFRESH_MS: i64 = 60_000;

const QUEUE_REFRESH_MS: i64 = 60_000;

const SUBPROCESS_TIMEOUT: Duration = Duration::from_secs(5);

const DAEMON_ORDER: &[&str] = &[
    "mailstackd",
    "mailstack-imap",
    "mailstack-web",
    "mailstack-webmail",
];

const COMM_TO_DAEMON: &[(&str, &str)] = &[
    ("mailstackd", "mailstackd"),
    ("mailstack-imap", "mailstack-imap"),
    ("mailstack-webmail", "mailstack-webmail"),
    ("mailstack-webmai", "mailstack-webmail"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CpuTimes {
    idle: u64,
    total: u64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct MemDetail {
    total_mb: f64,
    used_mb: f64,
    percent: f64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct DiskInfo {
    total_gb: f64,
    used_gb: f64,
    percent: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct QueueMetrics {
    total: u64,
    deferred: u64,
}

#[derive(Debug, Clone, PartialEq)]
struct DaemonStat {
    id: &'static str,
    pid: u32,
    memory_mb: f64,
    cpu_percent: f64,
    status: &'static str,
}

#[derive(Debug, Clone, PartialEq)]
struct Point {
    ts_ms: i64,
    cpu_percent: f64,

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

    disk_updated_ms: Option<i64>,

    queue: QueueMetrics,

    queue_updated_ms: Option<i64>,
}

pub struct TelemetryCollector {
    inner: Mutex<Inner>,
    proc_root: PathBuf,
    runner: Arc<dyn CommandRunner>,
    clock: MillisClock,

    web_pid: u32,
}

impl TelemetryCollector {
    pub fn system() -> Self {
        Self::new(
            mailstack_core::sysinfo::system_proc_root(),
            Arc::new(SystemCommandRunner),
            Arc::new(|| time::OffsetDateTime::now_utc().unix_timestamp_nanos() as i64 / 1_000_000),
            std::process::id(),
        )
    }

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
                queue: QueueMetrics::default(),
                queue_updated_ms: None,
            }),
            proc_root,
            runner,
            clock,
            web_pid,
        }
    }

    fn sample(&self) -> Point {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        self.sample_locked(&mut inner)
    }

    pub fn start_sampling(self: &Arc<Self>, interval: Duration) -> tokio::task::JoinHandle<()> {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;

                let sampler = Arc::clone(&this);
                let _ = tokio::task::spawn_blocking(move || sampler.sample()).await;
            }
        })
    }

    pub fn telemetry(&self, range: Option<&str>) -> Value {
        let timeframe = crate::contract::normalize_telemetry_range(range);
        let index = RANGES
            .iter()
            .position(|(name, _, _)| *name == timeframe)
            .unwrap_or(DEFAULT_RANGE_INDEX);
        let interval_ms = RANGES[index].1;

        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());

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

        let loads = load.map(|l| [l.one, l.five, l.fifteen]);
        let mem_available = self.proc_root.join("meminfo").is_file();
        let mut unavailable: Vec<&str> = Vec::new();
        if uptime.is_none() {
            unavailable.push("uptime");
        }
        if loads.is_none() {
            unavailable.push("loadavg");
        }
        if !mem_available {
            unavailable.push("meminfo");
        }

        json!({
            "timeframe": timeframe,
            "intervalMs": interval_ms,
            "samplingCount": points.len(),
            "unavailable": unavailable,
            "current": {
                "cpuPercent": latest.cpu_percent,
                "totalDaemonMemoryMb": total_daemon_mb,
                "systemMemoryUsedMb": mem.used_mb,
                "systemMemoryTotalMb": mem.total_mb,
                "systemMemoryPercent": mem.percent,
                "loadAvg": loads,
                "uptimeSec": uptime,
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

    fn sample_locked(&self, inner: &mut Inner) -> Point {
        let now = (self.clock)();
        let cpu = self.sample_cpu_locked(inner);
        let mem = self.read_mem();
        let (total_daemon_mb, daemons) = self.daemons_locked(inner);

        let queue = self.queue_locked(inner);
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

    fn sample_cpu_locked(&self, inner: &mut Inner) -> f64 {
        let now = read_cpu_times(&self.proc_root);
        if now.is_empty() {
            return 0.0;
        }

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
                entry.memory_mb = round1(entry.memory_mb + rss_mb);
                entry.status = "ACTIVE";
                if entry.pid == 0 {
                    entry.pid = pid;
                }
            }
        }

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

            inner.disk_updated_ms = Some(now);
        }
        inner.disk
    }

    fn read_disk(&self) -> Option<DiskInfo> {
        let output = self.run_subprocess("df", &["-kP", "/"])?;
        if output.status != 0 {
            return None;
        }
        parse_df_k(output.stdout.as_str())
    }

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
            let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
            let _ = tx.send(runner.run(&program, &arg_refs).ok());
        });
        rx.recv_timeout(SUBPROCESS_TIMEOUT).ok().flatten()
    }

    fn queue_locked(&self, inner: &mut Inner) -> QueueMetrics {
        let now = (self.clock)();
        let stale = inner
            .queue_updated_ms
            .map(|last| now - last >= QUEUE_REFRESH_MS)
            .unwrap_or(true);
        if stale {
            inner.queue = self.queue_metrics();

            inner.queue_updated_ms = Some(now);
        }
        inner.queue
    }

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

fn usage(total: u64, idle: u64, old_total: u64, old_idle: u64) -> f64 {
    let diff_total = total.saturating_sub(old_total);
    let diff_idle = idle.saturating_sub(old_idle);
    if diff_total == 0 {
        return 0.0;
    }
    let ratio = (diff_total - diff_idle.min(diff_total)) as f64 / diff_total as f64;
    round1((ratio * 100.0).clamp(0.0, 100.0))
}

fn read_cpu_times(proc_root: &Path) -> Vec<CpuTimes> {
    let Ok(text) = std::fs::read_to_string(proc_root.join("stat")) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for line in text.lines() {
        let Some(rest) = line.strip_prefix("cpu") else {
            continue;
        };

        let Some(first) = rest.chars().next() else {
            continue;
        };
        if !first.is_ascii_digit() {
            continue;
        }

        let counters = rest.trim_start_matches(|c: char| c.is_ascii_digit());
        let fields: Vec<u64> = counters
            .split_whitespace()
            .filter_map(|v| v.parse().ok())
            .collect();
        if fields.len() < 8 {
            continue;
        }

        out.push(CpuTimes {
            idle: fields[3],
            total: fields[..8].iter().sum(),
        });
    }
    out
}

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

fn ms_to_iso(ms: i64) -> String {
    let seconds = ms.div_euclid(1000);
    let sub_ms = ms.rem_euclid(1000) as u32;
    let dt = time::OffsetDateTime::from_unix_timestamp(seconds)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH)
        .replace_nanosecond(sub_ms * 1_000_000)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    mailstack_core::time_fmt::format_iso8601(dt)
}

fn round1(value: f64) -> f64 {
    if !value.is_finite() {
        return 0.0;
    }
    (value * 10.0).round() / 10.0
}

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

        fn postqueue_calls(&self) -> usize {
            self.calls
                .lock()
                .unwrap()
                .iter()
                .filter(|p| *p == "postqueue")
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

        assert_eq!(c.sample().cpu_percent, 0.0);

        f.write("stat", CPU_B);
        assert_eq!(c.sample().cpu_percent, 50.0);
    }

    #[test]
    fn daemons_come_from_proc_comm_and_an_absent_one_stays_stopped() {
        let f = Fixture::new("daemons");
        base_proc(&f);
        f.write("100/comm", "mailstackd\n");
        f.write("100/statm", "500 100 0 0 0 0 0\n");
        f.write("101/comm", "mailstack-imap\n");
        f.write("101/statm", "500 256 0 0 0 0 0\n");
        f.write("102/comm", "bash\n");
        f.write("103/comm", "node\n");
        f.write("4242/comm", "mailstack-web\n");
        f.write("4242/statm", "1 512 0 0 0 0 0\n");

        let c = collector(&f, FakeRunner::new("", ""), clock(0).1);
        let body = c.telemetry(None);
        let daemons = body["current"]["daemons"].as_array().unwrap();
        assert_eq!(daemons.len(), 4, "四个槽位恒在，缺席的也不许消失");

        let by_id = |id: &str| {
            daemons
                .iter()
                .find(|d| d["id"] == id)
                .unwrap_or_else(|| panic!("缺少守护进程 {id}"))
                .clone()
        };
        assert_eq!(by_id("mailstackd")["status"], "ACTIVE");
        assert_eq!(by_id("mailstackd")["pid"], 100);
        assert_eq!(by_id("mailstackd")["memoryMb"], 0.4);
        assert_eq!(by_id("mailstack-imap")["status"], "ACTIVE");
        assert_eq!(by_id("mailstack-imap")["pid"], 101);
        assert_eq!(by_id("mailstack-web")["status"], "ACTIVE");
        assert_eq!(by_id("mailstack-web")["pid"], 4242);
        assert_eq!(by_id("mailstack-web")["memoryMb"], 2.0);
        assert_eq!(by_id("mailstack-webmail")["status"], "STOPPED");
        assert_eq!(by_id("mailstack-webmail")["pid"], 0);

        assert_eq!(by_id("mailstackd")["cpuPercent"], 0.0);
        assert_eq!(body["current"]["totalDaemonMemoryMb"], 3.4);
    }

    #[test]
    fn several_processes_of_one_daemon_are_summed() {
        let f = Fixture::new("summing");
        base_proc(&f);
        f.write("100/comm", "mailstackd\n");
        f.write("100/statm", "500 100 0 0 0 0 0\n");
        f.write("104/comm", "mailstackd\n");
        f.write("104/statm", "500 256 0 0 0 0 0\n");

        let c = collector(&f, FakeRunner::new("", ""), clock(0).1);
        let body = c.telemetry(None);
        let daemon = body["current"]["daemons"]
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["id"] == "mailstackd")
            .unwrap()
            .clone();
        assert_eq!(daemon["memoryMb"], 1.4, "同一守护进程的多个进程要相加");
        assert_ne!(
            daemon["pid"], 0,
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
    fn postqueue_is_not_run_on_every_sample() {
        let f = Fixture::new("queuecache");
        base_proc(&f);
        let postqueue = "{\"queue_id\":\"A\",\"recipients\":[{\"address\":\"a@example.test\"}]}\n";
        let (now, clock) = clock(0);
        let runner = FakeRunner::new(DF_OK, postqueue);
        let c = collector(&f, Arc::clone(&runner), clock);

        for tick in 0..30 {
            now.store(tick * 2_000, Ordering::SeqCst);
            c.sample();
        }
        assert!(
            runner.postqueue_calls() <= 2,
            "60 秒内跑了 {} 次 postqueue（应 ≤ 2：首采一次 + 60 秒后一次）",
            runner.postqueue_calls()
        );

        let point = c.sample();
        assert_eq!(point.queue_total, 1, "缓存期间队列读数不得退化成 0");

        now.store(QUEUE_REFRESH_MS + 1, Ordering::SeqCst);
        c.sample();
        assert_eq!(runner.postqueue_calls(), 2, "60 秒后应刷新一次");
    }

    #[test]
    fn unreadable_proc_entries_are_reported_as_unavailable_not_as_zero() {
        let f = Fixture::new("unavailable");
        let c = collector(&f, FakeRunner::new("", ""), clock(0).1);

        let body = c.telemetry(None);
        assert!(
            body["current"]["uptimeSec"].is_null(),
            "读不到 uptime 时必须回 null，而不是 0（前端会渲染成「刚启动」）：{}",
            body["current"]["uptimeSec"]
        );
        assert!(
            body["current"]["loadAvg"].is_null(),
            "读不到 loadavg 时必须回 null，而不是 [0,0,0]（渲染成「空闲」）：{}",
            body["current"]["loadAvg"]
        );
        let unavailable = body["unavailable"].as_array().unwrap();
        for field in ["uptime", "loadavg", "meminfo"] {
            assert!(
                unavailable.iter().any(|item| item == field),
                "`unavailable` 必须登记 {field}：{unavailable:?}"
            );
        }

        let ok = Fixture::new("available");
        base_proc(&ok);
        let c = collector(&ok, FakeRunner::new(DF_OK, ""), clock(0).1);
        let body = c.telemetry(None);
        assert_eq!(body["current"]["uptimeSec"], 12345);
        assert_eq!(body["current"]["loadAvg"][0], 0.52);
        assert_eq!(body["unavailable"].as_array().unwrap().len(), 0);
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

        c.sample();
        now.store(1_000, Ordering::SeqCst);
        c.sample();
        assert_eq!(c.telemetry(Some("1m"))["samplingCount"], 2);
        assert_eq!(c.telemetry(Some("1h"))["samplingCount"], 1);

        now.store(3_600_000, Ordering::SeqCst);
        c.sample();
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

        assert_eq!(body["current"]["cores"], 2);
        assert_eq!(body["current"]["hostname"], "mail.example.test");
        assert_eq!(body["current"]["uptimeSec"], 12345);
        assert_eq!(body["summary"]["currentLoad"][0], 0.52);
        assert_eq!(body["summary"]["avgCpu"], 0.0);
    }

    #[test]
    fn missing_mem_available_falls_back_to_mem_free_instead_of_reporting_nothing() {
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

        let timestamp = point["timestamp"].as_str().unwrap();
        assert!(
            timestamp.contains('T') && (timestamp.ends_with("+00:00") || timestamp.ends_with('Z')),
            "非法时间戳 {timestamp}"
        );
    }
}
