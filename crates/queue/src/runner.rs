//! 队列运行器：调度、并发限流、退避重试、DSN 退信与快速失败（规格书 §5.8、§5.10.3）。
//!
//! ## 一次投递的决策树
//!
//! ```text
//! 收到投递结果
//!   ├─ 成功            → 移除该批收件人；条目空了就删文件
//!   ├─ 永久失败 (5xx)  → 立即退信（不重试）
//!   └─ 临时失败/未知   → 退避重试；达到上限则退信
//! ```
//!
//! ## 快速失败（§5.10.3 R-25-3）
//!
//! 出站 25 被封时，「每条消息各重试 10 次」会把队列撑成重试风暴，而运维看到的
//! 只是「队列在涨」。因此连续失败达到阈值后，运行器进入**快速失败**：每轮只允许
//! 一次探测投递（半开），其余条目原样留在队列里，并在报告里给出**明确结论**
//! （「出站 25 被封，请配置中继」）。结论持久化，重启后仍然可见。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use mailstack_smtp::{select_outbound_route, OutboundRoute, RelayEndpoint, RelayPolicy};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::backoff::BackoffPolicy;
use crate::delivery::{DeliveryFailure, DeliveryTarget, FailureClass, Transport};
use crate::dsn::{build_dsn, dsn_envelope_from, dsn_recipient, DsnRequest};
use crate::entry::{EntryKind, QueueEntry};
use crate::error::QueueResult;
use crate::signing::{MessageSigner, SigningTransport};
use crate::store::{OutboundHealthState, QueueStore};

/// 运行器配置。
#[derive(Debug, Clone)]
pub struct QueueConfig {
    /// 并发投递上限。生产值来自 `/etc/mailstack/settings.json` 的 `relayConcurrency`。
    pub relay_concurrency: u32,
    pub backoff: BackoffPolicy,
    /// `Reporting-MTA` 与本机 `MAILER-DAEMON@` 使用的域名。
    pub reporting_mta: String,
    /// 本机纳管域名（决定「本地投递」还是「外域投递」）。
    pub managed_domains: Vec<String>,
    /// 连续失败多少次后判定「出站不可用」并转入快速失败。
    pub blocked_threshold: u32,
}

impl Default for QueueConfig {
    fn default() -> Self {
        Self {
            relay_concurrency: 20,
            backoff: BackoffPolicy::default(),
            reporting_mta: "localhost".to_string(),
            // 空表 = fail-closed：所有收件人都按外域处理，绝不把外域邮件当本地投。
            managed_domains: Vec::new(),
            blocked_threshold: DEFAULT_BLOCKED_THRESHOLD,
        }
    }
}

/// 出站健康判据（§5.10.3 R-25-3 的对外结论）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundHealth {
    pub consecutive_failures: u32,
    /// 是否已判定出站不可用（转入快速失败）。
    pub blocked: bool,
    /// 结论是否为「必须配置中继」。
    pub needs_relay: bool,
    /// 面向运维的结论文案。
    pub message: String,
}

/// 连续失败达到多少次判定「出站被封」。
pub const DEFAULT_BLOCKED_THRESHOLD: u32 = 10;

/// 从**持久化的失败计数**推导出对外结论。
///
/// 抽成自由函数是为了让只读聚合面（`snapshot` / `metrics.realtime`）不必为了
/// 读一个结论就构造整个 [`QueueRunner`]（那需要本地与远端两个传输、签名器与信号量）。
/// 结论的算法只有这一份 —— 分叉出第二份就等于让管理台与调度器各说各话。
pub fn outbound_health_from(
    failures: u32,
    blocked_threshold: u32,
    relay_host: Option<&str>,
) -> OutboundHealth {
    let threshold = blocked_threshold.max(1);
    let blocked = failures >= threshold;
    let needs_relay = blocked && relay_host.is_none();

    let message = if !blocked {
        "outbound delivery is healthy".to_string()
    } else if needs_relay {
        format!(
            "Outbound port 25 is blocked ({failures} consecutive delivery failures); \
             configure a relay (smarthost)"
        )
    } else {
        format!(
            "Relay {} is failing repeatedly ({failures} consecutive delivery failures); \
             verify credentials and TLS mode",
            relay_host.unwrap_or_default()
        )
    };

    OutboundHealth {
        consecutive_failures: failures,
        blocked,
        needs_relay,
        message,
    }
}

/// 一轮调度的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueRunReport {
    /// 本轮到期的条目数。
    pub considered: usize,
    /// 成功投递的收件人次数。
    pub delivered: usize,
    /// 仍留在队列中等待重试的条目数。
    pub deferred: usize,
    /// 触发退信的收件人次数。
    pub bounced: usize,
    /// 无法退信而被迫丢弃的次数（null sender 或退信自身失败）。
    pub discarded: usize,
    /// 本轮是否因「出站不可用」而走了快速失败。
    pub fast_failed: bool,
    /// 本轮结束时的队列积压量（待投递条目数）。
    ///
    /// 与出站健康一起构成 §5.10.3 R-25-5 要求的「队列积压量」检查项。
    pub backlog: usize,
    /// 本轮处理中因落盘等内部错误而失败的条目数。
    ///
    /// 单条失败不中断整轮（只记日志），但只记日志不计数的话，运维从报告里
    /// 看不出「这一轮有 N 条没能处理」—— 这里把 `Ok(Err)` 也计入报告。
    pub failed: usize,
    /// 生效的中继并发上限（`relayConcurrency`，§5.9.8／Phase 2 验收第 5 条）。
    pub relay_concurrency: u32,
    pub outbound_health: OutboundHealth,
}

/// 队列的指标快照。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueMetrics {
    /// 队列积压量（条目数）。
    pub backlog: usize,
    /// 生效的中继并发上限。
    pub relay_concurrency: u32,
    pub outbound_health: OutboundHealth,
}

/// 单条条目的处理结果（内部累计量）。
#[derive(Debug, Default, Clone, Copy)]
struct EntryOutcome {
    delivered: usize,
    bounced: usize,
    discarded: usize,
    deferred: usize,
    fast_failed: bool,
}

/// 一笔待入队的 DSN 退信。
///
/// [`QueueRunner::apply_failure`] 只**决定**要退信；真正的入队由
/// [`QueueRunner::flush_bounces`] 在原条目状态落盘之后执行 —— 顺序即修复：
/// 先落盘、后退信，落盘失败就不会产生「磁盘收件人与退信不一致」的中间态。
#[derive(Debug)]
struct PendingBounce {
    /// 投递失败的收件人（DSN 的逐收件人状态块）。
    failed: Vec<String>,
    /// 失败原因（可能来自对端服务器，写出前会再经净化）。
    diagnostic: String,
    /// 对端状态码（若有）。
    code: Option<u16>,
}

impl EntryOutcome {
    fn merge(&mut self, other: EntryOutcome) {
        self.delivered += other.delivered;
        self.bounced += other.bounced;
        self.discarded += other.discarded;
        self.deferred += other.deferred;
        self.fast_failed |= other.fast_failed;
    }
}

/// 队列运行器。
pub struct QueueRunner {
    store: QueueStore,
    local: Arc<dyn Transport>,
    remote: Arc<dyn Transport>,
    config: QueueConfig,
    relay: Option<RelayEndpoint>,
    health: Mutex<OutboundHealthState>,
    /// 半开探测标记：快速失败期间每轮只放行一次远端尝试。
    half_open_used: AtomicBool,
    /// 5.9：`run_once` 重入标记。
    ///
    /// 原实现没有任何排他：两轮重叠时双方都会 `load_all()` 到**同一批**条目，
    /// 各自投递一次 → 收件人收到重复邮件，并且各自重置 `half_open_used`
    /// （快速失败期间的「只放行一次探测」也跟着失效）。
    /// store 侧没有 per-entry claim 标志，安全性此前完全依赖调用方（daemon）串行化 ——
    /// 而那只是一句注释，没有任何东西强制它。
    round_in_flight: AtomicBool,
    semaphore: Semaphore,
}

impl QueueRunner {
    /// 构造运行器。出站健康状态从磁盘读取，因此「出站不可用」的结论跨重启保留。
    ///
    /// `remote` 在这里被**无条件**套上 [`SigningTransport`]：调用方无论传进来什么
    /// 传输，外发邮件都必然经过 DKIM 签名决策，「一条未签名的出站路径」在本类型里
    /// 不可表达（见 `signing` 模块说明）。本地传输刻意不套 —— Dovecot 是本机自己的
    /// 用户，DKIM 的意义在于向外部接收方证明身份。
    pub fn new(
        store: QueueStore,
        local: Arc<dyn Transport>,
        remote: Arc<dyn Transport>,
        config: QueueConfig,
        relay: Option<RelayEndpoint>,
        signer: Arc<dyn MessageSigner>,
    ) -> Self {
        let health = store.load_health().unwrap_or_default();
        let permits = config.relay_concurrency.max(1) as usize;
        let remote: Arc<dyn Transport> = Arc::new(SigningTransport::new(remote, signer));
        Self {
            store,
            local,
            remote,
            config,
            relay,
            health: Mutex::new(health),
            half_open_used: AtomicBool::new(false),
            round_in_flight: AtomicBool::new(false),
            semaphore: Semaphore::new(permits),
        }
    }

    pub fn store(&self) -> &QueueStore {
        &self.store
    }

    /// 当前 生效的出站路由。
    ///
    /// **唯一**的路由来源：只要有中继配置就一律走中继，不存在退回直投的分支
    /// （INV-18 / INV-21）。DSN 退信走的也是它。
    pub fn outbound_route(&self) -> OutboundRoute {
        select_outbound_route(self.relay.as_ref())
    }

    /// 当前出站健康判据。
    pub fn outbound_health(&self) -> OutboundHealth {
        outbound_health_from(
            self.health_snapshot().consecutive_failures,
            self.config.blocked_threshold,
            self.relay.as_ref().map(|r| r.relayhost()).as_deref(),
        )
    }

    /// 调度一轮：处理所有已到期的条目。
    ///
    /// 需要 `Arc<Self>` 是因为各条目的投递要并发执行（受 `relayConcurrency` 约束）。
    pub async fn run_once(self: &Arc<Self>, now_unix: i64) -> QueueResult<QueueRunReport> {
        // 5.9：同一时刻只允许一轮在跑。
        //
        // 两轮重叠的后果不是「慢一点」，而是**重复投递**：双方都 `load_all()` 到
        // 同一批条目、都用同一份收件人列表去投，谁也看不见对方。
        // `compare_exchange` 而不是 `swap`：必须能分辨「我拿到了」与「别人在跑」。
        if self
            .round_in_flight
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(crate::error::QueueError::busy(
                "overlapping run_once would re-deliver the same entries",
            ));
        }
        // 用 guard 保证任何提前返回 / `?` 提前退出都会复位标记，
        // 否则一次错误就能让队列**永久停摆**（比重复投递更糟）。
        let _round_guard = RoundGuard(&self.round_in_flight);

        // 每轮重置半开标记：快速失败状态下也保留「一次探测机会」，否则出站恢复后
        // 队列会永远不再尝试，变成永久性停摆。
        self.half_open_used.store(false, Ordering::SeqCst);

        // 5.10：先清掉过期租约，再排除仍被有效租约持有的条目。
        //
        // 一条条目在「开始投递」与「把结果写回」之间，磁盘上没有任何它的状态
        // 变化。这段窗口里崩溃/掉电/停机取消，重启后它仍带全部收件人 —— 下一轮
        // 会整批重投。租约把这段窗口显式化：仍在租约内的条目**先跳过**，
        // 等租约过期再重试。
        //
        // 租约清理、租约枚举与全量读取都是同步文件 I/O（`read_dir` + 逐条 JSON
        // 解析**包括邮件正文**），不能占着 tokio worker 跑 —— 搬进
        // `spawn_blocking`（与 `store.len()` 的既有先例一致）。三者共用一个
        // 阻塞任务，少一次任务派生。
        let store = self.store.clone();
        let (entries, claimed) =
            tokio::task::spawn_blocking(
                move || -> QueueResult<(Vec<QueueEntry>, std::collections::HashSet<String>)> {
                    store.prune_claims(now_unix)?;
                    let claimed = store.claimed_ids(now_unix)?;
                    let entries = store.load_all()?;
                    Ok((entries, claimed))
                },
            )
            .await
            .map_err(|e| {
                crate::error::QueueError::Storage(format!("queue load task failed: {e}"))
            })??;
        let due: Vec<QueueEntry> = entries
            .into_iter()
            .filter(|entry| entry.is_due(now_unix) && !claimed.contains(&entry.id))
            .collect();

        // RelayPolicy（连同它背后的纳管域名克隆）每轮只构建一次，传给每条
        // 条目 —— 每条条目重建一遍纯属浪费（域名归一化 + 排序 + 去重）。
        let policy = RelayPolicy::new(self.config.managed_domains.iter().cloned());

        let mut tasks = JoinSet::new();
        for entry in due.iter().cloned() {
            // 认领必须在**这里**（spawn 之前）完成，而不是在任务内部：
            // 任务一多，两个任务并发认领同一条时就都拿到了。
            // `try_claim` 用 O_EXCL，只有一方能成功。
            if !self.store.try_claim(&entry.id, now_unix)? {
                continue;
            }
            let runner = Arc::clone(self);
            let policy = policy.clone();
            tasks.spawn(async move { runner.process(entry, now_unix, &policy).await });
        }

        let mut totals = EntryOutcome::default();
        let mut considered = 0usize;
        let mut failed = 0usize;
        let mut join_error: Option<crate::error::QueueError> = None;
        while let Some(joined) = tasks.join_next().await {
            match joined {
                Ok(Ok(outcome)) => {
                    considered += 1;
                    totals.merge(outcome);
                }
                Ok(Err(e)) => {
                    // 单条条目的落盘失败不应中断整轮调度，但要如实记录**并计数**：
                    // 只记日志不计数的话，报告看不出这一轮有多少条没能处理。
                    mailstack_core::warn::warn_with_detail(
                        "queue entry processing",
                        &e.to_string(),
                    );
                    failed += 1;
                    join_error.get_or_insert(e);
                }
                Err(e) => {
                    mailstack_core::warn::warn_with_detail("queue task join", &e.to_string());
                }
            }
        }

        // 结论落盘：重启后运维仍能看到「出站不可用」。
        let snapshot = self.health_snapshot();
        self.store.save_health(&snapshot)?;

        if let Some(err) = join_error {
            mailstack_core::warn::warn_with_detail("queue run had failures", &err.to_string());
        }

        // 积压量在调度之后统计，才反映「这一轮之后还剩多少」。
        // 同样是 `read_dir`，同样不占 async worker。
        let store = self.store.clone();
        let backlog = tokio::task::spawn_blocking(move || store.len())
            .await
            .map_err(|e| {
                crate::error::QueueError::Storage(format!("queue backlog task failed: {e}"))
            })??;

        Ok(QueueRunReport {
            considered,
            delivered: totals.delivered,
            deferred: totals.deferred,
            bounced: totals.bounced,
            discarded: totals.discarded,
            failed,
            fast_failed: totals.fast_failed,
            backlog,
            relay_concurrency: self.config.relay_concurrency.max(1),
            outbound_health: self.outbound_health(),
        })
    }

    /// 供指标上报的快照（§5.9.8 / §5.10.3 R-25-5）。
    ///
    /// 遥测采样需要「队列积压量 + 中继并发上限 + 出站健康」三者同时可见，否则
    /// 运维无法区分「投递慢」与「出站被封」。
    ///
    /// 积压量靠 `store.len()`（`read_dir`）统计，是同步文件 I/O —— 遥测每 2 秒
    /// 采样一次，不该每次都占用一个 async worker，因此本方法是 `async` 并把
    /// 计数搬进 `spawn_blocking`。
    pub async fn metrics_snapshot(&self) -> QueueMetrics {
        let store = self.store.clone();
        let backlog = tokio::task::spawn_blocking(move || store.len().unwrap_or(0))
            .await
            .unwrap_or(0);
        QueueMetrics {
            backlog,
            relay_concurrency: self.config.relay_concurrency.max(1),
            outbound_health: self.outbound_health(),
        }
    }

    /// 处理一条条目。
    async fn process(
        &self,
        mut entry: QueueEntry,
        now_unix: i64,
        policy: &RelayPolicy,
    ) -> QueueResult<EntryOutcome> {
        // 5.10：无论正常返回、提前 `?`、还是任务被取消/panic，租约都必须释放 ——
        // 否则该条目会被自己的租约挡住整整 CLAIM_TTL_SECONDS（默认 15 分钟）。
        // 用 Drop guard 而不是在函数末尾手写 release：`process` 里有多处 `?`。
        let _claim = ClaimGuard {
            store: self.store.clone(),
            id: entry.id.clone(),
        };

        let mut outcome = EntryOutcome::default();
        // 5.15：这一轮是否真的改过条目。
        //
        // 原实现无条件 `store.enqueue(&entry)` —— 于是「出站被封、快速失败」期间
        // 每一轮（10 秒）都会把**全部积压条目**原样重写一遍磁盘：内容一字未变，
        // 而恰恰是出站被封、积压最大、I/O 压力最该省的时候。
        let mut mutated = false;
        // DSN 退信先攒下，等原条目的更新状态落盘之后再入队（顺序见下方注释）。
        let mut pending_bounces: Vec<PendingBounce> = Vec::new();
        let route = self.outbound_route();
        let (local_recipients, remote_recipients) = self.partition(&entry, policy);

        // 并发限流：一次投递占用一个许可（relayConcurrency）。
        let _permit = self.semaphore.acquire().await;

        if !local_recipients.is_empty() {
            match self
                .local
                .deliver(&entry, DeliveryTarget::Local, &local_recipients)
                .await
            {
                Ok(receipt) => {
                    // 5.12：回执必须覆盖**全部**被尝试的收件人，否则「移除」就会
                    // 悄悄吞掉没被接受的那几个 —— 那些收件人既不会重试也不会退信，
                    // 等于静默丢信。
                    //
                    // 现在三条生产传输（LMTP / SMTP 中继 / 直投 / 签名包装）在成功
                    // 分支上都返回 `accepted == recipients.len()`，所以这个不变量今天
                    // 成立；但此前**没有任何东西强制它**，一次「部分成功也返回 Ok」
                    // 的实现改动就会变成静默丢信。这里把它钉成显式检查：
                    // 不满足就报错停下，宁可见红也不要悄悄少投一个收件人。
                    if receipt.accepted != local_recipients.len() {
                        return Err(crate::error::QueueError::invalid(format!(
                            "local transport reported {} accepted of {} attempted recipients \
                             (entry {}); refusing to drop the remainder silently",
                            receipt.accepted,
                            local_recipients.len(),
                            entry.id
                        )));
                    }
                    outcome.delivered += receipt.accepted;
                    remove_recipients(&mut entry, &local_recipients);
                    mutated = true;
                    entry.last_error = None;
                    entry.last_code = None;
                }
                Err(failure) => {
                    // 本地投递失败**不**计入出站健康：LMTP 出问题不代表外发 25 被封。
                    mutated = true;
                    self.apply_failure(
                        &mut entry,
                        &mut outcome,
                        &local_recipients,
                        failure,
                        now_unix,
                        &mut pending_bounces,
                    );
                }
            }
        }

        if !remote_recipients.is_empty() {
            if self.may_attempt_remote() {
                match self
                    .remote
                    .deliver(
                        &entry,
                        DeliveryTarget::Remote(route.clone()),
                        &remote_recipients,
                    )
                    .await
                {
                    Ok(receipt) => {
                        // 5.12：同本地分支，回执必须覆盖全部被尝试的收件人。
                        if receipt.accepted != remote_recipients.len() {
                            // 宁可见红（性质不变），但**先尽力落盘已经发生的进度**：
                            // 本地收件人可能已投递并从内存里摘掉，直接报错会把这份
                            // 进度丢在内存里，下一轮把本地收件人**再投一遍** ——
                            // 那是比报错更糟的静默重复投递。
                            if mutated {
                                self.persist_best_effort(&entry);
                            }
                            // 已判定要退信的收件人（apply_failure 已把它们从条目摘除）
                            // 的 DSN 也必须在这里入队：条目里已经没有他们，重试无从
                            // 补发，跳过 flush 就是静默丢信。flush 自带失败回收
                            // （入队失败会把收件人放回条目并写回）。
                            if !pending_bounces.is_empty() {
                                if let Err(error) = self.flush_bounces(
                                    &mut entry,
                                    &mut outcome,
                                    pending_bounces,
                                    now_unix,
                                ) {
                                    mailstack_core::warn::warn_with_detail(
                                        "queue bounce write-back",
                                        &error.to_string(),
                                    );
                                }
                            }
                            return Err(crate::error::QueueError::invalid(format!(
                                "remote transport reported {} accepted of {} attempted \
                                 recipients (entry {}); refusing to drop the remainder silently",
                                receipt.accepted,
                                remote_recipients.len(),
                                entry.id
                            )));
                        }
                        outcome.delivered += receipt.accepted;
                        remove_recipients(&mut entry, &remote_recipients);
                        mutated = true;
                        entry.last_error = None;
                        entry.last_code = None;
                        self.record_remote_success();
                    }
                    Err(failure) => {
                        self.record_remote_failure(&failure);
                        mutated = true;
                        self.apply_failure(
                            &mut entry,
                            &mut outcome,
                            &remote_recipients,
                            failure,
                            now_unix,
                            &mut pending_bounces,
                        );
                    }
                }
            } else {
                // 快速失败：出站已判定不可用，本轮不再逐条重试（避免重试风暴）。
                //
                // 5.15：这一分支**不改动** `entry`，因此 `mutated` 保持 false ——
                // 下面不会再把它原样重写一遍磁盘。
                outcome.fast_failed = true;
                outcome.deferred += 1;
            }
        }

        // 先落盘原条目的**最终**状态（全部收件人摘除、退避计数、失败原因都在这）。
        if entry.recipients.is_empty() {
            // 全部收件人已投递或已退信 → 条目使命完成。
            self.store.remove(&entry.id)?;
        } else if mutated {
            // 仍有未完成收件人（退避等待中，或本地/远端部分成功）→ 写回更新后的状态。
            entry.validate()?;
            self.store.enqueue(&entry)?;
        }
        // 否则：这一轮什么都没改（例如出站被封时的快速失败）。
        // 内容一字未变还去重写，只会在积压最大时制造无谓的 I/O 风暴。

        // ……然后才入队 DSN 退信。
        //
        // 顺序即正确性：DSN 入队**必须**发生在原条目状态落盘之后。反过来（先退信
        // 后落盘）时，落盘一步失败会让磁盘上的条目仍带着**全部**收件人 —— 下一轮
        // 整批重投：已投递的收件人收到重复邮件、失败的收件人收到重复退信。
        // 而落盘失败时上面的 `?` 已经提前返回，退信不会生成 —— 磁盘上的原条目
        // 仍带失败收件人，下一轮重投会重新生成同一封退信，不丢、不重。
        self.flush_bounces(&mut entry, &mut outcome, pending_bounces, now_unix)?;

        Ok(outcome)
    }

    /// 尽力把条目当前状态写回磁盘（失败只记日志，不向上传播）。
    ///
    /// 用于「马上要以错误返回、但内存里已经有真实进度」的路径：进度丢在内存里
    /// 等于把已投递的收件人再投一遍，那比返回错误更糟。
    fn persist_best_effort(&self, entry: &QueueEntry) {
        if let Err(error) = self.store.enqueue(entry) {
            mailstack_core::warn::warn_with_detail("queue entry write-back", &error.to_string());
        }
    }

    /// 把攒下的 DSN 退信逐封入队（调用前原条目状态必须已经落盘）。
    fn flush_bounces(
        &self,
        entry: &mut QueueEntry,
        outcome: &mut EntryOutcome,
        pending: Vec<PendingBounce>,
        now_unix: i64,
    ) -> QueueResult<()> {
        let mut first_error: Option<crate::error::QueueError> = None;
        for bounce in pending {
            let PendingBounce {
                failed,
                diagnostic,
                code,
            } = bounce;
            match self.bounce(entry, &failed, &diagnostic, code, now_unix) {
                Ok(true) => outcome.bounced += failed.len(),
                Ok(false) => outcome.discarded += failed.len(),
                Err(error) => {
                    // 退信入队失败：把失败的收件人**放回**条目并尽力写回，
                    // 让下一轮重投后重新生成退信 —— 而不是无声丢掉这批收件人
                    // （它们已经从磁盘条目里摘掉了，退信再没入队就是静默丢信）。
                    for recipient in &failed {
                        if !entry.recipients.contains(recipient) {
                            entry.recipients.push(recipient.clone());
                        }
                    }
                    first_error.get_or_insert(error);
                }
            }
        }
        if first_error.is_some() {
            self.persist_best_effort(entry);
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// 应用一次已判定的投递失败。
    ///
    /// 本方法**不再直接入队退信**（那是 [`Self::flush_bounces`] 在原条目落盘之后的
    /// 职责），因此不会失败：所有可能出错的 I/O 都被移出了这里。
    fn apply_failure(
        &self,
        entry: &mut QueueEntry,
        outcome: &mut EntryOutcome,
        attempted: &[String],
        failure: DeliveryFailure,
        now_unix: i64,
        pending: &mut Vec<PendingBounce>,
    ) {
        // 先摘掉本次**已经投出去**的收件人：它们既不重试、也不退信。
        // 少了这一步，一次部分成功（例如 LMTP 里一个用户已落箱、另一个超配额）
        // 会在重试时把已投递的收件人再投一遍，收件人会看到重复邮件。
        let accepted = failure.accepted.clone();
        if !accepted.is_empty() {
            outcome.delivered += accepted.len();
            remove_recipients(entry, &accepted);
        }
        let failed: Vec<String> = attempted
            .iter()
            .filter(|recipient| !accepted.contains(recipient))
            .cloned()
            .collect();
        if failed.is_empty() {
            // 全部收件人都已投递成功，只是整批以失败形态返回（部分成功的边界）。
            return;
        }

        match failure.class {
            FailureClass::Permanent => {
                // 5xx：重试无意义，退信（退信本体在原条目落盘后由 flush_bounces 入队）。
                remove_recipients(entry, &failed);
                pending.push(PendingBounce {
                    failed,
                    diagnostic: failure.message.clone(),
                    code: failure.code,
                });
            }
            FailureClass::Transient => {
                let exhausted = self.config.backoff.on_failure(
                    entry,
                    now_unix,
                    Some(failure.message.clone()),
                    failure.code,
                );
                if exhausted {
                    // 超过阈值 → 生成 DSN，不再无限重试（§5.8）。
                    remove_recipients(entry, &failed);
                    pending.push(PendingBounce {
                        failed,
                        diagnostic: failure.message,
                        code: failure.code,
                    });
                } else {
                    outcome.deferred += 1;
                }
            }
        }
    }

    /// 生成一封 DSN 退信报文并**入队**（INV-21：退信与用户邮件走同一条出站路径）。
    ///
    /// 返回是否确实生成了退信；`false` 表示被迫丢弃（防回环）。
    fn bounce(
        &self,
        entry: &QueueEntry,
        failed: &[String],
        diagnostic: &str,
        code: Option<u16>,
        now_unix: i64,
    ) -> QueueResult<bool> {
        // 双退信防护：null sender 的消息、以及退信自身，都**不得**再产生退信。
        if entry.kind == EntryKind::Bounce || entry.is_null_sender() {
            return Ok(false);
        }
        let Some(recipient) = dsn_recipient(entry) else {
            return Ok(false);
        };

        let message = build_dsn(&DsnRequest {
            reporting_mta: &self.config.reporting_mta,
            original: entry,
            failed_recipients: failed,
            diagnostic,
            status_code: code,
        });
        // 信封发件人为空（null sender）—— 退信自己失败时不会再退信。
        let mut dsn = QueueEntry::new(
            EntryKind::Bounce,
            dsn_envelope_from(),
            vec![recipient.to_string()],
            message,
            now_unix,
        )?;
        // 退信是**新**条目：只新增不覆盖 —— 一封撞了 id 的退信绝不能覆盖任何
        // 已经在队列里的邮件（撞车时 `enqueue_new` 会换 id）。
        self.store.enqueue_new(&mut dsn)?;
        Ok(true)
    }

    /// 按纳管域名把收件人分成「本地」与「外域」。
    ///
    /// 复用 [`RelayPolicy`] 的域名归一化，避免两处实现出现「大小写/空白」差异。
    /// 域名表为空时全部算外域 —— fail-closed，绝不把外部邮件当本地投递。
    /// 策略由调用方（`run_once`）每轮构建一次传入，而不是每条条目重建。
    fn partition(&self, entry: &QueueEntry, policy: &RelayPolicy) -> (Vec<String>, Vec<String>) {
        let mut local = Vec::new();
        let mut remote = Vec::new();
        for recipient in &entry.recipients {
            let domain = recipient
                .rsplit_once('@')
                .map(|(_, domain)| domain)
                .unwrap_or("");
            if policy.is_managed(domain) {
                local.push(recipient.clone());
            } else {
                remote.push(recipient.clone());
            }
        }
        (local, remote)
    }

    fn health_snapshot(&self) -> OutboundHealthState {
        match self.health.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    fn record_remote_success(&self) {
        // `unwrap_or_else(|p| p.into_inner())`：锁中毒只可能来自持锁线程 panic，
        // 而这里的临界区只做赋值。静默跳过会让「连续失败计数」停更 —— 出站已经
        // 恢复了管理台还显示被封（或反之），比 panic 更难排查。
        let mut guard = self
            .health
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.consecutive_failures = 0;
        guard.last_success_at = Some(mailstack_core::now_iso8601_utc());
        guard.last_failure = None;
    }

    fn record_remote_failure(&self, failure: &DeliveryFailure) {
        // 本机故障（例如 DKIM 签名失败）不是出站链路的问题。计进去会让运维看到
        // 「出站 25 被封，请配置中继」，然后去查一个完全无关的方向。
        if failure.local_fault {
            return;
        }
        // 5.11：**永久失败不得计入出站健康**。
        //
        // 这个计数驱动的结论是「25 端口被封，请配置中继」。而一次永久失败
        // （5xx：收件人不存在、邮箱已满、被策略拒收）恰恰说明**链路是通的** ——
        // 对端已经明确回了码。把它计进去，10 封「收件人不存在」的正常退信就能
        // 把整条出站链路判成「被封」，转入快速失败并停止全部外域投递，
        // 也就是**用正常退信自造一次全站故障**。
        //
        // 只有 Transient（连接超时、对端 4xx 过载、TLS 握手失败）才说明链路本身
        // 可能有问题，才该推进「被封」的判定。
        if failure.class != crate::delivery::FailureClass::Transient {
            return;
        }
        // 与 `record_remote_success` 相同的中毒纪律：计数停更比 panic 更难排查。
        let mut guard = self
            .health
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.consecutive_failures = guard.consecutive_failures.saturating_add(1);
        guard.last_failure = Some(failure.message.clone());
    }

    /// 是否允许本轮尝试远端投递。
    ///
    /// 健康时恒为真；判定不可用后每轮只放行一次（半开），既避免重试风暴，
    /// 又能在出站恢复后自动恢复投递。
    fn may_attempt_remote(&self) -> bool {
        let failures = self.health_snapshot().consecutive_failures;
        if failures < self.config.blocked_threshold.max(1) {
            return true;
        }
        !self.half_open_used.swap(true, Ordering::SeqCst)
    }
}

fn remove_recipients(entry: &mut QueueEntry, done: &[String]) {
    entry.recipients.retain(|r| !done.contains(r));
}

/// `run_once` 的重入标记守卫：任何退出路径都要复位。
///
/// 单独成类型而不是在函数末尾手动 store：`run_once` 里有多处 `?` 提前返回，
/// 手写复位的正确性依赖「以后没有人再加一个 `?`」—— 那种依赖迟早会破。
struct RoundGuard<'a>(&'a AtomicBool);

impl Drop for RoundGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// 投递租约守卫（5.10）：离开作用域即释放该条目的 claim。
///
/// `Drop` 不能返回错误，因此失败只记 warn —— 但**必须**留下痕迹：
/// 释放失败意味着这条条目要被自己的租约挡到过期，属于可观测异常。
struct ClaimGuard {
    store: QueueStore,
    id: String,
}

impl Drop for ClaimGuard {
    fn drop(&mut self) {
        if let Err(error) = self.store.release_claim(&self.id) {
            mailstack_core::warn::warn_with_detail("release queue claim", &error.to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delivery::{DeliveryFuture, DeliveryReceipt};
    use crate::signing::SigningOutcome;
    use mailstack_smtp::{validate_relay, RelayValidationRequest};
    use std::collections::VecDeque;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    /// 可编排的假传输：按脚本依次返回结果，并记录调用与并发峰值。
    struct ScriptedTransport {
        script: Mutex<VecDeque<Result<DeliveryReceipt, DeliveryFailure>>>,
        default: Mutex<Result<DeliveryReceipt, DeliveryFailure>>,
        calls: Mutex<Vec<(String, DeliveryTarget, Vec<String>)>>,
        inflight: AtomicUsize,
        max_inflight: AtomicUsize,
        hold: Duration,
    }

    impl ScriptedTransport {
        fn new(default: Result<DeliveryReceipt, DeliveryFailure>) -> Self {
            Self {
                script: Mutex::new(VecDeque::new()),
                default: Mutex::new(default),
                calls: Mutex::new(Vec::new()),
                inflight: AtomicUsize::new(0),
                max_inflight: AtomicUsize::new(0),
                hold: Duration::ZERO,
            }
        }

        fn ok() -> Arc<Self> {
            Arc::new(Self::new(Ok(DeliveryReceipt { accepted: 0 })))
        }

        fn failing(failure: DeliveryFailure) -> Arc<Self> {
            Arc::new(Self::new(Err(failure)))
        }

        fn with_hold(mut self: Arc<Self>, hold: Duration) -> Arc<Self> {
            if let Some(inner) = Arc::get_mut(&mut self) {
                inner.hold = hold;
            }
            self
        }

        fn calls(&self) -> Vec<(String, DeliveryTarget, Vec<String>)> {
            self.calls.lock().unwrap().clone()
        }

        fn observed_max_inflight(&self) -> usize {
            self.max_inflight.load(Ordering::SeqCst)
        }
    }

    impl Transport for ScriptedTransport {
        fn deliver<'a>(
            &'a self,
            entry: &'a QueueEntry,
            target: DeliveryTarget,
            recipients: &'a [String],
        ) -> DeliveryFuture<'a> {
            Box::pin(async move {
                let now = self
                    .inflight
                    .fetch_add(1, Ordering::SeqCst)
                    .saturating_add(1);
                self.max_inflight.fetch_max(now, Ordering::SeqCst);

                self.calls
                    .lock()
                    .unwrap()
                    .push((entry.id.clone(), target, recipients.to_vec()));

                if !self.hold.is_zero() {
                    tokio::time::sleep(self.hold).await;
                }

                self.inflight.fetch_sub(1, Ordering::SeqCst);

                let next = self.script.lock().unwrap().pop_front();
                match next {
                    Some(result) => result,
                    None => {
                        let fallback = self.default.lock().unwrap().clone();
                        match fallback {
                            Ok(receipt) => Ok(DeliveryReceipt {
                                accepted: if receipt.accepted == 0 {
                                    recipients.len()
                                } else {
                                    receipt.accepted
                                },
                            }),
                            Err(failure) => Err(failure),
                        }
                    }
                }
            })
        }
    }

    struct Harness {
        _dir: tempfile::TempDir,
        store: QueueStore,
        local: Arc<ScriptedTransport>,
        remote: Arc<ScriptedTransport>,
    }

    impl Harness {
        fn new(local: Arc<ScriptedTransport>, remote: Arc<ScriptedTransport>) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let store = QueueStore::new(dir.path().join("queue"));
            Self {
                _dir: dir,
                store,
                local,
                remote,
            }
        }

        fn runner(&self, config: QueueConfig, relay: Option<RelayEndpoint>) -> Arc<QueueRunner> {
            self.runner_with_signer(config, relay, Arc::new(NoSigning))
        }

        fn runner_with_signer(
            &self,
            config: QueueConfig,
            relay: Option<RelayEndpoint>,
            signer: Arc<dyn MessageSigner>,
        ) -> Arc<QueueRunner> {
            Arc::new(QueueRunner::new(
                self.store.clone(),
                self.local.clone(),
                self.remote.clone(),
                config,
                relay,
                signer,
            ))
        }
    }

    /// 调度测试不关心签名：显式声明「本封不需要签名」，让报文原样透传。
    struct NoSigning;

    impl MessageSigner for NoSigning {
        fn sign(&self, _message: &str) -> SigningOutcome {
            SigningOutcome::NotApplicable
        }
    }

    /// 模拟「该签却没签成」。
    struct FailingSigner;

    impl MessageSigner for FailingSigner {
        fn sign(&self, _message: &str) -> SigningOutcome {
            SigningOutcome::Failed("key is unreadable".to_string())
        }
    }

    fn config() -> QueueConfig {
        QueueConfig {
            relay_concurrency: 4,
            backoff: BackoffPolicy {
                base_secs: 10,
                factor: 2,
                max_secs: 100,
                max_attempts: 3,
            },
            reporting_mta: "mail.example.org".to_string(),
            managed_domains: vec!["example.org".to_string()],
            blocked_threshold: 3,
        }
    }

    fn enqueue_outbound(store: &QueueStore, id: &str, recipients: &[&str]) -> QueueEntry {
        enqueue_from(store, id, "sender@example.org", recipients)
    }

    fn enqueue_from(
        store: &QueueStore,
        id: &str,
        mail_from: &str,
        recipients: &[&str],
    ) -> QueueEntry {
        let mut entry = QueueEntry::new(
            EntryKind::Outbound,
            mail_from,
            recipients.iter().map(|r| r.to_string()).collect(),
            "Subject: t\r\n\r\nbody",
            1_000,
        )
        .unwrap();
        entry.id = id.to_string();
        store.enqueue(&entry).unwrap();
        entry
    }

    fn relay() -> RelayEndpoint {
        validate_relay(
            &RelayValidationRequest {
                host: "smtp.sendgrid.net".to_string(),
                port: 587,
                tls_mode: "STARTTLS".to_string(),
                username: "apikey".to_string(),
                password: "secret".to_string(),
                allow_private_network: false,
            },
            false,
        )
        .unwrap()
    }

    #[test]
    fn default_concurrency_matches_the_settings_schema() {
        // §2.6 的 settings schema 里 `relayConcurrency` 默认 20，且是**可调项**；
        // 队列侧的默认值必须与它一致，否则「配置里写 20、实际按别的值跑」。
        assert_eq!(QueueConfig::default().relay_concurrency, 20);
        assert_eq!(
            QueueConfig::default().relay_concurrency,
            mailstack_core::config::Settings::default().relay_concurrency
        );
    }

    #[tokio::test]
    async fn metrics_snapshot_exposes_backlog_concurrency_and_health() {
        // §5.9.8 / R-25-5：并发上限可配置且指标可见，否则运维无法区分
        // 「投递慢」与「出站被封」。
        let harness = Harness::new(ScriptedTransport::ok(), ScriptedTransport::ok());
        let mut cfg = config();
        cfg.relay_concurrency = 7;
        // 造一条未到期的积压条目，观察 backlog 是否可见。
        let mut entry = enqueue_outbound(&harness.store, "00000000001-0001", &["bob@example.net"]);
        entry.next_attempt_unix = 9_999_999;
        harness.store.enqueue(&entry).unwrap();

        let runner = harness.runner(cfg, None);
        let metrics = runner.metrics_snapshot().await;
        assert_eq!(metrics.relay_concurrency, 7, "并发上限必须可观测");
        assert_eq!(metrics.backlog, 1, "积压量必须可观测");
        assert!(!metrics.outbound_health.blocked);

        let report = runner.run_once(1_000).await.unwrap();
        assert_eq!(report.relay_concurrency, 7);
        assert_eq!(report.backlog, 1, "未到期条目仍算积压");
        assert_eq!(report.considered, 0);
    }

    #[tokio::test]
    async fn zero_concurrency_is_clamped_instead_of_deadlocking() {
        // `relayConcurrency = 0` 若照字面执行会让信号量永远无许可 ⇒ 队列死锁。
        let harness = Harness::new(ScriptedTransport::ok(), ScriptedTransport::ok());
        enqueue_outbound(&harness.store, "00000000001-0001", &["bob@example.net"]);
        let mut cfg = config();
        cfg.relay_concurrency = 0;
        let runner = harness.runner(cfg, None);

        let report = tokio::time::timeout(Duration::from_secs(5), runner.run_once(1_000))
            .await
            .expect("并发上限为 0 时不得死锁")
            .unwrap();
        assert_eq!(report.delivered, 1);
        assert_eq!(report.relay_concurrency, 1, "生效值应被夹到 1");
    }

    #[tokio::test]
    async fn delivered_entry_is_removed_from_the_queue() {
        let harness = Harness::new(ScriptedTransport::ok(), ScriptedTransport::ok());
        enqueue_outbound(&harness.store, "00000000001-0001", &["bob@example.net"]);
        let runner = harness.runner(config(), None);

        let report = runner.run_once(1_000).await.unwrap();
        assert_eq!(report.delivered, 1);
        assert_eq!(report.deferred, 0);
        assert!(
            harness.store.is_empty().unwrap(),
            "投递成功后条目必须从队列移除"
        );

        let calls = harness.remote.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].1, DeliveryTarget::Remote(OutboundRoute::Direct));
    }

    #[tokio::test]
    async fn local_recipients_use_the_local_transport_and_remote_use_the_remote_one() {
        let harness = Harness::new(ScriptedTransport::ok(), ScriptedTransport::ok());
        enqueue_outbound(
            &harness.store,
            "00000000001-0001",
            &["alice@example.org", "bob@example.net"],
        );
        let runner = harness.runner(config(), None);

        runner.run_once(1_000).await.unwrap();

        let local_calls = harness.local.calls();
        assert_eq!(local_calls.len(), 1, "本地收件人应走 LMTP 传输");
        assert_eq!(local_calls[0].2, vec!["alice@example.org".to_string()]);
        assert_eq!(local_calls[0].1, DeliveryTarget::Local);

        let remote_calls = harness.remote.calls();
        assert_eq!(remote_calls.len(), 1, "外域收件人应走出站传输");
        assert_eq!(remote_calls[0].2, vec!["bob@example.net".to_string()]);

        assert!(harness.store.is_empty().unwrap());
    }

    #[tokio::test]
    async fn recipients_accepted_by_a_partial_delivery_are_not_retried_or_bounced() {
        // 部分成功（LMTP 逐收件人应答的典型形态）：一个已落箱、一个超配额。
        // 已落箱的那个既不能再投一次（重复邮件），也不能被退信（它其实送到了）。
        let harness = Harness::new(ScriptedTransport::ok(), ScriptedTransport::ok());
        enqueue_outbound(
            &harness.store,
            "00000000001-0001",
            &["alice@example.net", "bob@example.net"],
        );
        *harness.remote.default.lock().unwrap() = Err(DeliveryFailure::transient(
            "LmtpPartial",
            "452 4.2.2 over quota",
        )
        .with_accepted(vec!["alice@example.net".to_string()]));
        let runner = harness.runner(config(), None);

        let report = runner.run_once(1_000).await.unwrap();
        assert_eq!(report.delivered, 1, "已投递的收件人应计入 delivered");
        assert_eq!(report.deferred, 1);
        assert_eq!(report.bounced, 0, "已投递的收件人不得被退信");

        let entries = harness.store.load_all().unwrap();
        assert_eq!(entries.len(), 1, "只剩未投递的收件人需要重试");
        assert_eq!(entries[0].recipients, vec!["bob@example.net".to_string()]);

        // 下一轮只应重投剩下的那一个。
        harness.remote.calls.lock().unwrap().clear();
        *harness.remote.default.lock().unwrap() = Ok(DeliveryReceipt { accepted: 0 });
        runner.run_once(1_000_000).await.unwrap();
        let calls = harness.remote.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].2, vec!["bob@example.net".to_string()]);
        assert!(harness.store.is_empty().unwrap());
    }

    #[tokio::test]
    async fn a_fully_accepted_but_failed_batch_does_not_retry_anything() {
        // 边界：整批都以失败形态返回，但每个收件人都已投递成功。
        let harness = Harness::new(ScriptedTransport::ok(), ScriptedTransport::ok());
        enqueue_outbound(&harness.store, "00000000001-0001", &["alice@example.net"]);
        *harness.remote.default.lock().unwrap() = Err(DeliveryFailure::transient(
            "LmtpPartial",
            "connection closed after delivery",
        )
        .with_accepted(vec!["alice@example.net".to_string()]));
        let runner = harness.runner(config(), None);

        let report = runner.run_once(1_000).await.unwrap();
        assert_eq!(report.delivered, 1);
        assert_eq!(report.deferred, 0, "没有剩余收件人就不该重试");
        assert_eq!(report.bounced, 0);
        assert!(
            harness.store.is_empty().unwrap(),
            "不得留下一条无从投递的空条目"
        );
    }

    #[tokio::test]
    async fn empty_managed_domains_treat_every_recipient_as_remote() {
        // fail-closed：没有配置纳管域名时，绝不能把外域邮件当本地投递。
        let harness = Harness::new(ScriptedTransport::ok(), ScriptedTransport::ok());
        enqueue_outbound(&harness.store, "00000000001-0001", &["alice@example.org"]);
        let mut cfg = config();
        cfg.managed_domains.clear();
        let runner = harness.runner(cfg, None);

        runner.run_once(1_000).await.unwrap();

        assert!(harness.local.calls().is_empty(), "不得走本地投递");
        assert_eq!(harness.remote.calls().len(), 1);
    }

    #[tokio::test]
    async fn permanent_failure_bounces_immediately_without_retry() {
        let local = ScriptedTransport::ok();
        let remote = ScriptedTransport::failing(
            DeliveryFailure::permanent("SmtpRejected", "550 no such user").with_code(550),
        );
        let harness = Harness::new(local, remote);
        let original = enqueue_outbound(&harness.store, "00000000001-0001", &["bob@example.net"]);
        let runner = harness.runner(config(), None);

        let report = runner.run_once(1_000).await.unwrap();
        assert_eq!(report.bounced, 1);
        assert_eq!(report.deferred, 0, "5xx 不得进入重试");

        // 原条目已移除，队列里只剩退信。
        let entries = harness.store.load_all().unwrap();
        assert_eq!(entries.len(), 1, "应恰好生成一封退信");
        let dsn = &entries[0];
        assert_eq!(dsn.kind, EntryKind::Bounce);
        assert!(
            dsn.is_null_sender(),
            "DSN 必须使用 null sender，否则退信自身失败会形成回环"
        );
        assert_eq!(dsn.recipients, vec!["sender@example.org".to_string()]);
        assert!(dsn.data.contains("550 no such user"));
        assert!(dsn.data.contains(&original.id), "退信应回附原邮件用以定位");
    }

    #[tokio::test]
    async fn transient_failures_retry_then_bounce_after_the_retry_limit() {
        let harness = Harness::new(
            ScriptedTransport::ok(),
            ScriptedTransport::failing(DeliveryFailure::transient(
                "ConnectionError",
                "connection refused",
            )),
        );
        enqueue_outbound(&harness.store, "00000000001-0001", &["bob@example.net"]);
        let runner = harness.runner(config(), None);

        // 第一轮：临时失败 → 退避重试，队列里仍只有原条目。
        let first = runner.run_once(1_000).await.unwrap();
        assert_eq!(first.deferred, 1);
        assert_eq!(first.bounced, 0);
        let entries = harness.store.load_all().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].attempts, 1);
        assert!(
            !entries[0].recipients.is_empty(),
            "临时失败必须保留收件人，否则重试无从谈起"
        );
        let after_first = entries[0].next_attempt_unix;
        assert!(after_first > 1_000, "必须推迟到未来");

        // 未到时间不得重试。
        let too_early = runner.run_once(1_000).await.unwrap();
        assert_eq!(too_early.considered, 0, "未到退避时间不应被调度");

        // 到时间后继续失败，直到耗尽重试预算（max_attempts = 3）。
        runner.run_once(after_first).await.unwrap();
        let third = runner.run_once(after_first + 10_000).await.unwrap();
        assert_eq!(third.bounced, 1, "超过阈值必须退信，而不是无限重试");

        let entries = harness.store.load_all().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].kind, EntryKind::Bounce);
        assert!(
            entries[0].data.contains("connection refused"),
            "退信应说明最后一次失败原因"
        );
    }

    #[tokio::test]
    async fn bounce_is_never_generated_for_a_null_sender() {
        // 防双退信回环（RFC 5321 §4.5.5）：null sender 的消息失败后只能丢弃。
        let harness = Harness::new(
            ScriptedTransport::ok(),
            ScriptedTransport::failing(DeliveryFailure::permanent("SmtpRejected", "550 nope")),
        );
        let mut entry = QueueEntry::new(
            EntryKind::Outbound,
            "",
            vec!["bob@example.net".to_string()],
            "body",
            1_000,
        )
        .unwrap();
        entry.id = "00000000001-0001".to_string();
        harness.store.enqueue(&entry).unwrap();
        let runner = harness.runner(config(), None);

        let report = runner.run_once(1_000).await.unwrap();
        assert_eq!(report.bounced, 0);
        assert_eq!(report.discarded, 1);
        assert!(
            harness.store.is_empty().unwrap(),
            "不得生成退信，也不得把 null sender 的邮件永远挂在队列里"
        );
    }

    #[tokio::test]
    async fn dsn_entries_are_never_bounced_again() {
        // 退信自身失败（例如发件人域不可达）时，只能丢弃；否则会互相触发。
        let harness = Harness::new(
            ScriptedTransport::ok(),
            ScriptedTransport::failing(DeliveryFailure::permanent(
                "SmtpRejected",
                "550 mailbox unavailable",
            )),
        );
        let mut dsn = QueueEntry::new(
            EntryKind::Bounce,
            "",
            vec!["sender@example.net".to_string()],
            "Subject: Undelivered Mail\r\n\r\nbody",
            1_000,
        )
        .unwrap();
        dsn.id = "00000000001-0001".to_string();
        harness.store.enqueue(&dsn).unwrap();
        let runner = harness.runner(config(), None);

        let report = runner.run_once(1_000).await.unwrap();
        assert_eq!(report.bounced, 0, "退信不得再退信");
        assert_eq!(report.discarded, 1);
        assert!(harness.store.is_empty().unwrap());
    }

    #[tokio::test]
    async fn bounces_use_the_same_outbound_route_as_user_mail() {
        // INV-21：relay 生效后，DSN 退信必须与用户邮件走**完全相同**的出站路径，
        // 不得有任何「退信走直投」的旁路。
        //
        // 原发件人刻意用**外域**地址：退信寄回本域的话它会走 LMTP 本地投递，
        // 那样就观察不到出站路由，等于没验证到 INV-21。
        let harness = Harness::new(ScriptedTransport::ok(), ScriptedTransport::ok());
        let endpoint = relay();
        enqueue_from(
            &harness.store,
            "00000000001-0001",
            "sender@remote.example",
            &["bob@example.net"],
        );
        let runner = harness.runner(config(), Some(endpoint.clone()));

        let expected = OutboundRoute::ViaRelay {
            host: endpoint.host.clone(),
            port: endpoint.port,
            wrappermode: endpoint.requires_wrappermode(),
        };
        assert_eq!(runner.outbound_route(), expected);

        // 1) 用户邮件：经中继。
        runner.run_once(1_000).await.unwrap();
        let user_call = harness.remote.calls();
        assert_eq!(user_call.len(), 1);
        assert_eq!(user_call[0].1, DeliveryTarget::Remote(expected.clone()));

        // 2) 让下一次投递永久失败，从而产生退信。
        *harness.remote.default.lock().unwrap() =
            Err(DeliveryFailure::permanent("SmtpRejected", "550 nope"));
        enqueue_from(
            &harness.store,
            "00000000001-0002",
            "sender@remote.example",
            &["carol@example.net"],
        );
        runner.run_once(2_000).await.unwrap();

        let dsn_entry = harness
            .store
            .load_all()
            .unwrap()
            .into_iter()
            .find(|e| e.kind == EntryKind::Bounce)
            .expect("应生成退信");
        assert_eq!(
            dsn_entry.recipients,
            vec!["sender@remote.example".to_string()],
            "退信应收给原信封发件人"
        );

        // 3) 让退信投递成功，观察它实际走的路由。
        *harness.remote.default.lock().unwrap() = Ok(DeliveryReceipt { accepted: 0 });
        harness.remote.calls.lock().unwrap().clear();
        runner.run_once(3_000).await.unwrap();

        let dsn_calls: Vec<_> = harness
            .remote
            .calls()
            .into_iter()
            .filter(|(id, _, _)| *id == dsn_entry.id)
            .collect();
        assert_eq!(dsn_calls.len(), 1, "退信必须经同一出站传输投递");
        assert_eq!(
            dsn_calls[0].1,
            DeliveryTarget::Remote(expected),
            "INV-21：退信与用户邮件不得走不同路径"
        );
        assert!(
            harness
                .local
                .calls()
                .iter()
                .all(|(id, _, _)| *id != dsn_entry.id),
            "退信不得走本地投递旁路"
        );
    }

    #[tokio::test]
    async fn a_bounce_addressed_to_a_local_sender_is_delivered_locally() {
        // 与上一条互补：原发件人是本域时，退信应当走 LMTP（本地）而不是绕去中继。
        let harness = Harness::new(ScriptedTransport::ok(), ScriptedTransport::ok());
        enqueue_from(
            &harness.store,
            "00000000001-0001",
            "sender@example.org",
            &["bob@example.net"],
        );
        *harness.remote.default.lock().unwrap() =
            Err(DeliveryFailure::permanent("SmtpRejected", "550 nope"));
        let runner = harness.runner(config(), Some(relay()));

        runner.run_once(1_000).await.unwrap();
        let dsn_entry = harness
            .store
            .load_all()
            .unwrap()
            .into_iter()
            .find(|e| e.kind == EntryKind::Bounce)
            .expect("应生成退信");

        *harness.remote.default.lock().unwrap() = Ok(DeliveryReceipt { accepted: 0 });
        harness.local.calls.lock().unwrap().clear();
        runner.run_once(2_000).await.unwrap();

        let local_calls: Vec<_> = harness
            .local
            .calls()
            .into_iter()
            .filter(|(id, _, _)| *id == dsn_entry.id)
            .collect();
        assert_eq!(local_calls.len(), 1, "本域发件人的退信应走本地投递");
        assert_eq!(local_calls[0].1, DeliveryTarget::Local);
    }

    #[tokio::test]
    async fn consecutive_outbound_failures_produce_the_blocked_verdict() {
        // §5.10.3 R-25-3：连续失败达阈值必须给出**明确结论**，而不是让队列默默变长。
        let harness = Harness::new(
            ScriptedTransport::ok(),
            ScriptedTransport::failing(DeliveryFailure::transient(
                "ConnectionError",
                "connection timed out",
            )),
        );
        enqueue_outbound(&harness.store, "00000000001-0001", &["bob@example.net"]);
        let runner = harness.runner(config(), None);

        let mut now = 1_000;
        for _ in 0..3 {
            runner.run_once(now).await.unwrap();
            now += 1_000_000;
        }

        let health = runner.outbound_health();
        assert!(health.blocked, "连续失败 3 次后必须判定出站不可用");
        assert!(health.needs_relay, "未配置中继时应明确要求配置中继");
        assert!(
            health.message.contains("Outbound port 25 is blocked"),
            "文案必须让运维一眼看出结论，实际：{}",
            health.message
        );
    }

    /// 5.11：**永久失败（5xx）不得推进「出站被封」的判定**。
    ///
    /// 这个计数驱动的结论是「25 端口被封，请配置中继」，而一次 5xx 恰恰说明
    /// 对端已经回了码 —— 链路是通的。原实现把永久失败也算进去，于是 10 封
    /// 「收件人不存在」的正常退信就能把整条出站链路判成「被封」，转入快速失败
    /// 并**停止全部外域投递**，等于用正常退信自造一次全站故障。
    #[tokio::test]
    async fn permanent_failures_never_trip_the_outbound_blocked_verdict() {
        let harness = Harness::new(
            ScriptedTransport::ok(),
            ScriptedTransport::failing(DeliveryFailure::permanent(
                "RcptRejected",
                "550 5.1.1 no such user",
            )),
        );
        let runner = harness.runner(config(), None);

        // 远超阈值（默认 3）的永久失败次数。
        for round in 0..12 {
            enqueue_outbound(
                &harness.store,
                &format!("000000{:05}-0001", round + 1),
                &[&format!("ghost{round}@example.net")],
            );
            runner
                .run_once(1_000 + round as i64 * 1_000_000)
                .await
                .unwrap();
        }

        let health = runner.outbound_health();
        assert_eq!(
            health.consecutive_failures, 0,
            "永久失败说明链路是通的，不得计入出站健康"
        );
        assert!(
            !health.blocked,
            "正常退信不得把出站判成被封（否则停止全部外域投递）"
        );
    }

    /// 5.10：被有效租约持有的条目不得被本轮投递。
    ///
    /// 这条模拟的是「上一个进程在投递中途崩溃」：条目文件完好、收件人齐全，
    /// 但磁盘上留着一份未过期的 claim。没有租约时，重启后第一轮就会把它
    /// **整批重投** —— 收件人收到重复邮件，而运维完全看不出为什么。
    #[tokio::test]
    async fn an_entry_under_a_live_claim_is_skipped_and_delivered_after_expiry() {
        let harness = Harness::new(ScriptedTransport::ok(), ScriptedTransport::ok());
        let entry = enqueue_outbound(&harness.store, "00000000001-0001", &["bob@example.net"]);
        let runner = harness.runner(config(), None);

        // 「上一个进程」留下的有效租约。
        let claimed_at = 1_000;
        assert!(harness.store.try_claim(&entry.id, claimed_at).unwrap());

        let report = runner
            .run_once(claimed_at + 60)
            .await
            .expect("本轮应当正常完成（只是跳过被租约持有的条目）");
        assert_eq!(report.considered, 0, "被租约持有的条目不应被处理");
        assert!(
            harness.remote.calls().is_empty(),
            "被租约持有的条目不得被投递 —— 否则就是重复投递"
        );
        assert_eq!(
            harness.store.load_all().unwrap().len(),
            1,
            "条目本身必须原样留在队列里，不能因为跳过而被删"
        );

        // 租约过期后（例如原持有者确实崩了），必须能正常接手投递。
        let after_expiry = claimed_at + crate::store::CLAIM_TTL_SECONDS + 1;
        let report = runner.run_once(after_expiry).await.unwrap();
        assert_eq!(report.considered, 1, "租约过期后应正常处理");
        assert_eq!(harness.remote.calls().len(), 1);
        assert!(
            harness.store.load_all().unwrap().is_empty(),
            "投递成功后条目应被移除"
        );
        // 处理结束后租约也要清掉，不能留孤儿。
        assert!(
            harness.store.claimed_ids(after_expiry).unwrap().is_empty(),
            "投递完成后租约必须被释放"
        );
    }

    /// 5.9：两轮重叠必须被拒绝，而不是各投一遍。
    #[tokio::test]
    async fn overlapping_rounds_are_refused_instead_of_double_delivering() {
        let harness = Harness::new(ScriptedTransport::ok(), ScriptedTransport::ok());
        enqueue_outbound(&harness.store, "00000000001-0001", &["bob@example.net"]);
        let runner = harness.runner(config(), None);

        // 模拟「上一轮还没结束」：手工占住重入标记。
        // 走真实的 compare_exchange 路径，而不是检查私有字段的初值。
        use std::sync::atomic::Ordering;
        assert!(runner
            .round_in_flight
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok());

        let error = runner
            .run_once(1_000)
            .await
            .expect_err("重叠轮次必须被拒绝");
        assert!(
            error.is_busy(),
            "必须是可识别的「跳过」而不是普通故障：{error}"
        );

        // 队列里的条目一条都没被投递。
        assert_eq!(
            harness.remote.calls().len(),
            0,
            "被拒绝的那一轮不得投递任何条目"
        );

        // 标记释放后能正常跑，且**没有**因为上一轮卡死而永久停摆。
        runner.round_in_flight.store(false, Ordering::SeqCst);
        runner.run_once(1_000).await.unwrap();
        assert_eq!(harness.remote.calls().len(), 1);
    }

    #[tokio::test]
    async fn blocked_verdict_survives_restart() {
        let harness = Harness::new(
            ScriptedTransport::ok(),
            ScriptedTransport::failing(DeliveryFailure::transient(
                "ConnectionError",
                "connection timed out",
            )),
        );
        enqueue_outbound(&harness.store, "00000000001-0001", &["bob@example.net"]);
        let runner = harness.runner(config(), None);
        runner.run_once(1_000).await.unwrap();
        runner.run_once(1_000_000).await.unwrap();
        runner.run_once(2_000_000).await.unwrap();
        assert!(runner.outbound_health().blocked);

        // 「重启」：用同一个 store 新建运行器。
        let restarted = harness.runner(config(), None);
        let health = restarted.outbound_health();
        assert!(health.blocked, "出站不可用的结论必须跨重启保留");
        assert!(health.needs_relay);
    }

    #[tokio::test]
    async fn blocked_queue_fast_fails_instead_of_hammering() {
        // 快速失败：判定不可用后，一轮里只放行一次探测，而不是每条消息各试一次。
        let harness = Harness::new(
            ScriptedTransport::ok(),
            ScriptedTransport::failing(DeliveryFailure::transient(
                "ConnectionError",
                "connection timed out",
            )),
        );
        let runner = harness.runner(config(), None);

        // 先把健康计数顶到阈值。
        for i in 0..3 {
            enqueue_outbound(
                &harness.store,
                &format!("0000000000{i}-0001"),
                &["bob@example.net"],
            );
            runner.run_once(1_000 + i as i64).await.unwrap();
        }
        assert!(runner.outbound_health().blocked);

        // 现在入队 5 条新消息，全部到期。
        for i in 0..5 {
            enqueue_outbound(
                &harness.store,
                &format!("000000000A{i}-0001"),
                &["bob@example.net"],
            );
        }
        harness.remote.calls.lock().unwrap().clear();
        let report = runner.run_once(10_000_000).await.unwrap();

        assert!(report.fast_failed, "判定出站不可用后必须走快速失败");
        assert_eq!(
            harness.remote.calls().len(),
            1,
            "快速失败期间每轮只允许一次探测投递，不得逐条重试"
        );
        assert!(report.deferred >= 5, "其余条目应原样留在队列里等待");
    }

    #[tokio::test]
    async fn a_successful_probe_clears_the_blocked_verdict() {
        // 出站恢复后必须能自愈，否则队列会永久停摆。
        let harness = Harness::new(
            ScriptedTransport::ok(),
            ScriptedTransport::failing(DeliveryFailure::transient(
                "ConnectionError",
                "connection timed out",
            )),
        );
        enqueue_outbound(&harness.store, "00000000001-0001", &["bob@example.net"]);
        let runner = harness.runner(config(), None);
        for i in 0..3 {
            runner.run_once(1_000 + i as i64 * 1_000_000).await.unwrap();
        }
        assert!(runner.outbound_health().blocked);

        // 出站恢复。
        *harness.remote.default.lock().unwrap() = Ok(DeliveryReceipt { accepted: 0 });
        enqueue_outbound(&harness.store, "00000000001-0002", &["bob@example.net"]);
        let report = runner.run_once(10_000_000).await.unwrap();

        assert!(!report.outbound_health.blocked, "成功投递应清除不可用判定");
        assert_eq!(report.outbound_health.consecutive_failures, 0);
        assert!(harness
            .store
            .load_all()
            .unwrap()
            .iter()
            .all(|e| !e.recipients.is_empty()));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrency_is_bounded_by_relay_concurrency() {
        // relayConcurrency 是配置项的语义所在：并发投递不得超过它。
        let remote =
            ScriptedTransport::with_hold(ScriptedTransport::ok(), Duration::from_millis(30));
        let harness = Harness::new(ScriptedTransport::ok(), remote);
        let mut cfg = config();
        cfg.relay_concurrency = 2;

        for i in 0..8 {
            enqueue_outbound(
                &harness.store,
                &format!("0000000000{i}-0001"),
                &["bob@example.net"],
            );
        }
        let runner = harness.runner(cfg, None);
        let report = runner.run_once(1_000).await.unwrap();

        assert_eq!(report.delivered, 8);
        assert!(
            harness.remote.observed_max_inflight() <= 2,
            "并发峰值 {} 超过了 relayConcurrency=2",
            harness.remote.observed_max_inflight()
        );
        assert!(
            harness.remote.observed_max_inflight() > 1,
            "并发完全没有发生，限流测试没有验证到任何东西"
        );
    }

    #[tokio::test]
    async fn a_local_transport_failure_does_not_trip_the_outbound_verdict() {
        // LMTP 出问题 ≠ 出站 25 被封。误报会让运维去查错方向。
        let harness = Harness::new(
            ScriptedTransport::failing(DeliveryFailure::transient(
                "LmtpUnavailable",
                "connection refused",
            )),
            ScriptedTransport::ok(),
        );
        enqueue_outbound(&harness.store, "00000000001-0001", &["alice@example.org"]);
        let runner = harness.runner(config(), None);

        runner.run_once(1_000).await.unwrap();
        assert_eq!(
            runner.outbound_health().consecutive_failures,
            0,
            "本地投递失败不得计入出站健康"
        );
        let entries = harness.store.load_all().unwrap();
        assert_eq!(entries[0].attempts, 1, "本地失败仍应触发退避重试");
        assert!(!entries[0].recipients.is_empty());
    }

    /// 任务返回 `Ok(Err)`（单条条目处理失败）必须被计入报告，而不只是日志。
    #[tokio::test]
    async fn entry_processing_errors_are_counted_in_the_report() {
        // 回执覆盖数与尝试数不符 → process 以错误结束（宁可见红）。
        // 该错误不得让整轮失败，但报告里必须看得到「这一轮有 1 条失败」。
        let harness = Harness::new(ScriptedTransport::ok(), ScriptedTransport::ok());
        enqueue_outbound(&harness.store, "00000000001-0001", &["bob@example.net"]);
        // script 路径按**原样**返回（不像 default 会把 0 修成 recipients.len()），
        // 才能构造「回执覆盖数与尝试数不符」。
        harness
            .remote
            .script
            .lock()
            .unwrap()
            .push_back(Ok(DeliveryReceipt { accepted: 0 }));
        let runner = harness.runner(config(), None);

        let report = runner.run_once(1_000).await.unwrap();
        assert_eq!(report.considered, 0, "失败的条目不计入 considered");
        assert_eq!(report.failed, 1, "Ok(Err) 必须被计数");
        // 条目原样留在队列里（未写回任何状态）。
        assert_eq!(harness.store.load_all().unwrap().len(), 1);
    }

    /// 远端阶段报错前，本地阶段已经发生的进度必须先尽力写回 ——
    /// 否则下次整批重投，本地收件人会收到重复邮件。
    #[tokio::test]
    async fn local_progress_is_persisted_before_a_remote_mismatch_error() {
        let harness = Harness::new(ScriptedTransport::ok(), ScriptedTransport::ok());
        enqueue_outbound(
            &harness.store,
            "00000000001-0001",
            &["alice@example.org", "bob@example.net"],
        );
        // 远端对 1 个收件人声称接受了 0 个 → 触发「宁可见红」错误
        // （script 路径按原样返回，才会出现覆盖数不符）。
        harness
            .remote
            .script
            .lock()
            .unwrap()
            .push_back(Ok(DeliveryReceipt { accepted: 0 }));
        let runner = harness.runner(config(), None);

        let report = runner.run_once(1_000).await.unwrap();
        assert_eq!(report.failed, 1);

        // 本地（alice）已投递的进度必须已经落盘：条目只剩远端收件人。
        let entries = harness.store.load_all().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].recipients,
            vec!["bob@example.net".to_string()],
            "本地已投递的收件人必须已从磁盘条目摘除"
        );
    }

    /// 远端回执不符而提前报错时，本地阶段**已判定要退信**的收件人必须仍然入队 DSN：
    /// 他们已经从条目摘除，重试无从补发 —— 随报错一起丢掉就是静默丢信。
    #[tokio::test]
    async fn a_remote_mismatch_error_still_flushes_pending_bounces() {
        let harness = Harness::new(ScriptedTransport::ok(), ScriptedTransport::ok());
        enqueue_outbound(
            &harness.store,
            "00000000001-0001",
            &["alice@example.org", "bob@example.net"],
        );
        // 本地：alice 的投递被永久拒绝 → 退信待入队（攒在 pending_bounces 里）。
        harness
            .local
            .script
            .lock()
            .unwrap()
            .push_back(Err(DeliveryFailure::permanent(
                "RcptRejected",
                "550 no such user",
            )));
        // 远端：回执覆盖数与尝试数不符 → 触发「宁可见红」错误。
        harness
            .remote
            .script
            .lock()
            .unwrap()
            .push_back(Ok(DeliveryReceipt { accepted: 0 }));
        let runner = harness.runner(config(), None);

        let report = runner.run_once(1_000).await.unwrap();
        assert_eq!(report.failed, 1);

        let entries = harness.store.load_all().unwrap();
        // 原条目：alice 已摘除，磁盘上只剩远端收件人。
        let original = entries
            .iter()
            .find(|e| e.id == "00000000001-0001")
            .expect("原条目必须保留（远端收件人待重试）");
        assert_eq!(original.recipients, vec!["bob@example.net".to_string()]);
        // 本地阶段判定的退信必须已入队，而不是随报错一起丢掉。
        let dsn = entries
            .iter()
            .find(|e| e.kind == EntryKind::Bounce)
            .expect("本地阶段判定的退信必须已入队");
        assert_eq!(dsn.recipients, vec!["sender@example.org".to_string()]);
        assert!(dsn.data.contains("550 no such user"));
    }

    #[tokio::test]
    async fn a_signing_failure_defers_without_tripping_the_outbound_verdict() {
        // 两个性质必须同时成立：
        //   1) 失败关闭 —— 未签名的邮件不允许发出去；
        //   2) 本机故障不得计入出站健康 —— 否则运维会看到「出站 25 被封，
        //      请配置中继」，然后去查一个和密钥毫无关系的方向。
        let harness = Harness::new(ScriptedTransport::ok(), ScriptedTransport::ok());
        enqueue_outbound(&harness.store, "00000000001-0001", &["bob@example.net"]);
        let runner = harness.runner_with_signer(config(), None, Arc::new(FailingSigner));

        let report = runner.run_once(1_000).await.unwrap();

        assert!(
            harness.remote.calls().is_empty(),
            "签名失败时绝不能把未签名邮件投出去"
        );
        assert_eq!(report.deferred, 1, "应退回队列重试");
        assert_eq!(report.bounced, 0, "第一次失败不该立即退信");

        let health = runner.outbound_health();
        assert_eq!(
            health.consecutive_failures, 0,
            "DKIM 签名失败不得计入出站健康"
        );
        assert!(!health.blocked, "不得因此判定出站不可用");

        let entries = harness.store.load_all().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].attempts, 1, "应已进入退避重试");
        assert!(
            entries[0]
                .last_error
                .as_deref()
                .unwrap_or_default()
                .contains("key is unreadable"),
            "失败原因必须留在条目上，否则运维无从定位：{:?}",
            entries[0].last_error
        );
    }
}
