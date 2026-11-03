//! 出站队列：装配投递链路，并按固定节奏驱动调度。
//!
//! ## 为什么必须自建循环
//!
//! [`QueueRunner`] 只提供 `run_once`，**没有**长驻循环。所以「多久跑一次」是守护进程
//! 的决定，而不是某个库的默认值 —— 这既是灵活，也意味着这里的取舍要写清楚：
//!
//! * **节奏**：固定 10s。出站投递的瓶颈在网络与退避策略，不在调度频率；更密的轮询
//!   只会白白扫目录。
//! * **首轮立即执行**：`interval` 的第一次 `tick` 会立刻返回，因此重启后积压的邮件
//!   马上被处理，而不是先等 10 秒。
//! * **单轮失败绝不退出进程**：`run_once` 返回 `Err` 只可能来自队列目录的 I/O 问题。
//!   为了一个目录抖动就让整台服务器停止收信，是明显更糟的取舍。超时同理。
//!
//! ## 本地与远端
//!
//! 远端传输在 [`QueueRunner::new`] 内被**无条件**套上 DKIM 签名，这里不需要（也不应该）
//! 再包一层。本地投递刻意不签名 —— Dovecot 是本机自己的用户。

use std::sync::Arc;
use std::time::Duration;

use mailstack_queue::{DkimSigner, QueueRunner, QueueStore, SmtpRemoteTransport, Transport};
use mailstack_smtp::{AddressPolicy, HickoryMxResolver, PinnedDialer};
use mailstack_store::{LmtpClient, LmtpTransport};

use crate::config::RuntimeConfig;
use crate::error::DaemonError;

/// 投递轮询间隔。
pub const SCHEDULE_INTERVAL: Duration = Duration::from_secs(10);

/// 单轮调度的整体上限。
///
/// 用来保证**停机不会被在途投递卡死**：收到信号后最多再等这么久就收工。
pub const ROUND_TIMEOUT: Duration = Duration::from_secs(600);

/// SMTP/LMTP 连接与命令超时。
const TRANSPORT_TIMEOUT: Duration = Duration::from_secs(30);

/// 装配队列运行器。
pub fn build_runner(config: &RuntimeConfig) -> Result<Arc<QueueRunner>, DaemonError> {
    let local: Arc<dyn Transport> = Arc::new(LmtpTransport::new(LmtpClient::new(
        config.lmtp_endpoint.clone(),
        config.mail_host.clone(),
        TRANSPORT_TIMEOUT,
    )));

    let dialer =
        PinnedDialer::with_webpki_roots(TRANSPORT_TIMEOUT).map_err(DaemonError::RelayConfig)?;
    let mut remote_transport =
        SmtpRemoteTransport::new(dialer, config.mail_host.clone(), TRANSPORT_TIMEOUT)
            .with_policy(address_policy(config))
            // 直投的 MX 解析。装上它不等于会走直投 —— 路由由 relay 配置唯一决定
            // （有中继就只有中继，INV-18/INV-21）。
            .with_mx(Arc::new(
                HickoryMxResolver::from_system().map_err(DaemonError::RelayConfig)?,
            ));
    if let Some(endpoint) = &config.relay_endpoint {
        if endpoint.has_credentials() {
            remote_transport = remote_transport
                .with_credentials(endpoint.username.clone(), endpoint.password.clone());
        }
    }
    let remote: Arc<dyn Transport> = Arc::new(remote_transport);

    let runner = QueueRunner::new(
        QueueStore::from_paths(&config.paths),
        local,
        remote,
        config.queue_config.clone(),
        config.relay_endpoint.clone(),
        Arc::new(DkimSigner::new(config.paths.clone())),
    );
    Ok(Arc::new(runner))
}

/// 地址策略：只有部署显式开启私网（非公网档）时才允许私网目标。
///
/// 这是 SSRF 的最后一道网 —— 中继主机名本身已在 [`crate::config::load_relay`] 里校验，
/// 这里约束的是**解析结果**。
fn address_policy(config: &RuntimeConfig) -> AddressPolicy {
    if config.allow_private_network {
        AddressPolicy::allow_private()
    } else {
        AddressPolicy::public_only()
    }
}

/// 按固定节奏驱动队列，直到收到停机信号。
///
/// ## 5.18：为什么在途轮次必须跑在**独立任务**里
///
/// 原实现把 `timeout(ROUND_TIMEOUT, runner.run_once(now))` 直接写在 `select!`
/// 的分支里。`select!` 在另一个分支先完成时会**丢弃**未完成的 future ——
/// 于是收到停机信号的那一刻，在途投递被就地取消：
///
/// * `ROUND_TIMEOUT` 这个「保证停机不会被在途投递卡死」的上限**从未生效** ——
///   代码根本等不到它，取消是立刻发生的；
/// * 被取消的条目已经部分投出、却还没把「投过了」写回磁盘，下一轮（或重启后）
///   会**整批重投**，收件人收到重复邮件。
///
/// 因此这里把每一轮 `spawn` 成独立任务：`select!` 丢弃的只是 `JoinHandle`
/// 的等待权，任务本身继续跑；停机时对句柄做**有界等待**，等满 `ROUND_TIMEOUT`
/// 才放弃。这样「停机不让在途投递卡死」与「不让它被静默取消」同时成立。
pub async fn schedule(runner: Arc<QueueRunner>, shutdown: impl std::future::Future<Output = ()>) {
    let mut shutdown = std::pin::pin!(shutdown);
    let mut ticker = tokio::time::interval(SCHEDULE_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // 在途轮次。`Option` 同时充当「本轮是否还在跑」的判据：
    // 上一轮没结束时 ticker 到点也不开新的一轮（与队列侧的 5.9 重入保护双保险）。
    let mut in_flight: Option<tokio::task::JoinHandle<()>> = None;

    loop {
        // 先回收已完成的轮次，避免句柄堆积。
        if in_flight
            .as_ref()
            .is_some_and(|handle| handle.is_finished())
        {
            if let Some(handle) = in_flight.take() {
                // `run_once` 的错误已在任务内部记日志；这里只需等它结束。
                let _ = handle.await;
            }
        }

        tokio::select! {
            _ = &mut shutdown => {
                // 5.18：有界等待在途轮次，而不是丢弃它的 future。
                if let Some(mut handle) = in_flight.take() {
                    match tokio::time::timeout(ROUND_TIMEOUT, &mut handle).await {
                        Ok(_) => tracing::info!("队列调度停止（在途轮次已收尾）"),
                        Err(_) => {
                            // 5.21：超时后**显式取消**，而不是把句柄 detach。
                            //
                            // `JoinHandle` 被 drop 不会 abort 任务：它会继续在后台
                            // 跑，而 `schedule()` 随即返回、进程随后退出 —— 在途投递
                            // 被进程退出硬杀在任意一次 write 中间，且 `ClaimGuard`
                            // 的 Drop 也来不及跑（租约要占满 TTL 才被接管）。
                            // `abort()` 让 future 在下一个 await 点被取消，Drop 守卫
                            // 正常释放租约，下一次启动即可重试而不是干等 15 分钟。
                            handle.abort();
                            let _ = handle.await;
                            tracing::warn!(
                                "队列调度停止：在途轮次超过 {:?}，已显式取消（本轮的未完成条目将在重启后重试）",
                                ROUND_TIMEOUT
                            );
                        }
                    }
                } else {
                    tracing::info!("队列调度停止");
                }
                return;
            }
            _ = ticker.tick() => {
                if in_flight.is_some() {
                    // 上一轮还在跑。打开新的一轮会重复投递同一批条目 ——
                    // 队列侧的 `run_once` 也会拒绝，但这里直接跳过更省一次日志。
                    tracing::debug!("上一轮队列调度尚未结束，跳过本轮");
                    continue;
                }
                let runner = Arc::clone(&runner);
                in_flight = Some(tokio::spawn(async move {
                    let now = mailstack_queue::now_unix();
                    match runner.run_once(now).await {
                        Ok(report) => tracing::debug!(
                            considered = report.considered,
                            delivered = report.delivered,
                            deferred = report.deferred,
                            bounced = report.bounced,
                            backlog = report.backlog,
                            "队列调度完成"
                        ),
                        // 「上一轮还在跑」是可预期的跳过，不是故障；别把它刷成 warn。
                        Err(error) if error.is_busy() => {
                            tracing::debug!(error = %error, "队列轮次被跳过")
                        }
                        // 运行期失败只告警：一次目录抖动不应让整台服务器停止收信。
                        Err(error) => {
                            tracing::warn!(error = %error, "本轮队列调度失败，继续下一轮")
                        }
                    }
                }));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DEFAULT_PORTS;
    use mailstack_core::Paths;

    const SETUP: &str = r#"{
  "domain": "example.org",
  "mailHost": "mail.example.org",
  "serverIp": "203.0.113.10",
  "dkimSelector": "mailstack",
  "updatedAt": "2026-10-01T00:00:00Z"
}"#;

    fn test_config() -> (tempfile::TempDir, RuntimeConfig) {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::rooted(dir.path());
        std::fs::create_dir_all(paths.etc.clone()).unwrap();
        std::fs::create_dir_all(paths.postfix.clone()).unwrap();
        std::fs::write(&paths.setup_config, SETUP).unwrap();
        std::fs::write(&paths.domains, "example.org ok\n").unwrap();
        let config = crate::config::assemble(paths, DEFAULT_PORTS).expect("装配配置");
        (dir, config)
    }

    #[test]
    fn the_runner_is_assembled_with_the_single_outbound_route_source() {
        let (_dir, config) = test_config();
        let runner = build_runner(&config).expect("装配队列运行器");
        // 未配置中继 → 直投（而不是「悄悄改走中继」，那是 INV-21 禁止的兜底）。
        assert!(matches!(
            runner.outbound_route(),
            mailstack_queue::OutboundRoute::Direct
        ));
    }

    #[test]
    fn a_configured_relay_becomes_the_outbound_route() {
        let (_dir, base) = test_config();
        std::fs::write(
            &base.paths.relay_config,
            r#"{
  "relayhost": "[smtp.example.net]:587",
  "smtp_tls_security_level": "encrypt"
}"#,
        )
        .unwrap();
        let config = crate::config::assemble(base.paths, DEFAULT_PORTS).expect("装配配置");
        let runner = build_runner(&config).expect("装配队列运行器");
        match runner.outbound_route() {
            mailstack_queue::OutboundRoute::ViaRelay { host, port, .. } => {
                assert_eq!(host, "smtp.example.net");
                assert_eq!(port, 587);
            }
            other => panic!("配置了中继就不得走直投：{other:?}"),
        }
    }

    #[tokio::test]
    async fn the_scheduler_stops_promptly_on_the_shutdown_signal() {
        let (_dir, config) = test_config();
        let runner = build_runner(&config).expect("装配队列运行器");
        let shutdown = crate::shutdown::Shutdown::channel();
        let waiter = shutdown.waiter();

        let handle = tokio::spawn(async move { schedule(runner, waiter).await });
        // 让首轮 tick 先跑起来。
        tokio::time::sleep(Duration::from_millis(50)).await;
        shutdown.trigger();
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("停机信号必须让调度循环退出")
            .expect("任务不得 panic");
    }
}
