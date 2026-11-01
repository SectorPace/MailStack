//! MailStack 守护进程 —— 把各个 crate 的**机制层**装配成一个能跑的服务。
//!
//! ## 这个 crate 只做装配
//!
//! 协议、队列、认证、投递本身都在各自的 crate 里并有测试。这里做的事只有三件：
//!
//! 1. 把磁盘上的配置（`setup.json` / `settings.json` / 域名表 / `relay.json`）
//!    翻译成一个**已经校验过**的 [`RuntimeConfig`]（见 [`config`]）。
//! 2. 按端口绑定入站监听，并让三个监听**共用同一份**限速器与封禁表（见 [`listeners`]）。
//! 3. 起出站队列调度，并绑定特权 RPC 的两个 Unix socket（见 [`rpc`]）。
//! 4. 收到 SIGINT/SIGTERM 时让**所有**部分一起停下（见 [`shutdown`]）；
//!    任一任务异常退出也触发整体停机 —— 宁可整体重启，也不要「半个服务」继续跑。
//!
//! ## 启动期的取舍：宁可不起，也不要带病起
//!
//! [`config::assemble`] 里每一条「拒绝启动」都对应一种**静默错误行为**：身份靠猜、
//! 域名表空导致全量拒收、中继配置损坏被当成未配置而退回直投、本应加密的端口没有证书。
//! 这些状态共同的特征是「服务看起来在跑，行为却是错的」—— 那比起不来难查得多。
//!
//! 与之相对，运行期的失败只告警（见 [`queue::schedule`]）：一次磁盘抖动不该让整台
//! 服务器停止收信。

pub mod config;
pub mod error;
pub mod listeners;
pub mod manual_bans;
pub mod queue;
// 本地投递的落箱面（LMTP + Sieve）用 Unix socket；非 Unix 目标不提供。
#[cfg(unix)]
pub mod lmtp;
// 特权 RPC 面用 Unix socket；生产目标为 Linux，非 Unix 目标不提供。
#[cfg(unix)]
pub mod rpc;
pub mod shutdown;

use std::sync::Arc;

use mailstack_core::Paths;
use mailstack_smtpd::{BanList, Clock, QueueSink, RateLimiter, SystemClock};

pub use config::{assemble, ListenerPlan, RuntimeConfig, DEFAULT_PORTS};
pub use error::DaemonError;

/// 装配并运行守护进程，直到收到停机信号。
///
/// 返回时所有监听与队列调度都已停下（各自的收尾宽限期在内部处理）。
pub async fn run(paths: Paths, ports: Vec<u16>) -> Result<(), DaemonError> {
    let runtime_config = config::assemble(paths, &ports)?;
    tracing::info!(
        domain = %runtime_config.domain,
        mail_host = %runtime_config.mail_host,
        ports = ?runtime_config.listeners.iter().map(|plan| plan.port).collect::<Vec<_>>(),
        relay = runtime_config
            .relay_endpoint
            .as_ref()
            .map(|endpoint| endpoint.host.as_str())
            .unwrap_or("<direct>"),
        "配置装配完成"
    );

    // 准入状态只有一份：限速配额与 strike 必须跨端口累计，否则轮换端口就等于绕过限速。
    let rate = Arc::new(RateLimiter::new(runtime_config.rate_limit));
    let bans = Arc::new(BanList::new(runtime_config.ban));
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);

    let sink = Arc::new(
        QueueSink::from_paths(
            &runtime_config.paths,
            runtime_config.mail_host.clone(),
            Arc::clone(&clock),
        )
        .map_err(|error| DaemonError::Sink(error.to_string()))?,
    );

    // 先绑定（任何端口失败即整体失败），再装配队列。
    let servers = listeners::bind_all(
        &runtime_config,
        Arc::clone(&sink),
        Arc::clone(&clock),
        Arc::clone(&rate),
        Arc::clone(&bans),
    )
    .await?;
    let runner = queue::build_runner(&runtime_config)?;

    // 本地投递的落箱服务：队列的 LmtpClient 连到这里，Sieve 在这里生效。
    let lmtp_server = lmtp::build_server(&runtime_config)?;
    let lmtp_socket = lmtp::socket_file(&runtime_config.paths)?;

    // RPC 面在启动阶段就绑定：socket 建不起来必须现在报错，而不是让后台任务悄悄失败。
    #[cfg(unix)]
    let rpc_faces = rpc::bind_all(&runtime_config.paths)?;

    let shutdown = shutdown::Shutdown::channel();
    let mut tasks: tokio::task::JoinSet<Result<(), String>> = tokio::task::JoinSet::new();

    #[cfg(unix)]
    rpc_faces.spawn(&mut tasks, &shutdown);

    #[cfg(unix)]
    {
        let receiver = shutdown.receiver();
        tasks.spawn(async move {
            lmtp_server
                .serve_unix(lmtp_socket, 0o660, receiver)
                .await
                .map_err(|error| format!("LMTP 落箱监听异常退出：{error}"))
        });
    }

    for (port, server) in servers {
        let waiter = shutdown.waiter();
        // 5.19：把异常退出**变成返回值**，而不是只记一行日志。
        tasks.spawn(async move {
            match server.run(waiter).await {
                Ok(()) => {
                    tracing::info!(port, "监听已停止");
                    Ok(())
                }
                Err(error) => {
                    tracing::error!(port, error = %error, "监听异常退出");
                    Err(format!("listener on port {port} exited: {error}"))
                }
            }
        });
    }

    {
        let waiter = shutdown.waiter();
        let runner = Arc::clone(&runner);
        tasks.spawn(async move {
            queue::schedule(runner, waiter).await;
            Ok(())
        });
    }

    // 手工封禁热重载：管理台改的是文件，这份循环把它对齐进上面那张内存表
    // （首轮立即执行，因此重启后封禁马上恢复）。读失败时保持现状，绝不解除。
    {
        let waiter = shutdown.waiter();
        let ban_list = Arc::clone(&bans);
        let paths = runtime_config.paths.clone();
        tasks.spawn(async move {
            manual_bans::watch(paths, ban_list, waiter).await;
            Ok(())
        });
    }

    tracing::info!("服务已就绪");

    // 5.19：收齐**每一个**任务的结果。
    //
    // 原先这里只是 `join_next()` 到一个 None 就 `Ok(())` —— 任何一块服务
    // 异常退出都只留下日志。systemd 看到的是正常退出，于是不重启：
    // 「进程活着但半个服务没了」，退出码也看不出来。
    // 现在把失败汇总成非零退出，让 supervisor 能真正接管。
    //
    // 并且**第一块**异常退出时就触发停机信号，让其余部分走各自的优雅收尾，
    // 而不是带着半死的服务继续跑。停机的两条来路在同一个 select 里汇合：
    //   * SIGINT/SIGTERM —— `watch_signals` 内部触发（它改为借用 `shutdown`，
    //     因此 `run` 在任务失败路径上仍握有触发权）；
    //   * 任务失败 —— 这里主动触发，只触发**一次**，重复触发没有意义。
    // 无论哪条路先到，都把剩余任务的收尾结果收完，再按失败集决定退出码。
    // `join_next` 是 cancel-safe，在 select 里反复轮询不会丢结果。
    let mut failures: Vec<String> = Vec::new();
    let mut shutdown_triggered = false;
    let mut signals = std::pin::pin!(shutdown::watch_signals(&shutdown));
    loop {
        tokio::select! {
            joined = tasks.join_next() => {
                let Some(joined) = joined else { break };
                match joined {
                    Ok(Ok(())) => {}
                    Ok(Err(message)) => {
                        if !shutdown_triggered {
                            shutdown_triggered = true;
                            tracing::error!(
                                %message,
                                "任务异常退出，触发其余部分的优雅停机（收尾完成后以非零退出）"
                            );
                            shutdown.trigger();
                        }
                        failures.push(message);
                    }
                    Err(join_error) => {
                        // panic / 被取消。panic 同样属于「这一块服务没了」；取消不是。
                        if join_error.is_panic() {
                            let message = format!("task panicked: {join_error}");
                            if !shutdown_triggered {
                                shutdown_triggered = true;
                                tracing::error!(
                                    %message,
                                    "任务 panic，触发其余部分的优雅停机（收尾完成后以非零退出）"
                                );
                                shutdown.trigger();
                            }
                            failures.push(message);
                        }
                    }
                }
            }
            // 信号已到，`watch_signals` 内部已触发停机；标记后继续在循环里收尾，
            // 直到所有任务结束（None）再按失败集决定退出码。
            //
            // `if !shutdown_triggered` 是**必须**的门：async fn 生成的 future
            // 完成后再被 poll 会 panic（"resumed after completion"）。没有门控时，
            // 信号先到的正常停机路径会在下一轮 select 里重新轮询已完成的
            // `signals`，把收尾过程整个炸掉。触发过就永久停用该分支 ——
            // 无论停机来路是信号还是任务失败，都不需要第二次。
            _ = &mut signals, if !shutdown_triggered => {
                shutdown_triggered = true;
            }
        }
    }

    if failures.is_empty() {
        tracing::info!("MailStack 守护进程已退出");
        return Ok(());
    }
    let summary = failures.join("; ");
    tracing::error!(failures = %summary, "MailStack 守护进程带着异常任务退出");
    Err(DaemonError::Task(summary))
}
