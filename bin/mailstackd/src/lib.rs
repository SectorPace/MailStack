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
//! 4. 收到 SIGINT/SIGTERM 时让**所有**部分一起停下（见 [`shutdown`]）。
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

    // RPC 面在启动阶段就绑定：socket 建不起来必须现在报错，而不是让后台任务悄悄失败。
    #[cfg(unix)]
    let rpc_faces = rpc::bind_all(&runtime_config.paths)?;

    let shutdown = shutdown::Shutdown::channel();
    let mut tasks = tokio::task::JoinSet::new();

    #[cfg(unix)]
    rpc_faces.spawn(&mut tasks, &shutdown);

    for (port, server) in servers {
        let waiter = shutdown.waiter();
        tasks.spawn(async move {
            match server.run(waiter).await {
                Ok(()) => tracing::info!(port, "监听已停止"),
                Err(error) => tracing::error!(port, error = %error, "监听异常退出"),
            }
        });
    }

    {
        let waiter = shutdown.waiter();
        let runner = Arc::clone(&runner);
        tasks.spawn(async move { queue::schedule(runner, waiter).await });
    }

    // 手工封禁热重载：管理台改的是文件，这份循环把它对齐进上面那张内存表
    // （首轮立即执行，因此重启后封禁马上恢复）。读失败时保持现状，绝不解除。
    {
        let waiter = shutdown.waiter();
        let ban_list = Arc::clone(&bans);
        let paths = runtime_config.paths.clone();
        tasks.spawn(async move { manual_bans::watch(paths, ban_list, waiter).await });
    }

    // 最后接管信号源：`waiter()` 的借用到这里全部结束。
    tasks.spawn(shutdown::watch_signals(shutdown));

    tracing::info!("服务已就绪");
    let mut task = tasks.join_next().await;
    while task.is_some() {
        task = tasks.join_next().await;
    }
    tracing::info!("MailStack 守护进程已退出");
    Ok(())
}
