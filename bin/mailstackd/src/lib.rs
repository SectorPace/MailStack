pub mod config;
pub mod error;
pub mod listeners;
pub mod manual_bans;
pub mod queue;

#[cfg(unix)]
pub mod lmtp;

#[cfg(unix)]
pub mod rpc;
pub mod shutdown;

use std::sync::Arc;

use mailstack_core::Paths;
use mailstack_smtpd::{BanList, Clock, QueueSink, RateLimiter, SystemClock};

pub use config::{assemble, ListenerPlan, RuntimeConfig, DEFAULT_PORTS};
pub use error::DaemonError;

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

    let servers = listeners::bind_all(
        &runtime_config,
        Arc::clone(&sink),
        Arc::clone(&clock),
        Arc::clone(&rate),
        Arc::clone(&bans),
    )
    .await?;
    let runner = queue::build_runner(&runtime_config)?;

    let lmtp_server = lmtp::build_server(&runtime_config)?;
    let lmtp_socket = lmtp::socket_file(&runtime_config.paths)?;

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
