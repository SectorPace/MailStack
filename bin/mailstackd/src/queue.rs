use std::sync::Arc;
use std::time::Duration;

use mailstack_queue::{DkimSigner, QueueRunner, QueueStore, SmtpRemoteTransport, Transport};
use mailstack_smtp::{AddressPolicy, HickoryMxResolver, PinnedDialer};
use mailstack_store::{LmtpClient, LmtpTransport};

use crate::config::RuntimeConfig;
use crate::error::DaemonError;

pub const SCHEDULE_INTERVAL: Duration = Duration::from_secs(10);

pub const ROUND_TIMEOUT: Duration = Duration::from_secs(600);

const TRANSPORT_TIMEOUT: Duration = Duration::from_secs(30);

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

fn address_policy(config: &RuntimeConfig) -> AddressPolicy {
    if config.allow_private_network {
        AddressPolicy::allow_private()
    } else {
        AddressPolicy::public_only()
    }
}

pub async fn schedule(runner: Arc<QueueRunner>, shutdown: impl std::future::Future<Output = ()>) {
    let mut shutdown = std::pin::pin!(shutdown);
    let mut ticker = tokio::time::interval(SCHEDULE_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let mut in_flight: Option<tokio::task::JoinHandle<()>> = None;

    loop {
        if in_flight
            .as_ref()
            .is_some_and(|handle| handle.is_finished())
        {
            if let Some(handle) = in_flight.take() {
                let _ = handle.await;
            }
        }

        tokio::select! {
            _ = &mut shutdown => {

                if let Some(mut handle) = in_flight.take() {
                    match tokio::time::timeout(ROUND_TIMEOUT, &mut handle).await {
                        Ok(_) => tracing::info!("队列调度停止（在途轮次已收尾）"),
                        Err(_) => {

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

                        Err(error) if error.is_busy() => {
                            tracing::debug!(error = %error, "队列轮次被跳过")
                        }

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

        tokio::time::sleep(Duration::from_millis(50)).await;
        shutdown.trigger();
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("停机信号必须让调度循环退出")
            .expect("任务不得 panic");
    }
}
