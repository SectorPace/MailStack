use std::future::Future;

use tokio::sync::watch;

#[derive(Debug)]
pub struct Shutdown {
    tx: watch::Sender<bool>,
}

impl Shutdown {
    pub fn channel() -> Self {
        let (tx, _rx) = watch::channel(false);
        Self { tx }
    }

    pub fn waiter(&self) -> impl Future<Output = ()> + Send + 'static {
        let mut rx = self.tx.subscribe();
        async move {
            if *rx.borrow() {
                return;
            }

            let _ = rx.changed().await;
        }
    }

    pub fn receiver(&self) -> watch::Receiver<bool> {
        self.tx.subscribe()
    }

    pub fn trigger(&self) {
        self.tx.send_replace(true);
    }

    pub fn is_triggered(&self) -> bool {
        *self.tx.borrow()
    }
}

pub async fn watch_signals(shutdown: &Shutdown) {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        match (
            signal(SignalKind::terminate()),
            signal(SignalKind::interrupt()),
        ) {
            (Ok(mut term), Ok(mut int)) => {
                tokio::select! {
                    _ = term.recv() => tracing::info!("收到 SIGTERM，开始优雅停机"),
                    _ = int.recv() => tracing::info!("收到 SIGINT，开始优雅停机"),
                }
            }
            (term, int) => {
                tracing::error!(
                    term_ok = term.is_ok(),
                    int_ok = int.is_ok(),
                    "Unix 信号处理器安装失败，回落到 ctrl_c"
                );
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("收到中断信号，开始优雅停机");
    }

    shutdown.trigger();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn a_waiter_completes_once_the_signal_is_triggered() {
        let shutdown = Shutdown::channel();
        let waiter = shutdown.waiter();
        assert!(!shutdown.is_triggered());
        shutdown.trigger();
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("触发后等待者必须完成");
    }

    #[tokio::test]
    async fn a_late_waiter_completes_immediately() {
        let shutdown = Shutdown::channel();
        shutdown.trigger();
        tokio::time::timeout(Duration::from_millis(200), shutdown.waiter())
            .await
            .expect("已触发时等待者必须立即完成");
    }

    #[tokio::test]
    async fn every_waiter_is_woken() {
        let shutdown = Shutdown::channel();
        let first = shutdown.waiter();
        let second = shutdown.waiter();
        let third = shutdown.waiter();
        shutdown.trigger();
        tokio::time::timeout(Duration::from_secs(1), async {
            first.await;
            second.await;
            third.await;
        })
        .await
        .expect("所有等待者都必须被唤醒");
    }
}
