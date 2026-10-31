//! 停机信号的**一次触发、多方等待**。
//!
//! 三个 `MailServer` 与队列调度循环都要在同一个信号上停下来，因此需要扇出。
//! 用 `watch` 而不是 `broadcast`：停机是一个**电平**（一直是「已停机」），不是一串
//! 事件 —— 后加入的等待者必须立刻看到「已经停了」，而不是错过那个事件后永远等下去。

use std::future::Future;

use tokio::sync::watch;

/// 停机信号源。
#[derive(Debug)]
pub struct Shutdown {
    tx: watch::Sender<bool>,
}

impl Shutdown {
    /// 建一个尚未触发的信号源。
    pub fn channel() -> Self {
        let (tx, _rx) = watch::channel(false);
        Self { tx }
    }

    /// 取一个「停机后完成」的 future。
    ///
    /// 每个消费者各取一个；若调用时信号已经触发，返回的 future 会**立即**完成。
    pub fn waiter(&self) -> impl Future<Output = ()> + Send + 'static {
        let mut rx = self.tx.subscribe();
        async move {
            if *rx.borrow() {
                return;
            }
            // `changed()` 只在值变化后返回；发送端被丢弃也算一种「停机」。
            let _ = rx.changed().await;
        }
    }

    /// 取一份原始的 `watch::Receiver<bool>`。
    ///
    /// 给需要 receiver 本体（而不是「停机后完成」的 future）的组件用：
    /// `mailstack-imappop3` 的监听器都以它作为优雅停机的信号源。
    pub fn receiver(&self) -> watch::Receiver<bool> {
        self.tx.subscribe()
    }

    /// 触发停机。
    ///
    /// 必须用 `send_replace` 而不是 `send`：`send` 在**没有任何接收者**时是空操作
    /// （不更新值）。而本类型的用法恰恰是「先触发、有人再后来等」—— 用 `send` 会让
    /// 后来者永远等不到信号。
    pub fn trigger(&self) {
        self.tx.send_replace(true);
    }

    /// 是否已触发。
    pub fn is_triggered(&self) -> bool {
        *self.tx.borrow()
    }
}

/// 等待 SIGINT / SIGTERM，然后触发 `shutdown`。
///
/// 非 Unix 平台回落到 `ctrl_c`。信号处理器安装失败时也回落到 `ctrl_c` —— 宁可少认
/// 一个信号，也不要出现「没有任何办法让它优雅退出」的状态。
pub async fn watch_signals(shutdown: Shutdown) {
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
        // 电平语义：信号已经触发后加入的等待者不能错过它。
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
