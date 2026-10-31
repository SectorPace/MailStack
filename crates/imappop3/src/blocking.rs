//! 把同步 Maildir 操作移出 async worker。
//!
//! Maildir 层刻意保持同步（文件原子性、flock、目录扫描都更容易写对），但
//! `std::fs` 在 Tokio worker 上执行会阻塞整个线程。会话层通过本模块把每次
//! 目录扫描 / 读写 / 改名丢给 blocking 线程池：
//!
//! * worker 只负责协议解析与写 socket；
//! * 慢盘只会堆积 blocking 池（可观测、可限流），不会让所有连接一起卡住。
//!
//! 闭包必须 `'static`：调用方需要克隆 `Arc<MailStore>` 与必要的参数。

use std::sync::Arc;

use crate::error::{MailError, Result};
use crate::maildir::MailStore;

pub async fn maildir<T, F>(store: &Arc<MailStore>, operation: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(&MailStore) -> Result<T> + Send + 'static,
{
    let store = Arc::clone(store);
    match tokio::task::spawn_blocking(move || operation(&store)).await {
        Ok(result) => result,
        Err(error) => {
            // JoinError 代表 blocking 任务 panic 或 runtime 关闭；这是服务器
            // 故障，不是客户端错误。
            tracing::warn!(%error, "maildir blocking task failed");
            Err(MailError::storage(format!(
                "maildir worker failed: {error}"
            )))
        }
    }
}
