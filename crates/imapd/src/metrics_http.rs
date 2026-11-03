//! 极简 `/metrics` HTTP 端点（Prometheus 文本格式）。
//!
//! ## 为什么不用 axum
//!
//! 这个端点只有一个 GET、一个固定响应体：为它拉进整套 HTTP 框架（及其依赖树）
//! 不划算。手写的部分刻意小到可以一眼看完 —— 读请求头（有界）、回 200 + 正文、
//! 关连接。**绑定地址必须只对监控网段开放**（生产是 `127.0.0.1:9100` 或内网），
//! 它不做任何认证。
//!
//! ## 指标的来源
//!
//! 每个协议监听器持有一份 [`Metrics`]（protocol 标签区分 imap/pop3/managesieve/lmtp）。
//! 调用方把要暴露的注册表收集成 `Vec` 传进来，这里按顺序拼接渲染 —— 指标的
//! 收集/埋点仍在本 crate 与 `mailstack-imappop3` 各自的路径上，这里只做展示。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use mailstack_imappop3::metrics::Metrics;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::watch;

/// 请求头的读取上限。GET /metrics 的请求头远小于这个值；超限直接断开。
const MAX_REQUEST_HEAD: usize = 8 * 1024;

/// 单次读请求头的超时。对端迟迟不发完整头（半开连接、慢速客户端）时断开，
/// 避免连接任务无限挂着；与其它监听器绑定握手/读超时的思路一致。
const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// 同时处理的连接上限（R5-019）。
///
/// 端点不做任何认证，每条连接最多占用 [`REQUEST_READ_TIMEOUT`]（10 秒）+ 1KB
/// 缓冲。没有上限时，一个只连不发的慢速连接洪水就能堆出任意多任务 —— 部署时
/// `--metrics 0.0.0.0:9100` 是一个很容易被写进脚本的形态。
///
/// 超过上限时**立刻关闭**新连接：抓取器会把连接重置当作「端点不可用」，
/// 与回 503 的语义一致，且不额外消耗任何任务/内存。
const MAX_CONCURRENT_CONNECTIONS: usize = 32;

/// 渲染全部注册表为 Prometheus 文本。
pub fn render(registries: &[Arc<Metrics>]) -> Vec<u8> {
    let mut body = Vec::new();
    for registry in registries {
        body.extend_from_slice(registry.render_prometheus().as_bytes());
    }
    body
}

/// 在 `addr` 上提供 `/metrics`，直到 `shutdown` 触发。
pub async fn serve(
    addr: SocketAddr,
    registries: Vec<Arc<Metrics>>,
    shutdown: watch::Receiver<bool>,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    serve_on(listener, registries, shutdown).await
}

/// 已绑定监听器的版本：让调用方（或测试）自己持有 socket，避免重复绑定。
pub async fn serve_on(
    listener: TcpListener,
    registries: Vec<Arc<Metrics>>,
    shutdown: watch::Receiver<bool>,
) -> std::io::Result<()> {
    tracing::info!(addr = %listener.local_addr()?, "metrics 端点已就绪");
    // 注册表以 Arc<[..]> 共享给每条连接；响应体**每请求渲染一次** ——
    // 指标是持续增长的，启动时渲染一份冻结快照会让每次抓取都拿到旧值。
    let registries: Arc<[Arc<Metrics>]> = Arc::from(registries);
    // 并发闸门：许可随连接任务存活，任务结束（含被取消）自动归还。
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
    let mut shutdown = shutdown;
    loop {
        tokio::select! {
            _ = shutdown.changed() => return Ok(()),
            accepted = listener.accept() => {
                let (stream, _peer) = match accepted {
                    Ok(pair) => pair,
                    Err(error) => {
                        tracing::warn!(%error, "metrics accept 失败");
                        continue;
                    }
                };
                let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else {
                    // 超出上限：直接断开。不 spawn 任务，不占任何资源。
                    tracing::warn!(
                        limit = MAX_CONCURRENT_CONNECTIONS,
                        "metrics 并发连接超过上限，拒绝新连接"
                    );
                    drop(stream);
                    continue;
                };
                let registries = Arc::clone(&registries);
                tokio::spawn(async move { respond(stream, registries, permit).await });
            }
        }
    }
}

/// 读掉请求头（有界），回 200 + 正文。任何方法/路径都按 /metrics 处理：
/// 抓取器只认响应体，探活也用同一个端点。
async fn respond(
    mut stream: tokio::net::TcpStream,
    registries: Arc<[Arc<Metrics>]>,
    // 只用于持有并发许可：连接任务结束（函数返回）时自动释放。
    _permit: tokio::sync::OwnedSemaphorePermit,
) {
    let mut head = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let read = match tokio::time::timeout(REQUEST_READ_TIMEOUT, stream.read(&mut chunk)).await {
            Ok(Ok(read)) => read,
            Ok(Err(_)) | Err(_) => return,
        };
        if read == 0 {
            return;
        }
        head.extend_from_slice(&chunk[..read]);
        if head.windows(4).any(|window| window == b"\r\n\r\n") || head.len() > MAX_REQUEST_HEAD {
            break;
        }
    }
    let body = render(&registries);
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.write_all(&body).await;
    let _ = stream.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn the_endpoint_serves_the_prometheus_body_then_closes() {
        let metrics = Arc::new(Metrics::new("imap"));
        metrics.connection_accepted();
        let live_metrics = Arc::clone(&metrics);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (tx, rx) = watch::channel(false);
        let handle = tokio::spawn(async move { serve_on(listener, vec![metrics], rx).await });

        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        stream
            .write_all(b"GET /metrics HTTP/1.1\r\nHost: m\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
            .await
            .expect("读超时")
            .unwrap();
        let text = String::from_utf8_lossy(&response);
        assert!(text.starts_with("HTTP/1.1 200 OK"), "{text}");
        assert!(
            text.contains("Content-Type: text/plain; version=0.0.4"),
            "{text}"
        );
        assert!(
            text.contains("mailstack_imappop3_connections_accepted_total{protocol=\"imap\"} 1"),
            "{text}"
        );

        // 服务启动后计数器继续增长：再抓一次必须看到新值 —— 响应体不能是
        // 启动时渲染的冻结快照。
        live_metrics.connection_accepted();
        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        stream
            .write_all(b"GET /metrics HTTP/1.1\r\nHost: m\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
            .await
            .expect("读超时")
            .unwrap();
        let text = String::from_utf8_lossy(&response);
        assert!(
            text.contains("mailstack_imappop3_connections_accepted_total{protocol=\"imap\"} 2"),
            "第二次抓取必须反映新计数: {text}"
        );

        // 通知停机，服务端应正常退出。
        tx.send(true).unwrap();
        handle.await.unwrap().unwrap();
    }

    /// R5-019：只连不发的连接洪水不得无限堆任务；超过上限的新连接被立刻关闭。
    #[tokio::test]
    async fn a_slow_connection_flood_is_capped() {
        let metrics = Arc::new(Metrics::new("imap"));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (tx, rx) = watch::channel(false);
        let handle = tokio::spawn(async move { serve_on(listener, vec![metrics], rx).await });

        // 占满全部许可：连上之后一句话都不发（模拟慢速连接洪水）。
        let mut held = Vec::new();
        for _ in 0..MAX_CONCURRENT_CONNECTIONS {
            held.push(tokio::net::TcpStream::connect(address).await.unwrap());
        }
        // 给 accept 循环一点时间把许可全部取走。
        tokio::time::sleep(Duration::from_millis(300)).await;

        // 超限的新连接必须在**很短**的时间内被关闭（而不是排成一个任务等 10 秒）。
        let mut closed = 0;
        for _ in 0..8 {
            let mut overflow = tokio::net::TcpStream::connect(address).await.unwrap();
            let mut buffer = [0u8; 1];
            match tokio::time::timeout(Duration::from_secs(1), overflow.read(&mut buffer)).await {
                Ok(Ok(0)) | Ok(Err(_)) => closed += 1,
                Ok(Ok(_)) => panic!("超限连接居然收到了响应字节"),
                Err(_) => {}
            }
        }
        assert!(closed > 0, "并发上限没有生效：{} 条超限连接全部被挂住", 8);

        tx.send(true).unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
        drop(held);
    }

    #[test]
    fn render_concatenates_registries_in_order() {
        let imap = Arc::new(Metrics::new("imap"));
        let lmtp = Arc::new(Metrics::new("lmtp"));
        lmtp.connection_accepted();
        let body = String::from_utf8(render(&[Arc::clone(&imap), lmtp])).unwrap();
        let imap_index = body.find("protocol=\"imap\"").expect("imap 段缺失");
        let lmtp_index = body.find("protocol=\"lmtp\"").expect("lmtp 段缺失");
        assert!(imap_index < lmtp_index, "渲染顺序必须与传入顺序一致");
    }
}
