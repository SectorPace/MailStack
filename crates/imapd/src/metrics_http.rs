use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use mailstack_imappop3::metrics::Metrics;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::watch;

const MAX_REQUEST_HEAD: usize = 8 * 1024;

const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(10);

const MAX_CONCURRENT_CONNECTIONS: usize = 32;

pub fn render(registries: &[Arc<Metrics>]) -> Vec<u8> {
    let mut body = Vec::new();
    for registry in registries {
        body.extend_from_slice(registry.render_prometheus().as_bytes());
    }
    body
}

pub async fn serve(
    addr: SocketAddr,
    registries: Vec<Arc<Metrics>>,
    shutdown: watch::Receiver<bool>,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    serve_on(listener, registries, shutdown).await
}

pub async fn serve_on(
    listener: TcpListener,
    registries: Vec<Arc<Metrics>>,
    shutdown: watch::Receiver<bool>,
) -> std::io::Result<()> {
    tracing::info!(addr = %listener.local_addr()?, "metrics 端点已就绪");

    let registries: Arc<[Arc<Metrics>]> = Arc::from(registries);

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

async fn respond(
    mut stream: tokio::net::TcpStream,
    registries: Arc<[Arc<Metrics>]>,

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

        tx.send(true).unwrap();
        handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn a_slow_connection_flood_is_capped() {
        let metrics = Arc::new(Metrics::new("imap"));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (tx, rx) = watch::channel(false);
        let handle = tokio::spawn(async move { serve_on(listener, vec![metrics], rx).await });

        let mut held = Vec::new();
        for _ in 0..MAX_CONCURRENT_CONNECTIONS {
            held.push(tokio::net::TcpStream::connect(address).await.unwrap());
        }

        tokio::time::sleep(Duration::from_millis(300)).await;

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
