use std::path::{Path, PathBuf};
use std::sync::Arc;

use mailstack_imapd::resolver::SystemMaildirResolver;
use mailstack_imappop3::lmtp::router::LmtpRouter;
use mailstack_imappop3::lmtp::server::{LmtpServer, LmtpServerConfig};
use mailstack_imappop3::lmtp::session::{LmtpConfig, LmtpContext};
use mailstack_imappop3::maildir::MailStore;
use mailstack_imappop3::outbound::QueueOutboundSink;
use mailstack_imappop3::resolver::MailboxResolver;

use crate::config::RuntimeConfig;
use crate::error::DaemonError;

const PASSWD_ROOT: &str = "/etc";
const MAILDIR_NAME: &str = "Maildir";

pub fn socket_path(paths: &mailstack_core::Paths) -> PathBuf {
    paths.run_dir.join("lmtp.sock")
}

struct ResolverRouter {
    resolver: Arc<dyn MailboxResolver>,
}

impl LmtpRouter for ResolverRouter {
    fn route(&self, recipient: &str) -> Option<Arc<MailStore>> {
        self.resolver.resolve(recipient)
    }
}

pub fn build_server(config: &RuntimeConfig) -> Result<LmtpServer, DaemonError> {
    build_server_at(Path::new(PASSWD_ROOT), MAILDIR_NAME, &config.queue_root)
}

pub fn build_server_at(
    passwd_root: &Path,
    maildir_name: &str,
    queue_root: &Path,
) -> Result<LmtpServer, DaemonError> {
    let resolver: Arc<dyn MailboxResolver> = Arc::new(SystemMaildirResolver::new(
        passwd_root.to_path_buf(),
        maildir_name.to_string(),
    ));
    let context = LmtpContext {
        router: Arc::new(ResolverRouter { resolver }),
        config: LmtpConfig::default(),
        outbound: Some(Arc::new(QueueOutboundSink::new(queue_root))),
    };
    let server = LmtpServer::new(context, LmtpServerConfig::default())
        .map_err(|error| DaemonError::Lmtp(format!("服务端配置非法：{error}")))?;
    Ok(server)
}

pub fn socket_file(paths: &mailstack_core::Paths) -> Result<PathBuf, DaemonError> {
    std::fs::create_dir_all(&paths.run_dir).map_err(|error| {
        DaemonError::Lmtp(format!(
            "无法创建 LMTP socket 目录 {}：{error}",
            paths.run_dir.display()
        ))
    })?;
    Ok(socket_path(paths))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::time::Duration;

    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;

    fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let passwd_root = dir.path().join("etc");
        std::fs::create_dir_all(&passwd_root).unwrap();
        let home = dir.path().join("home").join("dave");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(
            passwd_root.join("passwd"),
            format!("dave:x:1003:1003::{}:/usr/sbin/nologin\n", home.display()),
        )
        .unwrap();
        let queue_root = dir.path().join("queue");
        (dir, home, queue_root)
    }

    async fn wait_for_socket(socket: &Path) {
        for _ in 0..400 {
            if socket.exists() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("socket 未在预期时间内出现：{}", socket.display());
    }

    async fn command(
        writer: &mut tokio::io::WriteHalf<UnixStream>,
        reader: &mut BufReader<tokio::io::ReadHalf<UnixStream>>,
        line: &str,
    ) -> Vec<String> {
        writer.write_all(line.as_bytes()).await.unwrap();
        writer.write_all(b"\r\n").await.unwrap();
        writer.flush().await.unwrap();
        let mut replies = Vec::new();
        loop {
            let mut reply = String::new();
            reader.read_line(&mut reply).await.unwrap();
            assert!(!reply.is_empty(), "连接被对端关闭");
            let done = ["250 ", "354 ", "550 ", "221 "]
                .iter()
                .any(|prefix| reply.starts_with(prefix));
            replies.push(reply);
            if done {
                return replies;
            }
        }
    }

    #[tokio::test]
    async fn local_delivery_lands_in_the_recipients_maildir() {
        let (dir, home, queue_root) = fixture();
        let server = build_server_at(&dir.path().join("etc"), "Maildir", &queue_root).unwrap();
        let socket = dir.path().join("lmtp.sock");
        let (tx, rx) = tokio::sync::watch::channel(false);
        let server_socket = socket.clone();
        let handle = tokio::spawn(async move { server.serve_unix(server_socket, 0o600, rx).await });
        wait_for_socket(&socket).await;

        let stream = UnixStream::connect(&socket).await.unwrap();
        let (read_half, mut write_half) = tokio::io::split(stream);
        let mut reader = BufReader::new(read_half);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.unwrap();
        assert!(greeting.starts_with("220 "), "问候语异常：{greeting}");

        command(&mut write_half, &mut reader, "LHLO test.example").await;
        command(
            &mut write_half,
            &mut reader,
            "MAIL FROM:<sender@example.org>",
        )
        .await;
        let unknown = command(&mut write_half, &mut reader, "RCPT TO:<nobody@example.com>").await;
        assert!(
            unknown.last().unwrap().starts_with("550 "),
            "未知收件人必须被拒：{unknown:?}"
        );
        command(&mut write_half, &mut reader, "RCPT TO:<dave@example.com>").await;
        command(&mut write_half, &mut reader, "DATA").await;
        write_half
            .write_all(b"Subject: hi\r\n\r\nbody\r\n.\r\n")
            .await
            .unwrap();
        write_half.flush().await.unwrap();
        let mut delivered = String::new();
        reader.read_line(&mut delivered).await.unwrap();
        assert!(delivered.starts_with("250 "), "投递应成功：{delivered}");
        command(&mut write_half, &mut reader, "QUIT").await;

        let maildir = home.join("Maildir");
        let mut count = 0;
        for directory in ["new", "cur"] {
            count += std::fs::read_dir(maildir.join(directory))
                .unwrap()
                .filter_map(|entry| entry.ok())
                .count();
        }
        assert_eq!(count, 1, "收件人 Maildir 里应有一封信");

        drop(reader);
        drop(write_half);
        tx.send(true).unwrap();
        handle.await.unwrap().unwrap();
        assert!(!socket.exists(), "停机后应清理 socket 文件");
    }
}
