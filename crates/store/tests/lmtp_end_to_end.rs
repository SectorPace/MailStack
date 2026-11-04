use std::path::PathBuf;
use std::time::Duration;

use mailstack_store::lmtp::{LmtpClient, LmtpEndpoint, RecipientResult};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

struct Script {
    rcpt_replies: Vec<&'static str>,

    data_replies: Vec<&'static str>,
}

async fn spawn_server(dir: &std::path::Path, script: Script) -> PathBuf {
    let socket = dir.join("lmtp.sock");
    let listener = UnixListener::bind(&socket).unwrap();

    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        handle(stream, script).await;
    });

    socket
}

async fn say(write_half: &mut tokio::net::unix::OwnedWriteHalf, text: &str) {
    let _ = write_half.write_all(format!("{text}\r\n").as_bytes()).await;
    let _ = write_half.flush().await;
}

async fn handle(stream: UnixStream, script: Script) {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();

    say(&mut write_half, "220 test.invalid LMTP ready").await;

    line.clear();
    let _ = reader.read_line(&mut line).await;
    say(&mut write_half, "250-test.invalid").await;
    say(&mut write_half, "250-PIPELINING").await;
    say(&mut write_half, "250 SIZE 10240000").await;

    line.clear();
    let _ = reader.read_line(&mut line).await;
    say(&mut write_half, "250 2.1.0 ok").await;

    let mut accepted = 0usize;
    for reply in &script.rcpt_replies {
        line.clear();
        let _ = reader.read_line(&mut line).await;
        say(&mut write_half, reply).await;
        if reply.starts_with('2') {
            accepted += 1;
        }
    }

    if accepted == 0 {
        line.clear();
        let _ = reader.read_line(&mut line).await;
        say(&mut write_half, "221 bye").await;
        return;
    }

    line.clear();
    let _ = reader.read_line(&mut line).await;
    say(&mut write_half, "354 go ahead").await;

    loop {
        line.clear();
        if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
            return;
        }
        if line.trim_end_matches(['\r', '\n']) == "." {
            break;
        }
    }

    for reply in script.data_replies.iter().take(accepted) {
        say(&mut write_half, reply).await;
    }

    line.clear();
    let _ = reader.read_line(&mut line).await;
    say(&mut write_half, "221 bye").await;

    let mut sink = [0u8; 64];
    let _ = reader.read(&mut sink).await;
}

fn client(socket: &std::path::Path) -> LmtpClient {
    LmtpClient::new(
        LmtpEndpoint::unix(socket),
        "mail.example.org",
        Duration::from_secs(5),
    )
}

fn recipients(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}

#[tokio::test]
async fn delivers_to_every_recipient_and_reports_acceptance() {
    let dir = tempfile::tempdir().unwrap();
    let socket = spawn_server(
        dir.path(),
        Script {
            rcpt_replies: vec!["250 2.1.5 ok", "250 2.1.5 ok"],
            data_replies: vec!["250 2.0.0 delivered", "250 2.0.0 delivered"],
        },
    )
    .await;

    let delivery = client(&socket)
        .deliver(
            "sender@example.org",
            &recipients(&["a@example.org", "b@example.org"]),
            "Subject: hi\r\n\r\nbody",
        )
        .await
        .unwrap();

    assert!(delivery.all_accepted());
    assert_eq!(delivery.accepted().len(), 2);
    assert_eq!(delivery.results[0].recipient, "a@example.org");
    assert_eq!(delivery.results[1].recipient, "b@example.org");
}

#[tokio::test]
async fn reads_one_reply_per_recipient_after_data() {
    let dir = tempfile::tempdir().unwrap();
    let socket = spawn_server(
        dir.path(),
        Script {
            rcpt_replies: vec!["250 2.1.5 ok", "250 2.1.5 ok"],
            data_replies: vec!["250 2.0.0 delivered", "452 4.2.2 over quota"],
        },
    )
    .await;

    let delivery = client(&socket)
        .deliver(
            "sender@example.org",
            &recipients(&["ok@example.org", "full@example.org"]),
            "body",
        )
        .await
        .unwrap();

    assert!(!delivery.all_accepted(), "一个超配额，不应判为全部成功");
    assert_eq!(delivery.accepted(), vec!["ok@example.org"]);
    let failed = delivery.failed();
    assert_eq!(failed.len(), 1);
    assert_eq!(failed[0].recipient, "full@example.org");
    assert_eq!(failed[0].code, 452);

    assert_eq!(delivery.results[0].recipient, "ok@example.org");
    assert_eq!(delivery.results[1].recipient, "full@example.org");
}

#[tokio::test]
async fn a_recipient_rejected_at_rcpt_stage_still_appears_in_the_result() {
    let dir = tempfile::tempdir().unwrap();
    let socket = spawn_server(
        dir.path(),
        Script {
            rcpt_replies: vec!["250 2.1.5 ok", "550 5.1.1 unknown user"],
            data_replies: vec!["250 2.0.0 delivered"],
        },
    )
    .await;

    let delivery = client(&socket)
        .deliver(
            "sender@example.org",
            &recipients(&["ok@example.org", "ghost@example.org"]),
            "body",
        )
        .await
        .unwrap();

    assert_eq!(delivery.results.len(), 2, "两个收件人都要有结果");
    assert_eq!(delivery.results[0].code, 250);
    assert_eq!(delivery.results[1].recipient, "ghost@example.org");
    assert_eq!(delivery.results[1].code, 550);
    assert!(!delivery.results[1].accepted());
}

#[tokio::test]
async fn every_recipient_rejected_at_rcpt_skips_the_data_phase() {
    let dir = tempfile::tempdir().unwrap();
    let socket = spawn_server(
        dir.path(),
        Script {
            rcpt_replies: vec!["550 5.1.1 unknown", "550 5.1.1 unknown"],
            data_replies: vec![],
        },
    )
    .await;

    let delivery = client(&socket)
        .deliver(
            "sender@example.org",
            &recipients(&["a@example.org", "b@example.org"]),
            "body",
        )
        .await
        .unwrap();

    assert_eq!(delivery.results.len(), 2);
    assert!(delivery.accepted().is_empty());
    assert!(delivery.results.iter().all(|r| r.code == 550));
}

#[tokio::test]
async fn message_body_is_dot_stuffed_and_terminated() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("lmtp.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (read_half, mut write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);
        let mut line = String::new();

        say(&mut write_half, "220 ready").await;

        for reply in [
            "250 SIZE 10240000",
            "250 2.1.0 ok",
            "250 2.1.5 ok",
            "354 go",
        ] {
            line.clear();
            let _ = reader.read_line(&mut line).await;
            say(&mut write_half, reply).await;
        }

        let mut body = String::new();
        loop {
            line.clear();
            if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                break;
            }
            if line.trim_end_matches(['\r', '\n']) == "." {
                break;
            }
            body.push_str(&line);
        }
        let _ = tx.send(body);
        say(&mut write_half, "250 2.0.0 delivered").await;
        line.clear();
        let _ = reader.read_line(&mut line).await;
        say(&mut write_half, "221 bye").await;
    });

    client(&socket)
        .deliver(
            "sender@example.org",
            &recipients(&["a@example.org"]),
            "Subject: hi\r\n\r\n.hidden line\r\nnormal",
        )
        .await
        .unwrap();

    let body = rx.await.unwrap();
    assert!(
        body.contains("\r\n..hidden line\r\n"),
        "行首句点必须被转义，实际收到：{body:?}"
    );
    assert!(body.contains("normal"));
}

#[tokio::test]
async fn connection_failure_is_reported_as_an_error_not_a_silent_success() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("does-not-exist.sock");

    let result = client(&missing)
        .deliver(
            "sender@example.org",
            &recipients(&["a@example.org"]),
            "body",
        )
        .await;
    assert!(
        result.is_err(),
        "连不上 Dovecot 必须报错，否则邮件会凭空消失"
    );
}

#[tokio::test]
async fn an_empty_recipient_list_is_rejected_before_connecting() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("does-not-exist.sock");

    let result = client(&missing)
        .deliver("sender@example.org", &[], "body")
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn transport_reports_partial_success_so_nothing_is_delivered_twice() {
    use mailstack_queue::{DeliveryTarget, QueueEntry, Transport};

    let dir = tempfile::tempdir().unwrap();
    let socket = spawn_server(
        dir.path(),
        Script {
            rcpt_replies: vec!["250 2.1.5 ok", "250 2.1.5 ok"],
            data_replies: vec!["250 2.0.0 delivered", "452 4.2.2 over quota"],
        },
    )
    .await;

    let transport = mailstack_store::LmtpTransport::new(client(&socket));
    let entry = QueueEntry::new(
        mailstack_queue::EntryKind::Outbound,
        "sender@example.org",
        recipients(&["ok@example.org", "full@example.org"]),
        "body",
        0,
    )
    .unwrap();

    let failure = transport
        .deliver(&entry, DeliveryTarget::Local, &entry.recipients)
        .await
        .unwrap_err();

    assert_eq!(
        failure.accepted,
        vec!["ok@example.org".to_string()],
        "已落箱的收件人必须被带回，否则重试会重复投递"
    );
    assert!(
        failure.message.contains("full@example.org"),
        "失败收件人要有记录：{}",
        failure.message
    );
}

#[tokio::test]
async fn endpoint_overrides_are_honoured() {
    let endpoint = LmtpEndpoint::unix("/tmp/custom.sock");
    assert_eq!(endpoint.describe(), "/tmp/custom.sock");

    let tcp = LmtpEndpoint::loopback();
    assert_eq!(tcp.describe(), "127.0.0.1:24");

    assert_eq!(
        LmtpEndpoint::default_unix().describe(),
        mailstack_store::DEFAULT_LMTP_SOCKET
    );
}

#[test]
fn recipient_result_classification() {
    let ok = RecipientResult {
        recipient: "a@x".to_string(),
        code: 250,
        message: "delivered".to_string(),
    };
    assert!(ok.accepted());

    let quota = RecipientResult {
        recipient: "b@x".to_string(),
        code: 452,
        message: "over quota".to_string(),
    };
    assert!(!quota.accepted());
}
