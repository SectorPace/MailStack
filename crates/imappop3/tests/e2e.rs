//! 端到端测试：真实双工会话（内存双工）与真实 TCP 监听器。
//!
//! 目的不是重复单元测试，而是验证**跨层**行为：
//!
//! * 认证（PBKDF2 记录）→ SELECT → FETCH/SEARCH/STORE/EXPUNGE → 落盘；
//! * literal（含 LITERAL+）在会话层的读取与应答；
//! * POP3 的独占锁、UIDL 与 QUIT 提交语义；
//! * 监听器的问候语与优雅停机。

use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use mailstack_imappop3::auth::{AuthBackend, MemoryDirectory, PasswordDirectory};
use mailstack_imappop3::imap::server::{ImapServer, ImapServerConfig};
use mailstack_imappop3::imap::session::{
    serve_connection as imap_serve, ConnectionOptions, ImapConfig, ImapExit, ImapSessionContext,
};
use mailstack_imappop3::maildir::{Flag, FlagSet, MailStore, SystemClock, SystemFlag, INBOX};
use mailstack_imappop3::metrics::Metrics;
use mailstack_imappop3::pop3::session::{
    serve_connection as pop3_serve, Pop3Config, Pop3ConnectionOptions, Pop3Exit, Pop3SessionContext,
};
use sha2::Digest;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, DuplexStream};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::timeout;

const PASSWORD: &str = "Correct-Horse-9-Battery";
const PEER: &str = "192.0.2.10:50000";

struct Fixture {
    _directory: tempfile::TempDir,
    store: Arc<MailStore>,
    auth: AuthBackend,
}

fn fixture() -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(MailStore::new(directory.path(), Arc::new(SystemClock)).unwrap());
    let mut record = mailstack_core::password::password_record("bob", PASSWORD).unwrap();
    record.username = "bob@example.com".to_string();
    let mut users = MemoryDirectory::new();
    users.insert(record);
    Fixture {
        _directory: directory,
        store,
        auth: AuthBackend::new(Arc::new(PasswordDirectory::new(users))),
    }
}

fn imap_context(fixture: &Fixture) -> ImapSessionContext {
    ImapSessionContext {
        store: Arc::clone(&fixture.store),
        auth: fixture.auth.clone(),
        config: ImapConfig {
            server_name: "mail.test".to_string(),
            require_tls: false,
            idle_poll: Duration::from_millis(50),
            read_timeout: Duration::from_secs(10),
            ..ImapConfig::default()
        },
        metrics: Arc::new(Metrics::new("imap")),
        resolver: None,
    }
}

fn pop3_context(fixture: &Fixture) -> Pop3SessionContext {
    Pop3SessionContext {
        store: Arc::clone(&fixture.store),
        auth: fixture.auth.clone(),
        config: Pop3Config {
            server_name: "mail.test".to_string(),
            require_tls: false,
            read_timeout: Duration::from_secs(10),
            ..Pop3Config::default()
        },
        // 单用户夹具：不装配按用户名解析的邮箱目录（多用户见 tests/multi_user.rs）。
        resolver: None,
    }
}

fn seen() -> FlagSet {
    let mut flags = FlagSet::new();
    flags.insert(Flag::System(SystemFlag::Seen));
    flags
}

fn spawn_imap(
    fixture: &Fixture,
) -> (
    Client,
    JoinHandle<mailstack_imappop3::Result<ImapExit<DuplexStream>>>,
) {
    let (client_io, server_io) = tokio::io::duplex(256 * 1024);
    let context = Arc::new(imap_context(fixture));
    let handle = tokio::spawn(async move {
        imap_serve(
            server_io,
            &context,
            PEER.parse().unwrap(),
            ConnectionOptions {
                secured: false,
                starttls_available: false,
                greet: true,
            },
        )
        .await
    });
    (Client::new(client_io), handle)
}

fn spawn_with_context(
    context: ImapSessionContext,
) -> (
    Client,
    JoinHandle<mailstack_imappop3::Result<ImapExit<DuplexStream>>>,
) {
    let (client_io, server_io) = tokio::io::duplex(256 * 1024);
    let context = Arc::new(context);
    let handle = tokio::spawn(async move {
        imap_serve(
            server_io,
            &context,
            PEER.parse().unwrap(),
            ConnectionOptions {
                secured: false,
                starttls_available: false,
                greet: true,
            },
        )
        .await
    });
    (Client::new(client_io), handle)
}

fn spawn_pop3(
    fixture: &Fixture,
) -> (
    Client,
    JoinHandle<mailstack_imappop3::Result<Pop3Exit<DuplexStream>>>,
) {
    let (client_io, server_io) = tokio::io::duplex(256 * 1024);
    let context = Arc::new(pop3_context(fixture));
    let handle = tokio::spawn(async move {
        pop3_serve(
            server_io,
            &context,
            PEER.parse().unwrap(),
            Pop3ConnectionOptions {
                secured: false,
                starttls_available: false,
                greet: true,
            },
        )
        .await
    });
    (Client::new(client_io), handle)
}

struct Client {
    io: BufReader<DuplexStream>,
}

impl Client {
    fn new(stream: DuplexStream) -> Self {
        Self {
            io: BufReader::new(stream),
        }
    }

    async fn send(&mut self, line: &str) {
        let io = self.io.get_mut();
        io.write_all(line.as_bytes()).await.unwrap();
        io.write_all(b"\r\n").await.unwrap();
        io.flush().await.unwrap();
    }

    async fn send_raw(&mut self, bytes: &[u8]) {
        let io = self.io.get_mut();
        io.write_all(bytes).await.unwrap();
        io.flush().await.unwrap();
    }

    async fn line(&mut self) -> String {
        let mut line = String::new();
        let read = timeout(Duration::from_secs(15), self.io.read_line(&mut line))
            .await
            .expect("读取超时")
            .unwrap();
        assert!(read > 0, "连接被对端关闭");
        line
    }

    async fn until_tag(&mut self, tag: &str) -> Vec<String> {
        let mut lines = Vec::new();
        loop {
            let line = self.line().await;
            let done = line.starts_with(&format!("{tag} "));
            lines.push(line);
            if done {
                return lines;
            }
        }
    }

    async fn until_line(&mut self, expected: &str) -> Vec<String> {
        let mut lines = Vec::new();
        loop {
            let line = self.line().await;
            let done = line.trim_end_matches(['\r', '\n']) == expected;
            lines.push(line);
            if done {
                return lines;
            }
        }
    }
}

fn join_lines(lines: &[String]) -> String {
    lines.concat()
}

#[tokio::test]
async fn imap_login_select_fetch_and_logout() {
    let fixture = fixture();
    fixture
        .store
        .append(
            INBOX,
            b"From: Alice <alice@example.com>\r\nTo: bob@example.com\r\nSubject: first\r\n\
Date: Fri, 23 Oct 2026 14:30:00 +0800\r\nMIME-Version: 1.0\r\n\
Content-Type: text/plain; charset=utf-8\r\n\r\nfirst body\r\n",
            &FlagSet::new(),
            None,
        )
        .unwrap();
    fixture
        .store
        .append(
            INBOX,
            b"From: carol@example.com\r\nSubject: second\r\n\r\nsecond body\r\n",
            &seen(),
            None,
        )
        .unwrap();

    let (mut client, handle) = spawn_imap(&fixture);
    let greeting = client.line().await;
    assert!(
        greeting.starts_with("* OK [CAPABILITY IMAP4rev1"),
        "{greeting}"
    );
    assert!(greeting.contains("AUTH=PLAIN"));

    client.send("a1 LOGIN bob@example.com WrongPassword1").await;
    let lines = join_lines(&client.until_tag("a1").await);
    assert!(lines.contains("NO [AUTHENTICATIONFAILED]"), "{lines}");

    client
        .send(&format!("a2 LOGIN bob@example.com {PASSWORD}"))
        .await;
    let lines = join_lines(&client.until_tag("a2").await);
    assert!(lines.contains("OK [CAPABILITY"), "{lines}");

    client.send("a3 SELECT INBOX").await;
    let lines = join_lines(&client.until_tag("a3").await);
    assert!(lines.contains("* 2 EXISTS"), "{lines}");
    assert!(lines.contains("* 1 RECENT"), "{lines}");
    assert!(lines.contains("[UIDVALIDITY"), "{lines}");
    assert!(lines.contains("[UNSEEN 1]"), "{lines}");
    assert!(lines.contains("OK [READ-WRITE]"), "{lines}");

    client
        .send("a4 FETCH 1 (FLAGS UID RFC822.SIZE ENVELOPE BODYSTRUCTURE)")
        .await;
    let lines = join_lines(&client.until_tag("a4").await);
    assert!(lines.contains("* 1 FETCH ("), "{lines}");
    assert!(lines.contains("UID 1"), "{lines}");
    assert!(lines.contains("ENVELOPE (\""), "{lines}");
    assert!(
        lines.contains("BODYSTRUCTURE (\"TEXT\" \"PLAIN\""),
        "{lines}"
    );

    client
        .send("a5 UID FETCH 2 (BODY.PEEK[HEADER.FIELDS (SUBJECT)])")
        .await;
    let lines = join_lines(&client.until_tag("a5").await);
    assert!(lines.contains("UID 2"), "{lines}");
    assert!(
        lines.contains("BODY[HEADER.FIELDS (SUBJECT)]"),
        "section 标签必须原样回显：{lines}"
    );
    assert!(lines.contains("Subject: second"), "{lines}");

    client.send("a6 NOOP").await;
    let _ = client.until_tag("a6").await;

    client.send("a7 LIST \"\" \"\"").await;
    let lines = join_lines(&client.until_tag("a7").await);
    assert!(
        lines.contains("* LIST (\\Noselect) \".\" \"\""),
        "空模式必须回一条层级探测应答：{lines}"
    );

    client.send("a8 LOGOUT").await;
    let lines = join_lines(&client.until_tag("a8").await);
    assert!(lines.contains("* BYE"), "{lines}");

    let exit = handle.await.unwrap().unwrap();
    assert!(matches!(exit, ImapExit::Logout(_)));
}

#[tokio::test]
async fn imap_store_search_and_expunge_reach_the_disk() {
    let fixture = fixture();
    for body in [
        &b"Subject: one\r\n\r\nbody one\r\n"[..],
        b"Subject: two\r\n\r\nbody two\r\n",
    ] {
        fixture
            .store
            .append(INBOX, body, &FlagSet::new(), None)
            .unwrap();
    }

    let (mut client, handle) = spawn_imap(&fixture);
    let _ = client.line().await;
    client
        .send(&format!("b1 LOGIN bob@example.com {PASSWORD}"))
        .await;
    let _ = client.until_tag("b1").await;
    client.send("b2 SELECT INBOX").await;
    let _ = client.until_tag("b2").await;

    client.send("b3 STORE 1 +FLAGS (\\Deleted)").await;
    let lines = join_lines(&client.until_tag("b3").await);
    assert!(lines.contains("FLAGS (\\Deleted)"), "{lines}");

    client.send("b4 SEARCH DELETED").await;
    let lines = join_lines(&client.until_tag("b4").await);
    assert!(lines.contains("* SEARCH 1"), "{lines}");

    client.send("b5 EXPUNGE").await;
    let lines = join_lines(&client.until_tag("b5").await);
    assert!(lines.contains("* 1 EXPUNGE"), "{lines}");

    client.send("b6 SEARCH ALL").await;
    let lines = join_lines(&client.until_tag("b6").await);
    assert!(lines.contains("* SEARCH 1"), "{lines}");

    client.send("b7 CLOSE").await;
    let _ = client.until_tag("b7").await;
    client.send("b8 LOGOUT").await;
    let _ = client.until_tag("b8").await;
    let _ = handle.await.unwrap().unwrap();

    let state = fixture.store.open_folder(INBOX, false).unwrap();
    assert_eq!(state.messages.len(), 1, "EXPUNGE 必须真的删掉文件");
}

#[tokio::test]
async fn imap_non_peek_fetch_sets_seen() {
    let fixture = fixture();
    fixture
        .store
        .append(
            INBOX,
            b"Subject: unread\r\n\r\nhello\r\n",
            &FlagSet::new(),
            None,
        )
        .unwrap();

    let (mut client, handle) = spawn_imap(&fixture);
    let _ = client.line().await;
    client
        .send(&format!("c1 LOGIN bob@example.com {PASSWORD}"))
        .await;
    let _ = client.until_tag("c1").await;
    client.send("c2 SELECT INBOX").await;
    let _ = client.until_tag("c2").await;

    client.send("c3 FETCH 1 (BODY[TEXT])").await;
    let lines = join_lines(&client.until_tag("c3").await);
    assert!(lines.contains("BODY[TEXT]"), "{lines}");
    assert!(
        lines.contains("FLAGS (\\Seen)"),
        "非 PEEK 必须补发 Seen：{lines}"
    );

    client.send("c4 SEARCH UNSEEN").await;
    let lines = join_lines(&client.until_tag("c4").await);
    assert!(lines.contains("* SEARCH\r\n"), "{lines}");

    client.send("c5 LOGOUT").await;
    let _ = client.until_tag("c5").await;
    let _ = handle.await.unwrap().unwrap();

    let state = fixture.store.open_folder(INBOX, false).unwrap();
    assert!(state.messages[0]
        .flags
        .contains(&Flag::System(SystemFlag::Seen)));
}

#[tokio::test]
async fn imap_append_with_literal_plus_returns_appenduid() {
    let fixture = fixture();
    let (mut client, handle) = spawn_imap(&fixture);
    let _ = client.line().await;
    client
        .send(&format!("d1 LOGIN bob@example.com {PASSWORD}"))
        .await;
    let _ = client.until_tag("d1").await;

    let message = b"Subject: appended\r\n\r\nappended body\r\n";
    client
        .send_raw(format!("d2 APPEND INBOX {{{}+}}\r\n", message.len()).as_bytes())
        .await;
    client.send_raw(message).await;
    client.send_raw(b"\r\n").await;

    let lines = join_lines(&client.until_tag("d2").await);
    assert!(lines.contains("OK [APPENDUID"), "{lines}");

    client.send("d3 LOGOUT").await;
    let _ = client.until_tag("d3").await;
    let _ = handle.await.unwrap().unwrap();

    let state = fixture.store.open_folder(INBOX, false).unwrap();
    assert_eq!(state.messages.len(), 1);
    assert_eq!(state.messages[0].size, message.len() as u64);
}

#[tokio::test]
async fn imap_commands_outside_a_selected_state_are_bad() {
    let fixture = fixture();
    let (mut client, handle) = spawn_imap(&fixture);
    let _ = client.line().await;
    client
        .send(&format!("e1 LOGIN bob@example.com {PASSWORD}"))
        .await;
    let _ = client.until_tag("e1").await;

    client.send("e2 FETCH 1 (FLAGS)").await;
    let lines = join_lines(&client.until_tag("e2").await);
    assert!(lines.contains("e2 BAD"), "{lines}");

    client.send("e3 LOGOUT").await;
    let _ = client.until_tag("e3").await;
    let _ = handle.await.unwrap().unwrap();
}

#[tokio::test]
async fn pop3_retr_uidl_delete_and_commit() {
    let fixture = fixture();
    fixture
        .store
        .append(
            INBOX,
            b"Subject: one\r\n\r\n.leading dot\r\nsecond line\r\n",
            &FlagSet::new(),
            None,
        )
        .unwrap();
    fixture
        .store
        .append(INBOX, b"Subject: two\r\n\r\nbody two\r\n", &seen(), None)
        .unwrap();
    let uidvalidity = fixture.store.open_folder(INBOX, false).unwrap().uidvalidity;

    let (mut client, handle) = spawn_pop3(&fixture);
    let greeting = client.line().await;
    assert!(greeting.starts_with("+OK mail.test"), "{greeting}");

    client.send("CAPA").await;
    let lines = client.until_line(".").await;
    let capabilities = join_lines(&lines);
    assert!(capabilities.contains("UIDL"));
    assert!(capabilities.contains("TOP"));

    client.send("USER bob@example.com").await;
    assert!(client.line().await.starts_with("+OK"));
    client.send(&format!("PASS {PASSWORD}")).await;
    assert!(client.line().await.starts_with("+OK"), "登录应成功");

    client.send("STAT").await;
    let status = client.line().await;
    assert!(status.starts_with("+OK 2 "), "{status}");

    client.send("UIDL").await;
    let lines = client.until_line(".").await;
    let uidl = join_lines(&lines);
    assert!(uidl.contains(&format!("1 {uidvalidity}-")), "{uidl}");

    client.send("RETR 1").await;
    let lines = client.until_line(".").await;
    let message = join_lines(&lines);
    assert!(message.starts_with("+OK "), "{message}");
    assert!(
        message.contains("\r\n..leading dot\r\n"),
        "行首句点必须加倍：{message}"
    );

    client.send("DELE 1").await;
    assert!(client.line().await.starts_with("+OK"));
    client.send("RSET").await;
    assert!(client.line().await.starts_with("+OK"));
    client.send("DELE 1").await;
    assert!(client.line().await.starts_with("+OK"));
    client.send("QUIT").await;
    assert!(client.line().await.starts_with("+OK"));

    let exit = handle.await.unwrap().unwrap();
    assert!(matches!(exit, Pop3Exit::Logout(_)));
    let state = fixture.store.open_folder(INBOX, false).unwrap();
    assert_eq!(state.messages.len(), 1, "QUIT 才提交删除");
}

#[tokio::test]
async fn pop3_is_exclusive_per_mailbox() {
    let fixture = fixture();
    fixture
        .store
        .append(INBOX, b"Subject: x\r\n\r\nbody\r\n", &FlagSet::new(), None)
        .unwrap();

    let (mut first, first_handle) = spawn_pop3(&fixture);
    let _ = first.line().await;
    first.send("USER bob@example.com").await;
    let _ = first.line().await;
    first.send(&format!("PASS {PASSWORD}")).await;
    assert!(first.line().await.starts_with("+OK"));

    let (mut second, second_handle) = spawn_pop3(&fixture);
    let _ = second.line().await;
    second.send("USER bob@example.com").await;
    let _ = second.line().await;
    second.send(&format!("PASS {PASSWORD}")).await;
    let line = second.line().await;
    assert!(line.contains("[IN-USE]"), "{line}");
    second.send("QUIT").await;
    let _ = second.line().await;
    let _ = second_handle.await.unwrap().unwrap();

    first.send("QUIT").await;
    let _ = first.line().await;
    let _ = first_handle.await.unwrap().unwrap();
}

#[tokio::test]
async fn pop3_top_returns_headers_and_limited_body() {
    let fixture = fixture();
    fixture
        .store
        .append(
            INBOX,
            b"Subject: top test\r\n\r\nfirst\r\nsecond\r\nthird\r\n",
            &FlagSet::new(),
            None,
        )
        .unwrap();

    let (mut client, handle) = spawn_pop3(&fixture);
    let _ = client.line().await;
    client.send("USER bob@example.com").await;
    let _ = client.line().await;
    client.send(&format!("PASS {PASSWORD}")).await;
    let _ = client.line().await;

    client.send("TOP 1 1").await;
    let lines = client.until_line(".").await;
    let message = join_lines(&lines);
    assert!(message.starts_with("+OK "));
    assert!(message.contains("Subject: top test\r\n"));
    assert!(message.contains("first\r\n"));
    assert!(!message.contains("second"), "{message}");

    client.send("QUIT").await;
    let _ = client.line().await;
    let _ = handle.await.unwrap().unwrap();
}

#[tokio::test]
async fn tcp_listener_greets_and_shuts_down_gracefully() {
    let fixture = fixture();
    let server = ImapServer::new(
        imap_context(&fixture),
        ImapServerConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            rate_limit: None,
            ..ImapServerConfig::default()
        },
        None,
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server_handle = tokio::spawn(async move { server.serve_on(listener, shutdown_rx).await });

    let mut stream = timeout(Duration::from_secs(5), TcpStream::connect(address))
        .await
        .unwrap()
        .unwrap();
    let mut buffer = vec![0u8; 512];
    let read = timeout(Duration::from_secs(5), stream.read(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    let greeting = String::from_utf8_lossy(&buffer[..read]).to_string();
    assert!(greeting.starts_with("* OK [CAPABILITY"), "{greeting}");

    stream.write_all(b"z1 LOGOUT\r\n").await.unwrap();
    let mut response = Vec::new();
    let _ = timeout(Duration::from_secs(5), stream.read_to_end(&mut response)).await;
    let response = String::from_utf8_lossy(&response).to_string();
    assert!(
        response.contains("* BYE") || response.is_empty(),
        "{response}"
    );

    drop(stream);
    shutdown_tx.send(true).unwrap();
    timeout(Duration::from_secs(10), server_handle)
        .await
        .expect("停机超时")
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn imap_compress_deflate_switches_after_plaintext_ok() {
    use mailstack_imappop3::lineio::LineIo;

    let fixture = fixture();
    let (client_io, server_io) = tokio::io::duplex(256 * 1024);
    let context = Arc::new(imap_context(&fixture));
    let handle = tokio::spawn(async move {
        imap_serve(
            server_io,
            &context,
            PEER.parse().unwrap(),
            ConnectionOptions {
                secured: false,
                starttls_available: false,
                greet: true,
            },
        )
        .await
    });

    let mut client = LineIo::new(client_io);
    let greeting = String::from_utf8(client.read_line(8192).await.unwrap().unwrap()).unwrap();
    assert!(greeting.starts_with("* OK [CAPABILITY"), "{greeting}");
    assert!(
        !greeting.contains("COMPRESS=DEFLATE"),
        "认证前不得通告 COMPRESS: {greeting}"
    );

    client
        .write_all(b"a1 LOGIN bob@example.com Correct-Horse-9-Battery\r\n")
        .await
        .unwrap();
    client.flush().await.unwrap();
    let login = String::from_utf8(client.read_line(8192).await.unwrap().unwrap()).unwrap();
    assert!(login.starts_with("a1 OK"), "{login}");
    assert!(
        login.contains("COMPRESS=DEFLATE"),
        "认证后应通告 COMPRESS: {login}"
    );

    client.write_all(b"a2 COMPRESS DEFLATE\r\n").await.unwrap();
    client.flush().await.unwrap();
    let ok = String::from_utf8(client.read_line(8192).await.unwrap().unwrap()).unwrap();
    assert!(
        ok.starts_with("a2 OK"),
        "切换应答必须是明文 OK（之后才压缩）: {ok}"
    );

    // 客户端也在收到明文 OK 之后切换；之后双向都是 DEFLATE。
    client.enable_compression().unwrap();
    client.write_all(b"a3 NOOP\r\n").await.unwrap();
    client.flush().await.unwrap();
    let noop = String::from_utf8(client.read_line(8192).await.unwrap().unwrap()).unwrap();
    assert_eq!(noop, "a3 OK NOOP completed");

    client.write_all(b"a4 LOGOUT\r\n").await.unwrap();
    client.flush().await.unwrap();
    let bye = String::from_utf8(client.read_line(8192).await.unwrap().unwrap()).unwrap();
    assert!(bye.starts_with("* BYE"), "{bye}");
    let logout = String::from_utf8(client.read_line(8192).await.unwrap().unwrap()).unwrap();
    assert_eq!(logout, "a4 OK LOGOUT completed");

    let exit = timeout(Duration::from_secs(10), handle)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(matches!(exit, ImapExit::Logout(_)));
}

#[tokio::test]
async fn imap_metadata_set_and_get_round_trip() {
    let fixture = fixture();
    let (mut client, handle) = spawn_imap(&fixture);
    let _ = client.line().await;
    client
        .send("a1 LOGIN bob@example.com Correct-Horse-9-Battery")
        .await;
    let login = client.until_tag("a1").await;
    assert!(
        login.last().unwrap().contains("METADATA"),
        "认证后应通告 METADATA: {login:?}"
    );

    client
        .send("a2 SETMETADATA INBOX (/private/comment \"My note\")")
        .await;
    let set = client.until_tag("a2").await;
    assert!(set.last().unwrap().starts_with("a2 OK"), "{set:?}");

    client
        .send("a3 GETMETADATA INBOX (/private/comment /private/missing)")
        .await;
    let get = client.until_tag("a3").await;
    let joined = join_lines(&get);
    assert!(joined.contains("/private/comment"), "{joined}");
    assert!(joined.contains("My note"), "{joined}");
    assert!(
        joined.contains("NIL"),
        "missing entry must be NIL: {joined}"
    );

    // 用 NIL 删除条目后，再取应只剩 NIL。
    client
        .send("a4 SETMETADATA INBOX (/private/comment NIL)")
        .await;
    let _ = client.until_tag("a4").await;
    client.send("a5 GETMETADATA INBOX (/private/comment)").await;
    let get2 = client.until_tag("a5").await;
    let joined2 = join_lines(&get2);
    assert!(joined2.contains("NIL"), "{joined2}");

    client.send("a6 LOGOUT").await;
    let _ = client.until_tag("a6").await;
    let _ = handle.await.unwrap().unwrap();
}

#[tokio::test]
async fn imap_acl_set_get_list_and_delete() {
    let fixture = fixture();
    let (mut client, handle) = spawn_imap(&fixture);
    let _ = client.line().await;
    client
        .send("a1 LOGIN bob@example.com Correct-Horse-9-Battery")
        .await;
    let login = client.until_tag("a1").await;
    assert!(
        login.last().unwrap().contains("ACL"),
        "认证后应通告 ACL: {login:?}"
    );

    // 自己（owner）拥有全部权限。
    client.send("a2 MYRIGHTS INBOX").await;
    let my = client.until_tag("a2").await;
    assert!(
        my[0].contains("MYRIGHTS") && my[0].contains("lrswipkxtead"),
        "{my:?}"
    );

    client.send("a3 SETACL INBOX carol@example.com lrs").await;
    assert!(client
        .until_tag("a3")
        .await
        .last()
        .unwrap()
        .starts_with("a3 OK"));

    client.send("a4 GETACL INBOX").await;
    let acl = client.until_tag("a4").await;
    let joined = join_lines(&acl);
    assert!(joined.contains("carol@example.com"), "{joined}");
    assert!(joined.contains("lrs"), "{joined}");

    client.send("a5 LISTRIGHTS INBOX carol@example.com").await;
    let rights = client.until_tag("a5").await;
    assert!(rights[0].contains("LISTRIGHTS"), "{rights:?}");

    client.send("a6 DELETEACL INBOX carol@example.com").await;
    let _ = client.until_tag("a6").await;
    client.send("a7 GETACL INBOX").await;
    let acl2 = client.until_tag("a7").await;
    assert!(!join_lines(&acl2).contains("carol@example.com"), "{acl2:?}");

    client.send("a8 LOGOUT").await;
    let _ = client.until_tag("a8").await;
    let _ = handle.await.unwrap().unwrap();
}

#[tokio::test]
async fn imap_searchres_saves_and_dollar_refers_to_it() {
    let fixture = fixture();
    fixture
        .store
        .append(INBOX, b"Subject: first\r\n\r\nx", &FlagSet::new(), None)
        .unwrap();
    fixture
        .store
        .append(INBOX, b"Subject: second\r\n\r\nx", &FlagSet::new(), None)
        .unwrap();

    let (mut client, handle) = spawn_imap(&fixture);
    let _ = client.line().await;
    client
        .send("a1 LOGIN bob@example.com Correct-Horse-9-Battery")
        .await;
    let _ = client.until_tag("a1").await;
    client.send("a2 SELECT INBOX").await;
    let _ = client.until_tag("a2").await;

    // 没有 SAVE 之前用 $ 是错误（BAD），绝不静默当作空集。
    client.send("a3 UID FETCH $ (UID)").await;
    let bad = client.until_tag("a3").await;
    assert!(bad.last().unwrap().contains("BAD"), "{bad:?}");

    // SAVE 只回 tagged OK，不回 untagged SEARCH/ESEARCH。
    client
        .send("a4 SEARCH RETURN (SAVE) SUBJECT \"second\"")
        .await;
    let save = client.until_tag("a4").await;
    assert_eq!(save.len(), 1, "SAVE 只应有 tagged OK: {save:?}");
    assert!(save[0].starts_with("a4 OK"), "{save:?}");

    // $ 指向已保存结果的最高 UID（第二封 = uid 2）。
    client.send("a5 UID FETCH $ (UID)").await;
    let fetch = client.until_tag("a5").await;
    let joined = join_lines(&fetch);
    assert!(joined.contains("UID 2"), "{joined}");

    client.send("a6 LOGOUT").await;
    let _ = client.until_tag("a6").await;
    let _ = handle.await.unwrap().unwrap();
}

#[tokio::test]
async fn imap_shared_mailbox_enforces_acl_on_selected_operations() {
    use mailstack_imappop3::resolver::MapResolver;

    let dir = tempfile::tempdir().unwrap();
    let alice = Arc::new(MailStore::new(dir.path().join("alice"), Arc::new(SystemClock)).unwrap());
    let bob = Arc::new(MailStore::new(dir.path().join("bob"), Arc::new(SystemClock)).unwrap());
    alice
        .append(
            INBOX,
            b"Subject: secret one\r\n\r\nx",
            &FlagSet::new(),
            None,
        )
        .unwrap();
    alice
        .append(
            INBOX,
            b"Subject: secret two\r\n\r\nx",
            &FlagSet::new(),
            None,
        )
        .unwrap();

    let mut record = mailstack_core::password::password_record("bob", PASSWORD).unwrap();
    record.username = "bob@example.com".to_string();
    let mut users = MemoryDirectory::new();
    users.insert(record);
    let auth = AuthBackend::new(Arc::new(PasswordDirectory::new(users)));
    let mut resolver = MapResolver::new();
    resolver.insert("alice@example.com", Arc::clone(&alice));
    resolver.insert("bob@example.com", Arc::clone(&bob));

    let context = ImapSessionContext {
        store: Arc::clone(&bob),
        auth,
        config: ImapConfig {
            server_name: "mail.test".to_string(),
            require_tls: false,
            idle_poll: Duration::from_millis(50),
            read_timeout: Duration::from_secs(10),
            ..ImapConfig::default()
        },
        metrics: Arc::new(Metrics::new("imap")),
        resolver: Some(Arc::new(resolver)),
    };
    let (mut client, handle) = spawn_with_context(context);
    let _ = client.line().await;
    client
        .send("a1 LOGIN bob@example.com Correct-Horse-9-Battery")
        .await;
    let _ = client.until_tag("a1").await;

    // 没有 ACL → 共享 SELECT 被拒。
    client
        .send("a2 SELECT shared/alice@example.com/INBOX")
        .await;
    let denied = client.until_tag("a2").await;
    assert!(denied.last().unwrap().contains("NO"), "{denied:?}");

    // alice 授予 bob lrsw（不含 EXPUNGE 所需的 t）。
    let mut acl = std::collections::BTreeMap::new();
    acl.insert("bob@example.com".to_string(), "lrsw".to_string());
    alice.write_acl("INBOX", &acl).unwrap();

    client
        .send("a3 SELECT shared/alice@example.com/INBOX")
        .await;
    let selected = client.until_tag("a3").await;
    let joined = join_lines(&selected);
    assert!(joined.contains("a3 OK"), "granted select failed: {joined}");
    assert!(joined.contains("2 EXISTS"), "{joined}");

    // 读（r 已授予）。
    client
        .send("a4 FETCH 1 (BODY.PEEK[HEADER.FIELDS (SUBJECT)])")
        .await;
    let fetched = client.until_tag("a4").await;
    assert!(join_lines(&fetched).contains("secret"), "{fetched:?}");

    // 写标志（w 已授予）。
    client.send("a5 STORE 1 +FLAGS (\\Seen)").await;
    let stored = client.until_tag("a5").await;
    assert!(stored.last().unwrap().contains("OK"), "{stored:?}");

    // EXPUNGE 需要 t，未授予 → NO。
    client.send("a6 STORE 1 +FLAGS (\\Deleted)").await;
    let _ = client.until_tag("a6").await;
    client.send("a7 EXPUNGE").await;
    let expunge = client.until_tag("a7").await;
    assert!(expunge.last().unwrap().contains("NO"), "{expunge:?}");

    // NAMESPACE 通告共享命名空间。
    client.send("a8 NAMESPACE").await;
    let namespace = client.until_tag("a8").await;
    assert!(join_lines(&namespace).contains("shared/"), "{namespace:?}");

    client.send("a9 LOGOUT").await;
    let _ = client.until_tag("a9").await;
    let _ = handle.await.unwrap().unwrap();
}

#[tokio::test]
async fn imap_failed_select_deselects_the_previous_mailbox() {
    let fixture = fixture();
    fixture
        .store
        .append(INBOX, b"Subject: x\r\n\r\nbody\r\n", &FlagSet::new(), None)
        .unwrap();

    let (mut client, handle) = spawn_imap(&fixture);
    let _ = client.line().await;
    client
        .send(&format!("s1 LOGIN bob@example.com {PASSWORD}"))
        .await;
    let _ = client.until_tag("s1").await;
    client.send("s2 SELECT INBOX").await;
    let _ = client.until_tag("s2").await;

    client.send("s3 SELECT NoSuchMailbox").await;
    let lines = join_lines(&client.until_tag("s3").await);
    assert!(lines.contains("NO [NONEXISTENT]"), "{lines}");

    client.send("s4 FETCH 1 (FLAGS)").await;
    let lines = join_lines(&client.until_tag("s4").await);
    assert!(
        lines.contains("s4 BAD"),
        "选择失败后不得继续操作旧邮箱：{lines}"
    );

    client.send("s5 LOGOUT").await;
    let _ = client.until_tag("s5").await;
    let _ = handle.await.unwrap().unwrap();
}

#[tokio::test]
async fn imap_uid_expunge_only_removes_the_selected_uids() {
    let fixture = fixture();
    for body in [&b"one\r\n"[..], b"two\r\n", b"three\r\n"] {
        fixture
            .store
            .append(INBOX, body, &FlagSet::new(), None)
            .unwrap();
    }

    let (mut client, handle) = spawn_imap(&fixture);
    let _ = client.line().await;
    client
        .send(&format!("u1 LOGIN bob@example.com {PASSWORD}"))
        .await;
    let _ = client.until_tag("u1").await;
    client.send("u2 SELECT INBOX").await;
    let _ = client.until_tag("u2").await;

    client.send("u3 UID STORE 1,3 +FLAGS (\\Deleted)").await;
    let lines = join_lines(&client.until_tag("u3").await);
    assert!(lines.contains("UID 1"), "{lines}");
    assert!(lines.contains("UID 3"), "{lines}");

    client.send("u4 UID EXPUNGE 1").await;
    let lines = join_lines(&client.until_tag("u4").await);
    assert!(lines.contains("* 1 EXPUNGE"), "{lines}");
    assert!(!lines.contains("* 2 EXPUNGE"), "只应删除 UID 1：{lines}");

    client.send("u5 SEARCH DELETED").await;
    let lines = join_lines(&client.until_tag("u5").await);
    assert!(lines.contains("* SEARCH 2"), "UID 3 现在是序号 2：{lines}");

    client.send("u6 EXPUNGE").await;
    let lines = join_lines(&client.until_tag("u6").await);
    assert!(lines.contains("* 2 EXPUNGE"), "{lines}");

    client.send("u7 LOGOUT").await;
    let _ = client.until_tag("u7").await;
    let _ = handle.await.unwrap().unwrap();

    let state = fixture.store.open_folder(INBOX, false).unwrap();
    assert_eq!(state.messages.len(), 1);
}

#[tokio::test]
async fn imap_append_to_a_read_only_selection_is_refused() {
    let fixture = fixture();
    let (mut client, handle) = spawn_imap(&fixture);
    let _ = client.line().await;
    client
        .send(&format!("r1 LOGIN bob@example.com {PASSWORD}"))
        .await;
    let _ = client.until_tag("r1").await;
    client.send("r2 EXAMINE INBOX").await;
    let lines = join_lines(&client.until_tag("r2").await);
    assert!(lines.contains("OK [READ-ONLY]"), "{lines}");

    let message = b"Subject: nope\r\n\r\nbody\r\n";
    client
        .send_raw(format!("r3 APPEND INBOX {{{}+}}\r\n", message.len()).as_bytes())
        .await;
    client.send_raw(message).await;
    client.send_raw(b"\r\n").await;
    let lines = join_lines(&client.until_tag("r3").await);
    assert!(lines.contains("NO [READ-ONLY]"), "{lines}");

    client.send("r4 LOGOUT").await;
    let _ = client.until_tag("r4").await;
    let _ = handle.await.unwrap().unwrap();
    assert_eq!(
        fixture
            .store
            .open_folder(INBOX, false)
            .unwrap()
            .messages
            .len(),
        0
    );
}

#[tokio::test]
async fn implicit_tls_accepts_a_secured_session_from_the_first_byte() {
    let fixture = fixture();
    let cert_directory = tempfile::tempdir().unwrap();
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_path = cert_directory.path().join("fullchain.pem");
    let key_path = cert_directory.path().join("privkey.pem");
    std::fs::write(&cert_path, generated.cert.pem()).unwrap();
    std::fs::write(&key_path, generated.key_pair.serialize_pem()).unwrap();
    let acceptor = mailstack_imappop3::tls::acceptor(&cert_path, &key_path).unwrap();

    let base = imap_context(&fixture);
    let context = ImapSessionContext {
        config: ImapConfig {
            require_tls: true,
            ..base.config
        },
        ..base
    };
    let server = ImapServer::new(
        context,
        ImapServerConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            implicit_tls: true,
            rate_limit: None,
            ..ImapServerConfig::default()
        },
        Some(acceptor),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server_handle = tokio::spawn(async move { server.serve_on(listener, shutdown_rx).await });

    let stream = TcpStream::connect(address).await.unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls_pki_types::CertificateDer::from(
            generated.cert.der().to_vec(),
        ))
        .unwrap();
    let client_config = rustls::ClientConfig::builder_with_protocol_versions(
        mailstack_imappop3::tls::supported_versions(),
    )
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let server_name = rustls_pki_types::ServerName::try_from("localhost")
        .unwrap()
        .to_owned();
    let tls_stream = timeout(
        Duration::from_secs(5),
        connector.connect(server_name, stream),
    )
    .await
    .expect("TLS 握手超时")
    .expect("TLS 握手失败");
    let mut client = BufReader::new(tls_stream);

    let greeting = read_line(&mut client).await;
    assert!(greeting.starts_with("* OK [CAPABILITY"), "{greeting}");
    assert!(greeting.contains("AUTH=PLAIN"), "{greeting}");
    assert!(
        !greeting.contains("STARTTLS"),
        "隐式 TLS 下不应再通告 STARTTLS：{greeting}"
    );

    write_line(
        client.get_mut(),
        &format!("i1 LOGIN bob@example.com {PASSWORD}"),
    )
    .await;
    let mut lines = Vec::new();
    loop {
        let line = read_line(&mut client).await;
        let done = line.starts_with("i1 ");
        lines.push(line);
        if done {
            break;
        }
    }
    assert!(lines.concat().contains("i1 OK"), "{:?}", lines);

    write_line(client.get_mut(), "i2 LOGOUT").await;
    loop {
        let line = read_line(&mut client).await;
        if line.starts_with("i2 ") {
            break;
        }
    }
    drop(client);
    shutdown_tx.send(true).unwrap();
    timeout(Duration::from_secs(10), server_handle)
        .await
        .expect("停机超时")
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn imap_idle_reports_new_mail_arriving_from_another_writer() {
    let fixture = fixture();
    let (mut client, handle) = spawn_imap(&fixture);
    let _ = client.line().await;
    client
        .send(&format!("k1 LOGIN bob@example.com {PASSWORD}"))
        .await;
    let _ = client.until_tag("k1").await;
    client.send("k2 SELECT INBOX").await;
    let _ = client.until_tag("k2").await;

    client.send("k3 IDLE").await;
    let line = client.line().await;
    assert!(line.starts_with("+ idling"), "{line}");

    fixture
        .store
        .append(
            INBOX,
            b"Subject: pushed\r\n\r\nnew mail\r\n",
            &FlagSet::new(),
            None,
        )
        .unwrap();

    let mut announced = false;
    for _ in 0..20 {
        let line = client.line().await;
        if line.contains("* 1 EXISTS") {
            announced = true;
            break;
        }
    }
    assert!(announced, "IDLE 必须在不发 NOOP 的情况下报告新邮件");

    client.send("DONE").await;
    let lines = join_lines(&client.until_tag("k3").await);
    assert!(lines.contains("k3 OK"), "{lines}");

    client.send("k4 LOGOUT").await;
    let _ = client.until_tag("k4").await;
    let _ = handle.await.unwrap().unwrap();
}

#[tokio::test]
async fn imap_extensions_id_enable_unselect_and_sasl_ir() {
    let fixture = fixture();
    let (mut client, handle) = spawn_imap(&fixture);
    let greeting = client.line().await;
    let capabilities: Vec<&str> = greeting.split_whitespace().collect();
    for capability in [
        "SASL-IR",
        "UNSELECT",
        "MOVE",
        "MULTIAPPEND",
        "SPECIAL-USE",
        "ESEARCH",
        "ID",
        "ENABLE",
        "CONDSTORE",
        "QRESYNC",
    ] {
        assert!(
            capabilities.contains(&capability),
            "缺少 {capability}: {greeting}"
        );
    }

    client
        .send("x1 ID (\"name\" \"e2e\" \"version\" \"1\")")
        .await;
    let lines = join_lines(&client.until_tag("x1").await);
    assert!(lines.contains("* ID ("), "{lines}");

    let payload =
        base64::engine::general_purpose::STANDARD.encode(format!("\0bob@example.com\0{PASSWORD}"));
    client
        .send(&format!("x2 AUTHENTICATE PLAIN {payload}"))
        .await;
    let lines = join_lines(&client.until_tag("x2").await);
    assert!(lines.contains("x2 OK"), "SASL-IR 登录应成功：{lines}");

    client.send("x3 ENABLE CONDSTORE").await;
    let lines = join_lines(&client.until_tag("x3").await);
    assert!(lines.contains("x3 OK"), "{lines}");

    client.send("x4 SELECT INBOX").await;
    let _ = client.until_tag("x4").await;
    client.send("x5 UNSELECT").await;
    let lines = join_lines(&client.until_tag("x5").await);
    assert!(lines.contains("x5 OK"), "{lines}");
    client.send("x6 FETCH 1 (FLAGS)").await;
    let lines = join_lines(&client.until_tag("x6").await);
    assert!(lines.contains("x6 BAD"), "{lines}");

    client.send("x7 LOGOUT").await;
    let _ = client.until_tag("x7").await;
    let _ = handle.await.unwrap().unwrap();
}

#[tokio::test]
async fn imap_multi_append_move_and_special_use() {
    let fixture = fixture();
    let (mut client, handle) = spawn_imap(&fixture);
    let _ = client.line().await;
    client
        .send(&format!("m1 LOGIN bob@example.com {PASSWORD}"))
        .await;
    let _ = client.until_tag("m1").await;

    client.send("m2 CREATE Archive").await;
    let lines = join_lines(&client.until_tag("m2").await);
    assert!(lines.contains("m2 OK"), "{lines}");

    let one = b"Subject: one\r\n\r\none\r\n";
    let two = b"Subject: two\r\n\r\ntwo\r\n";
    client
        .send_raw(format!("m3 APPEND INBOX (\\Seen) {{{}+}}\r\n", one.len()).as_bytes())
        .await;
    client.send_raw(one).await;
    client
        .send_raw(format!(" (\\Flagged) {{{}+}}\r\n", two.len()).as_bytes())
        .await;
    client.send_raw(two).await;
    client.send_raw(b"\r\n").await;
    let lines = join_lines(&client.until_tag("m3").await);
    assert!(lines.contains("[APPENDUID"), "{lines}");
    assert!(lines.contains("m3 OK"), "{lines}");

    let state = fixture.store.open_folder(INBOX, false).unwrap();
    assert_eq!(state.messages.len(), 2);
    assert!(state.messages[0]
        .flags
        .contains(&Flag::System(SystemFlag::Seen)));
    assert!(state.messages[1]
        .flags
        .contains(&Flag::System(SystemFlag::Flagged)));

    client.send("m4 SELECT INBOX").await;
    let _ = client.until_tag("m4").await;
    client.send("m5 MOVE 1 Archive").await;
    let lines = join_lines(&client.until_tag("m5").await);
    assert!(lines.contains("[COPYUID"), "{lines}");
    assert!(lines.contains("* 1 EXPUNGE"), "{lines}");

    client.send("m6 UID MOVE 2 Archive").await;
    let lines = join_lines(&client.until_tag("m6").await);
    assert!(lines.contains("[COPYUID"), "{lines}");
    assert!(lines.contains("* 1 EXPUNGE"), "{lines}");

    client.send("m7 CREATE Sent USE (\\Sent)").await;
    let lines = join_lines(&client.until_tag("m7").await);
    assert!(lines.contains("m7 OK"), "{lines}");
    client.send("m8 LIST (SPECIAL-USE) \"\" \"*\"").await;
    let lines = join_lines(&client.until_tag("m8").await);
    assert!(
        lines.contains("\\Sent") && lines.contains("\"Sent\""),
        "{lines}"
    );
    assert!(!lines.contains("\"INBOX\""), "{lines}");

    client.send("m9 LOGOUT").await;
    let _ = client.until_tag("m9").await;
    let _ = handle.await.unwrap().unwrap();

    assert_eq!(
        fixture
            .store
            .open_folder(INBOX, false)
            .unwrap()
            .messages
            .len(),
        0
    );
    assert_eq!(
        fixture
            .store
            .open_folder("Archive", false)
            .unwrap()
            .messages
            .len(),
        2
    );
}

#[tokio::test]
async fn imap_esearch_returns_requested_fields() {
    let fixture = fixture();
    for body in [&b"one\r\n"[..], b"two\r\n", b"three\r\n"] {
        fixture
            .store
            .append(INBOX, body, &FlagSet::new(), None)
            .unwrap();
    }
    let (mut client, handle) = spawn_imap(&fixture);
    let _ = client.line().await;
    client
        .send(&format!("e1 LOGIN bob@example.com {PASSWORD}"))
        .await;
    let _ = client.until_tag("e1").await;
    client.send("e2 SELECT INBOX").await;
    let _ = client.until_tag("e2").await;

    client
        .send("e3 SEARCH RETURN (MIN MAX ALL COUNT) ALL")
        .await;
    let lines = join_lines(&client.until_tag("e3").await);
    assert!(lines.contains("* ESEARCH (TAG \"e3\")"), "{lines}");
    assert!(lines.contains("MIN 1"), "{lines}");
    assert!(lines.contains("MAX 3"), "{lines}");
    assert!(lines.contains("ALL 1:3"), "{lines}");
    assert!(lines.contains("COUNT 3"), "{lines}");

    client.send("e4 UID SEARCH RETURN (COUNT) UNSEEN").await;
    let lines = join_lines(&client.until_tag("e4").await);
    assert!(lines.contains("UID"), "{lines}");
    assert!(lines.contains("COUNT 3"), "{lines}");

    // SEARCHRES：SAVE 被接受，且只回 tagged OK（不回 untagged）。
    client.send("e5 SEARCH RETURN (SAVE) ALL").await;
    let save = client.until_tag("e5").await;
    assert_eq!(save.len(), 1, "SAVE 只应有 tagged OK: {save:?}");
    assert!(save[0].starts_with("e5 OK"), "{save:?}");

    client.send("e6 LOGOUT").await;
    let _ = client.until_tag("e6").await;
    let _ = handle.await.unwrap().unwrap();
}

#[tokio::test]
async fn imap_condstore_modseq_and_unchangedsince() {
    let fixture = fixture();
    fixture
        .store
        .append(
            INBOX,
            b"Subject: condstore\r\n\r\nbody\r\n",
            &FlagSet::new(),
            None,
        )
        .unwrap();
    let (mut client, handle) = spawn_imap(&fixture);
    let _ = client.line().await;
    client
        .send(&format!("z1 LOGIN bob@example.com {PASSWORD}"))
        .await;
    let _ = client.until_tag("z1").await;

    client.send("z2 ENABLE CONDSTORE").await;
    let lines = join_lines(&client.until_tag("z2").await);
    assert!(lines.contains("* ENABLED CONDSTORE"), "{lines}");

    client.send("z3 SELECT INBOX").await;
    let lines = join_lines(&client.until_tag("z3").await);
    assert!(lines.contains("[HIGHESTMODSEQ"), "{lines}");

    client.send("z4 FETCH 1 (UID MODSEQ)").await;
    let lines = join_lines(&client.until_tag("z4").await);
    assert!(lines.contains("MODSEQ ("), "{lines}");

    // modseq=1 > 0 → 条件不满足，不得修改，并回 MODIFIED。
    client
        .send("z5 STORE 1 +FLAGS (\\Seen) (UNCHANGEDSINCE 0)")
        .await;
    let lines = join_lines(&client.until_tag("z5").await);
    assert!(lines.contains("[MODIFIED 1]"), "{lines}");

    // 条件满足 → 修改成功，modseq 递增。
    client
        .send("z6 STORE 1 +FLAGS (\\Seen) (UNCHANGEDSINCE 100)")
        .await;
    let lines = join_lines(&client.until_tag("z6").await);
    assert!(lines.contains("FLAGS (\\Seen)"), "{lines}");
    assert!(lines.contains("MODSEQ ("), "{lines}");

    client.send("z7 FETCH 1 (MODSEQ) (CHANGEDSINCE 0)").await;
    let lines = join_lines(&client.until_tag("z7").await);
    assert!(lines.contains("MODSEQ ("), "{lines}");

    client.send("z8 SEARCH MODSEQ 1").await;
    let lines = join_lines(&client.until_tag("z8").await);
    assert!(lines.contains("* SEARCH 1"), "{lines}");

    client.send("z9 LOGOUT").await;
    let _ = client.until_tag("z9").await;
    let _ = handle.await.unwrap().unwrap();
}

#[tokio::test]
async fn imap_qresync_uses_vanished_and_replays_missing_uids() {
    let fixture = fixture();
    fixture
        .store
        .append(INBOX, b"one\r\n", &FlagSet::new(), None)
        .unwrap();
    fixture
        .store
        .append(INBOX, b"two\r\n", &FlagSet::new(), None)
        .unwrap();
    let baseline = fixture.store.open_folder(INBOX, false).unwrap();
    let uidvalidity = baseline.uidvalidity;

    let (mut client, handle) = spawn_imap(&fixture);
    let _ = client.line().await;
    client
        .send(&format!("q1 LOGIN bob@example.com {PASSWORD}"))
        .await;
    let _ = client.until_tag("q1").await;

    // 未 ENABLE 前使用 QRESYNC 参数必须被拒绝。
    client
        .send(&format!("q2 SELECT INBOX (QRESYNC ({uidvalidity} 0))"))
        .await;
    let lines = join_lines(&client.until_tag("q2").await);
    assert!(lines.contains("q2 BAD"), "{lines}");

    client.send("q3 ENABLE QRESYNC").await;
    let lines = join_lines(&client.until_tag("q3").await);
    assert!(lines.contains("* ENABLED CONDSTORE QRESYNC"), "{lines}");

    client
        .send(&format!("q4 SELECT INBOX (QRESYNC ({uidvalidity} 0))"))
        .await;
    let lines = join_lines(&client.until_tag("q4").await);
    assert!(
        lines.contains("FETCH (UID"),
        "应从 modseq 回放变更：{lines}"
    );

    client.send("q5 STORE 1 +FLAGS (\\Deleted)").await;
    let _ = client.until_tag("q5").await;
    client.send("q6 EXPUNGE").await;
    let lines = join_lines(&client.until_tag("q6").await);
    assert!(lines.contains("* VANISHED "), "{lines}");
    assert!(
        !lines.contains("* 1 EXPUNGE"),
        "QRESYNC 下不得回 untagged EXPUNGE：{lines}"
    );

    client.send("q7 LOGOUT").await;
    let _ = client.until_tag("q7").await;
    let _ = handle.await.unwrap().unwrap();

    // 第二个会话用旧 modseq 重新同步，必须收到 VANISHED (EARLIER)。
    let (mut client, handle) = spawn_imap(&fixture);
    let _ = client.line().await;
    client
        .send(&format!("r1 LOGIN bob@example.com {PASSWORD}"))
        .await;
    let _ = client.until_tag("r1").await;
    client.send("r2 ENABLE QRESYNC").await;
    let _ = client.until_tag("r2").await;
    client
        .send(&format!("r3 SELECT INBOX (QRESYNC ({uidvalidity} 0))"))
        .await;
    let lines = join_lines(&client.until_tag("r3").await);
    assert!(
        lines.contains("* VANISHED (EARLIER) 1"),
        "增量同步必须回报已消失的 UID：{lines}"
    );
    client.send("r4 LOGOUT").await;
    let _ = client.until_tag("r4").await;
    let _ = handle.await.unwrap().unwrap();
}

#[tokio::test]
async fn imap_quota_reports_usage_and_rejects_over_quota_append() {
    let fixture = fixture();
    fixture.store.set_quota(Some(1), None).unwrap();
    let (mut client, handle) = spawn_imap(&fixture);
    let _ = client.line().await;
    client
        .send(&format!("p1 LOGIN bob@example.com {PASSWORD}"))
        .await;
    let _ = client.until_tag("p1").await;

    client.send("p2 GETQUOTAROOT INBOX").await;
    let lines = join_lines(&client.until_tag("p2").await);
    assert!(lines.contains("* QUOTAROOT \"INBOX\" \"INBOX\""), "{lines}");
    assert!(lines.contains("MESSAGE 0 1"), "{lines}");

    let message = b"Subject: quota\r\n\r\nbody\r\n";
    client
        .send_raw(format!("p3 APPEND INBOX {{{}+}}\r\n", message.len()).as_bytes())
        .await;
    client.send_raw(message).await;
    client.send_raw(b"\r\n").await;
    let lines = join_lines(&client.until_tag("p3").await);
    assert!(lines.contains("p3 OK"), "{lines}");

    client
        .send_raw(format!("p4 APPEND INBOX {{{}+}}\r\n", message.len()).as_bytes())
        .await;
    client.send_raw(message).await;
    client.send_raw(b"\r\n").await;
    let lines = join_lines(&client.until_tag("p4").await);
    assert!(lines.contains("NO [OVERQUOTA]"), "{lines}");

    client.send("p5 GETQUOTA INBOX").await;
    let lines = join_lines(&client.until_tag("p5").await);
    assert!(lines.contains("MESSAGE 1 1"), "{lines}");

    client.send("p6 SETQUOTA INBOX (MESSAGE 5)").await;
    let lines = join_lines(&client.until_tag("p6").await);
    assert!(lines.contains("NO [NOPERM]"), "{lines}");

    // 删除唯一一封后配额回收，APPEND 重新可用。
    client.send("p7 SELECT INBOX").await;
    let _ = client.until_tag("p7").await;
    client.send("p8 STORE 1 +FLAGS (\\Deleted)").await;
    let _ = client.until_tag("p8").await;
    client.send("p9 EXPUNGE").await;
    let _ = client.until_tag("p9").await;
    client
        .send_raw(format!("p10 APPEND INBOX {{{}+}}\r\n", message.len()).as_bytes())
        .await;
    client.send_raw(message).await;
    client.send_raw(b"\r\n").await;
    let lines = join_lines(&client.until_tag("p10").await);
    assert!(lines.contains("p10 OK"), "{lines}");

    client.send("p11 LOGOUT").await;
    let _ = client.until_tag("p11").await;
    let _ = handle.await.unwrap().unwrap();
}

#[tokio::test]
async fn imap_sort_orders_by_header_and_size() {
    let fixture = fixture();
    fixture
        .store
        .append(
            INBOX,
            b"Subject: Zebra\r\n\r\n123456789012345\r\n",
            &FlagSet::new(),
            None,
        )
        .unwrap();
    fixture
        .store
        .append(
            INBOX,
            b"Subject: alpha\r\n\r\n12345\r\n",
            &FlagSet::new(),
            None,
        )
        .unwrap();
    fixture
        .store
        .append(
            INBOX,
            b"Subject: Alpha\r\n\r\n123456789\r\n",
            &FlagSet::new(),
            None,
        )
        .unwrap();

    let (mut client, handle) = spawn_imap(&fixture);
    let _ = client.line().await;
    client
        .send(&format!("o1 LOGIN bob@example.com {PASSWORD}"))
        .await;
    let _ = client.until_tag("o1").await;
    client.send("o2 SELECT INBOX").await;
    let _ = client.until_tag("o2").await;

    client.send("o3 SORT (SUBJECT) UTF-8 ALL").await;
    let lines = join_lines(&client.until_tag("o3").await);
    assert!(lines.contains("* SORT 2 3 1"), "{lines}");

    client.send("o4 SORT (REVERSE SIZE) UTF-8 ALL").await;
    let lines = join_lines(&client.until_tag("o4").await);
    assert!(lines.contains("* SORT 1 3 2"), "{lines}");

    client.send("o5 UID SORT (SIZE) UTF-8 ALL").await;
    let lines = join_lines(&client.until_tag("o5").await);
    assert!(lines.contains("* SORT 2 3 1"), "{lines}");

    client.send("o6 SORT (SUBJECT) KOI8-R ALL").await;
    let lines = join_lines(&client.until_tag("o6").await);
    assert!(
        lines.contains("NO [BADCHARSET (US-ASCII UTF-8)]"),
        "{lines}"
    );

    client.send("o7 SORT (BOGUS) UTF-8 ALL").await;
    let lines = join_lines(&client.until_tag("o7").await);
    assert!(lines.contains("o7 BAD"), "{lines}");

    client.send("o8 LOGOUT").await;
    let _ = client.until_tag("o8").await;
    let _ = handle.await.unwrap().unwrap();
}

#[tokio::test]
async fn imap_thread_builds_conversation_groups() {
    let fixture = fixture();
    for message in [
        &b"Subject: Topic\r\nMessage-ID: <a@example>\r\nDate: Tue, 20 Oct 2026 10:00:00 +0000\r\n\r\nbody\r\n"[..],
        b"Subject: Re: Topic\r\nMessage-ID: <b@example>\r\nIn-Reply-To: <a@example>\r\nReferences: <a@example>\r\nDate: Wed, 21 Oct 2026 10:00:00 +0000\r\n\r\nbody\r\n",
        b"Subject: Other\r\nMessage-ID: <c@example>\r\nDate: Thu, 22 Oct 2026 10:00:00 +0000\r\n\r\nbody\r\n",
    ] {
        fixture
            .store
            .append(INBOX, message, &FlagSet::new(), None)
            .unwrap();
    }
    let (mut client, handle) = spawn_imap(&fixture);
    let _ = client.line().await;
    client
        .send(&format!("t1 LOGIN bob@example.com {PASSWORD}"))
        .await;
    let _ = client.until_tag("t1").await;
    client.send("t2 SELECT INBOX").await;
    let _ = client.until_tag("t2").await;

    client.send("t3 THREAD ORDEREDSUBJECT UTF-8 ALL").await;
    let lines = join_lines(&client.until_tag("t3").await);
    assert!(lines.contains("* THREAD (1 2)(3)"), "{lines}");

    client.send("t4 THREAD REFERENCES UTF-8 ALL").await;
    let lines = join_lines(&client.until_tag("t4").await);
    assert!(lines.contains("* THREAD (1 2)(3)"), "{lines}");

    client.send("t5 UID THREAD REFERENCES UTF-8 ALL").await;
    let lines = join_lines(&client.until_tag("t5").await);
    assert!(lines.contains("* THREAD (1 2)(3)"), "{lines}");

    client.send("t6 THREAD BOGUS UTF-8 ALL").await;
    let lines = join_lines(&client.until_tag("t6").await);
    assert!(lines.contains("t6 BAD"), "{lines}");

    client.send("t7 LOGOUT").await;
    let _ = client.until_tag("t7").await;
    let _ = handle.await.unwrap().unwrap();
}

#[tokio::test]
async fn imap_scram_sha_256_authenticates() {
    let fixture = fixture();
    let (mut client, handle) = spawn_imap(&fixture);
    let greeting = client.line().await;
    assert!(greeting.contains("AUTH=SCRAM-SHA-256"), "{greeting}");

    let client_nonce = "clientnonce123";
    let client_first_bare = format!("n=bob@example.com,r={client_nonce}");
    let client_first = format!("n,,{client_first_bare}");
    client
        .send(&format!(
            "w1 AUTHENTICATE SCRAM-SHA-256 {}",
            base64::engine::general_purpose::STANDARD.encode(&client_first)
        ))
        .await;

    let challenge = read_sasl_challenge(&mut client).await;
    let server_first = String::from_utf8(
        base64::engine::general_purpose::STANDARD
            .decode(challenge)
            .unwrap(),
    )
    .unwrap();
    let mut fields = server_first.split(',');
    let nonce = fields
        .next()
        .and_then(|value| value.strip_prefix("r="))
        .unwrap()
        .to_string();
    let salt = base64::engine::general_purpose::STANDARD
        .decode(
            fields
                .next()
                .and_then(|value| value.strip_prefix("s="))
                .unwrap(),
        )
        .unwrap();
    let iterations: u32 = fields
        .next()
        .and_then(|value| value.strip_prefix("i="))
        .unwrap()
        .parse()
        .unwrap();
    assert!(nonce.starts_with(client_nonce));

    let salted = pbkdf2_sha256(PASSWORD.as_bytes(), &salt, iterations);
    let client_key = hmac_sha256(&salted, b"Client Key");
    let stored_key: [u8; 32] = sha2::Sha256::digest(client_key).into();
    let client_final_without_proof = format!("c=biws,r={nonce}");
    let auth_message = format!("{client_first_bare},{server_first},{client_final_without_proof}");
    let client_signature = hmac_sha256(&stored_key, auth_message.as_bytes());
    let mut proof = [0u8; 32];
    for index in 0..32 {
        proof[index] = client_key[index] ^ client_signature[index];
    }
    let client_final = format!(
        "{client_final_without_proof},p={}",
        base64::engine::general_purpose::STANDARD.encode(proof)
    );
    client
        .send(&base64::engine::general_purpose::STANDARD.encode(client_final))
        .await;

    let challenge = read_sasl_challenge(&mut client).await;
    let final_message = String::from_utf8(
        base64::engine::general_purpose::STANDARD
            .decode(challenge)
            .unwrap(),
    )
    .unwrap();
    let expected_signature = hmac_sha256(
        &hmac_sha256(&salted, b"Server Key"),
        auth_message.as_bytes(),
    );
    assert_eq!(
        final_message,
        format!(
            "v={}",
            base64::engine::general_purpose::STANDARD.encode(expected_signature)
        )
    );
    client.send("").await;
    let lines = join_lines(&client.until_tag("w1").await);
    assert!(lines.contains("w1 OK"), "{lines}");

    client.send("w2 SELECT INBOX").await;
    let lines = join_lines(&client.until_tag("w2").await);
    assert!(lines.contains("OK [READ-WRITE]"), "{lines}");
    client.send("w3 LOGOUT").await;
    let _ = client.until_tag("w3").await;
    let _ = handle.await.unwrap().unwrap();
}

async fn read_sasl_challenge(client: &mut Client) -> String {
    let line = client.line().await;
    assert!(line.starts_with("+ "), "expected SASL challenge: {line}");
    line[2..].trim().to_string()
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    const BLOCK: usize = 64;
    let mut normalized = [0u8; BLOCK];
    if key.len() > BLOCK {
        normalized[..32].copy_from_slice(&sha2::Sha256::digest(key));
    } else {
        normalized[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36u8; BLOCK];
    let mut outer_pad = [0x5cu8; BLOCK];
    for index in 0..BLOCK {
        inner_pad[index] ^= normalized[index];
        outer_pad[index] ^= normalized[index];
    }
    let mut inner = sha2::Sha256::new();
    inner.update(inner_pad);
    inner.update(data);
    let inner = inner.finalize();
    let mut outer = sha2::Sha256::new();
    outer.update(outer_pad);
    outer.update(inner);
    outer.finalize().into()
}

fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut first = Vec::new();
    first.extend_from_slice(salt);
    first.extend_from_slice(&1u32.to_be_bytes());
    let mut u = hmac_sha256(password, &first);
    let mut result = u;
    for _ in 1..iterations {
        u = hmac_sha256(password, &u);
        for index in 0..32 {
            result[index] ^= u[index];
        }
    }
    result
}

/// 编译期守卫：`AuthBackend` 必须是 `Clone + Send + Sync`（服务器配置需要跨任务共享）。
#[allow(dead_code)]
fn assert_auth_backend_is_shareable(backend: &AuthBackend) -> impl Send + Sync + Clone + '_ {
    backend.clone()
}

#[tokio::test]
async fn starttls_upgrades_in_place_and_plaintext_login_is_refused() {
    let fixture = fixture();

    let cert_directory = tempfile::tempdir().unwrap();
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_path = cert_directory.path().join("fullchain.pem");
    let key_path = cert_directory.path().join("privkey.pem");
    std::fs::write(&cert_path, generated.cert.pem()).unwrap();
    std::fs::write(&key_path, generated.key_pair.serialize_pem()).unwrap();
    let acceptor = mailstack_imappop3::tls::acceptor(&cert_path, &key_path).unwrap();

    let context = ImapSessionContext {
        config: ImapConfig {
            require_tls: true,
            ..imap_context(&fixture).config
        },
        ..imap_context(&fixture)
    };
    let server = ImapServer::new(
        context,
        ImapServerConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            rate_limit: None,
            ..ImapServerConfig::default()
        },
        Some(acceptor),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server_handle = tokio::spawn(async move { server.serve_on(listener, shutdown_rx).await });

    let stream = TcpStream::connect(address).await.unwrap();
    let mut plain = BufReader::new(stream);
    let greeting = read_line(&mut plain).await;
    assert!(greeting.contains("STARTTLS"), "{greeting}");
    assert!(greeting.contains("LOGINDISABLED"), "{greeting}");

    write_line(
        plain.get_mut(),
        &format!("t1 LOGIN bob@example.com {PASSWORD}"),
    )
    .await;
    let mut lines = Vec::new();
    loop {
        let line = read_line(&mut plain).await;
        let done = line.starts_with("t1 ");
        lines.push(line);
        if done {
            break;
        }
    }
    let refusal = lines.concat();
    assert!(refusal.contains("NO [PRIVACYREQUIRED]"), "{refusal}");

    write_line(plain.get_mut(), "t2 STARTTLS").await;
    let line = read_line(&mut plain).await;
    assert!(line.starts_with("t2 OK"), "{line}");

    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls_pki_types::CertificateDer::from(
            generated.cert.der().to_vec(),
        ))
        .unwrap();
    let client_config = rustls::ClientConfig::builder_with_protocol_versions(
        mailstack_imappop3::tls::supported_versions(),
    )
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let server_name = rustls_pki_types::ServerName::try_from("localhost")
        .unwrap()
        .to_owned();
    let tls_stream = timeout(
        Duration::from_secs(5),
        connector.connect(server_name, plain.into_inner()),
    )
    .await
    .expect("TLS 握手超时")
    .expect("TLS 握手失败");
    let mut secure = BufReader::new(tls_stream);

    write_line(
        secure.get_mut(),
        &format!("t3 LOGIN bob@example.com {PASSWORD}"),
    )
    .await;
    let mut lines = Vec::new();
    loop {
        let line = read_line(&mut secure).await;
        let done = line.starts_with("t3 ");
        lines.push(line);
        if done {
            break;
        }
    }
    let success = lines.concat();
    assert!(success.contains("t3 OK"), "TLS 之上登录应成功：{success}");

    write_line(secure.get_mut(), "t4 LOGOUT").await;
    loop {
        let line = read_line(&mut secure).await;
        if line.starts_with("t4 ") {
            break;
        }
    }
    drop(secure);
    shutdown_tx.send(true).unwrap();
    timeout(Duration::from_secs(10), server_handle)
        .await
        .expect("停机超时")
        .unwrap()
        .unwrap();
}

async fn read_line<R: tokio::io::AsyncBufRead + Unpin>(reader: &mut R) -> String {
    let mut line = String::new();
    timeout(Duration::from_secs(10), reader.read_line(&mut line))
        .await
        .expect("读取超时")
        .unwrap();
    assert!(!line.is_empty(), "连接被对端关闭");
    line
}

async fn write_line<W: tokio::io::AsyncWrite + Unpin>(writer: &mut W, line: &str) {
    writer.write_all(line.as_bytes()).await.unwrap();
    writer.write_all(b"\r\n").await.unwrap();
    writer.flush().await.unwrap();
}
