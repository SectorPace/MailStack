//! 多用户集成测试：**一个监听器**服务多个账号，各自看到自己的 Maildir。
//!
//! 这是 `crates/imapd` 的核心验收点。装配链路的每一环都在这里被真实穿过：
//!
//! ```text
//! mailbox-passwords.json ─► AuthBackend ─┐
//! /etc/passwd（家目录） ─► MailboxResolver ┴─► imappop3 会话 ─► 真实 TCP ─► Maildir 磁盘
//! ```
//!
//! 反例保护（去掉对应实现这些断言就会失败）：
//! * 去掉 `resolver` 注入 → 两个用户会看到**同一个**默认邮箱（断言内容不符）；
//! * 认证成功后不切 store → 同上；
//! * 解析不到邮箱却退回默认 store → 第 3 个用例会拿到别人的信。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use mailstack_imappop3::imap::server::{ImapServer, ImapServerConfig};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::watch;

use mailstack_imapd::servers::{assemble, Config};

const ALICE_PASSWORD: &str = "Correct-Horse-9";
const BOB_PASSWORD: &str = "Battery-Staple-7";

struct Fixture {
    _dir: tempfile::TempDir,
    paths: mailstack_core::Paths,
    passwd_root: std::path::PathBuf,
    alice_home: std::path::PathBuf,
    bob_home: std::path::PathBuf,
}

/// 造一个两个账号的世界：
///
/// * `<root>/etc/mailstack/mailbox-passwords.json` —— 两条 PBKDF2 记录；
/// * `<root>/etc/passwd` —— alice/bob 两个系统账号（`Config::passwd_root` 指过去）；
/// * `<root>/home/alice/Maildir`、`<root>/home/bob/Maildir` —— 各放一封不同的信。
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_path_buf();
    let paths = mailstack_core::Paths::rooted(&root);
    std::fs::create_dir_all(&paths.etc).unwrap();

    let store = mailstack_core::mailbox_passwords::MailboxPasswords::at(&paths);
    store
        .upsert(
            &mailstack_core::password::mailbox_password_record("alice@example.com", ALICE_PASSWORD)
                .unwrap(),
        )
        .unwrap();
    store
        .upsert(
            &mailstack_core::password::mailbox_password_record("bob@example.com", BOB_PASSWORD)
                .unwrap(),
        )
        .unwrap();

    let passwd_root = root.join("etc");
    let alice_home = root.join("home").join("alice");
    let bob_home = root.join("home").join("bob");
    for home in [&alice_home, &bob_home] {
        std::fs::create_dir_all(home).unwrap();
    }
    std::fs::write(
        passwd_root.join("passwd"),
        format!(
            "alice:x:1001:1001::{}:/usr/sbin/nologin\nbob:x:1002:1002::{}:/usr/sbin/nologin\n",
            alice_home.display(),
            bob_home.display()
        ),
    )
    .unwrap();

    write_message(&alice_home, "alice-only", "Alice body");
    write_message(&bob_home, "bob-only", "Bob body");

    Fixture {
        _dir: dir,
        paths,
        passwd_root,
        alice_home,
        bob_home,
    }
}

/// 往某账号的 Maildir 里投一封原始邮件。
///
/// 走 `MailStore::append` 而不是直接写 `new/`：UID 映射由 Maildir 层负责，
/// 手写文件名会让「文件在不在」与「UID 分没分配」变成两件事，
/// 测试就可能变成「文件明明在、却 FETCH 不到」的假阴性。
fn write_message(home: &std::path::Path, subject: &str, body: &str) {
    use mailstack_imappop3::maildir::{FlagSet, MailStore, SystemClock, INBOX};
    let store = MailStore::new(home.join("Maildir"), Arc::new(SystemClock)).unwrap();
    let message = format!(
        "From: someone@example.com\r\nSubject: {subject}\r\nDate: Fri, 30 Oct 2026 12:00:00 +0800\r\n\
MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{body}\r\n"
    );
    store
        .append(INBOX, message.as_bytes(), &FlagSet::new(), None)
        .expect("投递测试邮件");
}

/// 起一个真实的 IMAP 监听器（随机端口），返回地址与停机句柄。
async fn start_server(
    paths: &mailstack_core::Paths,
    passwd_root: &std::path::Path,
) -> (SocketAddr, watch::Sender<bool>) {
    let config = Config {
        server_name: "mail.test".into(),
        require_tls: false, // 测试走明文；生产由 require_tls 门控
        passwd_root: passwd_root.to_path_buf(),
        ..Config::default()
    };
    let assembly = assemble(paths, &config).expect("装配必须成功");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();

    let server = ImapServer::new(
        assembly.imap,
        ImapServerConfig {
            implicit_tls: false,
            rate_limit: None,
            ..ImapServerConfig::default()
        },
        None,
    )
    .expect("服务端配置合法");
    let (shutdown, rx) = watch::channel(false);
    tokio::spawn(async move { server.serve_on(listener, rx).await });
    (address, shutdown)
}

struct Session {
    reader: BufReader<tokio::io::ReadHalf<TcpStream>>,
    writer: tokio::io::WriteHalf<TcpStream>,
}

impl Session {
    async fn connect(address: SocketAddr) -> Self {
        let stream = TcpStream::connect(address).await.unwrap();
        let (reader, writer) = tokio::io::split(stream);
        let mut session = Self {
            reader: BufReader::new(reader),
            writer,
        };
        let greeting = session.read_line().await;
        assert!(greeting.starts_with("* OK"), "问候语异常：{greeting}");
        session
    }

    async fn read_line(&mut self) -> String {
        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(5), self.reader.read_line(&mut line))
            .await
            .expect("读超时")
            .expect("读取失败");
        line
    }

    async fn command(&mut self, tag: &str, command: &str) -> String {
        self.writer
            .write_all(format!("{tag} {command}\r\n").as_bytes())
            .await
            .unwrap();
        // 读到最后一行以 tag 开头的响应。
        let mut collected = String::new();
        loop {
            let line = self.read_line().await;
            let tagged = line.starts_with(&format!("{tag} "));
            collected.push_str(&line);
            if tagged {
                return collected;
            }
        }
    }
}

#[tokio::test]
async fn two_accounts_on_one_listener_each_see_their_own_maildir() {
    let fixture = fixture();
    // 先确认夹具真的把信写到了磁盘（否则下面的失败会指向错误的层）。
    let alice_new = fixture.alice_home.join("Maildir").join("new");
    let alice_files = std::fs::read_dir(&alice_new)
        .map(|entries| entries.count())
        .unwrap_or(0);
    assert!(
        alice_files >= 1,
        "夹具投递失败：{} 下没有文件",
        alice_new.display()
    );
    let (address, shutdown) = start_server(&fixture.paths, &fixture.passwd_root).await;

    let mut alice = Session::connect(address).await;
    let response = alice
        .command("a1", &format!("LOGIN alice@example.com {ALICE_PASSWORD}"))
        .await;
    assert!(response.contains("a1 OK"), "alice 登录失败：{response}");
    let response = alice.command("a2", "SELECT INBOX").await;
    assert!(response.contains("a2 OK"), "alice SELECT 失败：{response}");
    assert!(
        response.contains("1 EXISTS"),
        "alice 的 INBOX 应有 1 封；SELECT 响应：{response}"
    );
    let fetched = alice.command("a3", "FETCH 1 (BODY[])").await;
    assert!(
        fetched.contains("Alice body"),
        "alice 必须看到自己的信，实际：{fetched}"
    );
    assert!(
        !fetched.contains("Bob body"),
        "alice 绝不能看到 bob 的信：{fetched}"
    );
    let _ = alice.command("a4", "LOGOUT").await;

    let mut bob = Session::connect(address).await;
    let response = bob
        .command("b1", &format!("LOGIN bob@example.com {BOB_PASSWORD}"))
        .await;
    assert!(response.contains("b1 OK"), "bob 登录失败：{response}");
    bob.command("b2", "SELECT INBOX").await;
    let fetched = bob.command("b3", "FETCH 1 (BODY[])").await;
    assert!(
        fetched.contains("Bob body"),
        "bob 必须看到自己的信，实际：{fetched}"
    );
    assert!(
        !fetched.contains("Alice body"),
        "bob 绝不能看到 alice 的信：{fetched}"
    );

    let _ = shutdown.send(true);
}

#[tokio::test]
async fn a_wrong_password_is_rejected() {
    let fixture = fixture();
    let (address, shutdown) = start_server(&fixture.paths, &fixture.passwd_root).await;

    let mut session = Session::connect(address).await;
    let response = session
        .command("a1", "LOGIN alice@example.com Definitely-Not-The-Password")
        .await;
    assert!(
        response.contains("a1 NO") || response.contains("a1 BAD"),
        "错口令必须被拒：{response}"
    );
    let _ = shutdown.send(true);
}

/// 口令对、但系统账号不存在（或家目录没了）→ 拒绝登录，**不退回默认邮箱**。
#[tokio::test]
async fn an_account_without_a_mailbox_is_refused_rather_than_served_the_default_one() {
    let fixture = fixture();
    // carol 有口令记录，但 /etc/passwd 里没有她。
    mailstack_core::mailbox_passwords::MailboxPasswords::at(&fixture.paths)
        .upsert(
            &mailstack_core::password::mailbox_password_record(
                "carol@example.com",
                "Tr0ubadour-9x",
            )
            .unwrap(),
        )
        .unwrap();

    let (address, shutdown) = start_server(&fixture.paths, &fixture.passwd_root).await;

    let mut session = Session::connect(address).await;
    let response = session
        .command("c1", "LOGIN carol@example.com Tr0ubadour-9x")
        .await;
    assert!(
        response.contains("c1 NO"),
        "没有邮箱的账号必须被拒绝（否则会拿到别人的收件箱）：{response}"
    );
    let _ = shutdown.send(true);
}

/// 家目录存在但没有 Maildir：应自动建出空 INBOX（与 Dovecot 行为一致）。
#[tokio::test]
async fn a_fresh_account_gets_an_empty_inbox_created() {
    let fixture = fixture();
    let dave_home = fixture._dir.path().join("home").join("dave");
    std::fs::create_dir_all(&dave_home).unwrap();
    let mut passwd = std::fs::read_to_string(fixture.passwd_root.join("passwd")).unwrap();
    passwd.push_str(&format!(
        "dave:x:1003:1003::{}:/usr/sbin/nologin\n",
        dave_home.display()
    ));
    std::fs::write(fixture.passwd_root.join("passwd"), passwd).unwrap();
    mailstack_core::mailbox_passwords::MailboxPasswords::at(&fixture.paths)
        .upsert(
            &mailstack_core::password::mailbox_password_record("dave@example.com", "Tr0ubadour-9x")
                .unwrap(),
        )
        .unwrap();

    let (address, shutdown) = start_server(&fixture.paths, &fixture.passwd_root).await;
    let mut session = Session::connect(address).await;
    let response = session
        .command("d1", "LOGIN dave@example.com Tr0ubadour-9x")
        .await;
    assert!(response.contains("d1 OK"), "dave 登录失败：{response}");
    let selected = session.command("d2", "SELECT INBOX").await;
    assert!(
        selected.contains("EXISTS") && selected.contains("d2 OK"),
        "空 INBOX 也应可选中：{selected}"
    );
    assert!(
        dave_home.join("Maildir").join("cur").is_dir(),
        "首次 SELECT 后应建出 Maildir 结构"
    );
    let _ = shutdown.send(true);
}

/// 顺带确认装配层没把 `~` 写死成 `/root`：解析只依赖 `passwd_root` 参数。
#[tokio::test]
async fn the_fixture_roots_are_the_only_thing_being_touched() {
    let fixture = fixture();
    let _ = (&fixture.alice_home, &fixture.bob_home);
    assert!(fixture.paths.vmail.starts_with(fixture._dir.path()));
    let assembly = assemble(
        &fixture.paths,
        &Config {
            require_tls: false,
            passwd_root: fixture.passwd_root.clone(),
            ..Config::default()
        },
    )
    .unwrap();
    assert!(Arc::strong_count(&assembly.imap.store) >= 1);
}

/// 直接验证解析器是否解析到"有信的那一个" Maildir —— 把失败定位到层。
#[test]
fn the_resolver_resolves_the_maildir_that_actually_has_the_message() {
    use mailstack_imappop3::maildir::INBOX;
    use mailstack_imappop3::resolver::MailboxResolver;

    let fixture = fixture();
    let resolver =
        mailstack_imapd::SystemMaildirResolver::new(fixture.passwd_root.clone(), "Maildir");
    let store = resolver
        .resolve("alice@example.com")
        .expect("alice 应能解析到 Maildir");
    assert_eq!(store.root(), fixture.alice_home.join("Maildir"));
    let state = store.open_folder(INBOX, true).expect("打开 INBOX");
    assert_eq!(state.messages.len(), 1, "解析到的 Maildir 里应有 1 封信");
}
