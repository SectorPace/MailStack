use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use mailstack_smtp::client::{MessageOutcome, SmtpSession};
use mailstack_smtp::{
    resolve_mx_targets, resolve_pinned, AddressPolicy, MxResolver, OutboundRoute, PinnedDialer,
    PinnedTarget, SmtpError, TlsMode, DIRECT_DELIVERY_PORT,
};

use crate::entry::QueueEntry;

pub type DeliveryFuture<'a> =
    Pin<Box<dyn Future<Output = Result<DeliveryReceipt, DeliveryFailure>> + Send + 'a>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureClass {
    Transient,

    Permanent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryFailure {
    pub class: FailureClass,

    pub kind: &'static str,

    pub message: String,

    pub code: Option<u16>,

    pub accepted: Vec<String>,

    pub local_fault: bool,
}

impl DeliveryFailure {
    pub fn transient(kind: &'static str, message: impl Into<String>) -> Self {
        Self {
            class: FailureClass::Transient,
            kind,
            message: message.into(),
            code: None,
            accepted: Vec::new(),
            local_fault: false,
        }
    }

    pub fn permanent(kind: &'static str, message: impl Into<String>) -> Self {
        Self {
            class: FailureClass::Permanent,
            kind,
            message: message.into(),
            code: None,
            accepted: Vec::new(),
            local_fault: false,
        }
    }

    pub fn with_local_fault(mut self) -> Self {
        self.local_fault = true;
        self
    }

    pub fn with_accepted(mut self, accepted: Vec<String>) -> Self {
        self.accepted = accepted;
        self
    }

    pub fn with_code(mut self, code: u16) -> Self {
        self.code = Some(code);
        self
    }

    pub fn is_permanent(&self) -> bool {
        self.class == FailureClass::Permanent
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeliveryReceipt {
    pub accepted: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryTarget {
    Local,

    Remote(OutboundRoute),
}

pub trait Transport: Send + Sync {
    fn deliver<'a>(
        &'a self,
        entry: &'a QueueEntry,
        target: DeliveryTarget,
        recipients: &'a [String],
    ) -> DeliveryFuture<'a>;
}

pub fn classify_code(code: u16) -> FailureClass {
    if (500..600).contains(&code) {
        FailureClass::Permanent
    } else {
        FailureClass::Transient
    }
}

pub fn classify_smtp_error(error: &SmtpError) -> DeliveryFailure {
    let kind = error.kind();
    let message = error.to_string();
    match error {
        SmtpError::InvalidEndpoint(_)
        | SmtpError::TlsRequired
        | SmtpError::IncompleteCredentials
        | SmtpError::PrivateRelayDisabled
        | SmtpError::NoAcceptableAddress(_)
        | SmtpError::NullMx(_) => DeliveryFailure::permanent(kind, message),
        _ => DeliveryFailure::transient(kind, message),
    }
}

pub fn classify_response(code: u16, banner: impl Into<String>) -> DeliveryFailure {
    DeliveryFailure {
        class: classify_code(code),
        kind: "SmtpRejected",
        message: banner.into(),
        code: Some(code),
        accepted: Vec::new(),
        local_fault: false,
    }
}

#[derive(Debug, Clone, Copy)]
enum DeliveryTls {
    Required(TlsMode),

    Plaintext,
}

pub struct SmtpRemoteTransport {
    dialer: PinnedDialer,
    timeout: Duration,
    helo_name: String,
    credentials: Option<(String, String)>,
    policy: AddressPolicy,

    mx: Option<Arc<dyn MxResolver>>,

    direct_port: u16,
}

impl std::fmt::Debug for SmtpRemoteTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmtpRemoteTransport")
            .field("helo_name", &self.helo_name)
            .field("has_credentials", &self.credentials.is_some())
            .field("has_mx_resolver", &self.mx.is_some())
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl SmtpRemoteTransport {
    pub fn new(dialer: PinnedDialer, helo_name: impl Into<String>, timeout: Duration) -> Self {
        Self {
            dialer,
            timeout,
            helo_name: helo_name.into(),
            credentials: None,
            policy: AddressPolicy::public_only(),
            mx: None,
            direct_port: DIRECT_DELIVERY_PORT,
        }
    }

    pub fn with_credentials(mut self, username: String, password: String) -> Self {
        self.credentials = Some((username, password));
        self
    }

    pub fn with_policy(mut self, policy: AddressPolicy) -> Self {
        self.policy = policy;
        self
    }

    pub fn with_mx(mut self, resolver: Arc<dyn MxResolver>) -> Self {
        self.mx = Some(resolver);
        self
    }

    pub fn with_direct_port(mut self, port: u16) -> Self {
        self.direct_port = port;
        self
    }

    async fn deliver_remote(
        &self,
        entry: &QueueEntry,
        target: DeliveryTarget,
        recipients: &[String],
    ) -> Result<DeliveryReceipt, DeliveryFailure> {
        let route = match target {
            DeliveryTarget::Remote(route) => route,
            DeliveryTarget::Local => {
                return Err(DeliveryFailure::permanent(
                    "WrongTransport",
                    "本地投递不应经 SMTP 传输",
                ))
            }
        };

        match &route {
            OutboundRoute::ViaRelay {
                host,
                port,
                wrappermode,
            } => {
                let pinned = resolve_pinned(host, *port, self.policy)
                    .await
                    .map_err(|e| classify_smtp_error(&e))?;

                let mode = if *wrappermode || *port == 465 {
                    TlsMode::Implicit
                } else {
                    TlsMode::StartTls
                };
                self.deliver_one(&pinned, DeliveryTls::Required(mode), entry, recipients)
                    .await
            }
            OutboundRoute::Direct => self.deliver_direct(entry, recipients).await,
        }
    }

    async fn deliver_one(
        &self,
        pinned: &PinnedTarget,
        tls: DeliveryTls,
        entry: &QueueEntry,
        recipients: &[String],
    ) -> Result<DeliveryReceipt, DeliveryFailure> {
        let connect_mode = match tls {
            DeliveryTls::Required(mode) => mode,
            DeliveryTls::Plaintext => TlsMode::StartTls,
        };

        let (mut session, _banner) =
            SmtpSession::connect(&self.dialer, pinned, connect_mode, self.timeout)
                .await
                .map_err(|e| classify_smtp_error(&e))?;

        let ehlo = session
            .ehlo(&self.helo_name)
            .await
            .map_err(|e| classify_smtp_error(&e))?;
        if !ehlo.is_positive_completion() {
            return Err(classify_response(ehlo.code, ehlo.banner()));
        }

        if let DeliveryTls::Required(mode) = tls {
            if mode == TlsMode::StartTls {
                if !session.capabilities().starttls {
                    return Err(DeliveryFailure::permanent(
                        "TlsUnavailable",
                        "relay does not offer STARTTLS; refusing to send credentials in the clear",
                    ));
                }
                let (upgraded, _) = session
                    .starttls(&self.dialer, pinned)
                    .await
                    .map_err(|e| classify_smtp_error(&e))?;
                session = upgraded;
                let re_ehlo = session
                    .ehlo(&self.helo_name)
                    .await
                    .map_err(|e| classify_smtp_error(&e))?;
                if !re_ehlo.is_positive_completion() {
                    return Err(classify_response(re_ehlo.code, re_ehlo.banner()));
                }
            }

            if let Some((username, password)) = &self.credentials {
                if session.capabilities().auth_mechanisms.is_empty() {
                    return Err(DeliveryFailure::permanent(
                        "AuthNotOffered",
                        "relay offers no AUTH mechanism but credentials are configured",
                    ));
                }
                let auth = session
                    .authenticate(username, password)
                    .await
                    .map_err(|e| classify_smtp_error(&e))?;
                if !auth.is_positive_completion() {
                    return Err(classify_response(auth.code, auth.banner()));
                }
            }
        }

        let outcome = session
            .send_message_detailed(&entry.mail_from, recipients, &entry.data)
            .await
            .map_err(|e| classify_smtp_error(&e))?;
        let _ = session.quit().await;

        match outcome {
            MessageOutcome::Accepted { .. } => Ok(DeliveryReceipt {
                accepted: recipients.len(),
            }),
            MessageOutcome::Rejected {
                response, accepted, ..
            } => Err(classify_response(response.code, response.banner()).with_accepted(accepted)),
        }
    }

    async fn deliver_direct(
        &self,
        entry: &QueueEntry,
        recipients: &[String],
    ) -> Result<DeliveryReceipt, DeliveryFailure> {
        let Some(mx) = self.mx.as_ref() else {
            return Err(DeliveryFailure::transient(
                "DirectDeliveryUnavailable",
                "direct MX delivery is not configured on this transport; configure a relay (smarthost)",
            ));
        };

        let mut accepted: Vec<String> = Vec::new();
        let mut failures: Vec<DeliveryFailure> = Vec::new();

        for (domain, group) in group_by_domain(recipients) {
            match self
                .deliver_direct_to_domain(mx.as_ref(), &domain, &group, entry)
                .await
            {
                Ok(_) => accepted.extend(group),
                Err(failure) => {
                    accepted.extend(failure.accepted.iter().cloned());
                    failures.push(failure);
                }
            }
        }

        if failures.is_empty() {
            return Ok(DeliveryReceipt {
                accepted: accepted.len(),
            });
        }

        let merged = if failures.len() == 1 {
            failures.pop().expect("已判定非空")
        } else {
            let any_transient = failures.iter().any(|failure| !failure.is_permanent());
            let detail = failures
                .iter()
                .map(|failure| failure.message.clone())
                .collect::<Vec<_>>()
                .join("; ");
            if any_transient {
                DeliveryFailure::transient("DirectDeliveryFailed", detail)
            } else {
                DeliveryFailure::permanent("DirectDeliveryFailed", detail)
            }
        };
        Err(merged.with_accepted(accepted))
    }

    async fn deliver_direct_to_domain(
        &self,
        mx: &dyn MxResolver,
        domain: &str,
        recipients: &[String],
        entry: &QueueEntry,
    ) -> Result<DeliveryReceipt, DeliveryFailure> {
        let targets = resolve_mx_targets(mx, domain, self.direct_port, self.policy)
            .await
            .map_err(|error| classify_smtp_error(&error))?;

        let mut last: Option<DeliveryFailure> = None;
        for pinned in &targets {
            match self
                .deliver_one(pinned, DeliveryTls::Plaintext, entry, recipients)
                .await
            {
                Ok(receipt) => return Ok(receipt),
                Err(failure) => {
                    if failure.is_permanent() {
                        return Err(failure);
                    }

                    if !failure.accepted.is_empty() {
                        return Err(failure);
                    }
                    last = Some(failure);
                }
            }
        }

        Err(last.unwrap_or_else(|| {
            DeliveryFailure::transient("NoMxTarget", format!("no usable MX target for {domain}"))
        }))
    }
}

fn group_by_domain(recipients: &[String]) -> Vec<(String, Vec<String>)> {
    let mut groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for recipient in recipients {
        let domain = recipient
            .rsplit_once('@')
            .map(|(_, domain)| domain.to_ascii_lowercase())
            .unwrap_or_default();
        groups.entry(domain).or_default().push(recipient.clone());
    }
    groups.into_iter().collect()
}

impl Transport for SmtpRemoteTransport {
    fn deliver<'a>(
        &'a self,
        entry: &'a QueueEntry,
        target: DeliveryTarget,
        recipients: &'a [String],
    ) -> DeliveryFuture<'a> {
        Box::pin(async move { self.deliver_remote(entry, target, recipients).await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn four_xx_is_transient_and_five_xx_is_permanent() {
        for code in [400u16, 421, 450, 451, 452, 499] {
            assert_eq!(
                classify_code(code),
                FailureClass::Transient,
                "{code} 应可重试"
            );
        }
        for code in [500u16, 550, 551, 552, 553, 554, 599] {
            assert_eq!(
                classify_code(code),
                FailureClass::Permanent,
                "{code} 应退信"
            );
        }

        assert_eq!(classify_code(250), FailureClass::Transient);
    }

    #[test]
    fn unknown_transport_errors_are_retryable_never_bounces() {
        let cases = vec![
            SmtpError::Connect {
                addr: "1.2.3.4:25".parse().unwrap(),
                source: std::io::Error::other("refused"),
            },
            SmtpError::ConnectTimeout {
                addr: "1.2.3.4:25".parse().unwrap(),
                secs: 20,
            },
            SmtpError::Protocol("bad framing".into()),
            SmtpError::Io(std::io::Error::other("reset")),
            SmtpError::Tls("handshake aborted".into()),
            SmtpError::Dns("timeout".into()),
        ];
        for error in cases {
            let failure = classify_smtp_error(&error);
            assert_eq!(
                failure.class,
                FailureClass::Transient,
                "{} 必须可重试（否则可能误退信已投递的邮件）",
                error.kind()
            );
        }
    }

    #[test]
    fn misconfiguration_is_permanent_so_it_does_not_flood_the_queue() {
        let cases = vec![
            SmtpError::InvalidEndpoint("bad host".into()),
            SmtpError::TlsRequired,
            SmtpError::IncompleteCredentials,
            SmtpError::PrivateRelayDisabled,
            SmtpError::NoAcceptableAddress("relay.example.test".into()),
        ];
        for error in cases {
            assert!(
                classify_smtp_error(&error).is_permanent(),
                "{} 应判为永久失败",
                error.kind()
            );
        }
    }

    #[test]
    fn response_classification_keeps_the_status_code() {
        let transient = classify_response(421, "421 service not available");
        assert_eq!(transient.class, FailureClass::Transient);
        assert_eq!(transient.code, Some(421));
        assert_eq!(transient.kind, "SmtpRejected");

        let permanent = classify_response(550, "550 no such user");
        assert!(permanent.is_permanent());
        assert_eq!(permanent.code, Some(550));
    }

    struct StubMxResolver {
        records: Vec<mailstack_smtp::MxRecord>,
    }

    impl mailstack_smtp::MxResolver for StubMxResolver {
        fn lookup_mx(&self, domain: &str) -> mailstack_smtp::MxFuture<'_> {
            let domain = domain.to_string();
            let records = self.records.clone();
            Box::pin(async move {
                if domain.is_empty() {
                    return Err(SmtpError::Dns("empty domain".to_string()));
                }
                Ok(records)
            })
        }
    }

    fn outbound_entry(recipients: &[&str]) -> QueueEntry {
        QueueEntry::new(
            crate::entry::EntryKind::Outbound,
            "s@example.org",
            recipients.iter().map(|r| r.to_string()).collect(),
            "body",
            0,
        )
        .unwrap()
    }

    fn dialer() -> PinnedDialer {
        PinnedDialer::with_webpki_roots(Duration::from_secs(2)).unwrap()
    }

    #[tokio::test]
    async fn direct_route_fails_loudly_and_never_falls_back_to_the_relay() {
        let transport =
            SmtpRemoteTransport::new(dialer(), "mail.example.org", Duration::from_secs(1));
        let entry = outbound_entry(&["r@example.net"]);

        let failure = transport
            .deliver(
                &entry,
                DeliveryTarget::Remote(OutboundRoute::Direct),
                &entry.recipients,
            )
            .await
            .unwrap_err();

        assert_eq!(failure.kind, "DirectDeliveryUnavailable");
        assert_eq!(
            failure.class,
            FailureClass::Transient,
            "不得把「不可用」伪装成永久失败去退掉用户的邮件"
        );
        assert!(failure.message.contains("configure a relay"));
    }

    #[tokio::test]
    async fn a_null_mx_is_a_permanent_failure_not_a_retry() {
        let transport =
            SmtpRemoteTransport::new(dialer(), "mail.example.org", Duration::from_secs(1))
                .with_policy(AddressPolicy::allow_private())
                .with_mx(Arc::new(StubMxResolver {
                    records: vec![mailstack_smtp::MxRecord {
                        preference: 0,
                        host: String::new(),
                    }],
                }));
        let entry = outbound_entry(&["r@example.net"]);

        let failure = transport
            .deliver(
                &entry,
                DeliveryTarget::Remote(OutboundRoute::Direct),
                &entry.recipients,
            )
            .await
            .unwrap_err();

        assert_eq!(failure.kind, "NullMx");
        assert_eq!(failure.class, FailureClass::Permanent, "null MX 必须退信");
    }

    #[tokio::test]
    async fn direct_delivery_is_refused_when_the_mx_points_into_private_space() {
        let transport =
            SmtpRemoteTransport::new(dialer(), "mail.example.org", Duration::from_secs(1))
                .with_policy(AddressPolicy::public_only())
                .with_mx(Arc::new(StubMxResolver {
                    records: vec![mailstack_smtp::MxRecord {
                        preference: 10,
                        host: "127.0.0.1".to_string(),
                    }],
                }));
        let entry = outbound_entry(&["r@example.net"]);

        let failure = transport
            .deliver(
                &entry,
                DeliveryTarget::Remote(OutboundRoute::Direct),
                &entry.recipients,
            )
            .await
            .unwrap_err();

        assert_eq!(failure.kind, "NoAcceptableAddress");
        assert_eq!(failure.class, FailureClass::Permanent);
    }

    #[tokio::test]
    async fn a_recipient_without_a_domain_is_never_silently_accepted() {
        let transport =
            SmtpRemoteTransport::new(dialer(), "mail.example.org", Duration::from_secs(1))
                .with_policy(AddressPolicy::allow_private())
                .with_mx(Arc::new(StubMxResolver {
                    records: vec![mailstack_smtp::MxRecord {
                        preference: 10,
                        host: "127.0.0.1".to_string(),
                    }],
                }));
        let entry = QueueEntry::new(
            crate::entry::EntryKind::Outbound,
            "s@example.org",
            vec!["no-at-sign".to_string()],
            "body",
            0,
        )
        .unwrap();

        let failure = transport
            .deliver(
                &entry,
                DeliveryTarget::Remote(OutboundRoute::Direct),
                &entry.recipients,
            )
            .await
            .unwrap_err();
        assert_eq!(failure.kind, "DnsError", "空域名应报解析错误");
        assert!(failure.accepted.is_empty(), "不得声称投出去过");
    }

    async fn serve_fake_mx(
        listener: tokio::net::TcpListener,
        seen: Arc<std::sync::Mutex<Vec<String>>>,
    ) {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let (socket, _) = listener.accept().await.expect("接受直投连接");
        let (read_half, mut write) = socket.into_split();
        let mut reader = BufReader::new(read_half);
        write
            .write_all(b"220 fake.example.org ESMTP\r\n")
            .await
            .unwrap();

        let mut line = String::new();
        loop {
            line.clear();
            let read = reader.read_line(&mut line).await.unwrap();
            if read == 0 {
                break;
            }
            let command = line.trim_end().to_string();
            seen.lock().unwrap().push(command.clone());
            let upper = command.to_ascii_uppercase();
            let reply: &[u8] = if upper.starts_with("EHLO") {
                b"250-fake.example.org\r\n250 SIZE 10240000\r\n"
            } else if upper.starts_with("DATA") {
                write
                    .write_all(b"354 End data with <CRLF>.<CRLF>\r\n")
                    .await
                    .unwrap();

                let mut body: Vec<u8> = Vec::new();
                let mut chunk = [0u8; 1024];
                loop {
                    let read = tokio::io::AsyncReadExt::read(&mut reader, &mut chunk)
                        .await
                        .unwrap();
                    if read == 0 {
                        break;
                    }
                    body.extend_from_slice(&chunk[..read]);
                    if body.ends_with(b"\r\n.\r\n") || body == b".\r\n" {
                        break;
                    }
                }
                b"250 2.0.0 Ok: queued\r\n"
            } else if upper.starts_with("QUIT") {
                write.write_all(b"221 Bye\r\n").await.unwrap();
                break;
            } else if upper.starts_with("STARTTLS") {
                b"454 TLS not available\r\n"
            } else {
                b"250 OK\r\n"
            };
            write.write_all(reply).await.unwrap();
        }
    }

    #[tokio::test]
    async fn direct_delivery_follows_the_mx_and_never_sends_credentials() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let handle = {
            let seen = Arc::clone(&seen);
            tokio::spawn(async move { serve_fake_mx(listener, seen).await })
        };

        let transport =
            SmtpRemoteTransport::new(dialer(), "mail.example.org", Duration::from_secs(5))
                .with_policy(AddressPolicy::allow_private())
                .with_direct_port(port)
                .with_credentials("relay-user".to_string(), "relay-pass".to_string())
                .with_mx(Arc::new(StubMxResolver {
                    records: vec![mailstack_smtp::MxRecord {
                        preference: 10,
                        host: "127.0.0.1".to_string(),
                    }],
                }));

        let entry = outbound_entry(&["r@example.net"]);
        let result = transport
            .deliver(
                &entry,
                DeliveryTarget::Remote(OutboundRoute::Direct),
                &entry.recipients,
            )
            .await;

        let commands = seen.lock().unwrap().clone();
        let receipt = match result {
            Ok(receipt) => receipt,
            Err(failure) => panic!("直投应成功，实际 {failure:?}；对端收到的命令：{commands:?}"),
        };
        assert_eq!(receipt.accepted, 1);

        handle.await.expect("假 MX 任务不应 panic");
        assert!(
            commands
                .iter()
                .any(|c| c.to_uppercase().starts_with("EHLO")),
            "{commands:?}"
        );
        assert!(
            commands
                .iter()
                .any(|c| c.to_lowercase().starts_with("mail from:<s@example.org>")),
            "信封发件人必须原样送达：{commands:?}"
        );
        assert!(
            !commands
                .iter()
                .any(|c| c.to_uppercase().starts_with("AUTH")),
            "直投路径绝不能发送凭证：{commands:?}"
        );
        assert!(
            !commands
                .iter()
                .any(|c| c.to_uppercase().starts_with("STARTTLS")),
            "直投当前不做机会式 TLS：{commands:?}"
        );
    }

    #[test]
    fn recipients_are_grouped_by_domain_in_a_deterministic_order() {
        let groups = group_by_domain(&[
            "b@y.test".to_string(),
            "a@x.test".to_string(),
            "c@y.test".to_string(),
        ]);
        assert_eq!(
            groups,
            vec![
                ("x.test".to_string(), vec!["a@x.test".to_string()]),
                (
                    "y.test".to_string(),
                    vec!["b@y.test".to_string(), "c@y.test".to_string()]
                ),
            ],
            "顺序必须确定（按域名），否则行为不可复现"
        );
    }

    #[tokio::test]
    async fn local_target_is_rejected_by_the_smtp_transport() {
        let transport =
            SmtpRemoteTransport::new(dialer(), "mail.example.org", Duration::from_secs(1));
        let entry = outbound_entry(&["r@example.net"]);

        let failure = transport
            .deliver(&entry, DeliveryTarget::Local, &entry.recipients)
            .await
            .unwrap_err();
        assert_eq!(failure.kind, "WrongTransport");
        assert!(failure.is_permanent());
    }
}
