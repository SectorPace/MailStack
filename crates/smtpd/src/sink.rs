use std::net::SocketAddr;
use std::sync::Arc;

use mailstack_auth::{dmarc, DmarcStatus, MessageAuthenticator, TxtCache};
use mailstack_queue::{EntryKind, QueueEntry, QueueStore};

use crate::auth_results;
use crate::connection::{MessageSink, SinkFuture};
use crate::listener::Clock;
use crate::reply::{texts, Reply};
use crate::session::{AcceptedMessage, SessionRole};

pub const MAX_RECEIVED_HOPS: usize = 50;

pub struct QueueSink {
    hostname: String,
    resolver: MessageAuthenticator,
    cache: TxtCache,
    store: QueueStore,
    clock: Arc<dyn Clock>,
}

impl QueueSink {
    pub fn new(
        hostname: impl Into<String>,
        resolver: MessageAuthenticator,
        cache: TxtCache,
        store: QueueStore,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            hostname: hostname.into(),
            resolver,
            cache,
            store,
            clock,
        }
    }

    pub fn from_paths(
        paths: &mailstack_core::Paths,
        hostname: impl Into<String>,
        clock: Arc<dyn Clock>,
    ) -> mailstack_auth::AuthResult<Self> {
        Ok(Self::new(
            hostname,
            mailstack_auth::system_resolver()?,
            TxtCache::new(),
            QueueStore::from_paths(paths),
            clock,
        ))
    }

    pub fn store(&self) -> &QueueStore {
        &self.store
    }

    async fn handle(&self, message: AcceptedMessage, peer: SocketAddr) -> Result<(), Reply> {
        if received_hops(&message.data) >= MAX_RECEIVED_HOPS
            || received_via_host(&message.data, &self.hostname)
        {
            return Err(Reply::with_enhanced(554, "5.4.6", texts::TOO_MANY_HOPS));
        }

        let submission = message.role == SessionRole::Submission;
        let now_unix = self.clock.now_millis() / 1000;
        let mut headers = String::with_capacity(256);
        headers.push_str(&received_header(&self.hostname, &message, peer, now_unix));

        if !submission {
            let check = dmarc::evaluate(
                &self.resolver,
                &self.cache,
                &message.data,
                peer.ip(),
                &message.helo,
                &self.hostname,
                &message.mail_from,
            )
            .await
            .map_err(|_| Reply::with_enhanced(451, "4.7.0", texts::AUTH_EVAL_FAILED))?;

            if matches!(check.status, DmarcStatus::Fail(_)) && check.policy_is_reject() {
                return Err(Reply::with_enhanced(550, "5.7.1", texts::DMARC_REJECTED));
            }

            headers.push_str(&format!("Return-Path: <{}>\r\n", message.mail_from));
            headers.push_str(&auth_results::render(
                &self.hostname,
                &message.mail_from,
                &check,
                None,
            ));
        }

        let mut text = String::from_utf8(message.data)
            .map_err(|_| Reply::with_enhanced(554, "5.6.0", texts::MESSAGE_NOT_UTF8))?;
        text.reserve(headers.len());
        text.insert_str(0, &headers);

        let mut entry = QueueEntry::new(
            EntryKind::Outbound,
            message.mail_from,
            message.recipients,
            text,
            now_unix,
        )
        .map_err(|_| Reply::with_enhanced(451, "4.3.0", texts::QUEUE_WRITE_FAILED))?;

        self.store
            .enqueue_new(&mut entry)
            .map_err(|_| Reply::with_enhanced(451, "4.3.0", texts::QUEUE_WRITE_FAILED))?;

        Ok(())
    }
}

impl MessageSink for QueueSink {
    fn accept<'a>(&'a self, message: AcceptedMessage, peer: SocketAddr) -> SinkFuture<'a> {
        Box::pin(async move { self.handle(message, peer).await })
    }
}

fn received_header(
    hostname: &str,
    message: &AcceptedMessage,
    peer: SocketAddr,
    now_unix: i64,
) -> String {
    let helo = if message.helo.trim().is_empty() {
        "unknown".to_string()
    } else {
        message
            .helo
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect()
    };
    let peer_text = match peer.ip() {
        std::net::IpAddr::V4(ip) => ip.to_string(),
        std::net::IpAddr::V6(ip) => format!("[{ip}]"),
    };
    let protocol = if message.authenticated {
        "ESMTPSA"
    } else if message.secured {
        "ESMTPS"
    } else {
        "ESMTP"
    };
    let for_clause = message
        .recipients
        .first()
        .map(|recipient| format!(" for <{recipient}>"))
        .unwrap_or_default();
    format!(
        "Received: from {helo} ({peer_text}) by {hostname} with {protocol}{for_clause}; {}\r\n",
        format_rfc5322_date(now_unix)
    )
}

fn received_hops(data: &[u8]) -> usize {
    let mut count = 0;
    for raw in data.split(|&byte| byte == b'\n') {
        let line = raw.strip_suffix(b"\r").unwrap_or(raw);
        if line.is_empty() {
            break;
        }
        if matches!(line.first(), Some(b' ') | Some(b'\t')) {
            continue;
        }
        if has_header_name(line, b"received") {
            count += 1;
        }
    }
    count
}

fn received_via_host(data: &[u8], hostname: &str) -> bool {
    let needle = format!("by {}", hostname.trim());
    let needle = needle.as_bytes();
    let mut current_is_received = false;
    for raw in data.split(|&byte| byte == b'\n') {
        let line = raw.strip_suffix(b"\r").unwrap_or(raw);
        if line.is_empty() {
            return false;
        }
        if matches!(line.first(), Some(b' ') | Some(b'\t')) {
            if current_is_received && contains_ignore_ascii_case(line, needle) {
                return true;
            }
            continue;
        }
        current_is_received = has_header_name(line, b"received");
        if current_is_received && contains_ignore_ascii_case(line, needle) {
            return true;
        }
    }
    false
}

fn has_header_name(line: &[u8], name: &[u8]) -> bool {
    line.len() > name.len()
        && line[..name.len()].eq_ignore_ascii_case(name)
        && line[name.len()] == b':'
}

fn contains_ignore_ascii_case(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    if !needle.iter().all(u8::is_ascii) {
        return false;
    }
    let lower = |byte: u8| byte.to_ascii_lowercase();
    haystack.windows(needle.len()).any(|window| {
        window
            .iter()
            .zip(needle)
            .all(|(left, right)| lower(*left) == lower(*right))
    })
}

fn format_rfc5322_date(unix_seconds: i64) -> String {
    const WEEKDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];

    let days = unix_seconds.div_euclid(86_400);
    let seconds_of_day = unix_seconds.rem_euclid(86_400);
    let weekday = (days + 4).rem_euclid(7) as usize;
    let (year, month, day) = civil_from_days(days);
    let hour = seconds_of_day / 3600;
    let minute = (seconds_of_day % 3600) / 60;
    let second = seconds_of_day % 60;

    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} +0000",
        WEEKDAYS[weekday],
        day,
        MONTHS[(month - 1) as usize],
        year,
        hour,
        minute,
        second
    )
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::listener::SystemClock;
    use std::net::{IpAddr, Ipv4Addr};

    const MESSAGE: &[u8] = concat!(
        "From: alice@example.com\r\n",
        "To: bob@example.net\r\n",
        "Subject: inbound\r\n",
        "Date: Wed, 01 Oct 2026 10:00:00 +0800\r\n",
        "\r\n",
        "body\r\n"
    )
    .as_bytes();

    struct FixedClock;

    impl Clock for FixedClock {
        fn now_millis(&self) -> i64 {
            1_790_848_800_000
        }
    }

    fn peer(ip: [u8; 4]) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])), 40000)
    }

    fn accepted(data: &[u8]) -> AcceptedMessage {
        AcceptedMessage {
            mail_from: "alice@example.com".to_string(),
            recipients: vec!["bob@example.net".to_string()],
            data: data.to_vec(),
            helo: "mail.example.com".to_string(),
            role: SessionRole::Mx,
            authenticated: false,
            secured: false,
        }
    }

    fn submission(data: &[u8]) -> AcceptedMessage {
        AcceptedMessage {
            role: SessionRole::Submission,
            authenticated: true,
            secured: true,
            ..accepted(data)
        }
    }

    fn sink(dir: &std::path::Path, spf: &[u8], dmarc_record: &[u8]) -> QueueSink {
        let cache = TxtCache::new();

        cache.pin_dmarc_walk("example.com");

        cache.pin_absent("mail.example.com");
        cache.add_spf("example.com", spf).unwrap();
        cache.add_dmarc("_dmarc.example.com", dmarc_record).unwrap();
        QueueSink::new(
            "mx.mailstack.test",
            mailstack_auth::system_resolver().expect("构造系统解析器"),
            cache,
            QueueStore::new(dir),
            Arc::new(FixedClock),
        )
    }

    fn queued(dir: &std::path::Path) -> Vec<QueueEntry> {
        QueueStore::new(dir).load_all().expect("读取队列")
    }

    #[test]
    fn rfc5322_dates_match_the_reference_format() {
        assert_eq!(
            format_rfc5322_date(1_790_848_800),
            "Thu, 01 Oct 2026 10:00:00 +0000"
        );
        assert_eq!(format_rfc5322_date(0), "Thu, 01 Jan 1970 00:00:00 +0000");
        assert_eq!(
            format_rfc5322_date(1_790_848_800 + 86_400),
            "Fri, 02 Oct 2026 10:00:00 +0000"
        );

        assert_eq!(
            format_rfc5322_date(1_709_164_800),
            "Thu, 29 Feb 2024 00:00:00 +0000"
        );
    }

    #[test]
    fn hop_counting_only_looks_at_the_header_block() {
        let data =
            b"Received: from a by b; d\r\nReceived: from c by d; e\r\n\r\nReceived: body\r\n";
        assert_eq!(received_hops(data), 2, "正文里的 Received: 不是跳数");

        let folded = b"Received: from a\r\n\tby b;\r\n\t d\r\nSubject: x\r\n\r\nbody\r\n";
        assert_eq!(received_hops(folded), 1);
    }

    #[test]
    fn a_received_header_that_already_passed_through_this_host_is_a_loop() {
        let data = b"Received: from a (1.2.3.4) by MX.Mailstack.Test with ESMTP; d\r\n\r\nbody";
        assert!(received_via_host(data, "mx.mailstack.test"));

        assert!(!received_via_host(data, "mx.other.test"));
    }

    #[tokio::test]
    async fn a_dmarc_aligned_message_is_enqueued_with_trace_headers_and_authentication_results() {
        let dir = tempfile::tempdir().unwrap();
        let sink = sink(
            dir.path(),
            b"v=spf1 ip4:203.0.113.10 -all",
            b"v=DMARC1; p=reject",
        );

        sink.accept(accepted(MESSAGE), peer([203, 0, 113, 10]))
            .await
            .expect("对齐的邮件应被接受");

        let entries = queued(dir.path());
        assert_eq!(entries.len(), 1, "必须正好入队一封");
        let entry = &entries[0];

        assert!(
            entry.data.starts_with(
                "Received: from mail.example.com (203.0.113.10) by mx.mailstack.test with ESMTP for <bob@example.net>; Thu, 01 Oct 2026 10:00:00 +0000\r\n"
            ),
            "Received 头格式/顺序不符：{:?}",
            &entry.data[..entry.data.len().min(200)]
        );
        assert!(
            entry.data.contains("Return-Path: <alice@example.com>\r\n"),
            "入站必须写 Return-Path（信封发件人）：{}",
            entry.data
        );
        assert!(
            entry
                .data
                .contains("Authentication-Results: mx.mailstack.test;"),
            "认证结论必须存在：{}",
            entry.data
        );
        assert!(entry.data.contains("spf=pass"), "{}", entry.data);
        assert!(entry.data.contains("dmarc=pass"), "{}", entry.data);
        assert!(entry.data.ends_with("body\r\n"), "原始正文必须被完整保留");
        assert_eq!(entry.mail_from, "alice@example.com");
        assert_eq!(entry.recipients, vec!["bob@example.net".to_string()]);
    }

    #[tokio::test]
    async fn a_dmarc_fail_under_a_reject_policy_is_refused_and_not_enqueued() {
        let dir = tempfile::tempdir().unwrap();
        let sink = sink(
            dir.path(),
            b"v=spf1 ip4:203.0.113.10 -all",
            b"v=DMARC1; p=reject",
        );

        let reply = sink
            .accept(accepted(MESSAGE), peer([198, 51, 100, 7]))
            .await
            .expect_err("reject 策略下的失败邮件必须被拒绝");
        assert_eq!(reply.code, 550);
        assert!(queued(dir.path()).is_empty(), "被策略拒绝的邮件绝不能入队");
    }

    #[tokio::test]
    async fn a_dmarc_fail_under_a_none_policy_is_still_delivered_with_the_verdict() {
        let dir = tempfile::tempdir().unwrap();
        let sink = sink(
            dir.path(),
            b"v=spf1 ip4:203.0.113.10 -all",
            b"v=DMARC1; p=none",
        );

        sink.accept(accepted(MESSAGE), peer([198, 51, 100, 7]))
            .await
            .expect("p=none 只做标注，不应拒收");

        let entries = queued(dir.path());
        assert_eq!(entries.len(), 1);
        assert!(
            entries[0].data.contains("dmarc=fail") && entries[0].data.contains("policy=none"),
            "必须如实记录失败与策略：{}",
            entries[0].data
        );
    }

    #[tokio::test]
    async fn submission_is_not_judged_by_inbound_authentication_and_gets_no_verdict_header() {
        let dir = tempfile::tempdir().unwrap();
        let sink = sink(
            dir.path(),
            b"v=spf1 ip4:203.0.113.10 -all",
            b"v=DMARC1; p=reject",
        );

        sink.accept(submission(MESSAGE), peer([198, 51, 100, 7]))
            .await
            .expect("提交口的邮件不得被入站 DMARC 判死");

        let entries = queued(dir.path());
        assert_eq!(entries.len(), 1);
        let data = &entries[0].data;
        assert!(
            data.starts_with(
                "Received: from mail.example.com (198.51.100.7) by mx.mailstack.test with ESMTPSA"
            ),
            "提交邮件仍应有本跳 trace 头（且标明认证/TLS）：{:?}",
            &data[..data.len().min(160)]
        );
        assert!(
            !data.contains("Authentication-Results:"),
            "提交路径不得写入站 Authentication-Results：{data}"
        );
        assert!(
            !data.contains("dmarc=fail") && !data.contains("spf=fail"),
            "提交路径不得写入站 SPF/DMARC 判定：{data}"
        );
        assert!(
            !data.contains("Return-Path:"),
            "Return-Path 由最终投递方按投递结果写，提交口不写：{data}"
        );
    }

    #[tokio::test]
    async fn a_message_with_too_many_received_hops_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let sink = sink(
            dir.path(),
            b"v=spf1 ip4:203.0.113.10 -all",
            b"v=DMARC1; p=none",
        );

        let mut data = String::new();
        for index in 0..MAX_RECEIVED_HOPS {
            data.push_str(&format!(
                "Received: from relay{index}.test (192.0.2.1) by hop{index}.test with ESMTP; Thu, 01 Oct 2026 10:00:00 +0000\r\n"
            ));
        }
        data.push_str("From: alice@example.com\r\n\r\nbody\r\n");

        let reply = sink
            .accept(accepted(data.as_bytes()), peer([203, 0, 113, 10]))
            .await
            .expect_err("超过跳数上限必须拒绝");
        assert_eq!(reply.code, 554);
        assert_eq!(reply.enhanced, Some("5.4.6"));
        assert!(queued(dir.path()).is_empty(), "环路报文绝不能入队");
    }

    #[tokio::test]
    async fn a_message_that_already_passed_through_this_host_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let sink = sink(
            dir.path(),
            b"v=spf1 ip4:203.0.113.10 -all",
            b"v=DMARC1; p=none",
        );

        let data = concat!(
            "Received: from relay.test (192.0.2.1) by MX.Mailstack.Test with ESMTP; ",
            "Thu, 01 Oct 2026 10:00:00 +0000\r\n",
            "From: alice@example.com\r\n",
            "\r\n",
            "body\r\n"
        );

        let reply = sink
            .accept(accepted(data.as_bytes()), peer([203, 0, 113, 10]))
            .await
            .expect_err("已经过本机的报文必须拒绝");
        assert_eq!(reply.code, 554);
        assert!(queued(dir.path()).is_empty());
    }

    #[tokio::test]
    async fn a_non_utf8_body_is_refused_rather_than_silently_corrupted() {
        let dir = tempfile::tempdir().unwrap();
        let sink = sink(
            dir.path(),
            b"v=spf1 ip4:203.0.113.10 -all",
            b"v=DMARC1; p=none",
        );

        let mut data = MESSAGE.to_vec();
        data.extend_from_slice(&[0xff, 0xfe, 0x80]);

        let reply = sink
            .accept(accepted(&data), peer([203, 0, 113, 10]))
            .await
            .expect_err("非 UTF-8 报文必须被拒绝");
        assert_eq!(reply.code, 554);
        assert!(queued(dir.path()).is_empty());
    }

    #[test]
    fn the_clock_is_injected_so_dates_are_deterministic() {
        assert_eq!(FixedClock.now_millis() / 1000, 1_790_848_800);
        let _ = Arc::new(SystemClock);
    }
}
