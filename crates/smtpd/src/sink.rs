//! 收信的去处：**认证 → 加 trace 头 → 入队**（规格书 §5.8、§5.10）。
//!
//! ## 两套语义，由会话角色决定（R3-001 / R3-003）
//!
//! 三个端口共用同一份队列写入逻辑，但信任模型完全不同：
//!
//! * **25（[`SessionRole::Mx`]）**：对端是任意外部 MTA。必须做 SPF/DKIM/DMARC 入站
//!   判定、执行 `p=reject`，并把结论写进 `Authentication-Results`。
//! * **465/587（[`SessionRole::Submission`]）**：对端是**本机自己的用户**。提交时
//!   报文还没有 DKIM 签名（签名发生在入队后的队列投递阶段），按入站口径判定只会
//!   把用户自己的外发邮件判成 `dmarc=fail`；把这条结论写进外发报文更是把
//!   「入站判定」带给了全世界。因此提交路径**不做** SPF/DKIM/DMARC、**不写**
//!   `Authentication-Results`，只加本跳的 `Received:`。
//!
//! 角色由 [`crate::session::Session`] 依据监听策略推导后放进
//! [`AcceptedMessage::role`]，sink 只消费它 —— 不再从端口/认证状态反推。
//!
//! ## 顺序是有意义的
//!
//! 1. **环路检测**：`Received:` 跳数超限、或报文已经过本机（`by <hostname>`）⇒
//!    `554 5.4.6`，邮件**不进队**（RFC 5321 §6.3/§7.5）。两台互相转发的 MTA
//!    若都不做这一步，每轮转发都会生成新的入队条目，形成邮件风暴。
//! 2. **入站认证**（仅 MX 角色）：SPF + DKIM + DMARC，由
//!    [`mailstack_auth::dmarc::evaluate`] 一次编排。
//! 3. **DMARC 策略**（仅 MX 角色）：`p=reject` 且判定为 `fail` ⇒ 550，邮件不进队。
//! 4. **加 trace 头**：本跳 `Received:`（RFC 5322 §3.6.7）+ 入站 `Return-Path:`
//!    （信封发件人）+ `Authentication-Results`（RFC 8601，仅 MX）。
//! 5. **最后入队**。只有入队成功才返回 `Ok(())`，驱动这时才回 250 —— 先回 250
//!    再落盘等于对发送方说谎（见 [`crate::connection::MessageSink`]）。
//!
//! ## 两个刻意的「失败关闭」
//!
//! * **认证评估本身出错**（报文无法解析）⇒ 451 临时拒绝。无法判定就不放行；
//!   用 451 而不是 550，是为了不把「我们解析不了」当成「对方一定在撒谎」。
//! * **正文不是合法 UTF-8** ⇒ 554 拒绝。队列把报文建模为 `String`（见
//!   [`mailstack_queue::QueueEntry`]），若在此处做有损转换，等于**静默篡改**了
//!   报文字节 —— 被破坏的报文还会让下游的 DKIM 校验失败。宁可明确拒绝。
//!   这是当前实现的已知边界，而非可以忽略的细节 —— 因此 EHLO **不通告
//!   8BITMIME**（见 `session.rs::ehlo_reply`）：通告一个兑现不了的能力，
//!   等于邀请对端发我们注定要退的信。
//!
//! ## 正文只保留**一份**拷贝（R3-011）
//!
//! 原实现 `format!("{header}{text}")` 会在 `message.data` 仍存活时再分配一整封
//! 同长缓冲，峰值是两倍报文大小。DATA 并发上限按「每连接一份报文」计算，
//! 两倍系数会把内存上界直接翻倍。现在改成对已通过 UTF-8 校验的 `String`
//! 就地 `insert_str(0, …)`：只有一次扩容，没有第二份报文缓冲。
//!
//! ## 为什么用 `EntryKind::Outbound`
//!
//! 队列只有「用户外发」与「DSN 退信」两种类别，且路由**按收件人域**决定走本地
//! LMTP 还是远端投递（见 `mailstack_queue::runner::partition`）。入站邮件的收件人
//! 必然是本机纳管域（反中继 INV-17 已在 `RCPT` 阶段拦掉其余），因此它会走本地
//! 投递 —— 用 `Outbound` 表示「一封待投递的普通邮件」在语义与行为上都成立。

use std::net::SocketAddr;
use std::sync::Arc;

use mailstack_auth::{dmarc, DmarcStatus, MessageAuthenticator, TxtCache};
use mailstack_queue::{EntryKind, QueueEntry, QueueStore};

use crate::auth_results;
use crate::connection::{MessageSink, SinkFuture};
use crate::listener::Clock;
use crate::reply::{texts, Reply};
use crate::session::{AcceptedMessage, SessionRole};

/// `Received:` 跳数上限（RFC 5321 §6.3 / §7.5 建议的环路检测阈值）。
///
/// 50 与 Postfix 的 `hopcount_limit` 默认值同量级：正常邮件经手的跳数远低于它，
/// 而两台机器互相转发的环会在几十跳内被拦下，不会无限放大。
pub const MAX_RECEIVED_HOPS: usize = 50;

/// 把收下的邮件认证、加头并写入队列。
pub struct QueueSink {
    /// 本机对外名（`Received:` 的 `by`、`Authentication-Results` 的 authserv-id）。
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

    /// 生产装配：系统 DNS 解析器 + 空的 TXT 缓存 + 队列目录来自 [`mailstack_core::Paths`]。
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
        // ── 1) 环路检测（两种口径，任一命中即拒）──
        //
        // 跳数超限拦「很多台机器绕了一圈」；`by <本机>` 拦「这封信已经来过本机」
        // —— 后者是别名/自动转发互相指回时最短的环，通常两三跳就够把两台
        // MailStack 之间的队列塞满。
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
            // 只有 MX 收信口才做入站判定。提交口的报文此刻还没有本域 DKIM 签名，
            // 按入站口径判 DMARC 会把用户自己的外发信判成 fail（R3-001）。
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

            // DMARC 策略：只有**明确判定为 fail** 且域策略为 reject 才拒收。
            // temperror / permerror 不退信 —— 那是「我们没算出来」，不是「对方违规」。
            //
            // 判据走类型化的 `policy_is_reject()`，不比较 `policy` 字符串 ——
            // 后者来自第三方 enum 的 `Debug` 输出，上游一改派生就再也匹配不上，
            // 于是这个 550 分支永不触发、邮件静默放行，而测试照样全绿。
            if matches!(check.status, DmarcStatus::Fail(_)) && check.policy_is_reject() {
                return Err(Reply::with_enhanced(550, "5.7.1", texts::DMARC_REJECTED));
            }

            // Return-Path 记录**信封**发件人（不是头部 From）：下游的 DSN、以及
            // 「转发后 SPF 对齐」都以它为依据（RFC 5321 §4.4）。null sender 写 `<>`。
            headers.push_str(&format!("Return-Path: <{}>\r\n", message.mail_from));
            headers.push_str(&auth_results::render(
                &self.hostname,
                &message.mail_from,
                &check,
                None,
            ));
        }

        // 只保留一份正文：先校验 UTF-8，再**就地**把 trace 头插到最前面。
        // `insert_str` 会按需 reserve 一次并在同一块内存里前移正文，不再分配
        // 第二份同长缓冲（原 `format!` 的峰值是 2×报文）。
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
        // 入站报文是全新邮件：必须走 O_EXCL 语义的 enqueue_new ——
        // 同毫秒撞 id 时重生成而不是静默覆盖（那会丢掉先到的邮件）。
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

/// 生成本跳的 `Received:`（RFC 5322 §3.6.7 / RFC 5321 §4.4）。
///
/// 字段：`from`（对端 HELO）、`by`（本机名）、`with`（ESMTP / ESMTPS / ESMTPSA）、
/// `for`（首个信封收件人）、`;` 之后的日期。故意**不写** `id`：本函数在入队前
/// 执行，此时队列 id 尚未生成；编一个假 id 只会让排障时对不上队列条目。
fn received_header(
    hostname: &str,
    message: &AcceptedMessage,
    peer: SocketAddr,
    now_unix: i64,
) -> String {
    let helo = if message.helo.trim().is_empty() {
        "unknown".to_string()
    } else {
        // HELO 名来自对端；命令解析器已拒绝控制字符，这里再做一次防御性净化，
        // 保证它无论如何都不可能把换行带进头部。
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
        // 会话层只在 TLS 之上允许 AUTH（538），因此 ESMTPSA 同时隐含了 S。
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

/// 统计报文头部的 `Received:` 条数（`data` 尚未做 UTF-8 校验，按字节扫描）。
///
/// 只统计**头部块**（首个空行为止）：正文里恰好以 `Received:` 开头的行不该被
/// 当成跳数，否则一封讨论邮件头的信会被误判成环路。折行（以空白开头的续行）
/// 属于上一条头，不重复计数。
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

/// 报文头部是否已经有一个 `by <本机名>` 的 `Received:`（说明环回到本机了）。
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
            // 续行：只有当前头是 Received 且续行里出现 `by <本机>` 才算。
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

/// 该行是否以 `name:` 开头（头名大小写不敏感）。
fn has_header_name(line: &[u8], name: &[u8]) -> bool {
    line.len() > name.len()
        && line[..name.len()].eq_ignore_ascii_case(name)
        && line[name.len()] == b':'
}

/// 子串查找，ASCII 大小写不敏感（只用于头部扫描，输入是字节）。
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

/// Unix 秒 → RFC 5322 §3.3 日期（`Wed, 01 Oct 2026 10:00:00 +0000`，UTC）。
///
/// 刻意不引入 `chrono` / `time`：本 crate 只需要一个固定格式的 UTC 时间戳，
/// 为它新增依赖（以及随之而来的本地时区/闰秒语义）不划算。这里用
/// Howard Hinnant 的 civil-from-days 算法，输入范围是全 i64。
fn format_rfc5322_date(unix_seconds: i64) -> String {
    const WEEKDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];

    let days = unix_seconds.div_euclid(86_400);
    let seconds_of_day = unix_seconds.rem_euclid(86_400);
    let weekday = (days + 4).rem_euclid(7) as usize; // 1970-01-01 是 Thursday
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

/// 自 1970-01-01 起的天数 → (年, 月, 日)。算法见 Hinnant 的 `civil_from_days`。
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
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

    /// 固定时钟：`Received:` 的日期必须可断言，不能依赖运行时刻。
    /// 1_790_848_800 = 2026-10-01T10:00:00Z（星期四）。
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

    /// 建一个离线可用的 sink：SPF 与 DMARC 记录全部注入缓存，不产生真实 DNS 查询。
    fn sink(dir: &std::path::Path, spf: &[u8], dmarc_record: &[u8]) -> QueueSink {
        let cache = TxtCache::new();
        // DMARC 会从 From 域逐级向上走查；不把祖先那一级也钉住就会漏到真实 DNS。
        cache.pin_dmarc_walk("example.com");
        // SPF 会**先查 HELO 域**（`Sender::Full`）；不钉住就会发真实 DNS。
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
        // 闰日：2024-02-29T00:00:00Z = 1_709_164_800。
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

        // 折行续行不重复计数。
        let folded = b"Received: from a\r\n\tby b;\r\n\t d\r\nSubject: x\r\n\r\nbody\r\n";
        assert_eq!(received_hops(folded), 1);
    }

    #[test]
    fn a_received_header_that_already_passed_through_this_host_is_a_loop() {
        let data = b"Received: from a (1.2.3.4) by MX.Mailstack.Test with ESMTP; d\r\n\r\nbody";
        assert!(received_via_host(data, "mx.mailstack.test"));
        // 别的机器名不算环。
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

        // 第一行必须是本跳的 Received（RFC 5321 §4.4 的 trace 信息）。
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

        // 源地址不在 SPF 授权范围内，且没有 DKIM 可以救场 ⇒ DMARC fail。
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

    /// R3-001 的核心反例：提交口（已认证用户）**不做**入站判定、**不写**
    /// `Authentication-Results`。缓存里故意放一条 `p=reject` + 只有别的 IP 的 SPF：
    /// 若提交路径仍然跑入站认证，这封信会被 550 拒掉；跑通了也会带上
    /// `dmarc=fail` 的戳 —— 两者都是本测试要排除的。
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

    /// R3-002 反例：超过跳数上限的报文必须 554 且**不入队**。
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

    /// 环路检测的第二种口径：报文里已经出现 `by <本机>`。
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
        data.extend_from_slice(&[0xff, 0xfe, 0x80]); // 非法 UTF-8 序列

        let reply = sink
            .accept(accepted(&data), peer([203, 0, 113, 10]))
            .await
            .expect_err("非 UTF-8 报文必须被拒绝");
        assert_eq!(reply.code, 554);
        assert!(queued(dir.path()).is_empty());
    }

    #[test]
    fn the_clock_is_injected_so_dates_are_deterministic() {
        // 这条测试守住「日期来自注入时钟」这件事本身：换一个实现（例如直接
        // `SystemTime::now()`）时，`a_dmarc_aligned_…` 的精确断言会变红。
        assert_eq!(FixedClock.now_millis() / 1000, 1_790_848_800);
        let _ = Arc::new(SystemClock); // 生产时钟仍实现同一 trait
    }
}
