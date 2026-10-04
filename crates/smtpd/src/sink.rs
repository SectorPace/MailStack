//! 收信的去处：**认证 → 加头 → 入队**（规格书 §5.8、§5.10）。
//!
//! ## 顺序是有意义的
//!
//! 1. **先认证**（SPF + DKIM + DMARC，由 [`mailstack_auth::dmarc::evaluate`] 一次编排）。
//! 2. **再判定 DMARC 策略**：`p=reject` 且判定为 `fail` ⇒ 550 拒绝，邮件**不进队**。
//! 3. **加 `Authentication-Results` 头**（RFC 8601），让下游收件人不必重算。
//! 4. **最后入队**。只有入队成功才返回 `Ok(())`，驱动这时才回 250 —— 先回 250
//!    再落盘等于对发送方说谎（见 [`crate::connection::MessageSink`]）。
//!
//! ## 两个刻意的「失败关闭」
//!
//! * **认证评估本身出错**（报文无法解析）⇒ 451 临时拒绝。无法判定就不放行；
//!   用 451 而不是 550，是为了不把「我们解析不了」当成「对方一定在撒谎」。
//! * **正文不是合法 UTF-8** ⇒ 554 拒绝。队列把报文建模为 `String`（见
//!   [`mailstack_queue::QueueEntry`]），若在此处做有损转换，等于**静默篡改**了
//!   报文字节 —— 被破坏的报文还会让下游的 DKIM 校验失败。宁可明确拒绝。
//!   这是当前实现的已知边界，而非可以忽略的细节。
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
use crate::session::AcceptedMessage;

/// 把收下的邮件认证、加头并写入队列。
pub struct QueueSink {
    /// 本机对外名（`Authentication-Results` 的 authserv-id）。
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

        let header = auth_results::render(&self.hostname, &message.mail_from, &check, None);
        let text = String::from_utf8(message.data)
            .map_err(|_| Reply::with_enhanced(554, "5.6.0", texts::MESSAGE_NOT_UTF8))?;
        let data = format!("{header}{text}");

        let now_unix = self.clock.now_millis() / 1000;
        let entry = QueueEntry::new(
            EntryKind::Outbound,
            message.mail_from,
            message.recipients,
            data,
            now_unix,
        )
        .map_err(|_| Reply::with_enhanced(451, "4.3.0", texts::QUEUE_WRITE_FAILED))?;
        self.store
            .enqueue(&entry)
            .map_err(|_| Reply::with_enhanced(451, "4.3.0", texts::QUEUE_WRITE_FAILED))?;

        Ok(())
    }
}

impl MessageSink for QueueSink {
    fn accept<'a>(&'a self, message: AcceptedMessage, peer: SocketAddr) -> SinkFuture<'a> {
        Box::pin(async move { self.handle(message, peer).await })
    }
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

    fn peer(ip: [u8; 4]) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])), 40000)
    }

    fn accepted(data: &[u8]) -> AcceptedMessage {
        AcceptedMessage {
            mail_from: "alice@example.com".to_string(),
            recipients: vec!["bob@example.net".to_string()],
            data: data.to_vec(),
            helo: "mail.example.com".to_string(),
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
            Arc::new(SystemClock),
        )
    }

    fn queued(dir: &std::path::Path) -> Vec<QueueEntry> {
        QueueStore::new(dir).load_all().expect("读取队列")
    }

    #[tokio::test]
    async fn a_dmarc_aligned_message_is_enqueued_with_an_authentication_results_header() {
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
            entry
                .data
                .starts_with("Authentication-Results: mx.mailstack.test;"),
            "认证结论必须前置在报文最前面：{:?}",
            &entry.data[..entry.data.len().min(120)]
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
}
