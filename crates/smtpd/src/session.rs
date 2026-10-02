//! 会话状态机（RFC 5321 §4.1.4）。
//!
//! 本模块**不做任何 I/O**：它只接收「一行命令」或「一封正文」，返回「该发什么应答」。
//! 这样做的直接收益是事务规则可以被穷举测试 —— 而事务规则正是反中继
//! （INV-17）与「未授权的中继尝试必须被拒绝」这两条的落点。
//!
//! ## 三处刻意做成「不商量」的判定
//!
//! 1. **序列**：`MAIL` 之前必须有 `EHLO/HELO`，`RCPT` 之前必须有 `MAIL`，
//!    `DATA` 之前必须有 `RCPT`。缺少前置即 503 —— 不替客户端补全。
//! 2. **反中继**：不在本机纳管域内、且会话未认证的收件人一律拒绝，且**复用**
//!    `mailstack_smtp::RelayPolicy`（出站侧同一份实现），避免两处语义漂移。
//!    域名表为空时拒绝而非放行（历史缺陷不得复现）。
//! 3. **VRFY**：恒为 502。它唯一的现实用途是**目录枚举**，本机不需要。
//!
//! ## SASL 认证为什么也留在这里（而不是丢给驱动）
//!
//! `AUTH` 的**前置条件**（是否通告、是否已在 TLS 上、是否 ESMTP、是否已有事务、
//! 是否已认证过）与「认证成功后会话有哪些权限」都属于会话状态，必须和别的命令
//! 走同一条判定链，否则「认证了但事务序列错乱」这类问题会散落在驱动里。
//! 状态机自己不调认证后端：它产出 [`Action::AuthVerify`]，由驱动去调，再用
//! [`Session::complete_auth`] 把结果交回来 —— 这样口令永远不进入会话状态。

use mailstack_smtp::{RelayDecision, RelayPolicy};

use crate::command::{Command, MailParams};
use crate::data::BareNewlinePolicy;
use crate::reply::{texts, Reply};
use crate::sasl::{is_valid_base64, AuthOutcome};

/// 会话配置。
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// 通告给对端的本机名（EHLO 的应答里）。
    pub hostname: String,
    /// 单封报文的大小上限（字节）。
    pub max_message_size: usize,
    /// 单封报文的收件人数量上限。
    pub max_recipients: usize,
    /// DATA 阶段对裸 LF 的策略。
    pub bare_newline_policy: BareNewlinePolicy,
    /// `<postmaster>` 要解析成的地址；`None` 表示本机没有可用的 postmaster
    /// （此时拒绝，而不是猜一个）。
    pub postmaster: Option<String>,
    /// 是否提供 STARTTLS。
    pub offer_starttls: bool,
    /// 是否提供 SASL 提交认证。
    pub offer_auth: bool,
    /// 会话是否**已经**在 TLS 之上（隐式 TLS，如 465 端口）。
    pub tls_active: bool,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            hostname: "localhost".to_string(),
            // 25 MiB：与常见 MTA 默认值同量级；真正的上限应由 settings.json 提供。
            max_message_size: 25 * 1024 * 1024,
            max_recipients: 100,
            // 默认最严格：正文里出现裸 LF 即拒收（见 `data` 模块的走私说明）。
            bare_newline_policy: BareNewlinePolicy::Reject,
            postmaster: None,
            offer_starttls: false,
            offer_auth: false,
            tls_active: false,
        }
    }
}

/// 状态机给出的动作。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// 回一条应答，继续读命令。
    Reply(Reply),
    /// 回一条应答并进入 DATA；驱动收完正文后调用 [`Session::finish_data`]。
    EnterData(Reply),
    /// 回 220 并**升级到 TLS**：驱动写完应答后必须完成握手，
    /// 且**丢弃**明文读缓冲（否则升级前注入的明文会被当作 TLS 之后的命令）。
    StartTls(Reply),
    /// 回一条应答并**关闭**连接（不再解析后续字节）。
    Close(Reply),
    /// 发起 SASL 挑战：驱动写出应答后，读取**下一行原始字节**交给
    /// [`Session::continue_auth`]（**不经过命令解析器** —— 那一行是 base64，
    /// 不是命令）。
    AuthChallenge(Reply),
    /// 需要校验凭据：驱动调用认证后端，拿到 [`AuthOutcome`] 后交给
    /// [`Session::complete_auth`]。状态机本身**不做 I/O**。
    AuthVerify {
        mechanism: String,
        /// 客户端给的 base64 应答（已校验字符集）。
        response: String,
    },
}

/// 一封被接受的邮件（交给投递方）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedMessage {
    /// 信封发件人；空串表示 null sender。
    pub mail_from: String,
    pub recipients: Vec<String>,
    /// 原始正文（RFC 5322，CRLF 行结束，已去点）。
    pub data: Vec<u8>,
    /// 对端在 HELO/EHLO 里声明的名字（SPF 的 `%{h}` 与日志都需要）。
    pub helo: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// 已连接，尚未 EHLO/HELO。
    Connected,
    /// 已 EHLO/HELO，可以开始事务。
    Greeted,
    /// 已 MAIL FROM，等待 RCPT。
    Mail,
}

/// 一次会话。
pub struct Session {
    config: SessionConfig,
    relay: RelayPolicy,
    phase: Phase,
    helo: Option<String>,
    esmtp: bool,
    mail_from: Option<String>,
    recipients: Vec<String>,
    authenticated: bool,
    /// 已认证身份（仅用于日志与 `AUTH=` 参数；口令永不进入会话状态）。
    auth_user: Option<String>,
    /// 正在进行的 SASL 交换所等待的机制；`None` 表示没有交换在进行。
    pending_auth: Option<String>,
    tls_active: bool,
}

impl Session {
    pub fn new(config: SessionConfig, relay: RelayPolicy) -> Self {
        let tls_active = config.tls_active;
        Self {
            config,
            relay,
            phase: Phase::Connected,
            helo: None,
            esmtp: false,
            mail_from: None,
            recipients: Vec::new(),
            authenticated: false,
            auth_user: None,
            pending_auth: None,
            tls_active,
        }
    }

    pub fn config(&self) -> &SessionConfig {
        &self.config
    }

    pub fn is_authenticated(&self) -> bool {
        self.authenticated
    }

    /// 已认证身份；未认证时为 `None`。
    pub fn auth_user(&self) -> Option<&str> {
        self.auth_user.as_deref()
    }

    /// 驱动据此判断「当前这一行是 SASL 应答，不能当命令解析」。
    pub fn awaiting_auth_response(&self) -> bool {
        self.pending_auth.is_some()
    }

    pub fn is_tls_active(&self) -> bool {
        self.tls_active
    }

    pub fn helo(&self) -> Option<&str> {
        self.helo.as_deref()
    }

    /// 连接建立后的 220 问候。
    pub fn greeting(&self) -> Reply {
        Reply::new(220, format!("{} {}", self.config.hostname, texts::GREETING))
    }

    /// 当前 `MAIL FROM`（供驱动在 DATA 未结束时判断上下文）。
    pub fn mail_from(&self) -> Option<&str> {
        self.mail_from.as_deref()
    }

    pub fn recipients(&self) -> &[String] {
        &self.recipients
    }

    /// 处理一条命令。
    pub fn handle(&mut self, command: Command) -> Action {
        match command {
            Command::Ehlo(name) => self.hello(name, true),
            Command::Helo(name) => self.hello(name, false),
            Command::Mail { from, params } => self.mail(from, params),
            Command::Rcpt { to } => self.rcpt(to),
            Command::Data => self.data(),
            Command::Rset => {
                self.reset_transaction();
                Action::Reply(Reply::new(250, texts::RSET_OK))
            }
            Command::Noop => Action::Reply(Reply::new(250, texts::NOOP_OK)),
            Command::Quit => {
                self.reset_transaction();
                Action::Close(Reply::with_enhanced(221, "2.0.0", texts::BYE))
            }
            // 恒为 502：不对未实现的命令做任何「尽力而为」的解析。
            Command::Vrfy(_) => {
                Action::Reply(Reply::with_enhanced(502, "5.5.1", texts::VRFY_DISABLED))
            }
            Command::Help(_) => Action::Reply(Reply::new(214, texts::HELP)),
            Command::StartTls => self.start_tls(),
            Command::Auth { mechanism, initial } => self.auth(mechanism, initial),
            // 动词不回显给对端（否则是一个反射面）；只告诉它「不认识」。
            Command::Unknown(_) => {
                Action::Reply(Reply::with_enhanced(500, "5.5.1", texts::UNKNOWN_COMMAND))
            }
        }
    }

    fn hello(&mut self, name: String, esmtp: bool) -> Action {
        // EHLO/HELO 是事务边界：重发即重置事务（RFC 5321 §4.1.4）。
        self.reset_transaction();
        self.helo = Some(name);
        self.esmtp = esmtp;
        self.phase = Phase::Greeted;

        if esmtp {
            Action::Reply(self.ehlo_reply())
        } else {
            Action::Reply(Reply::new(
                250,
                format!("{} {}", self.config.hostname, texts::EHLO_OK),
            ))
        }
    }

    fn ehlo_reply(&self) -> Reply {
        let mut lines = vec![format!("{} {}", self.config.hostname, texts::EHLO_OK)];
        lines.push(format!("SIZE {}", self.config.max_message_size));
        lines.push("8BITMIME".to_string());
        lines.push("ENHANCEDSTATUSCODES".to_string());
        if self.config.offer_starttls && !self.tls_active {
            lines.push("STARTTLS".to_string());
        }
        if self.config.offer_auth && self.tls_active {
            lines.push("AUTH PLAIN".to_string());
        }
        lines.push("HELP".to_string());
        Reply::multiline(250, lines)
    }

    fn mail(&mut self, from: String, params: MailParams) -> Action {
        if self.phase == Phase::Connected {
            return Action::Reply(Reply::with_enhanced(503, "5.5.1", texts::SEQUENCE));
        }
        if self.mail_from.is_some() {
            return Action::Reply(Reply::with_enhanced(503, "5.5.1", texts::NESTED_MAIL));
        }
        // 客户端先声明了 SIZE 且超限：**在收正文之前**就拒绝，避免白白接收几十 MB。
        if let Some(size) = params.size {
            if size > self.config.max_message_size as u64 {
                return Action::Reply(Reply::with_enhanced(552, "5.3.4", texts::MESSAGE_TOO_LARGE));
            }
        }
        self.mail_from = Some(from);
        self.recipients.clear();
        self.phase = Phase::Mail;
        Action::Reply(Reply::with_enhanced(250, "2.1.0", texts::MAIL_OK))
    }

    fn rcpt(&mut self, to: String) -> Action {
        if self.phase != Phase::Mail {
            return Action::Reply(Reply::with_enhanced(503, "5.5.1", texts::SEQUENCE));
        }

        // `<postmaster>` 没有域，按 RFC 5321 §4.1.1.3 必须接受 —— 但补哪个域是
        // **本机策略**，不是猜测。没有配置就明确拒绝。
        let to = if to == "postmaster" {
            match &self.config.postmaster {
                Some(address) => address.clone(),
                None => {
                    return Action::Reply(Reply::with_enhanced(
                        550,
                        "5.1.1",
                        "postmaster address is not configured on this host",
                    ))
                }
            }
        } else {
            to
        };

        if self.recipients.len() >= self.config.max_recipients {
            return Action::Reply(Reply::with_enhanced(
                452,
                "4.5.3",
                texts::TOO_MANY_RECIPIENTS,
            ));
        }

        let domain = to.rsplit_once('@').map_or("", |(_, domain)| domain);
        match self.relay.evaluate(domain, self.authenticated) {
            RelayDecision::DeliverLocal | RelayDecision::RelayAuthenticated => {}
            RelayDecision::Reject { code, message } => {
                // 拒绝文案来自策略（单一来源），并带上被拒的收件人便于排障。
                // 注：地址是主人可控输入，`Reply` 会净化掉其中的 CR/LF。
                return Action::Reply(Reply::with_enhanced(code, "5.7.1", message));
            }
        }

        if self.recipients.iter().any(|existing| existing == &to) {
            // 重复收件人不报错（客户端有权这么做），但只记一次 ——
            // 否则一次投递会被重复计费，也会让「收件人数量上限」被轻易撑满。
            return Action::Reply(Reply::with_enhanced(250, "2.1.5", texts::RCPT_OK));
        }

        self.recipients.push(to);
        Action::Reply(Reply::with_enhanced(250, "2.1.5", texts::RCPT_OK))
    }

    fn data(&mut self) -> Action {
        if self.phase != Phase::Mail || self.recipients.is_empty() {
            return Action::Reply(Reply::with_enhanced(503, "5.5.1", texts::NO_RECIPIENTS));
        }
        Action::EnterData(Reply::with_enhanced(354, "2.0.0", texts::DATA_START))
    }

    /// DATA 收完后的结算。返回应答与（成功时）被接受的邮件。
    ///
    /// 无论接受与否都会重置事务 —— 事务已经结束，留在半开会话里只会让
    /// 下一条命令的判定建立在错误的前提上。
    pub fn finish_data(&mut self, data: Vec<u8>) -> (Reply, Option<AcceptedMessage>) {
        let (mail_from, recipients, helo) = match (
            self.mail_from.take(),
            std::mem::take(&mut self.recipients),
            self.helo.clone(),
        ) {
            (Some(mail_from), recipients, helo) => (mail_from, recipients, helo),
            (None, _, _) => {
                self.phase = Phase::Greeted;
                return (Reply::with_enhanced(503, "5.5.1", texts::SEQUENCE), None);
            }
        };
        self.phase = Phase::Greeted;

        if data.len() > self.config.max_message_size {
            // 声明了 SIZE 却被绕过、或根本没声明：仍然要拦住。
            return (
                Reply::with_enhanced(552, "5.3.4", texts::MESSAGE_TOO_LARGE),
                None,
            );
        }

        (
            Reply::with_enhanced(250, "2.0.0", texts::DATA_OK),
            Some(AcceptedMessage {
                mail_from,
                recipients,
                data,
                helo: helo.unwrap_or_default(),
            }),
        )
    }

    fn start_tls(&mut self) -> Action {
        if self.tls_active {
            return Action::Reply(Reply::with_enhanced(503, "5.5.1", texts::ALREADY_TLS));
        }
        if !self.config.offer_starttls {
            return Action::Reply(Reply::with_enhanced(
                502,
                "5.5.1",
                texts::STARTTLS_UNAVAILABLE,
            ));
        }
        if self.mail_from.is_some() {
            // 事务进行中不允许升级：TLS 之后必须重新 EHLO，事务边界就乱了。
            return Action::Reply(Reply::with_enhanced(503, "5.5.1", texts::SEQUENCE));
        }
        // 真正的 TLS 升级由驱动完成；这里只负责「允许」并把会话打回未问候状态
        // （RFC 3207 §4.2：升级后客户端必须重新发 EHLO）。
        //
        // 注意这里**不**置 `tls_active`：握手尚未完成。只有驱动在握手成功之后
        // 调用 [`Session::activate_tls`] 才算「已加密」—— 提前置位会让会话在
        // 握手失败时错误地认为自己已在 TLS 上。
        self.reset_transaction();
        self.helo = None;
        self.phase = Phase::Connected;
        self.esmtp = false;
        Action::StartTls(Reply::new(220, "Ready to start TLS"))
    }

    /// TLS 握手成功后由驱动调用：把会话标记为已加密。
    pub fn activate_tls(&mut self) {
        self.tls_active = true;
    }

    /// `AUTH` 的前置判定与首次应答（RFC 4954 §4）。
    ///
    /// 只支持 `PLAIN`：它是唯一被广泛支持的「一次把凭据给全」的机制，其余机制
    /// （LOGIN 的多轮、CRAM/DIGEST 的字典攻击面）本机不需要。**不认识就回 504**，
    /// 而不是含糊的 502 —— 客户端要靠状态码决定换哪个机制。
    fn auth(&mut self, mechanism: String, initial: Option<String>) -> Action {
        if !self.config.offer_auth {
            return Action::Reply(Reply::with_enhanced(502, "5.5.1", texts::AUTH_UNAVAILABLE));
        }
        if !self.tls_active {
            // 明文口令一律不发：这是「凭证明文传输」的最低防线。
            return Action::Reply(Reply::with_enhanced(
                538,
                "5.7.11",
                texts::AUTH_REQUIRED_FIRST,
            ));
        }
        // AUTH 是 ESMTP 扩展：HELO（非 EHLO）之后不提供；EHLO 本身是事务边界，
        // 因此事务进行中（mail_from 已置位）也不允许。
        if !self.esmtp || self.phase == Phase::Connected || self.mail_from.is_some() {
            return Action::Reply(Reply::with_enhanced(503, "5.5.1", texts::SEQUENCE));
        }
        // RFC 4954 §4：认证成功后不得再次认证。
        if self.authenticated {
            return Action::Reply(Reply::with_enhanced(503, "5.5.1", texts::AUTH_ALREADY));
        }
        if self.pending_auth.is_some() {
            // 上一次交换还没结束；不叠加第二次，否则「哪条应答属于谁」就说不清了。
            return Action::Reply(Reply::with_enhanced(503, "5.5.1", texts::SEQUENCE));
        }
        if !mechanism.eq_ignore_ascii_case("PLAIN") {
            return Action::Reply(Reply::with_enhanced(
                504,
                "5.5.4",
                texts::AUTH_MECHANISM_UNKNOWN,
            ));
        }

        let mechanism = mechanism.to_ascii_uppercase();
        match initial {
            Some(response) => Self::request_verification(mechanism, response),
            None => {
                // 没有初始应答：发一个空挑战（PLAIN 的挑战就是空串），等客户端把
                // base64 单独送一行来。
                self.pending_auth = Some(mechanism);
                Action::AuthChallenge(Reply::new(334, ""))
            }
        }
    }

    /// 处理 `334` 挑战之后客户端送来的一行（**原始字节，未经命令解析器**）。
    pub fn continue_auth(&mut self, line: &[u8]) -> Action {
        let Some(mechanism) = self.pending_auth.clone() else {
            // 没有交换在进行却收到了应答：双方状态已经分叉。
            return Action::Reply(Reply::with_enhanced(503, "5.5.1", texts::SEQUENCE));
        };
        // RFC 4954 §4：单独一行 `*` 表示客户端放弃本次交换。
        if line == b"*" {
            self.pending_auth = None;
            return Action::Reply(Reply::with_enhanced(501, "5.5.2", texts::AUTH_CANCELLED));
        }
        let Ok(response) = std::str::from_utf8(line) else {
            self.pending_auth = None;
            return Action::Reply(Reply::with_enhanced(501, "5.5.2", texts::AUTH_BAD_BASE64));
        };

        self.pending_auth = None;
        Self::request_verification(mechanism, response.to_string())
    }

    /// 把（已校验字符集的）应答交回驱动去调认证后端。
    fn request_verification(mechanism: String, response: String) -> Action {
        if !is_valid_base64(&response) {
            // 非 base64 一律不发往 auth socket：那里是制表符分隔协议，
            // 一个 TAB 就能凭空多出一个字段（见 `sasl` 模块说明）。
            return Action::Reply(Reply::with_enhanced(501, "5.5.2", texts::AUTH_BAD_BASE64));
        }
        Action::AuthVerify {
            mechanism,
            response,
        }
    }

    /// 认证后端给出结果后由驱动调用：更新状态并给出应答。
    ///
    /// 535 与 454 严格区分：凭据错与「后端不可达」是两回事，混为一谈会让客户端
    /// 在 Dovecot 抖动时去改密码。失败文案不区分「用户不存在」与「口令错」，
    /// 避免把认证端点变成目录枚举工具。
    pub fn complete_auth(&mut self, outcome: AuthOutcome) -> Reply {
        self.pending_auth = None;
        match outcome {
            AuthOutcome::Success { user } => {
                self.authenticated = true;
                self.auth_user = Some(user);
                Reply::with_enhanced(235, "2.7.0", texts::AUTH_OK)
            }
            AuthOutcome::InvalidCredentials => {
                Reply::with_enhanced(535, "5.7.8", texts::AUTH_FAILED)
            }
            AuthOutcome::TemporaryFailure(_) => {
                Reply::with_enhanced(454, "4.7.0", texts::AUTH_TEMPORARY_FAILURE)
            }
        }
    }

    fn reset_transaction(&mut self) {
        self.mail_from = None;
        self.recipients.clear();
        if self.phase == Phase::Mail {
            self.phase = Phase::Greeted;
        }
    }
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("phase", &self.phase)
            .field("helo", &self.helo)
            .field("has_mail_from", &self.mail_from.is_some())
            .field("recipients", &self.recipients.len())
            .field("authenticated", &self.authenticated)
            .field("tls_active", &self.tls_active)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(domains: &[&str]) -> Session {
        session_with(
            domains,
            SessionConfig {
                hostname: "mail.example.org".to_string(),
                postmaster: Some("postmaster@example.org".to_string()),
                ..SessionConfig::default()
            },
        )
    }

    fn session_with(domains: &[&str], config: SessionConfig) -> Session {
        Session::new(config, RelayPolicy::new(domains.iter().copied()))
    }

    /// 走一遍 `EHLO` → `MAIL` → `RCPT`，返回会话。
    fn ready(session: &mut Session, from: &str, to: &str) {
        let _ = session.handle(Command::Ehlo("client.test".into()));
        let _ = session.handle(Command::Mail {
            from: from.into(),
            params: MailParams::default(),
        });
        let action = session.handle(Command::Rcpt { to: to.into() });
        assert!(
            matches!(action, Action::Reply(ref reply) if reply.is_positive_completion()),
            "RCPT 应被接受，实际 {action:?}"
        );
    }

    #[test]
    fn greeting_is_220_and_ehlo_advertises_the_capabilities_we_really_have() {
        let session = session(&["example.org"]);
        assert_eq!(session.greeting().code, 220);

        let mut session = session;
        let Action::Reply(reply) = session.handle(Command::Ehlo("c.test".into())) else {
            panic!("EHLO 应回应答");
        };
        assert_eq!(reply.code, 250);
        let rendered = reply.render();
        assert!(
            rendered.contains("SIZE "),
            "必须通告 SIZE，否则客户端不会先报大小"
        );
        assert!(rendered.contains("8BITMIME"));
        // 没配置 TLS / AUTH 时**不得**通告 —— 通告了却做不到会误导客户端。
        assert!(!rendered.contains("STARTTLS"));
        assert!(!rendered.contains("AUTH"));
    }

    #[test]
    fn capabilities_only_appear_when_actually_available() {
        let mut session = session_with(
            &["example.org"],
            SessionConfig {
                offer_starttls: true,
                offer_auth: true,
                tls_active: true,
                ..SessionConfig::default()
            },
        );
        let Action::Reply(reply) = session.handle(Command::Ehlo("c.test".into())) else {
            panic!("EHLO 应回应答");
        };
        let rendered = reply.render();
        assert!(rendered.contains("AUTH PLAIN"), "TLS 已建立时才通告 AUTH");
        assert!(
            !rendered.contains("STARTTLS"),
            "已在 TLS 上就不再通告 STARTTLS"
        );
    }

    #[test]
    fn commands_before_helo_are_out_of_sequence() {
        let mut session = session(&["example.org"]);
        for command in [
            Command::Mail {
                from: "a@b.test".into(),
                params: MailParams::default(),
            },
            Command::Rcpt {
                to: "x@example.org".into(),
            },
            Command::Data,
        ] {
            match session.handle(command.clone()) {
                Action::Reply(reply) => assert_eq!(reply.code, 503, "{command:?} 应判序列错误"),
                other => panic!("{command:?} 应只回应答，实际 {other:?}"),
            }
        }
    }

    #[test]
    fn rcpt_without_mail_and_data_without_rcpt_are_rejected() {
        let mut session = session(&["example.org"]);
        let _ = session.handle(Command::Ehlo("c.test".into()));

        let Action::Reply(reply) = session.handle(Command::Rcpt {
            to: "x@example.org".into(),
        }) else {
            panic!("应回应答");
        };
        assert_eq!(reply.code, 503);

        let _ = session.handle(Command::Mail {
            from: "a@b.test".into(),
            params: MailParams::default(),
        });
        let Action::Reply(reply) = session.handle(Command::Data) else {
            panic!("应回应答");
        };
        assert_eq!(reply.code, 503, "没有收件人就 DATA 必须拒绝");
    }

    #[test]
    fn a_second_mail_without_rset_is_rejected() {
        let mut session = session(&["example.org"]);
        let _ = session.handle(Command::Ehlo("c.test".into()));
        let _ = session.handle(Command::Mail {
            from: "a@b.test".into(),
            params: MailParams::default(),
        });
        let Action::Reply(reply) = session.handle(Command::Mail {
            from: "c@d.test".into(),
            params: MailParams::default(),
        }) else {
            panic!("应回应答");
        };
        assert_eq!(reply.code, 503);
    }

    #[test]
    fn unauthenticated_foreign_recipient_is_rejected_with_the_policy_text() {
        // INV-17 的服务端落点：开放中继防护。
        let mut session = session(&["example.org"]);
        let _ = session.handle(Command::Ehlo("c.test".into()));
        let _ = session.handle(Command::Mail {
            from: "attacker@evil.test".into(),
            params: MailParams::default(),
        });
        let Action::Reply(reply) = session.handle(Command::Rcpt {
            to: "victim@gmail.com".into(),
        }) else {
            panic!("应回应答");
        };
        assert_eq!(reply.code, 554);
        assert!(reply.first_line().contains("Relaying denied"));
        assert!(session.recipients().is_empty(), "被拒的收件人不得进入事务");
    }

    #[test]
    fn an_empty_domain_table_rejects_rather_than_relaying() {
        // 历史缺陷不得复现：域名表为空时旧实现整体跳过检查。
        let mut session = session(&[]);
        let _ = session.handle(Command::Ehlo("c.test".into()));
        let _ = session.handle(Command::Mail {
            from: "attacker@evil.test".into(),
            params: MailParams::default(),
        });
        let Action::Reply(reply) = session.handle(Command::Rcpt {
            to: "victim@gmail.com".into(),
        }) else {
            panic!("应回应答");
        };
        assert_eq!(reply.code, 554);
        assert!(reply.first_line().contains("no managed domains"));
    }

    #[test]
    fn local_recipients_are_accepted_and_deduplicated() {
        let mut session = session(&["example.org"]);
        ready(&mut session, "a@b.test", "alice@example.org");
        let _ = session.handle(Command::Rcpt {
            to: "alice@example.org".into(),
        });
        assert_eq!(session.recipients().len(), 1, "重复收件人只记一次");
    }

    #[test]
    fn too_many_recipients_are_refused() {
        let mut session = session_with(
            &["example.org"],
            SessionConfig {
                max_recipients: 2,
                ..SessionConfig::default()
            },
        );
        let _ = session.handle(Command::Ehlo("c.test".into()));
        let _ = session.handle(Command::Mail {
            from: "a@b.test".into(),
            params: MailParams::default(),
        });
        for index in 0..2 {
            let action = session.handle(Command::Rcpt {
                to: format!("u{index}@example.org"),
            });
            assert!(matches!(action, Action::Reply(ref r) if r.is_positive_completion()));
        }
        let Action::Reply(reply) = session.handle(Command::Rcpt {
            to: "u3@example.org".into(),
        }) else {
            panic!("应回应答");
        };
        assert_eq!(reply.code, 452);
    }

    #[test]
    fn a_declared_oversized_message_is_refused_before_data_starts() {
        // 先拒绝，避免白白接收几十 MB。
        let mut session = session_with(
            &["example.org"],
            SessionConfig {
                max_message_size: 1024,
                ..SessionConfig::default()
            },
        );
        let _ = session.handle(Command::Ehlo("c.test".into()));
        let Action::Reply(reply) = session.handle(Command::Mail {
            from: "a@b.test".into(),
            params: MailParams {
                size: Some(4096),
                ..MailParams::default()
            },
        }) else {
            panic!("应回应答");
        };
        assert_eq!(reply.code, 552);
    }

    #[test]
    fn an_undeclared_oversized_message_is_still_refused_after_data() {
        // SIZE 只是**声明**；不给 SIZE 也不能绕过上限。
        let mut session = session_with(
            &["example.org"],
            SessionConfig {
                max_message_size: 16,
                ..SessionConfig::default()
            },
        );
        ready(&mut session, "a@b.test", "alice@example.org");
        let (reply, accepted) = session.finish_data(vec![b'x'; 64]);
        assert_eq!(reply.code, 552);
        assert!(accepted.is_none());
    }

    #[test]
    fn a_complete_transaction_yields_the_accepted_message_and_resets() {
        let mut session = session(&["example.org"]);
        ready(&mut session, "a@b.test", "alice@example.org");
        let Action::EnterData(reply) = session.handle(Command::Data) else {
            panic!("DATA 应进入正文收集");
        };
        assert_eq!(reply.code, 354);

        let (reply, accepted) = session.finish_data(b"Subject: t\r\n\r\nbody\r\n".to_vec());
        assert_eq!(reply.code, 250);
        let accepted = accepted.expect("应产出被接受的邮件");
        assert_eq!(accepted.mail_from, "a@b.test");
        assert_eq!(accepted.recipients, vec!["alice@example.org".to_string()]);
        assert_eq!(accepted.helo, "client.test");

        // 事务已重置：可以立刻开下一个，但不能再 DATA。
        assert!(session.mail_from().is_none());
        assert!(session.recipients().is_empty());
        let Action::Reply(reply) = session.handle(Command::Data) else {
            panic!("应回应答");
        };
        assert_eq!(reply.code, 503);
    }

    #[test]
    fn null_sender_is_preserved_end_to_end() {
        let mut session = session(&["example.org"]);
        ready(&mut session, "", "alice@example.org");
        let (_, accepted) = session.finish_data(b"bounce\r\n".to_vec());
        let accepted = accepted.unwrap();
        assert_eq!(accepted.mail_from, "", "null sender 必须原样保留");
    }

    #[test]
    fn rset_clears_the_transaction_without_dropping_the_greeting() {
        let mut session = session(&["example.org"]);
        ready(&mut session, "a@b.test", "alice@example.org");
        let _ = session.handle(Command::Rset);
        assert!(session.mail_from().is_none());
        assert!(session.recipients().is_empty());
        // 仍在 Greeted：MAIL 应被接受，而不是要求重新 EHLO。
        let action = session.handle(Command::Mail {
            from: "c@d.test".into(),
            params: MailParams::default(),
        });
        assert!(matches!(action, Action::Reply(ref r) if r.code == 250));
    }

    #[test]
    fn vrfy_is_always_refused() {
        // 502 且不区分地址是否存在 —— 否则就是一个目录枚举接口。
        let mut session = session(&["example.org"]);
        for target in ["alice@example.org", "nobody@example.org", "postmaster"] {
            let Action::Reply(reply) = session.handle(Command::Vrfy(target.into())) else {
                panic!("应回应答");
            };
            assert_eq!(reply.code, 502, "{target} 的 VRFY 必须同样被拒");
        }
    }

    #[test]
    fn postmaster_is_resolved_to_the_configured_address() {
        let mut session = session(&["example.org"]);
        let _ = session.handle(Command::Ehlo("c.test".into()));
        let _ = session.handle(Command::Mail {
            from: "a@b.test".into(),
            params: MailParams::default(),
        });
        let action = session.handle(Command::Rcpt {
            to: "postmaster".into(),
        });
        assert!(matches!(action, Action::Reply(ref r) if r.code == 250));
        assert_eq!(
            session.recipients(),
            &["postmaster@example.org".to_string()]
        );
    }

    #[test]
    fn postmaster_is_refused_when_not_configured_instead_of_guessed() {
        let mut session = session_with(&["example.org"], SessionConfig::default());
        let _ = session.handle(Command::Ehlo("c.test".into()));
        let _ = session.handle(Command::Mail {
            from: "a@b.test".into(),
            params: MailParams::default(),
        });
        let Action::Reply(reply) = session.handle(Command::Rcpt {
            to: "postmaster".into(),
        }) else {
            panic!("应回应答");
        };
        assert_eq!(reply.code, 550);
        assert!(reply.first_line().contains("not configured"));
    }

    #[test]
    fn quit_closes_the_connection_after_221() {
        let mut session = session(&["example.org"]);
        let Action::Close(reply) = session.handle(Command::Quit) else {
            panic!("QUIT 应关闭连接");
        };
        assert_eq!(reply.code, 221);
    }

    #[test]
    fn starttls_is_refused_when_not_offered_and_in_sequence_when_it_is() {
        let mut session = session(&["example.org"]);
        let Action::Reply(reply) = session.handle(Command::StartTls) else {
            panic!("应回应答");
        };
        assert_eq!(reply.code, 502, "没提供 TLS 就不能假装可以");

        let mut session = session_with(
            &["example.org"],
            SessionConfig {
                offer_starttls: true,
                ..SessionConfig::default()
            },
        );
        let _ = session.handle(Command::Ehlo("c.test".into()));
        let Action::StartTls(reply) = session.handle(Command::StartTls) else {
            panic!("应回 StartTls");
        };
        assert_eq!(reply.code, 220);
        assert_eq!(session.helo(), None, "升级后必须重新 EHLO");
        assert!(
            !session.is_tls_active(),
            "握手尚未完成，此时不得声称已在 TLS 上"
        );

        // 驱动在握手成功后置位。
        session.activate_tls();
        assert!(session.is_tls_active());
    }

    #[test]
    fn starttls_during_a_transaction_is_refused() {
        let mut session = session_with(
            &["example.org"],
            SessionConfig {
                offer_starttls: true,
                ..SessionConfig::default()
            },
        );
        ready(&mut session, "a@b.test", "alice@example.org");
        let Action::Reply(reply) = session.handle(Command::StartTls) else {
            panic!("应回应答");
        };
        assert_eq!(reply.code, 503);
    }

    #[test]
    fn auth_over_a_plaintext_session_is_refused() {
        // 明文口令一律不发。
        let mut session = session_with(
            &["example.org"],
            SessionConfig {
                offer_auth: true,
                ..SessionConfig::default()
            },
        );
        let _ = session.handle(Command::Ehlo("c.test".into()));
        let Action::Reply(reply) = session.handle(Command::Auth {
            mechanism: "PLAIN".into(),
            initial: None,
        }) else {
            panic!("应回应答");
        };
        assert_eq!(reply.code, 538);
        assert!(!session.is_authenticated());
    }

    #[test]
    fn hello_resets_a_transaction_in_progress() {
        let mut session = session(&["example.org"]);
        ready(&mut session, "a@b.test", "alice@example.org");
        let _ = session.handle(Command::Helo("other.test".into()));
        assert!(session.mail_from().is_none(), "HELO 是事务边界");
        assert!(session.recipients().is_empty());
    }

    // ─────────────────────────── SASL 提交认证 ───────────────────────────

    /// 提交端口上的会话：已在 TLS 之上且通告 AUTH。
    fn submission_session() -> Session {
        session_with(
            &["example.org"],
            SessionConfig {
                offer_auth: true,
                tls_active: true,
                ..SessionConfig::default()
            },
        )
    }

    fn auth_plain(initial: Option<&str>) -> Command {
        Command::Auth {
            mechanism: "PLAIN".into(),
            initial: initial.map(str::to_string),
        }
    }

    #[test]
    fn a_successful_auth_sets_the_identity_and_a_second_attempt_is_refused() {
        let mut session = submission_session();
        let _ = session.handle(Command::Ehlo("c.test".into()));

        let action = session.handle(auth_plain(Some("AGJvYg==")));
        let Action::AuthVerify {
            mechanism,
            response,
        } = action
        else {
            panic!("应请求校验，实际 {action:?}");
        };
        assert_eq!(mechanism, "PLAIN");
        assert_eq!(response, "AGJvYg==");
        assert!(
            !session.is_authenticated(),
            "后端结果回来之前不得置为已认证"
        );

        let reply = session.complete_auth(AuthOutcome::Success {
            user: "alice@example.org".to_string(),
        });
        assert_eq!(reply.code, 235);
        assert!(session.is_authenticated());
        assert_eq!(session.auth_user(), Some("alice@example.org"));

        // RFC 4954 §4：认证成功后不得再次认证。
        let Action::Reply(reply) = session.handle(auth_plain(Some("AGJvYg=="))) else {
            panic!("应回应答");
        };
        assert_eq!(reply.code, 503);
    }

    #[test]
    fn authentication_is_what_unlocks_relaying_to_a_foreign_domain() {
        // INV-17 的服务端落点之一：同一个外域收件人，认证前拒绝、认证后放行。
        let mut session = submission_session();
        let _ = session.handle(Command::Ehlo("c.test".into()));
        let _ = session.handle(Command::Mail {
            from: "alice@example.org".into(),
            params: MailParams::default(),
        });
        let Action::Reply(before) = session.handle(Command::Rcpt {
            to: "bob@gmail.com".into(),
        }) else {
            panic!("应回应答");
        };
        assert_eq!(before.code, 554, "未认证时不得中继");
        let _ = session.handle(Command::Rset);

        let action = session.handle(auth_plain(Some("AGJvYg==")));
        assert!(matches!(action, Action::AuthVerify { .. }), "{action:?}");
        let _ = session.complete_auth(AuthOutcome::Success {
            user: "alice@example.org".to_string(),
        });

        let _ = session.handle(Command::Mail {
            from: "alice@example.org".into(),
            params: MailParams::default(),
        });
        let Action::Reply(after) = session.handle(Command::Rcpt {
            to: "bob@gmail.com".into(),
        }) else {
            panic!("应回应答");
        };
        assert!(after.is_positive_completion(), "认证后应放行：{after:?}");
    }

    #[test]
    fn an_unsupported_mechanism_is_refused_with_504_not_a_vague_502() {
        // 客户端要靠状态码决定换哪个机制；含糊的 502 会让它以为服务器没有 SASL。
        let mut session = submission_session();
        let _ = session.handle(Command::Ehlo("c.test".into()));
        let Action::Reply(reply) = session.handle(Command::Auth {
            mechanism: "LOGIN".into(),
            initial: None,
        }) else {
            panic!("应回应答");
        };
        assert_eq!(reply.code, 504);
        assert!(!session.awaiting_auth_response());
    }

    #[test]
    fn sasl_is_an_esmtp_extension_so_helo_sessions_cannot_authenticate() {
        let mut session = submission_session();
        let _ = session.handle(Command::Helo("c.test".into()));
        let Action::Reply(reply) = session.handle(auth_plain(Some("AGJvYg=="))) else {
            panic!("应回应答");
        };
        assert_eq!(reply.code, 503);
    }

    #[test]
    fn a_bare_auth_gets_an_empty_challenge_and_the_continuation_must_be_base64() {
        let mut session = submission_session();
        let _ = session.handle(Command::Ehlo("c.test".into()));

        let Action::AuthChallenge(reply) = session.handle(auth_plain(None)) else {
            panic!("无初始应答应发挑战");
        };
        assert_eq!(reply.code, 334, "PLAIN 的挑战是空串");
        assert!(session.awaiting_auth_response());

        // 非 base64 的续行绝不进入校验 —— 它会被拼进 Dovecot 的制表符协议行。
        let action = session.continue_auth(b"AAAA\tresp=injected");
        assert!(
            matches!(action, Action::Reply(ref reply) if reply.code == 501),
            "应回 501，实际 {action:?}"
        );
        assert!(!session.awaiting_auth_response(), "交换应已结束");
        assert!(!session.is_authenticated());
    }

    #[test]
    fn a_star_cancels_the_sasl_exchange() {
        // RFC 4954 §4：单独一行 `*` 表示放弃。
        let mut session = submission_session();
        let _ = session.handle(Command::Ehlo("c.test".into()));
        let _ = session.handle(auth_plain(None));
        let action = session.continue_auth(b"*");
        assert!(
            matches!(action, Action::Reply(ref reply) if reply.code == 501),
            "实际 {action:?}"
        );
        assert!(!session.awaiting_auth_response());
    }

    #[test]
    fn a_continuation_without_an_exchange_in_progress_is_out_of_sequence() {
        // 双方状态已经分叉，不能把这一行当成凭据。
        let mut session = submission_session();
        let _ = session.handle(Command::Ehlo("c.test".into()));
        let action = session.continue_auth(b"AGJvYg==");
        assert!(
            matches!(action, Action::Reply(ref reply) if reply.code == 503),
            "实际 {action:?}"
        );
    }

    #[test]
    fn credential_failure_and_backend_failure_are_different_replies() {
        // 535 与 454 混同会让客户端在 Dovecot 抖动时去改密码。
        let mut session = submission_session();
        let _ = session.handle(Command::Ehlo("c.test".into()));
        let _ = session.handle(auth_plain(Some("AGJvYg==")));
        assert_eq!(
            session.complete_auth(AuthOutcome::InvalidCredentials).code,
            535
        );
        assert!(!session.is_authenticated());
        assert_eq!(session.auth_user(), None);

        let _ = session.handle(auth_plain(Some("AGJvYg==")));
        let reply = session.complete_auth(AuthOutcome::TemporaryFailure("down".to_string()));
        assert_eq!(reply.code, 454);
        assert!(!session.is_authenticated(), "临时失败不得置位");
    }

    #[test]
    fn an_invalid_initial_response_is_refused_before_any_backend_call() {
        let mut session = submission_session();
        let _ = session.handle(Command::Ehlo("c.test".into()));
        let action = session.handle(auth_plain(Some("not base64")));
        assert!(
            matches!(action, Action::Reply(ref reply) if reply.code == 501),
            "实际 {action:?}"
        );
        assert!(!session.awaiting_auth_response());
    }
}
