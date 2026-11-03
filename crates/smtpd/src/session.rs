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
//! 3. **本地收件人存在性**：本域收件人还要过 [`RecipientChecker`]。`VRFY` 恒回
//!    502 就是为了堵目录枚举，若 `RCPT` 逐地址给 250/550 差别，等于把同一个
//!    信息面重新打开；拒掉不存在的收件人同时消掉了 backscatter。
//!    **只有「确认不存在」才 550**，「查不了」保持现状 —— 见 [`RecipientChecker`]。
//! 4. **VRFY**：恒为 502。它唯一的现实用途是**目录枚举**，本机不需要。
//!
//! ## SASL 认证为什么也留在这里（而不是丢给驱动）
//!
//! `AUTH` 的**前置条件**（是否通告、是否已在 TLS 上、是否 ESMTP、是否已有事务、
//! 是否已认证过）与「认证成功后会话有哪些权限」都属于会话状态，必须和别的命令
//! 走同一条判定链，否则「认证了但事务序列错乱」这类问题会散落在驱动里。
//! 状态机自己不调认证后端：它产出 [`Action::AuthVerify`]，由驱动去调，再用
//! [`Session::complete_auth`] 把结果交回来 —— 这样口令永远不进入会话状态。

use mailstack_smtp::{RelayDecision, RelayPolicy};
use mailstack_store::LocalRecipients;

use crate::command::{Command, MailParams};
use crate::data::BareNewlinePolicy;
use crate::reply::{texts, Reply};
use crate::sasl::{is_valid_base64, AuthOutcome};

/// 本地收件人存在性判定（`RCPT` 阶段用）。
///
/// ## 为什么不直接把查询写在状态机里
///
/// 状态机**不做 I/O**（见模块说明），而查注册表是 I/O。抽成 trait 之后，
/// 「查得到就 550、查不到就保持现状」这条判定链可以在不起真实文件的情况下
/// 被穷举测试 —— 尤其「后端不可用」那一支，若只能靠真的把文件搞坏来触发，
/// 就没有测试愿意写它。
///
/// 实现者**不得**把「查不了」报告成「不存在」：那会让一次磁盘抖动变成全站拒收。
pub trait RecipientChecker: Send + Sync {
    /// 该地址是否为本机可投递收件人。`Err` 一律表示**查不了**，不表示不存在。
    fn exists(&self, address: &str) -> Result<bool, String>;
}

impl std::fmt::Debug for dyn RecipientChecker + '_ {
    // 名录内容是**用户数据**（邮箱列表），不进日志：日志会被转发到别处，
    // 而邮箱清单对收信方没有价值。
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecipientChecker")
    }
}

/// 生产实现：读既有的注册表（`managed-mailboxes.json` + 别名表）。
#[derive(Debug, Clone)]
pub struct DirectoryRecipients {
    directory: LocalRecipients,
}

impl DirectoryRecipients {
    pub fn new(directory: LocalRecipients) -> Self {
        Self { directory }
    }
}

impl RecipientChecker for DirectoryRecipients {
    fn exists(&self, address: &str) -> Result<bool, String> {
        match self.directory.lookup(address) {
            mailstack_store::Lookup::Known => Ok(true),
            mailstack_store::Lookup::Missing => Ok(false),
            mailstack_store::Lookup::Unavailable(reason) => Err(reason),
        }
    }
}

/// 什么都不查的占位实现。
///
/// 用在**不配置**收件人名录的场合：此时行为与引入本判定之前完全一致
/// （只判域）。存在的意义是让「没配置」成为**显式选择**而不是隐式遗漏。
#[derive(Debug, Default, Clone, Copy)]
pub struct AnyRecipient;

impl RecipientChecker for AnyRecipient {
    fn exists(&self, _address: &str) -> Result<bool, String> {
        Ok(true)
    }
}

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
    /// 提交口策略：未认证会话是否被禁止开新事务（`MAIL` → `530 5.7.0`）。
    ///
    /// 只有**提交端口**（587）由装配层显式置位；默认 `false` 保持既有行为 ——
    /// MX 收信口（25）的双方都是服务器、不存在「登录」的概念，绝不能误开这道门。
    /// 拦在 `MAIL`（而不是 `RCPT`）是刻意的：事务入口处拒绝最省双方的力气，
    /// 客户端还没开始发正文，认证重试也不必重传任何数据。
    pub require_auth_for_submission: bool,
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
            require_auth_for_submission: false,
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

/// 会话所属监听的角色 —— 决定收下的邮件走哪一套语义。
///
/// ## 为什么必须由**会话**告诉 sink，而不是让 sink 自己猜
///
/// 同一个进程里三个端口共用一份队列写入逻辑，但 25 与 465/587 的信任模型完全
/// 不同：25 的对端是任意外部 MTA（必须做 SPF/DKIM/DMARC 入站判定），465/587 的
/// 对端是**本机自己的用户**（已认证的外发提交，不能按「陌生对端」判）。
/// 把这个区分做成消息字段而不是让 sink 从端口/认证状态反推，是为了不再出现
/// 「提交邮件被自家 DMARC 判死」这类跨端口语义串线（R3-001）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRole {
    /// MX 收信口（25）：入站语义。
    Mx,
    /// 提交口（465/587）：用户外发语义。
    Submission,
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
    /// 会话角色（见 [`SessionRole`]）。sink 依据它决定是否做入站认证判定。
    pub role: SessionRole,
    /// 会话是否已通过 SASL 认证（仅提交口可能为真）。
    pub authenticated: bool,
    /// 会话是否运行在 TLS 之上（决定 `Received:` 的 `with ESMTP`/`ESMTP(S)`）。
    pub secured: bool,
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
pub struct Session<'a> {
    config: SessionConfig,
    relay: RelayPolicy,
    /// 本地收件人名录（`RCPT` 阶段的存在性判定）。
    ///
    /// 刻意**不**叫 `recipients`：那个名字已经属于事务里已接受的收件人列表，
    /// 两个含义混在一个字段上会让人读错判定链。
    directory: &'a dyn RecipientChecker,
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
    /// 本会话属于 MX 收信口还是提交口（见 [`SessionRole`]）。
    ///
    /// 由装配层给出的 `offer_auth` / `require_auth_for_submission` 推导：
    /// 只有 465/587 会通告 AUTH 或强制提交认证，25 两者都不置位。
    /// 推导放在构造期而不是每条命令里，保证整条会话的角色不会中途改变。
    role: SessionRole,
}

impl<'a> Session<'a> {
    pub fn new(config: SessionConfig, relay: RelayPolicy) -> Self {
        Self::with_recipients(config, relay, &AnyRecipient)
    }

    /// 带收件人名录的构造：生产用 [`DirectoryRecipients`]。
    pub fn with_recipients(
        config: SessionConfig,
        relay: RelayPolicy,
        recipients: &'a dyn RecipientChecker,
    ) -> Self {
        let tls_active = config.tls_active;
        // 角色由装配层的端口策略推导（见字段说明）。派生时**同时**看两个标志：
        // 465 只通告 AUTH、587 两者都有；25 两者都不置位。
        let role = if config.offer_auth || config.require_auth_for_submission {
            SessionRole::Submission
        } else {
            SessionRole::Mx
        };
        Self {
            config,
            relay,
            directory: recipients,
            phase: Phase::Connected,
            helo: None,
            esmtp: false,
            mail_from: None,
            recipients: Vec::new(),
            authenticated: false,
            auth_user: None,
            pending_auth: None,
            tls_active,
            role,
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

    /// 本会话所属监听的角色（MX 收信口 / 提交口）。
    pub fn role(&self) -> SessionRole {
        self.role
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
        // 不通告 8BITMIME：本管道把报文建模为 UTF-8 `String`（见 `crate::sink`
        // 的文档），非 UTF-8 的 8bit 正文会被 554 拒收。通告一个兑现不了的能力
        // 等于邀请对端发我们注定要退的信。
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
        // 提交口策略（RFC 8314 §5 / RFC 4954）：要求认证的提交口上，未认证会话
        // 不得开事务。放在全部序列/尺寸检查**之后** —— 只拦「这条 MAIL 本来会
        // 成功」的请求，序列错误（503）与超限（552）仍按各自的语义先报。
        if self.config.require_auth_for_submission && !self.authenticated {
            return Action::Reply(Reply::with_enhanced(
                530,
                "5.7.0",
                texts::SUBMISSION_AUTH_REQUIRED,
            ));
        }
        // 提交口发件人归属（R3-003）：已认证会话只能以自己的身份发信。
        //
        // 在此之前，任意一个普通账号都能用 `MAIL FROM:<ceo@本域>` 提交，队列再按
        // 头部 `From:` 域用本域 DKIM 私钥签名 —— 外部收件方看到的就是一封
        // 「DKIM 通过且与 From 对齐」的、密码学上真实的伪造信。反中继只判断
        // 「已认证 ⇒ 可外发」，它管不了**以谁的名义**外发。
        //
        // 判定放在 530 之后、写入状态之前：未认证的提交由 530 负责（策略开关），
        // 这里只处理「有身份却用了别人的发件人」。
        if self.role == SessionRole::Submission {
            if let Some(user) = self.auth_user.as_deref() {
                if !sender_owned_by(user, &from) {
                    return Action::Reply(Reply::with_enhanced(
                        550,
                        "5.7.1",
                        texts::SENDER_NOT_OWNED,
                    ));
                }
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

        // 重复收件人在**任何查名录/查策略之前**就短路（R3-008）：
        // 去重此前发生在 `accept_recipient`，晚于 `directory.exists()` —— 于是
        // 同一条连接连发 100 个相同 RCPT 就等于 100 次同步文件读 + JSON 解析。
        // 这里提前返回 250 与最终应答完全一致（RFC 5321 允许重复收件人）。
        if self.recipients.iter().any(|existing| existing == &to) {
            return Action::Reply(Reply::with_enhanced(250, "2.1.5", texts::RCPT_OK));
        }

        // `postmaster`（无域）与 `postmaster@<任一纳管网域>` 都是 RFC 5321
        // §4.1.1.3 要求必须接受的保留地址 —— 它们映射到 `SessionConfig::postmaster`
        // 这条**运维策略值**，不保证是一个注册邮箱。让名录去判它会把
        // 「按 RFC 必须接受的保留地址」变成 550（Abuse 报告、DSN 都往这里发）。
        //
        // 大小写不敏感：RFC 规定 <POSTMASTER>（任意大小写）与 <postmaster> 等价，
        // 精确等值比较会把合规客户端的保留地址投递拒成 550。
        //
        // `postmaster@<外域>` **不**走这里：它要么是未认证会话的转发（反中继会拒），
        // 要么是已认证会话的合法外发 —— 两种都不是本机的保留地址。
        let reserved_postmaster = match to.rsplit_once('@') {
            Some((local, domain)) => {
                local.eq_ignore_ascii_case("postmaster") && self.relay.is_managed(domain)
            }
            None => to.eq_ignore_ascii_case("postmaster"),
        };
        if reserved_postmaster {
            return match &self.config.postmaster {
                // 显式接受，**不查收件人名录**：见上。
                Some(address) => {
                    let address = address.clone();
                    self.accept_recipient(address)
                }
                None => Action::Reply(Reply::with_enhanced(
                    550,
                    "5.1.1",
                    "postmaster address is not configured on this host",
                )),
            };
        }

        if self.recipients.len() >= self.config.max_recipients {
            return Action::Reply(Reply::with_enhanced(
                452,
                "4.5.3",
                texts::TOO_MANY_RECIPIENTS,
            ));
        }

        let domain = to.rsplit_once('@').map_or("", |(_, domain)| domain);
        match self.relay.evaluate(domain, self.authenticated) {
            // 只有 `DeliverLocal` 才继续往下查收件人：`RelayAuthenticated`（提交
            // 到外部域）去本地名录里查**没有意义**，而且会把「提交」变成一条
            // 拒绝服务向量 —— 只要后端稍慢，587 就整体不可用。
            RelayDecision::DeliverLocal => {}
            RelayDecision::RelayAuthenticated => {
                return self.accept_recipient(to);
            }
            RelayDecision::Reject { code, message } => {
                // 拒绝文案来自策略（单一来源），并带上被拒的收件人便于排障。
                // 注：地址是主人可控输入，`Reply` 会净化掉其中的 CR/LF。
                return Action::Reply(Reply::with_enhanced(code, "5.7.1", message));
            }
        }

        // 本地域：查收件人是否存在。
        //
        // `VRFY` 已经恒回 502，但 `RCPT` 逐地址的 250/550 差别会把同一个信息面
        // 重新打开 —— 目录枚举。拒掉不存在的收件人同时消掉了 backscatter
        // （伪造发件人 + 不存在的本域收件人 ⇒ 本机向第三方发 DSN）。
        match self.directory.exists(&to) {
            Ok(true) => {}
            // 只有**确认**不存在才回 550。`Err` 是「查不了」（磁盘/权限抖动），
            // 把它当成不存在会让一次抖动变成全站拒收真邮件 —— 那比放过一次枚举
            // 严重得多。保持现状（只判域），并如实记日志。
            Ok(false) => {
                return Action::Reply(Reply::with_enhanced(550, "5.1.1", texts::RECIPIENT_UNKNOWN))
            }
            Err(reason) => {
                tracing::warn!(
                    helo = %self.helo.clone().unwrap_or_default(),
                    reason = %reason,
                    "收件人名录不可用，本次 RCPT 只判域（不据此拒绝）"
                );
            }
        }

        self.accept_recipient(to)
    }

    /// 收件人已通过全部判定：去重后接受。
    fn accept_recipient(&mut self, to: String) -> Action {
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

    /// 超限丢弃路径的事务重置。
    ///
    /// RFC 5321 §4.1.1.4：DATA 的最终应答（超限时是 552）**同样结束事务**。
    /// 不重置的话 `mail_from`/`recipients` 残留在会话里 —— 客户端的下一条
    /// `MAIL` 撞 503「嵌套 MAIL」，重复 `DATA` 会把新正文投给上一位收件人。
    /// 与 [`Session::finish_data`] 的区别：这里没有报文可结算，只做状态归位。
    pub fn discard_data(&mut self) {
        self.mail_from = None;
        self.recipients.clear();
        self.phase = Phase::Greeted;
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
                role: self.role,
                authenticated: self.authenticated,
                secured: self.tls_active,
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

/// 提交口的信封发件人是否属于已认证身份（R3-003）。
///
/// 放行的形态只有三类：
///
/// 1. **null sender**（`<>`）：DSN/退信没有身份可冒用，且认证会话也可能是
///    自动化投递的发起方；拦掉它只会让退信发不出去。
/// 2. 与认证身份**完全相同**的地址（大小写不敏感 —— 账号名在本项目里一律小写）。
/// 3. 认证身份是**裸账号名**（`alice`，unix 风格登录）时，允许 `alice@<任意域>`：
///    口令库两种键都可能存在（`candidate_keys`），而「alice 用自己名字的信箱
///    发信」是同一个主体，不是冒用。
///
/// 明确**不**放行：同名不同人（`alice@example.org` 认证后发
/// `alice@other.example`）、别人的地址（`ceo@example.org`）、以及任何需要查外部
/// 别名表的形态。别名归属需要读别名表的目标列，装配层目前没有把这份数据交给
/// 会话；在拿到之前按**更严格**的一侧失败关闭 —— 宁可让运维给别名单独开账号，
/// 也不能让一个普通账号以任意本域地址外发。
fn sender_owned_by(authenticated_user: &str, mail_from: &str) -> bool {
    if mail_from.is_empty() {
        return true;
    }
    let user = authenticated_user.trim().to_ascii_lowercase();
    if user.is_empty() {
        return false;
    }
    let from = mail_from.trim().to_ascii_lowercase();
    if from == user {
        return true;
    }
    if !user.contains('@') {
        let local = from.rsplit_once('@').map_or(from.as_str(), |(l, _)| l);
        return local == user;
    }
    false
}

impl std::fmt::Debug for Session<'_> {
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

    fn session(domains: &[&str]) -> Session<'static> {
        session_with(
            domains,
            SessionConfig {
                hostname: "mail.example.org".to_string(),
                postmaster: Some("postmaster@example.org".to_string()),
                ..SessionConfig::default()
            },
        )
    }

    fn session_with(domains: &[&str], config: SessionConfig) -> Session<'static> {
        Session::new(config, RelayPolicy::new(domains.iter().copied()))
    }

    /// 走一遍 `EHLO` → `MAIL` → `RCPT`，返回会话。
    fn ready(session: &mut Session<'_>, from: &str, to: &str) {
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
        // 管道只收 UTF-8 报文（QueueEntry 建模为 String），不得通告兑现不了的 8BITMIME。
        assert!(!rendered.contains("8BITMIME"));
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
    fn submission_session() -> Session<'static> {
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

    // ─────────────────────────── 提交口认证策略（587） ───────────────────────────

    /// 置位了「提交先认证」策略的会话（587 装配层的形状）。
    fn submission_session_requiring_auth() -> Session<'static> {
        session_with(
            &["example.org"],
            SessionConfig {
                offer_auth: true,
                tls_active: true,
                require_auth_for_submission: true,
                ..SessionConfig::default()
            },
        )
    }

    /// 反例守卫：策略置位 + 未认证 ⇒ `MAIL` 必须在事务入口处被 530 拦下。
    #[test]
    fn a_submission_session_that_requires_auth_refuses_an_unauthenticated_mail_with_530() {
        let mut session = submission_session_requiring_auth();
        let _ = session.handle(Command::Ehlo("c.test".into()));
        let Action::Reply(reply) = session.handle(Command::Mail {
            from: "alice@example.org".into(),
            params: MailParams::default(),
        }) else {
            panic!("应回应答");
        };
        assert_eq!(reply.code, 530, "未认证的提交必须被 530 拒绝");
        assert_eq!(reply.enhanced, Some("5.7.0"));
        assert!(reply.first_line().contains("Authentication required"));
        assert!(session.mail_from().is_none(), "被拒的事务不得置位发件人");
        // 会话没有错位：认证之后同一状态机可以正常开事务（见下一用例）。
    }

    /// 认证之后，策略不再拦截 —— 事务照常建立。
    #[test]
    fn an_authenticated_submission_passes_the_auth_gate() {
        let mut session = submission_session_requiring_auth();
        let _ = session.handle(Command::Ehlo("c.test".into()));
        let _ = session.handle(auth_plain(Some("AGJvYg==")));
        let _ = session.complete_auth(AuthOutcome::Success {
            user: "alice@example.org".to_string(),
        });

        let _ = session.handle(Command::Mail {
            from: "alice@example.org".into(),
            params: MailParams::default(),
        });
        let action = session.handle(Command::Rcpt {
            to: "alice@example.org".into(),
        });
        assert!(
            matches!(action, Action::Reply(ref reply) if reply.is_positive_completion()),
            "认证后的提交应放行：{action:?}"
        );
    }

    /// 回归守卫：策略未置位（默认）时行为与引入之前完全一致 ——
    /// 未认证 `MAIL` 照常 250，25 端口的既有语义不得被误伤。
    #[test]
    fn without_the_flag_the_previous_unauthenticated_behaviour_is_preserved() {
        let mut session = submission_session();
        let _ = session.handle(Command::Ehlo("c.test".into()));
        let action = session.handle(Command::Mail {
            from: "someone@example.org".into(),
            params: MailParams::default(),
        });
        assert!(
            matches!(action, Action::Reply(ref reply) if reply.code == 250),
            "默认配置下未认证 MAIL 必须照旧接受：{action:?}"
        );
    }

    // ───────────────── 提交口发件人归属（R3-003）─────────────────

    /// 认证成 `user` 的提交会话。
    fn authenticated_submission(user: &str) -> Session<'static> {
        let mut session = submission_session();
        let _ = session.handle(Command::Ehlo("c.test".into()));
        let _ = session.handle(auth_plain(Some("AGJvYg==")));
        let reply = session.complete_auth(AuthOutcome::Success {
            user: user.to_string(),
        });
        assert_eq!(reply.code, 235);
        session
    }

    /// 反例守卫：认证 alice 后用 `ceo@example.org` 作信封发件人必须 550。
    ///
    /// 修复前这条 MAIL 是 250：反中继只判断「已认证 ⇒ 可外发」，队列再按头部
    /// `From:` 域用本域 DKIM 私钥签名，外部收件方看到的是「DKIM 通过且对齐」的
    /// 伪造信 —— 一个普通账号就能冒充本域任何地址。
    #[test]
    fn an_authenticated_submission_may_not_use_another_senders_address() {
        let mut session = authenticated_submission("alice@example.org");
        let Action::Reply(reply) = session.handle(Command::Mail {
            from: "ceo@example.org".into(),
            params: MailParams::default(),
        }) else {
            panic!("应回应答");
        };
        assert_eq!(reply.code, 550, "冒用他人发件人必须被拒绝：{reply:?}");
        assert_eq!(reply.enhanced, Some("5.7.1"));
        assert!(session.mail_from().is_none(), "被拒的事务不得置位发件人");

        // 用**自己**的地址则照常通过（反例与正例在同一条会话上）。
        let action = session.handle(Command::Mail {
            from: "alice@example.org".into(),
            params: MailParams::default(),
        });
        assert!(
            matches!(action, Action::Reply(ref reply) if reply.code == 250),
            "认证身份自己的地址必须放行：{action:?}"
        );
    }

    /// 裸账号名（unix 风格登录名）允许其对应的 `name@domain` 形式。
    #[test]
    fn a_bare_account_name_may_send_from_its_own_address() {
        let mut session = authenticated_submission("alice");
        let action = session.handle(Command::Mail {
            from: "alice@example.org".into(),
            params: MailParams::default(),
        });
        assert!(
            matches!(action, Action::Reply(ref reply) if reply.code == 250),
            "alice 用 alice@example.org 发信是同一主体：{action:?}"
        );

        let mut session = authenticated_submission("alice");
        let Action::Reply(reply) = session.handle(Command::Mail {
            from: "bob@example.org".into(),
            params: MailParams::default(),
        }) else {
            panic!("应回应答");
        };
        assert_eq!(reply.code, 550, "裸账号名也不得冒用别人的地址");
    }

    /// null sender（`<>`）没有身份可冒用，认证会话的退信必须能发出。
    #[test]
    fn the_null_sender_is_allowed_from_an_authenticated_submission() {
        let mut session = authenticated_submission("alice@example.org");
        let action = session.handle(Command::Mail {
            from: String::new(),
            params: MailParams::default(),
        });
        assert!(
            matches!(action, Action::Reply(ref reply) if reply.code == 250),
            "null sender 不得被发件人归属校验拦下：{action:?}"
        );
    }

    /// 回归守卫：MX 收信口（25）不做发件人归属校验 —— 对端是外部 MTA，
    /// 信封发件人本来就可以是任意域。
    #[test]
    fn an_mx_session_is_not_subject_to_sender_ownership() {
        let mut session = session(&["example.org"]);
        let _ = session.handle(Command::Ehlo("c.test".into()));
        let action = session.handle(Command::Mail {
            from: "ceo@example.org".into(),
            params: MailParams::default(),
        });
        assert!(
            matches!(action, Action::Reply(ref reply) if reply.code == 250),
            "25 端口不得出现提交口语义：{action:?}"
        );
    }

    // ────────────────────── 本地收件人存在性（反枚举 / 反 backscatter）──────────────────────

    /// 可编程的假名录：回答「存在 / 确认不存在 / 查不了」三态，并记录查询。
    struct FakeDirectory {
        known: Vec<String>,
        /// `Some(reason)` 表示后端不可用（**不等于**「不存在」）。
        unavailable: Option<String>,
        seen: std::sync::Mutex<Vec<String>>,
    }

    impl FakeDirectory {
        fn knowing(known: &[&str]) -> Self {
            Self {
                known: known.iter().map(|s| s.to_string()).collect(),
                unavailable: None,
                seen: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn broken() -> Self {
            Self {
                known: Vec::new(),
                unavailable: Some("registry is corrupt".to_string()),
                seen: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn queried(&self) -> Vec<String> {
            self.seen.lock().unwrap().clone()
        }
    }

    impl RecipientChecker for FakeDirectory {
        fn exists(&self, address: &str) -> Result<bool, String> {
            self.seen.lock().unwrap().push(address.to_string());
            if let Some(reason) = &self.unavailable {
                return Err(reason.clone());
            }
            Ok(self.known.iter().any(|k| k == address))
        }
    }

    /// 开着名录的会话。名录必须活得比会话久，因此借用它。
    fn session_with_directory<'a>(domains: &[&str], directory: &'a FakeDirectory) -> Session<'a> {
        Session::with_recipients(
            SessionConfig {
                hostname: "mail.example.org".to_string(),
                postmaster: Some("postmaster@example.org".to_string()),
                ..SessionConfig::default()
            },
            RelayPolicy::new(domains.iter().copied()),
            directory,
        )
    }

    /// 走到 `RCPT` 之前（`EHLO` + `MAIL`）。
    fn opened(session: &mut Session<'_>, from: &str) {
        let _ = session.handle(Command::Ehlo("client.test".into()));
        let _ = session.handle(Command::Mail {
            from: from.into(),
            params: MailParams::default(),
        });
    }

    /// 反例守卫（目录枚举）：本地域 + **不存在**的收件人 ⇒ 550，且不进事务。
    ///
    /// 改回坏代码（只判域）时这条会红：那时会回 250 并把收件人记进事务，
    /// 攻击者就能在 25 端口逐地址试出全部真实邮箱。
    #[test]
    fn an_unknown_local_recipient_is_refused_with_550_and_never_enters_the_transaction() {
        let directory = FakeDirectory::knowing(&["alice@example.org"]);
        let mut session = session_with_directory(&["example.org"], &directory);
        opened(&mut session, "attacker@evil.test");

        let action = session.handle(Command::Rcpt {
            to: "nobody@example.org".into(),
        });
        let Action::Reply(reply) = action else {
            panic!("应回应答");
        };
        assert_eq!(reply.code, 550, "不存在的本域收件人必须 550");
        assert_eq!(reply.enhanced, Some("5.1.1"), "必须是 user unknown");
        assert!(session.recipients().is_empty(), "被拒的收件人不得进入事务");
        // 也不能走到 DATA。
        let action = session.handle(Command::Data);
        assert!(
            matches!(action, Action::Reply(ref r) if r.code == 503),
            "没有收件人时 DATA 必须拒绝：{action:?}"
        );
    }

    /// 回归守卫：名录里**存在**的收件人照旧 250。
    ///
    /// 这条挡的是「为了反枚举把真实收件人也拒了」这种过度实现。
    #[test]
    fn a_known_local_recipient_is_still_accepted() {
        let directory = FakeDirectory::knowing(&["alice@example.org"]);
        let mut session = session_with_directory(&["example.org"], &directory);
        opened(&mut session, "a@remote.test");

        let action = session.handle(Command::Rcpt {
            to: "alice@example.org".into(),
        });
        let Action::Reply(reply) = action else {
            panic!("应回应答");
        };
        assert!(reply.is_positive_completion(), "{reply:?}");
        assert_eq!(session.recipients(), &["alice@example.org".to_string()]);
    }

    /// R3-008：重复收件人必须在**查名录之前**短路。
    ///
    /// 名录查询是同步文件读 + JSON 解析（每条 RCPT 两次）。未认证攻击者只要
    /// `EHLO` + `MAIL` 后连发 100 个相同 `RCPT`，原实现就产生 200 次文件读；
    /// 修复后同一地址只该查一次。
    #[test]
    fn repeated_recipients_are_deduplicated_before_any_directory_lookup() {
        let directory = FakeDirectory::knowing(&["alice@example.org"]);
        let mut session = session_with_directory(&["example.org"], &directory);
        opened(&mut session, "a@remote.test");

        for _ in 0..100 {
            let action = session.handle(Command::Rcpt {
                to: "alice@example.org".into(),
            });
            assert!(
                matches!(action, Action::Reply(ref reply) if reply.is_positive_completion()),
                "重复收件人应答必须与首次一致：{action:?}"
            );
        }
        assert_eq!(session.recipients(), &["alice@example.org".to_string()]);
        assert_eq!(
            directory.queried().len(),
            1,
            "同一地址 100 次 RCPT 只应查一次名录，实际 {:?}",
            directory.queried()
        );
    }

    /// 反例守卫：**远程域不去查本地名录**，反中继规则照旧。
    ///
    /// 两条都必须成立：
    /// 1. 未认证的外域收件人仍按 `RelayPolicy` 拒（554），不能因为查了本地表
    ///    就把外域全拒掉（那会把 587 的正常提交也一起打死）；
    /// 2. 名录**一次都没被查** —— 去本地名录里问「bob@gmail.com 在不在」既没有
    ///    意义，又等于把名录变成一个可探测的拒绝服务面。
    #[test]
    fn a_remote_domain_is_judged_by_relay_policy_and_never_queries_the_directory() {
        let directory = FakeDirectory::knowing(&[]);
        let mut session = session_with_directory(&["example.org"], &directory);
        opened(&mut session, "a@remote.test");

        // 未认证 + 外域：反中继拒绝。
        let Action::Reply(reply) = session.handle(Command::Rcpt {
            to: "bob@gmail.com".into(),
        }) else {
            panic!("应回应答");
        };
        assert_eq!(reply.code, 554, "外域未认证必须按反中继拒");
        assert!(
            directory.queried().is_empty(),
            "远程域不得查本地名录（实际查了 {:?}）",
            directory.queried()
        );
    }

    /// 认证后的**提交**到远程域也不查名录 —— 587 的正常路径不能被拖慢或被拒。
    #[test]
    fn an_authenticated_relay_to_a_remote_domain_never_queries_the_directory() {
        let directory = FakeDirectory::broken();
        let mut session = Session::with_recipients(
            SessionConfig {
                offer_auth: true,
                tls_active: true,
                ..SessionConfig::default()
            },
            RelayPolicy::new(["example.org"]),
            &directory,
        );
        let _ = session.handle(Command::Ehlo("c.test".into()));
        let _ = session.handle(auth_plain(Some("AGJvYg==")));
        let _ = session.complete_auth(AuthOutcome::Success {
            user: "alice@example.org".to_string(),
        });
        let _ = session.handle(Command::Mail {
            from: "alice@example.org".into(),
            params: MailParams::default(),
        });

        // 名录**坏着**：若这里去查了名录，提交就会 550 —— 那是一个真实的
        // 拒绝服务缺陷（磁盘一抖，全站提交不可用）。
        let action = session.handle(Command::Rcpt {
            to: "bob@gmail.com".into(),
        });
        let Action::Reply(reply) = action else {
            panic!("应回应答");
        };
        assert!(
            reply.is_positive_completion(),
            "认证后提交到外域必须放行：{reply:?}"
        );
        assert!(directory.queried().is_empty(), "提交路径不得查本地名录");
    }

    /// 反例守卫：**「查不到」不得误拒**。
    ///
    /// 名录损坏（磁盘/权限抖动）时若把它当成「不存在」，一次抖动就会让全站
    /// 拒收真邮件 —— 那比放过一次目录枚举严重得多。所以这里必须**保持现状**
    /// （只判域、回 250），把判断留给投递阶段。
    #[test]
    fn an_unavailable_directory_never_turns_into_a_rejection() {
        let directory = FakeDirectory::broken();
        let mut session = session_with_directory(&["example.org"], &directory);
        opened(&mut session, "a@remote.test");

        let action = session.handle(Command::Rcpt {
            to: "alice@example.org".into(),
        });
        let Action::Reply(reply) = action else {
            panic!("应回应答");
        };
        assert!(
            reply.is_positive_completion(),
            "查不了时必须保持现状（只判域），不得误拒：{reply:?}"
        );
        assert_eq!(
            directory.queried(),
            vec!["alice@example.org".to_string()],
            "确实问过名录（否则这条测试什么也没证明）"
        );
    }

    /// 同一个地址在「查得到」与「查不了」两种后端下必须给出**不同**结果 ——
    /// 这正是 `Result` 而非 `bool` 的意义。
    #[test]
    fn unknown_and_unavailable_are_distinguished_and_only_the_first_one_refuses() {
        let missing = FakeDirectory::knowing(&[]);
        let mut session = session_with_directory(&["example.org"], &missing);
        opened(&mut session, "a@remote.test");
        let Action::Reply(refused) = session.handle(Command::Rcpt {
            to: "nobody@example.org".into(),
        }) else {
            panic!("应回应答");
        };
        assert_eq!(refused.code, 550);

        let broken = FakeDirectory::broken();
        let mut session = session_with_directory(&["example.org"], &broken);
        opened(&mut session, "a@remote.test");
        let Action::Reply(allowed) = session.handle(Command::Rcpt {
            to: "nobody@example.org".into(),
        }) else {
            panic!("应回应答");
        };
        assert!(
            allowed.is_positive_completion(),
            "同一个地址：查得到 ⇒ 550，查不了 ⇒ 放行。实际 {allowed:?}"
        );
    }

    /// 不挂名录（默认构造）时行为与引入本判定之前**完全一致**：只判域。
    ///
    /// 这条是「没配置 = 有意的选择」这条设计的回归守卫。
    #[test]
    fn without_a_directory_the_previous_domain_only_behaviour_is_preserved() {
        let mut session = session(&["example.org"]);
        opened(&mut session, "a@remote.test");
        let action = session.handle(Command::Rcpt {
            to: "nobody@example.org".into(),
        });
        let Action::Reply(reply) = action else {
            panic!("应回应答");
        };
        assert!(
            reply.is_positive_completion(),
            "未挂名录时不得拒本域收件人：{reply:?}"
        );
    }

    /// 别名目标（不是邮箱）也必须是合法收件人 —— 名录判定要认别名表。
    /// 用真实的 [`DirectoryRecipients`] 走一遍，证明生产接线是通的。
    #[test]
    fn the_production_directory_reads_the_real_registries() {
        let dir = tempfile::tempdir().unwrap();
        let paths = mailstack_core::paths::Paths::rooted(dir.path());
        std::fs::create_dir_all(&paths.postfix).unwrap();
        std::fs::create_dir_all(paths.managed_mailboxes.parent().unwrap()).unwrap();
        std::fs::write(
            &paths.managed_mailboxes,
            r#"[{"email":"alice@example.org","unixUser":"alice"}]"#,
        )
        .unwrap();
        std::fs::write(&paths.aliases, "sales@example.org alice\n").unwrap();

        let recipients = DirectoryRecipients::new(mailstack_store::LocalRecipients::new(&paths));
        let mut session = Session::with_recipients(
            SessionConfig::default(),
            RelayPolicy::new(["example.org"]),
            &recipients,
        );
        opened(&mut session, "a@remote.test");

        for known in ["alice@example.org", "sales@example.org"] {
            let action = session.handle(Command::Rcpt {
                to: known.to_string(),
            });
            assert!(
                matches!(action, Action::Reply(ref r) if r.is_positive_completion()),
                "{known} 应当在名录里：{action:?}"
            );
        }
        let Action::Reply(reply) = session.handle(Command::Rcpt {
            to: "nobody@example.org".into(),
        }) else {
            panic!("应回应答");
        };
        assert_eq!(reply.code, 550, "名录外的本域地址必须 550");
    }

    /// 回归守卫：**`RCPT TO:<postmaster>` 不受名录约束**。
    ///
    /// `postmaster` 的地址是运维在 `SessionConfig::postmaster` 里配的策略值，
    /// **不保证**是一个注册邮箱。若让它走名录判定，RFC 5321 §4.1.1.3 要求必须
    /// 接受的保留地址就会变成 550 —— 而 Abuse 报告与 DSN 都往这里发。
    #[test]
    fn the_rfc_mandated_postmaster_address_is_not_judged_by_the_directory() {
        // 名录里**只有** alice：配置里的 postmaster 地址并不在其中。
        let directory = FakeDirectory::knowing(&["alice@example.org"]);
        let mut session = session_with_directory(&["example.org"], &directory);
        opened(&mut session, "a@remote.test");

        let action = session.handle(Command::Rcpt {
            to: "postmaster".into(),
        });
        let Action::Reply(reply) = action else {
            panic!("应回应答");
        };
        assert!(
            reply.is_positive_completion(),
            "RFC 5321 §4.1.1.3 要求必须接受 postmaster：{reply:?}"
        );
        assert_eq!(
            session.recipients(),
            &["postmaster@example.org".to_string()]
        );
        assert!(
            directory.queried().is_empty(),
            "postmaster 不该查名录（实际查了 {:?}）",
            directory.queried()
        );
    }

    /// R3-012：`postmaster@<本机纳管网域>` 同样是不受名录约束的保留地址。
    ///
    /// 修复前只有裸 `postmaster` 被特判；`postmaster@example.org` 会走名录，
    /// 而名录里通常没有这个地址（配置项只是「裸 postmaster 映射到的地址」）→ 550。
    /// Abuse 报告与 DSN 惯用带域形式，被拒会直接影响滥用处置与退信可达性。
    #[test]
    fn postmaster_at_a_managed_domain_is_reserved_too() {
        let directory = FakeDirectory::knowing(&["alice@example.org"]);
        let mut session = session_with_directory(&["example.org"], &directory);
        opened(&mut session, "a@remote.test");

        // 大小写不敏感（RFC 5321 §4.5.1）。
        let Action::Reply(reply) = session.handle(Command::Rcpt {
            to: "PostMaster@Example.ORG".into(),
        }) else {
            panic!("应回应答");
        };
        assert!(
            reply.is_positive_completion(),
            "postmaster@纳管网域必须接受：{reply:?}"
        );
        assert_eq!(
            session.recipients(),
            &["postmaster@example.org".to_string()],
            "必须映射到配置的 postmaster 地址"
        );
        assert!(
            directory.queried().is_empty(),
            "保留地址不得查名录（实际查了 {:?}）",
            directory.queried()
        );
    }

    /// `postmaster@<外域>` 不是本机保留地址：未认证会话照旧按反中继拒绝。
    #[test]
    fn postmaster_at_a_foreign_domain_is_not_reserved() {
        let directory = FakeDirectory::knowing(&["alice@example.org"]);
        let mut session = session_with_directory(&["example.org"], &directory);
        opened(&mut session, "a@remote.test");

        let Action::Reply(reply) = session.handle(Command::Rcpt {
            to: "postmaster@evil.test".into(),
        }) else {
            panic!("应回应答");
        };
        assert_eq!(reply.code, 554, "外域 postmaster 必须按反中继拒");
        assert!(session.recipients().is_empty());
    }
}
