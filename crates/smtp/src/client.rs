//! 最小 SMTP 客户端（请求-响应式）。
//!
//! 刻意自研而不是直接用高层客户端：分阶段中继测试需要**逐步可观测**
//! （DNS → connect → TLS → auth 各自独立成阶段，§5.9.4），而队列投递又需要
//! 精确控制拨号目标（IP 固定）。两者都要求对会话有完全控制权。
//!
//! 行读取用自带的缓冲而不是 `BufReader`：`BufReader` 无法在 `&mut self` 下交出
//! 底层流的所有权，而 STARTTLS 恰好需要「升级底层流」，且升级时**必须丢弃**
//! 明文读缓冲（否则 TLS 握手后可能读到握手前的残留字节）。

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::Instant;

use crate::dial::{EstablishedStream, PinnedDialer, TlsMode};
use crate::error::{SmtpError, SmtpResult};
use crate::target::PinnedTarget;

/// 单次 SMTP 会话（一次投递尝试）的总时限（R3-010）。
///
/// ## 为什么「单次读写超时」不够
///
/// 直投模式下对端是任意收件域的 MX（完全恶意）。原实现的超时全是**逐次**的：
/// `read_response` 每读一行各领一份 `timeout`，正文每 32 KiB 块各领一份。
/// 对端只要在每次超时前发 1 字节，一次投递就能占用 worker 数小时（单行上限
/// 4096 字节 × 64 行 × 单行超时）；正文阶段同理按块无限延长。队列的
/// `relay_concurrency` 有限，少数恶意收件域即可吃满出站并发，所有外发积压
/// （连 DSN 告警都发不出去）。
///
/// 会话级 deadline 与入站侧的 `SESSION_TOTAL_TIMEOUT` 对称：每个 await 点都用
/// 「剩余总预算」与单次超时中较小者兜住，整条 `MAIL → RCPT → DATA → 250`
/// 有确定上界。
pub const SESSION_BUDGET: Duration = Duration::from_secs(300);

/// 出站单行长度上限。
///
/// ## 为什么出站也要限长（入站早就限了）
///
/// 入站侧有两道限长（`MAX_COMMAND_BUFFER` + `data.rs` 的 `max_size`），出站侧
/// 原先**一道都没有**：`read_line` 一直 append 到出现 `\n` 为止。而直投模式
/// 会连向**任意收件域的 MX** —— 对端可以完全恶意，一条永不出 LF 的应答就能让
/// 投递任务的内存无界增长。这条路径不需要认证、不需要被攻击者认识本机，
/// 只要收到一封邮件就会自动触发。
pub const MAX_RESPONSE_LINE_BYTES: usize = 4096;

/// 出站单条应答的最大行数。
///
/// 多行应答（`250-` 续行）没有上限时，对端可以用海量续行撑爆内存。
/// 真实的 EHLO 能力通常在 10 行以内，64 行留足了余量。
pub const MAX_RESPONSE_LINES: usize = 64;

/// 单条响应。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub code: u16,
    pub lines: Vec<String>,
}

impl Response {
    /// 首行（不含状态码）。
    pub fn first_line(&self) -> &str {
        self.lines.first().map(String::as_str).unwrap_or("")
    }

    /// banner/文本前 200 字符（§5.9.4 规定）。
    pub fn banner(&self) -> String {
        self.lines.join(" ").chars().take(200).collect()
    }

    /// 2xx/3xx 视为「非失败」。
    pub fn is_positive(&self) -> bool {
        (200..400).contains(&self.code)
    }

    /// 2xx 视为完成。
    pub fn is_positive_completion(&self) -> bool {
        (200..300).contains(&self.code)
    }
}

/// 一次投递尝试的**已判定**结果（服务器给出了明确答复）。
///
/// 与「协议层失败」相对：后者是未知结果（可能已投递也可能没有），不得据此退信。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageOutcome {
    /// 服务器接受。
    Accepted { response: Response },
    /// 服务器拒绝。`permanent` 为真表示 5xx（永久失败，重试无意义）。
    ///
    /// `accepted` 是**在失败发生之前已被对端接受并成功投递**的收件人。SMTP 投递可以
    /// 部分成功（部分 `RCPT` 通过后其余被拒，或 `RCPT` 全过但正文被拒），已投出去的
    /// 这批人 —— 调用方（队列）必须把他们从重试/退信集合里摘除，否则整批按失败
    /// 处理时他们会**再投一遍**。RCPT 阶段的拒绝现在逐个尝试、不再终止事务：
    /// 有人通过且正文投递成功时，`accepted` 带回全部已投者、`response` 带回一个
    /// 代表性的拒绝响应；正文阶段失败时保守填充空集（整批重试，宁重投不丢信）。
    Rejected {
        response: Response,
        permanent: bool,
        accepted: Vec<String>,
    },
}

impl MessageOutcome {
    /// 状态码。
    pub fn code(&self) -> u16 {
        match self {
            MessageOutcome::Accepted { response } | MessageOutcome::Rejected { response, .. } => {
                response.code
            }
        }
    }

    pub fn is_accepted(&self) -> bool {
        matches!(self, MessageOutcome::Accepted { .. })
    }

    /// 是否应停止重试。
    pub fn is_permanent_failure(&self) -> bool {
        matches!(
            self,
            MessageOutcome::Rejected {
                permanent: true,
                ..
            }
        )
    }
}

/// EHLO 能力。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Capabilities {
    pub starttls: bool,
    pub auth_mechanisms: Vec<String>,
    pub raw: Vec<String>,
}

impl Capabilities {
    pub fn supports(&self, mechanism: &str) -> bool {
        self.auth_mechanisms
            .iter()
            .any(|m| m.eq_ignore_ascii_case(mechanism))
    }
}

/// 自有缓冲的行式 IO 包装。
struct LineIo {
    inner: EstablishedStream,
    buf: Vec<u8>,
    pos: usize,
}

impl LineIo {
    fn new(inner: EstablishedStream) -> Self {
        Self {
            inner,
            buf: Vec::with_capacity(2048),
            pos: 0,
        }
    }

    fn is_encrypted(&self) -> bool {
        self.inner.is_encrypted()
    }

    /// 读一行（含结尾换行）。
    ///
    /// ## 为什么这里必须限长
    ///
    /// 对端是任意收件域的 MX（直投模式下），可以完全恶意。原实现只等 `\n`，
    /// 于是「一条永不出 LF 的应答」能让 `buf` 无界增长 —— 每个收到邮件的
    /// 部署都自动暴露这条路径，不需要任何认证。
    ///
    /// 超限按**协议错误**断开而不是截断：截断出来的半行会被上层当作完整应答
    /// 解析（状态码恰好在前 3 字节），那比直接断开更危险。
    async fn read_line(&mut self) -> std::io::Result<String> {
        loop {
            if let Some(idx) = self.buf[self.pos..].iter().position(|&b| b == b'\n') {
                let end = self.pos + idx + 1;
                let line = String::from_utf8_lossy(&self.buf[self.pos..end]).into_owned();
                self.pos = end;
                return Ok(line);
            }

            // 压缩已消费的前缀，避免缓冲区无界增长。
            if self.pos > 0 {
                self.buf.drain(..self.pos);
                self.pos = 0;
            }

            // 判据放在 append **之前**：未消费的部分就已超限，说明对端在发一条
            // 不肯换行的应答。再等下去只会把内存吃光。
            if self.buf.len() >= MAX_RESPONSE_LINE_BYTES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "response line exceeded {MAX_RESPONSE_LINE_BYTES} bytes without a newline"
                    ),
                ));
            }

            let mut chunk = [0u8; 2048];
            let n = self.inner.read(&mut chunk).await?;
            if n == 0 {
                if self.buf.is_empty() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "connection closed by server",
                    ));
                }
                // EOF 时缓冲里还压着没有换行的残余字节：那是一条**不完整**的应答，
                // 不能当成完整行交出去 —— 截断出来的半行会被上层按「前 3 字节
                // 状态码」解析成一条看似合法的应答（见 `parse_response_line`），
                // 把未知结果伪装成已判定结果，比直接断开更危险。与「超限按协议
                // 错误断开」同一立场：不完整的应答不参与任何投递判定。
                let leftover = String::from_utf8_lossy(&self.buf).into_owned();
                self.buf.clear();
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    format!("connection closed with an incomplete response: {leftover:?}"),
                ));
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }

    async fn write_line(&mut self, line: &str) -> std::io::Result<()> {
        let payload = format!("{line}\r\n");
        self.inner.write_all(payload.as_bytes()).await?;
        self.inner.flush().await
    }

    /// 交出底层流（升级 TLS 用）。**缓冲被一并丢弃**，这是有意的：
    /// TLS 之后任何明文残留字节都属于协议违规输入。
    fn into_inner(self) -> EstablishedStream {
        self.inner
    }
}

/// SMTP 会话。
pub struct SmtpSession {
    io: LineIo,
    timeout: Duration,
    /// 整条会话的绝对截止时刻（构造时 `now + budget`）。
    ///
    /// 与 `timeout`（单次读写上限）同时生效：每个 await 点用两者中**先到**者
    /// 兜底，因此既防「一次读挂太久」，也防「每次都在超时前动一下」的滴水
    /// 攻击（R3-010）。
    deadline: Instant,
    /// 构造时声明的整体预算（只用于错误文案与观测，判定用 `deadline`）。
    budget: Duration,
    capabilities: Capabilities,
}

impl SmtpSession {
    /// 建立连接并读取 banner（尚未发送 EHLO）。
    pub async fn connect(
        dialer: &PinnedDialer,
        target: &PinnedTarget,
        mode: TlsMode,
        timeout: Duration,
    ) -> SmtpResult<(Self, Response)> {
        let stream = dialer.connect_with_mode(target, mode).await?;
        let mut session = Self::from_stream(stream, timeout);
        // banner 读取也受同一个会话 deadline 约束（connect 的 TCP/TLS 阶段
        // 各有自己的超时；从 banner 开始进入 SMTP 会话预算）。
        let banner = session.read_response().await?;
        Ok((session, banner))
    }

    pub fn from_stream(stream: EstablishedStream, timeout: Duration) -> Self {
        Self::from_stream_with_budget(stream, timeout, SESSION_BUDGET)
    }

    /// 显式指定整体预算的构造（测试与需要更短预算的部署）。
    pub fn from_stream_with_budget(
        stream: EstablishedStream,
        timeout: Duration,
        budget: Duration,
    ) -> Self {
        Self {
            io: LineIo::new(stream),
            timeout,
            deadline: Instant::now() + budget,
            budget,
            capabilities: Capabilities::default(),
        }
    }

    pub fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    pub fn is_encrypted(&self) -> bool {
        self.io.is_encrypted()
    }

    /// 本次 await 可用的等待预算：单次超时与会话剩余预算中的较小者。
    fn wait_budget(&self) -> Duration {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        self.timeout.min(remaining)
    }

    /// 超时后的错误：区分「单次超时」与「会话总预算耗尽」，便于排障定位。
    fn timeout_error(&self, what: &str) -> SmtpError {
        if Instant::now() >= self.deadline {
            SmtpError::Protocol(format!(
                "SMTP session deadline ({}ms) exceeded while {what}",
                self.budget.as_millis()
            ))
        } else {
            SmtpError::Protocol(format!("timed out {what}"))
        }
    }

    /// 读取一条（可能多行的）响应。
    pub async fn read_response(&mut self) -> SmtpResult<Response> {
        let mut lines = Vec::new();
        let mut code: Option<u16> = None;

        loop {
            let wait = self.wait_budget();
            let line = tokio::time::timeout(wait, self.io.read_line())
                .await
                .map_err(|_| self.timeout_error("waiting for server response"))?
                .map_err(SmtpError::Io)?;

            let trimmed = line.trim_end_matches(['\r', '\n']).to_string();
            let (this_code, continued) = parse_response_line(&trimmed)?;

            // 多行应答的每一行都必须携带**同一个**状态码（RFC 5321 §4.2）。
            // 原实现只记首行：混码应答（`250-…` 续到 `550 …`）会被折算成首行的
            // 250 当作成功 —— 对端可控的判定翻转。
            match code {
                None => code = Some(this_code),
                Some(first) if first == this_code => {}
                Some(first) => {
                    return Err(SmtpError::Protocol(format!(
                        "multiline reply mixed status codes: {first} then {this_code}"
                    )));
                }
            }
            lines.push(trimmed);

            if !continued {
                break;
            }
            // 续行数有上界：否则对端可以用海量 `250-` 续行撑爆内存。
            // 判据放在 push **之后**，故超限时表里最多多留一行。
            if lines.len() > MAX_RESPONSE_LINES {
                return Err(SmtpError::Protocol(format!(
                    "response exceeded {MAX_RESPONSE_LINES} lines"
                )));
            }
        }

        Ok(Response {
            code: code.unwrap_or(0),
            lines,
        })
    }

    /// 发送一行命令并读取响应。
    pub async fn command(&mut self, line: &str) -> SmtpResult<Response> {
        let wait = self.wait_budget();
        tokio::time::timeout(wait, self.io.write_line(line))
            .await
            .map_err(|_| self.timeout_error("writing command"))?
            .map_err(SmtpError::Io)?;
        self.read_response().await
    }

    /// 发送 EHLO 并解析能力。
    pub async fn ehlo(&mut self, client_name: &str) -> SmtpResult<Response> {
        let response = self.command(&format!("EHLO {client_name}")).await?;
        if response.is_positive_completion() {
            self.capabilities = parse_capabilities(&response);
        }
        Ok(response)
    }

    /// STARTTLS 升级。
    ///
    /// **按值消费并返回新会话**，而不是原地修改：STARTTLS 在语义上就是一次状态跃迁
    /// （能力必须重算、明文缓冲必须丢弃、此后所有 IO 都经 TLS）。用类型表达这个跃迁，
    /// 就不会出现「升级后忘了重算能力」或「复用了明文缓冲」这类错误。
    pub async fn starttls(
        mut self,
        dialer: &PinnedDialer,
        target: &PinnedTarget,
    ) -> SmtpResult<(Self, Response)> {
        let response = self.command("STARTTLS").await?;
        if !response.is_positive_completion() {
            return Err(SmtpError::Rejected(response.banner()));
        }

        let timeout = self.timeout;
        let deadline = self.deadline;
        let budget = self.budget;
        // 明文读缓冲在此被丢弃 —— 这是必须的：TLS 之后任何明文残留字节
        // 都属于协议违规输入，绝不能进入解密后的读路径。
        let upgraded = self.io.into_inner().upgrade(dialer, target).await?;
        let mut next = Self::from_stream_with_budget(upgraded, timeout, budget);
        // 升级不能重置会话预算：否则一个「先 STARTTLS 再滴水」的对端可以靠
        // 重入拿到一份全新的预算（与入站侧 STARTTLS 重入的处理同一立场）。
        next.deadline = deadline;
        Ok((next, response))
    }

    /// AUTH PLAIN / LOGIN。
    ///
    /// ## 凭证先过闸，机制先核对
    ///
    /// 1. **凭证不含 CR/LF/NUL/空白**：线上载荷虽经 base64（命令流注入不成立），
    ///    但 PLAIN 的消息格式是 `\0{user}\0{pass}`，凭证里的 NUL 会让字段错位；
    ///    CR/LF 与空白则让凭证无法在 sasl_passwd 这类空白分隔的载体里往返
    ///    （见 `validate.rs` 与 `relay_store::parse_sasl_passwd`）。在入口拒绝，
    ///    宁可报错也不把可疑凭证发上网络。错误信息**不带凭证原文**（避免口令进日志）。
    /// 2. **对端没声明机制就不发凭证**：原实现在能力集为空时回落到盲试 PLAIN，
    ///    会把 base64 凭证发给一个从未声明支持认证的对端。回落已删除：
    ///    PLAIN/LOGIN 都必须在对端 EHLO 里出现过。
    pub async fn authenticate(&mut self, username: &str, password: &str) -> SmtpResult<Response> {
        for (label, value) in [("username", username), ("password", password)] {
            if value.contains(['\r', '\n', '\0', ' ', '\t']) {
                return Err(SmtpError::HeaderInjection(format!(
                    "SMTP {label} must not contain CR, LF, NUL or whitespace"
                )));
            }
        }

        if self.capabilities.supports("PLAIN") {
            let payload = base64(&format!("\0{username}\0{password}"));
            return self.command(&format!("AUTH PLAIN {payload}")).await;
        }

        if self.capabilities.supports("LOGIN") {
            let challenge = self.command("AUTH LOGIN").await?;
            if challenge.code != 334 {
                return Err(SmtpError::Rejected(challenge.banner()));
            }
            let user_step = self.command(&base64(username)).await?;
            if user_step.code != 334 {
                return Err(SmtpError::Rejected(user_step.banner()));
            }
            return self.command(&base64(password)).await;
        }

        Err(SmtpError::Rejected(
            "no supported AUTH mechanism offered by the server".to_string(),
        ))
    }

    /// 投递一封邮件：MAIL FROM → RCPT TO → DATA（失败即 `Err`）。
    ///
    /// 队列投递需要区分「4xx 临时失败（应重试）」与「5xx 永久失败（应退信）」，
    /// 因此队列路径请用 [`SmtpSession::send_message_detailed`]：本方法会把两者
    /// 一并压成 [`SmtpError::Rejected`]，丢失状态码这一关键信息。
    pub async fn send_message(
        &mut self,
        mail_from: &str,
        recipients: &[String],
        data: &str,
    ) -> SmtpResult<Response> {
        let outcome = self
            .send_message_detailed(mail_from, recipients, data)
            .await?;
        match outcome {
            MessageOutcome::Accepted { response } => Ok(response),
            MessageOutcome::Rejected { response, .. } => {
                Err(SmtpError::Rejected(response.banner()))
            }
        }
    }

    /// 投递一封邮件，并**保留最终响应的状态码**供调用方分类。
    ///
    /// 协议层失败（连接断开、超时、格式错误）仍以 `Err` 返回；只有服务器明确
    /// 拒绝了信封或正文时才返回 [`MessageOutcome::Rejected`]。这一区分是有意的：
    /// 前者是**未知**结果，后者是**已判定**结果，队列对两者的处理不同
    /// （未知结果不得直接退信，必须是可重试失败）。
    pub async fn send_message_detailed(
        &mut self,
        mail_from: &str,
        recipients: &[String],
        data: &str,
    ) -> SmtpResult<MessageOutcome> {
        let mail = self
            .command(&format!("MAIL FROM:<{}>", checked_addr(mail_from)?))
            .await?;
        if !mail.is_positive_completion() {
            return Ok(MessageOutcome::Rejected {
                permanent: mail.code >= 500,
                response: mail,
                accepted: Vec::new(),
            });
        }

        // 空收件人列表（上游入口不应发生，防御性兜底）：不开事务按已判定失败返回。
        if recipients.is_empty() {
            return Ok(MessageOutcome::Rejected {
                permanent: true,
                response: Response {
                    code: 554,
                    lines: vec!["no valid recipients".to_string()],
                },
                accepted: Vec::new(),
            });
        }

        // 逐个尝试全部收件人：此前「第一个被拒即终止」会让同批其余有效收件人
        // 从未被尝试、整批按失败退信 —— 真实邮件丢失。现在收集拒绝并继续；
        // 只要还有人被接受就继续 DATA（事务里本来就只含 RCPT 通过的人）。
        let mut rcpt_accepted: Vec<String> = Vec::new();
        let mut first_transient: Option<Response> = None;
        let mut first_permanent: Option<Response> = None;
        for rcpt in recipients {
            let response = self
                .command(&format!("RCPT TO:<{}>", checked_addr(rcpt)?))
                .await?;
            if response.is_positive_completion() {
                rcpt_accepted.push(rcpt.clone());
            } else if response.code >= 500 {
                first_permanent = first_permanent.or(Some(response));
            } else {
                first_transient = first_transient.or(Some(response));
            }
        }

        // 失败回执携带的响应必须与分类语义一致：队列按响应码判临时/永久，
        // 混合拒绝时优先带回临时拒绝，让重试只处理还没死透的收件人。
        // 按引用选取再 clone：first_transient 稍后还要参与 permanent 判定。
        let rcpt_rejection = first_transient
            .as_ref()
            .or(first_permanent.as_ref())
            .cloned();

        if rcpt_accepted.is_empty() {
            let response = rcpt_rejection.expect("全部被拒时至少存在一个拒绝响应");
            return Ok(MessageOutcome::Rejected {
                permanent: first_transient.is_none(),
                response,
                accepted: Vec::new(),
            });
        }

        let data_cmd = self.command("DATA").await?;
        if data_cmd.code != 354 {
            // RCPT 已有人通过但事务没能继续：正文未被任何人收到，
            // 保守起见不带 accepted（整批重试），宁可重投不可丢信。
            return Ok(MessageOutcome::Rejected {
                permanent: data_cmd.code >= 500,
                response: data_cmd,
                accepted: Vec::new(),
            });
        }

        // DATA 阶段：内容后跟单独一行的 "."，且必须对行首句点做 dot-stuffing。
        // 正文可能远超单次超时的承受量（大附件 × 慢链路）：按块写、每块限时，
        // 整体耗时随载荷伸缩，但每一块都被超时兜住，连接健康时不再误判超时。
        let terminated = terminate_data(data);
        for chunk in terminated.as_bytes().chunks(DATA_WRITE_CHUNK_BYTES) {
            let wait = self.wait_budget();
            tokio::time::timeout(wait, self.io.write_chunk_raw(chunk))
                .await
                .map_err(|_| self.timeout_error("writing message body"))?
                .map_err(SmtpError::Io)?;
        }
        let wait = self.wait_budget();
        tokio::time::timeout(wait, self.io.flush_raw())
            .await
            .map_err(|_| self.timeout_error("flushing message body"))?
            .map_err(SmtpError::Io)?;

        let response = self.read_response().await?;
        if response.is_positive_completion() {
            match rcpt_rejection {
                // 全部收件人被接受：原有成功路径。
                None => Ok(MessageOutcome::Accepted { response }),
                // 混合：正文已投给 RCPT 通过的人；拒绝者随失败带回，队列
                // 摘除已投者后按各自拒绝响应退信/重试。
                Some(response) => Ok(MessageOutcome::Rejected {
                    permanent: first_transient.is_none(),
                    response,
                    accepted: rcpt_accepted,
                }),
            }
        } else {
            // DATA 本身失败：已接受者是否收到不可知，保守重投整批。
            Ok(MessageOutcome::Rejected {
                permanent: response.code >= 500,
                response,
                accepted: Vec::new(),
            })
        }
    }

    pub async fn quit(&mut self) -> SmtpResult<Response> {
        self.command("QUIT").await
    }
}

impl LineIo {
    /// 追加写入一块字节（不 flush）。DATA 大正文按块写入时使用：
    /// 分块边界可能落在多字节字符中间，所以收 `&[u8]` 而不是 `&str`。
    async fn write_chunk_raw(&mut self, payload: &[u8]) -> std::io::Result<()> {
        self.inner.write_all(payload).await
    }

    /// 冲刷写缓冲。
    async fn flush_raw(&mut self) -> std::io::Result<()> {
        self.inner.flush().await
    }
}

/// DATA 正文单块写入的字节数。块越小超时粒度越细，越大调度开销越低；
/// 32 KiB 在慢链路（每秒几 KB）下也能在一轮超时内稳定写完。
const DATA_WRITE_CHUNK_BYTES: usize = 32 * 1024;

/// 校验一个即将拼进命令行的信封地址。
///
/// ## 为什么必须查 CR/LF
///
/// `MAIL FROM:<{}>` 是**字符串拼接**。地址里若有 `\r\n`，拼出来就是两条命令：
/// `MAIL FROM:<a@example.org>` 换行后接 `RCPT TO:<victim@elsewhere>`。
/// 本机随即以自己的身份向第三方投递 —— 这正是入站侧 `smtpd` 拼了命防的走私形态，
/// 只是方向相反：这里发生在**发送侧**。
///
/// 原实现信任上游生产者「会校验」，那是把安全性质建立在约定上；队列的入口
/// 有多个（`queue.action`、DSN 生成、恢复的备份），漏一个就能注入。
/// 在**拼接点**拒绝，才对所有调用点同时成立。
///
/// 顺带禁掉 NUL：它同样能截断某些下游的 C 字符串处理。
pub fn checked_addr(addr: &str) -> SmtpResult<&str> {
    if addr.contains(['\r', '\n', '\0']) {
        return Err(SmtpError::HeaderInjection(addr.to_string()));
    }
    Ok(addr)
}

/// 把正文封成 DATA 阶段的字节：dot-stuffing + `CRLF.CRLF` 终止符。
///
/// 两处细节都是**真机联调才会暴露**的（自建的脚本化测试服务端不读正文，所以看不见）：
///
/// 1. 终止符必须是 `CRLF.CRLF`，结尾那个 CRLF **不能少**。少了它，对端会一直等
///    「这一行还没结束」—— 表现为双方都觉得自己没错、却永远投递超时。
/// 2. 正文**已经**以 CRLF 结尾时不再补一个，否则每封外发邮件尾部会凭空多出一个空行。
///    那是对正文的改写，会让上游发件人的 DKIM 签名失效。
pub fn terminate_data(data: &str) -> String {
    let body = dot_stuff(data);
    let separator = if body.ends_with("\r\n") { "" } else { "\r\n" };
    format!("{body}{separator}.\r\n")
}

/// 对行首的 `.` 做 dot-stuffing（RFC 5321 §4.5.2）。
///
/// ## 为什么必须同时按裸 LF 切行
///
/// 原实现只按 `\r\n` 切分，于是**含裸 LF 的行完全不做 stuffing**。而队列
/// 是公共写入面（`queue.action`、DSN 生成、恢复的备份都能塞进正文），攻击者
/// 只需让正文里出现 `<裸 LF>.` 开头的行，邮件就会在那个「句点行」处被对端
/// **截断**，剩余部分被当作 SMTP 命令解析。
///
/// 这与入站侧严防的走私形态**完全同构**，只是发生在发送方向：入站是
/// 「防别人走私进我」，这里是「我不小心替别人走私出去」。
///
/// ## 副作用：行尾一律规范成 CRLF
///
/// 按 `\n` 切分后必然要重新用 CRLF 拼接，这会把正文里的**裸 LF 也变成 CRLF**。
/// 这是有意的，且是必须的：SMTP 的行边界就是 CRLF（RFC 5321 §2.1），
/// 保留裸 LF 意味着交给对端一份「行边界与对端理解不一致」的数据。
/// 入站侧对裸 LF 的默认策略也是 `Reject`，即本项目两端对裸 LF 的立场一致。
///
/// **裸 CR 保留**（不删）：删掉它会改变正文、破坏上游的 DKIM body hash。
/// 保留它则接收侧的逐字节状态机会原样收下 —— 与 `smtpd::data` 的既定
/// 行为一致（有测试钉住）。
pub fn dot_stuff(data: &str) -> String {
    data.split('\n')
        .map(|line| {
            // 去掉切分带来的 `\r`（它属于行终止符，不属于行内容），
            // 行首判定与重新拼接都在「干净的行」上做。
            let line = line.strip_suffix('\r').unwrap_or(line);
            if line.starts_with('.') {
                format!(".{line}")
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\r\n")
}

/// 解析 `250-FOO` / `250 FOO` → (code, continued)。
///
/// ## 为什么按字节而不是按字符切
///
/// 状态码是三个 **ASCII 数字**，位置固定在首字节。但 [`line`] 来自
/// `String::from_utf8_lossy` —— 它是任意合法 UTF-8。若按 `line[..3]` 切 &str，
/// 对端发一个以多字节字符开头的 banner（`"éé"` = `C3 A9 C3 A9 ...`，`len() == 4`）
/// 就会让下标 3 落在字符中间，**Rust 判定为非法边界直接 panic**。
///
/// 而本 crate 的投递路径由 `mailstackd` 承载，根 `Cargo.toml` 设有
/// `panic = "abort"` ⇒ 这是**对端可控的整进程终止**。这条代码路径在
/// `SmtpSession::connect` 之后**立即**对原始 banner 调用，因此不配置中继
/// （默认直投）时任意收件域的 MX 都能触发。
///
/// 按字节处理同时天然覆盖了非 ASCII：非数字的首 3 字节走 `parse` 失败分支，
/// 返回协议错误而不是崩溃。
fn parse_response_line(line: &str) -> SmtpResult<(u16, bool)> {
    let bytes = line.as_bytes();
    if bytes.len() < 3 {
        return Err(SmtpError::Protocol(format!("malformed response: {line:?}")));
    }
    // 前三位必须是 ASCII 数字，故可安全地逐字节拼装，无需字符边界。
    let digits = &bytes[..3];
    if !digits.iter().all(u8::is_ascii_digit) {
        return Err(SmtpError::Protocol(format!(
            "malformed status code: {line:?}"
        )));
    }
    let code: u16 = std::str::from_utf8(digits)
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| SmtpError::Protocol(format!("malformed status code: {line:?}")))?;
    let continued = bytes.get(3) == Some(&b'-');
    Ok((code, continued))
}

/// 解析 EHLO 能力行。
fn parse_capabilities(response: &Response) -> Capabilities {
    let mut caps = Capabilities {
        raw: response.lines.clone(),
        ..Default::default()
    };

    for line in &response.lines {
        let body = line.get(4..).unwrap_or("").trim();
        let upper = body.to_ascii_uppercase();

        if upper.starts_with("STARTTLS") {
            caps.starttls = true;
        } else if let Some(rest) = upper.strip_prefix("AUTH ") {
            for mech in rest.split_whitespace() {
                let mech = mech.to_string();
                if !caps.auth_mechanisms.contains(&mech) {
                    caps.auth_mechanisms.push(mech);
                }
            }
        }
    }

    caps
}

/// 标准 base64 编码（避免为一个编码引入额外依赖）。
pub fn base64(input: &str) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);

    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;

        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[n as usize & 63] as char
        } else {
            '='
        });
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_line_response() {
        let (code, continued) = parse_response_line("250 OK").unwrap();
        assert_eq!(code, 250);
        assert!(!continued);
    }

    #[test]
    fn parses_multiline_continuation() {
        let (code, continued) = parse_response_line("250-STARTTLS").unwrap();
        assert_eq!(code, 250);
        assert!(continued, "连字符表示后续还有行");
    }

    #[test]
    fn rejects_malformed_status_lines() {
        assert!(parse_response_line("hi").is_err());
        assert!(parse_response_line("abc def").is_err());
        assert!(parse_response_line("").is_err());
    }

    #[test]
    fn parses_starttls_and_auth_capabilities() {
        let response = Response {
            code: 250,
            lines: vec![
                "250-mail.example.com".to_string(),
                "250-STARTTLS".to_string(),
                "250-AUTH PLAIN LOGIN".to_string(),
                "250 SIZE 52428800".to_string(),
            ],
        };
        let caps = parse_capabilities(&response);
        assert!(caps.starttls);
        assert!(caps.supports("PLAIN"));
        assert!(caps.supports("LOGIN"));
        assert!(caps.supports("plain"), "机制匹配应大小写不敏感");
        assert!(!caps.supports("CRAM-MD5"));
    }

    #[test]
    fn capability_parsing_handles_absent_starttls() {
        let response = Response {
            code: 250,
            lines: vec!["250 mail.example.com".to_string()],
        };
        let caps = parse_capabilities(&response);
        assert!(!caps.starttls, "未声明 STARTTLS 时不得假定支持");
        assert!(caps.auth_mechanisms.is_empty());
    }

    #[test]
    fn banner_is_truncated_to_two_hundred_chars() {
        let response = Response {
            code: 220,
            lines: vec!["x".repeat(500)],
        };
        assert_eq!(response.banner().chars().count(), 200);
    }

    #[test]
    fn response_classification() {
        let positive = Response {
            code: 250,
            lines: vec![],
        };
        assert!(positive.is_positive());
        assert!(positive.is_positive_completion());

        let intermediate = Response {
            code: 334,
            lines: vec![],
        };
        assert!(intermediate.is_positive(), "3xx 是中间响应");
        assert!(!intermediate.is_positive_completion());

        let failure = Response {
            code: 535,
            lines: vec![],
        };
        assert!(!failure.is_positive());
    }

    #[test]
    fn base64_matches_reference_vectors() {
        assert_eq!(base64(""), "");
        assert_eq!(base64("f"), "Zg==");
        assert_eq!(base64("fo"), "Zm8=");
        assert_eq!(base64("foo"), "Zm9v");
        assert_eq!(base64("foob"), "Zm9vYg==");
        assert_eq!(base64("fooba"), "Zm9vYmE=");
        assert_eq!(base64("foobar"), "Zm9vYmFy");
    }

    #[test]
    fn base64_encodes_auth_plain_payload() {
        assert_eq!(base64("\0user\0pass"), "AHVzZXIAcGFzcw==");
    }

    #[test]
    fn base64_handles_non_ascii() {
        assert_eq!(base64("密码"), "5a+G56CB");
    }

    #[test]
    fn dot_stuffing_prefixes_leading_dots_only() {
        // 行首句点必须加倍，行中间的句点不动。
        assert_eq!(dot_stuff("hello"), "hello");
        assert_eq!(dot_stuff(".hidden"), "..hidden");
        assert_eq!(dot_stuff("a.b"), "a.b");
        assert_eq!(dot_stuff(".a\r\n.b"), "..a\r\n..b");
        assert_eq!(dot_stuff("text\r\n.\r\nmore"), "text\r\n..\r\nmore");
    }

    /// 反例守卫：**裸 LF 开头的句点行也必须被 stuffing**。
    ///
    /// ## 为什么这条是漏洞
    ///
    /// 原实现只按 `\r\n` 切分，所以正文里一行以 `<裸 LF>.` 开头时**完全不做
    /// stuffing**。邮件发出去后，对端在那个「句点行」处认为 DATA 结束，剩余
    /// 正文被当作 SMTP 命令解析 —— 这就是 CVE-2023-51764 的**发送侧**形态。
    ///
    /// 队列是公共写入面（`queue.action`、DSN 生成、备份恢复都能塞正文），
    /// 所以这不是假想输入。
    #[test]
    fn a_bare_lf_dot_line_is_stuffed_too() {
        // 关键用例：分隔符是裸 LF，不是 CRLF。
        assert_eq!(
            dot_stuff("body\n.evil\nrest"),
            "body\r\n..evil\r\nrest",
            "裸 LF 后的句点行必须被加倍，否则邮件在该行被截断"
        );
        // 混合分隔符：逐行都按「行首有没有点」判定，与用什么分隔无关。
        assert_eq!(dot_stuff("a\r\n.b\n.c"), "a\r\n..b\r\n..c");
        // 无点行不受影响。
        assert_eq!(dot_stuff("a\nb"), "a\r\nb");
    }

    /// 反例守卫：信封地址里的 CR/LF 必须**硬失败**，不得拼进命令行。
    ///
    /// `MAIL FROM:<a@example.org>\r\nRCPT TO:<victim@x>` 会让本机以自己的
    /// 身份向第三方投递第二条命令。原实现在拼接点没有任何检查，把安全性质
    /// 建立在「上游生产者会校验」这个约定上 —— 而队列入口有多个。
    #[test]
    fn an_address_containing_crlf_is_refused() {
        for evil in [
            "a@example.org\r\nRCPT TO:<victim@elsewhere>",
            "a@example.org\nRCPT TO:<victim@elsewhere>",
            "a@example.org\rDATA",
            "evil\0null",
        ] {
            match checked_addr(evil) {
                Ok(_) => panic!("地址 {evil:?} 含 CR/LF/NUL，必须被拒绝"),
                Err(SmtpError::HeaderInjection(_)) => {}
                Err(other) => panic!("应报 HeaderInjection，实际 {other:?}"),
            }
        }
        // 正常地址（含空格的显示名形式）必须放行。
        assert_eq!(checked_addr("a@example.org").unwrap(), "a@example.org");
        assert_eq!(
            checked_addr("Real Name <a@example.org>").unwrap(),
            "Real Name <a@example.org>"
        );
    }

    #[test]
    fn dot_stuffing_preserves_empty_lines() {
        assert_eq!(dot_stuff("a\r\n\r\nb"), "a\r\n\r\nb");
    }

    #[test]
    fn data_is_terminated_with_crlf_dot_crlf_and_the_body_is_never_rewritten() {
        // 终止符少了结尾的 CRLF 时，对端会一直等这一行结束 —— 实机投递会永久超时。
        assert_eq!(terminate_data("body"), "body\r\n.\r\n");
        assert!(terminate_data("body").ends_with("\r\n.\r\n"));

        // 正文已以 CRLF 结尾：**不得**再补一个（那会在每封邮件尾部多出一个空行，
        // 并让上游的 DKIM 签名失效）。
        assert_eq!(terminate_data("body\r\n"), "body\r\n.\r\n");

        // dot-stuffing 与终止符一起生效。
        assert_eq!(terminate_data(".\r\n"), "..\r\n.\r\n");
    }

    #[test]
    fn message_outcome_classification() {
        let accepted = MessageOutcome::Accepted {
            response: Response {
                code: 250,
                lines: vec!["250 OK".to_string()],
            },
        };
        assert!(accepted.is_accepted());
        assert!(!accepted.is_permanent_failure());
        assert_eq!(accepted.code(), 250);

        let transient = MessageOutcome::Rejected {
            response: Response {
                code: 450,
                lines: vec!["450 try later".to_string()],
            },
            permanent: false,
            accepted: Vec::new(),
        };
        assert!(!transient.is_accepted());
        assert!(!transient.is_permanent_failure(), "4xx 是可重试的临时失败");
        assert_eq!(transient.code(), 450);

        let permanent = MessageOutcome::Rejected {
            response: Response {
                code: 550,
                lines: vec!["550 no such user".to_string()],
            },
            permanent: true,
            accepted: Vec::new(),
        };
        assert!(
            permanent.is_permanent_failure(),
            "5xx 是永久失败，重试无意义"
        );
    }

    /// 起一个按脚本应答的最小 SMTP 服务端，返回已连接的客户端流。
    ///
    /// 脚本首行是 banner，其余每行对应「读一条客户端命令 → 写一条应答」。
    /// 注意 [`SmtpSession::send_message_detailed`] 会依次发出 MAIL FROM / RCPT TO /
    /// DATA / 正文，**不发 EHLO** —— 脚本必须与这条命令序列一一对应。
    async fn scripted_session(script: Vec<&'static str>) -> SmtpSession {
        use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let (read_half, mut write_half) = server.into_split();

        tokio::spawn(async move {
            let mut reader = tokio::io::BufReader::new(read_half);
            let mut line = String::new();
            for response in script {
                if !response.starts_with("220 ") {
                    line.clear();
                    if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                        return;
                    }
                }
                if write_half
                    .write_all(format!("{response}\r\n").as_bytes())
                    .await
                    .is_err()
                {
                    return;
                }
                let _ = write_half.flush().await;
            }
            // 保持连接直到客户端关闭（过早 RST 会污染断言）。
            let mut buf = [0u8; 1024];
            let _ = reader.read(&mut buf).await;
        });

        let mut session = SmtpSession::from_stream(
            crate::dial::EstablishedStream::Plain(client),
            std::time::Duration::from_secs(5),
        );
        session.read_response().await.unwrap(); // banner
        session
    }

    #[tokio::test]
    async fn detailed_send_reports_acceptance() {
        let mut session = scripted_session(vec![
            "220 ready",
            "250 sender ok",
            "250 rcpt ok",
            "354 go",
            "250 queued",
        ])
        .await;

        let outcome = session
            .send_message_detailed(
                "a@example.com",
                &["b@example.net".to_string()],
                "Subject: x\r\n\r\nbody",
            )
            .await
            .unwrap();
        assert!(outcome.is_accepted());
        assert_eq!(outcome.code(), 250);
    }

    #[tokio::test]
    async fn detailed_send_classifies_transient_and_permanent_rejections() {
        // 450（RCPT 阶段）→ 临时失败，应重试。
        let mut session =
            scripted_session(vec!["220 ready", "250 sender ok", "450 mailbox busy"]).await;
        let outcome = session
            .send_message_detailed("a@example.com", &["b@example.net".to_string()], "body")
            .await
            .unwrap();
        assert!(!outcome.is_accepted());
        assert!(!outcome.is_permanent_failure(), "450 必须可重试");
        assert_eq!(outcome.code(), 450);

        // 550（RCPT 阶段）→ 永久失败，应退信而不是无休止重试。
        let mut session =
            scripted_session(vec!["220 ready", "250 sender ok", "550 no such user"]).await;
        let outcome = session
            .send_message_detailed("a@example.com", &["b@example.net".to_string()], "body")
            .await
            .unwrap();
        assert!(outcome.is_permanent_failure(), "550 必须判定为永久失败");
        assert_eq!(outcome.code(), 550);
    }

    #[tokio::test]
    async fn detailed_send_keeps_protocol_failures_as_errors() {
        // 连接提前关闭：结果**未知**，必须是 Err 而不是 Rejected —— 队列据此
        // 只重试、绝不退信。
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        drop(server);

        let mut session = SmtpSession::from_stream(
            crate::dial::EstablishedStream::Plain(client),
            std::time::Duration::from_secs(5),
        );
        let result = session
            .send_message_detailed("a@example.com", &["b@example.net".to_string()], "body")
            .await;
        assert!(result.is_err(), "未知结果不得伪装成已判定的拒绝");
    }

    /// R3-010 反例：只按「单次读」限时的恶意对端会把投递挂到单行上限 × 单次超时。
    ///
    /// 服务端每 50ms 只吐一个字符、永不换行 —— 每次 `read` 都在单次超时前被喂活，
    /// 单次超时永远不会到点。修复前这条投递要等到 4096 字节（约 200 秒）才因
    /// 行长超限失败；会话级 deadline 必须在 300ms 左右把它掐断。
    #[tokio::test]
    async fn a_trickling_server_is_stopped_by_the_session_deadline() {
        use tokio::io::AsyncWriteExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        tokio::spawn(async move {
            if server.write_all(b"220 ready\r\n").await.is_err() {
                return;
            }
            loop {
                if server.write_all(b"2").await.is_err() {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        });

        let mut session = SmtpSession::from_stream_with_budget(
            crate::dial::EstablishedStream::Plain(client),
            std::time::Duration::from_secs(5),
            std::time::Duration::from_millis(300),
        );
        let banner = session.read_response().await.expect("banner 应可读");
        assert_eq!(banner.code, 220);

        let started = tokio::time::Instant::now();
        let error = session
            .command("EHLO client.test")
            .await
            .expect_err("滴水对端必须在会话 deadline 处失败");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "会话级 deadline 未生效：耗时 {:?}",
            started.elapsed()
        );
        assert!(
            error.to_string().contains("session deadline"),
            "错误应指明是会话总预算耗尽：{error}"
        );
    }
}
