//! Dovecot LMTP 客户端（规格书 §3.5；INV-11）。
//!
//! > 收信落箱的**唯一**投递路径；返回 250 才算投递成功，否则进重试队列。
//! > Rust 侧**不得**直接写 Maildir 索引文件。
//!
//! ## 基线其实没用 LMTP
//!
//! 现状是 Postfix 的 `local` 投递代理直接写系统用户的 `~/Maildir`
//! （安装脚本里既没有 `virtual_transport` 也没有 `virtual_mailbox_*`）。
//! 改用 LMTP 是**重写要求**，因此 LMTP 端点必须可配置 —— 不存在「沿用现状」这个选项。
//!
//! ## LMTP 与 SMTP 的两处协议差异（都是易错点）
//!
//! 1. 问候语之后的命令是 **`LHLO`**，不是 `EHLO`；
//! 2. `DATA` 之后服务器**按收件人逐个应答**，而不是像 SMTP 那样只回一条。
//!    少读一条应答，多出来的那条会被当成下一条命令的响应 —— 连接就此错位，
//!    后续每个响应都对应错误的命令。这是 LMTP 客户端最典型的缺陷。

use std::path::PathBuf;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UnixStream};

use crate::error::{StoreError, StoreResult};

/// 默认的 Dovecot LMTP unix socket。
///
/// Dovecot 自带默认值（基线配置未覆盖 `service lmtp`），去掉 Postfix 之后不再有
/// `/var/spool/postfix/private/dovecot-lmtp` 这个 postfix 专属路径。
pub const DEFAULT_LMTP_SOCKET: &str = "/run/dovecot/lmtp";

/// LMTP 端点。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LmtpEndpoint {
    Unix(PathBuf),
    Tcp(String, u16),
}

impl LmtpEndpoint {
    /// 默认 unix socket（[`DEFAULT_LMTP_SOCKET`]）。
    pub fn default_unix() -> Self {
        LmtpEndpoint::Unix(PathBuf::from(DEFAULT_LMTP_SOCKET))
    }

    pub fn unix(path: impl Into<PathBuf>) -> Self {
        LmtpEndpoint::Unix(path.into())
    }

    /// 环回 TCP 的 24 端口（LMTP 的注册端口）。
    pub fn loopback() -> Self {
        LmtpEndpoint::Tcp("127.0.0.1".to_string(), 24)
    }

    /// 从环境变量读取端点，供部署期覆盖：
    ///
    /// * `MAILSTACK_LMTP_SOCKET=/path/to/socket` —— 优先
    /// * `MAILSTACK_LMTP_ADDR=host:port` —— 其次
    ///
    /// 都没有则回落到 [`LmtpEndpoint::default_unix`]。
    pub fn from_env() -> Self {
        if let Ok(path) = std::env::var("MAILSTACK_LMTP_SOCKET") {
            if !path.trim().is_empty() {
                return LmtpEndpoint::Unix(PathBuf::from(path.trim()));
            }
        }
        if let Ok(addr) = std::env::var("MAILSTACK_LMTP_ADDR") {
            if let Some((host, port)) = addr.trim().rsplit_once(':') {
                if let Ok(port) = port.parse::<u16>() {
                    return LmtpEndpoint::Tcp(host.to_string(), port);
                }
            }
        }
        LmtpEndpoint::default_unix()
    }

    /// 便于日志与错误文案的展示形式。
    pub fn describe(&self) -> String {
        match self {
            LmtpEndpoint::Unix(path) => path.display().to_string(),
            LmtpEndpoint::Tcp(host, port) => format!("{host}:{port}"),
        }
    }
}

/// 单个收件人的投递结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientResult {
    pub recipient: String,
    /// 服务器给出的状态码（`DATA` 之后的那条应答）。
    pub code: u16,
    /// 应答文本（已去掉状态码与换行）。
    pub message: String,
}

impl RecipientResult {
    pub fn accepted(&self) -> bool {
        (200..300).contains(&self.code)
    }
}

/// 一次 LMTP 事务的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LmtpDelivery {
    /// 逐收件人的结果，顺序与传入的 `recipients` 一致。
    pub results: Vec<RecipientResult>,
}

impl LmtpDelivery {
    pub fn accepted(&self) -> Vec<&str> {
        self.results
            .iter()
            .filter(|r| r.accepted())
            .map(|r| r.recipient.as_str())
            .collect()
    }

    pub fn failed(&self) -> Vec<&RecipientResult> {
        self.results.iter().filter(|r| !r.accepted()).collect()
    }

    pub fn all_accepted(&self) -> bool {
        self.results.iter().all(RecipientResult::accepted)
    }
}

/// LMTP 客户端。
#[derive(Debug, Clone)]
pub struct LmtpClient {
    endpoint: LmtpEndpoint,
    /// `LHLO` 参数：必须是合法主机名。
    helo_name: String,
    timeout: Duration,
}

impl LmtpClient {
    pub fn new(endpoint: LmtpEndpoint, helo_name: impl Into<String>, timeout: Duration) -> Self {
        Self {
            endpoint,
            helo_name: helo_name.into(),
            timeout,
        }
    }

    pub fn endpoint(&self) -> &LmtpEndpoint {
        &self.endpoint
    }

    /// 投递一封邮件给一组收件人。
    ///
    /// 返回逐收件人的结果 —— **不**把「部分成功」压成一个布尔值：调用方需要知道
    /// 哪些收件人已经落箱，才不会在重试时重复投递。
    pub async fn deliver(
        &self,
        mail_from: &str,
        recipients: &[String],
        data: &str,
    ) -> StoreResult<LmtpDelivery> {
        if recipients.is_empty() {
            return Err(StoreError::Lmtp("no recipients to deliver".to_string()));
        }

        let stream = self.connect().await?;
        let mut io = BufReader::new(stream);

        let (greeting_code, greeting_text) = self.read_response(&mut io).await?;
        if !is_positive(greeting_code) {
            return Err(StoreError::Lmtp(format!(
                "LMTP server refused the connection: {greeting_code} {greeting_text}"
            )));
        }

        // LMTP 打招呼用 LHLO（不是 EHLO）。
        let (lhlo_code, lhlo_text) = self
            .command(&mut io, &format!("LHLO {}", self.helo_name))
            .await?;
        if !is_positive(lhlo_code) {
            return Err(StoreError::Lmtp(format!(
                "LHLO rejected: {lhlo_code} {lhlo_text}"
            )));
        }

        let (mail_code, mail_text) = self
            .command(&mut io, &format!("MAIL FROM:<{mail_from}>"))
            .await?;
        if !is_positive(mail_code) {
            return Err(StoreError::Lmtp(format!(
                "MAIL FROM rejected: {mail_code} {mail_text}"
            )));
        }

        // RCPT 阶段：被拒的收件人在这里就定案，其余进入 DATA。
        // `slots` 与 `recipients` 一一对应，因此最终结果顺序就是调用方传入的顺序。
        let mut slots: Vec<Option<RecipientResult>> = vec![None; recipients.len()];
        let mut pending: Vec<usize> = Vec::new();
        for (index, recipient) in recipients.iter().enumerate() {
            let (code, message) = self
                .command(&mut io, &format!("RCPT TO:<{recipient}>"))
                .await?;
            if is_positive(code) {
                pending.push(index);
            } else {
                slots[index] = Some(RecipientResult {
                    recipient: recipient.clone(),
                    code,
                    message,
                });
            }
        }

        if pending.is_empty() {
            // 全部在 RCPT 阶段被拒，没有内容需要提交。
            let _ = self.command(&mut io, "QUIT").await;
            return Ok(LmtpDelivery {
                results: collect(slots)?,
            });
        }

        let (data_code, data_text) = self.command(&mut io, "DATA").await?;
        if data_code != 354 {
            let _ = self.command(&mut io, "QUIT").await;
            return Err(StoreError::Lmtp(format!(
                "DATA rejected: {data_code} {data_text}"
            )));
        }

        // 正文已以 CRLF 结尾时**不得**再补一个。
        //
        // 原实现是 `format!("{}\r\n.\r\n", ...)` 无条件补，于是正文已以 CRLF
        // 结尾的邮件（绝大多数）落箱后**尾部凭空多出一个空行** ——
        // 那是对正文的改写，收件人转发或校验时上游的 DKIM body hash 会失效。
        //
        // 这正是 `smtp::client::terminate_data` 早就修好的同一个坑（同仓的
        // 注释里写着「与出站路径行为不一致」），LMTP 这一侧当时漏了。
        //
        // 刻意**不复用**那个函数：`store` 当前不依赖 `smtp`，为一个函数引入
        // 一条 crate 边（而 `smtp` 还带 TLS/拨号栈）不划算。判据与它逐条一致。
        let body = dot_stuff(data);
        let separator = if body.ends_with("\r\n") { "" } else { "\r\n" };
        let payload = format!("{body}{separator}.\r\n");
        self.write_all(&mut io, payload.as_bytes()).await?;

        // LMTP 的关键差异：DATA 之后**每个进入队列的收件人各回一条**应答。
        // 少读一条，多出来的那条就会被当成下一条命令的响应，连接就此错位。
        for &index in &pending {
            let (code, message) = self.read_response(&mut io).await?;
            slots[index] = Some(RecipientResult {
                recipient: recipients[index].clone(),
                code,
                message,
            });
        }

        let _ = self.command(&mut io, "QUIT").await;
        Ok(LmtpDelivery {
            results: collect(slots)?,
        })
    }

    async fn connect(&self) -> StoreResult<Stream> {
        let connect = async {
            match &self.endpoint {
                LmtpEndpoint::Unix(path) => UnixStream::connect(path)
                    .await
                    .map(Stream::Unix)
                    .map_err(|e| {
                        StoreError::Lmtp(format!("cannot connect to unix:{}: {e}", path.display()))
                    }),
                LmtpEndpoint::Tcp(host, port) => TcpStream::connect((host.as_str(), *port))
                    .await
                    .map(Stream::Tcp)
                    .map_err(|e| StoreError::Lmtp(format!("cannot connect to {host}:{port}: {e}"))),
            }
        };

        tokio::time::timeout(self.timeout, connect)
            .await
            .map_err(|_| {
                StoreError::Lmtp(format!(
                    "timed out after {:?} connecting to {}",
                    self.timeout,
                    self.endpoint.describe()
                ))
            })?
    }

    async fn command(&self, io: &mut BufReader<Stream>, line: &str) -> StoreResult<(u16, String)> {
        let payload = format!("{line}\r\n");
        self.write_all(io, payload.as_bytes()).await?;
        self.read_response(io).await
    }

    async fn read_response(&self, io: &mut BufReader<Stream>) -> StoreResult<(u16, String)> {
        let mut code: Option<u16> = None;
        let mut lines: Vec<String> = Vec::new();

        loop {
            let mut line = String::new();
            let read = tokio::time::timeout(self.timeout, io.read_line(&mut line))
                .await
                .map_err(|_| StoreError::Lmtp("timed out waiting for LMTP response".to_string()))?
                .map_err(|e| StoreError::Lmtp(format!("read failed: {e}")))?;
            if read == 0 {
                return Err(StoreError::Lmtp(
                    "connection closed by LMTP server".to_string(),
                ));
            }
            let trimmed = line.trim_end_matches(['\r', '\n']).to_string();
            let (this_code, continued) = parse_status_line(&trimmed)?;
            if code.is_none() {
                code = Some(this_code);
            }
            lines.push(trimmed);
            if !continued {
                break;
            }
        }

        Ok((code.unwrap_or(0), lines.join(" ")))
    }

    async fn write_all(&self, io: &mut BufReader<Stream>, bytes: &[u8]) -> StoreResult<()> {
        tokio::time::timeout(self.timeout, async {
            io.get_mut().write_all(bytes).await?;
            io.get_mut().flush().await
        })
        .await
        .map_err(|_| StoreError::Lmtp("timed out writing to LMTP server".to_string()))?
        .map_err(|e| StoreError::Lmtp(format!("write failed: {e}")))
    }
}

/// 建连后的流（unix socket 或 TCP）。
enum Stream {
    Unix(UnixStream),
    Tcp(TcpStream),
}

impl AsyncRead for Stream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Stream::Unix(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            Stream::Tcp(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Stream::Unix(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            Stream::Tcp(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Stream::Unix(s) => std::pin::Pin::new(s).poll_flush(cx),
            Stream::Tcp(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Stream::Unix(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            Stream::Tcp(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// 解析 `250-...` / `250 ...` → (状态码, 是否还有后续行)。
///
/// ## 为什么按字节切
///
/// 与 [`mailstack_smtp::client`](../../smtp/client.rs) 同一处缺陷的另一个副本：
/// `line[..3]` 是 &str 的**字节**索引，而状态码固定是 ASCII 三位数字。
/// 对端（Dovecot）回一个以多字节字符开头的行即让下标落在字符中间 → panic。
/// 可达性低于 SMTP 那一处（对端是本机 Dovecot），但修法一致：**按字节判定**，
/// 非数字直接返回协议错误。
fn parse_status_line(line: &str) -> StoreResult<(u16, bool)> {
    let bytes = line.as_bytes();
    if bytes.len() < 3 {
        return Err(StoreError::Lmtp(format!("malformed response: {line:?}")));
    }
    let digits = &bytes[..3];
    if !digits.iter().all(u8::is_ascii_digit) {
        return Err(StoreError::Lmtp(format!("malformed status code: {line:?}")));
    }
    let code: u16 = std::str::from_utf8(digits)
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| StoreError::Lmtp(format!("malformed status code: {line:?}")))?;
    Ok((code, bytes.get(3) == Some(&b'-')))
}

fn is_positive(code: u16) -> bool {
    (200..300).contains(&code)
}

/// 把逐位填充的 `slots` 收拢成结果列表。
///
/// 每个位置要么在 RCPT 阶段定案、要么在 DATA 之后定案，因此 `None` 只可能意味着
/// 服务器少给了应答 —— 那是协议错乱，必须报错而不是静默丢弃一个收件人。
fn collect(slots: Vec<Option<RecipientResult>>) -> StoreResult<Vec<RecipientResult>> {
    if slots.iter().any(Option::is_none) {
        return Err(StoreError::Lmtp(
            "LMTP server did not answer for every recipient".to_string(),
        ));
    }
    Ok(slots.into_iter().flatten().collect())
}

/// DATA 阶段的行首句点转义（RFC 5321 §4.5.2，LMTP 沿用同一套 DATA 帧格式）。
///
/// 与 `smtp::client::dot_stuff` 逐条一致，包括**按裸 LF 切行**：
/// 只按 `\r\n` 切分会让 `<裸 LF>.` 开头的行逃过转义，Dovecot 在那一行判定
/// DATA 结束，剩余正文被当作 LMTP 命令解析。
fn dot_stuff(data: &str) -> String {
    data.split('\n')
        .map(|line| {
            // 去掉切分带来的 `\r`（它属于行终止符，不属于行内容）。
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

#[cfg(test)]
mod tests {
    use super::*;

    /// 反例守卫：正文已以 CRLF 结尾时，落箱帧**不得**多出一个空行。
    ///
    /// 原实现无条件 `format!("{}\r\n.\r\n", ...)`，于是每封以 CRLF 结尾的邮件
    /// （绝大多数）落箱后尾部凭空多出一个空行 —— 对正文的改写，收件人转发或
    /// 校验时上游的 DKIM body hash 会失效。
    ///
    /// 端到端测试测不出来：它们只读到单独的 `.` 就停，不检查 `.` 之前的内容。
    #[test]
    fn a_body_already_ending_with_crlf_gets_no_extra_blank_line() {
        let stuff = dot_stuff("line1\r\nline2\r\n");
        assert_eq!(stuff, "line1\r\nline2\r\n", "转义不得改动正文的行结构");
        let separator = if stuff.ends_with("\r\n") { "" } else { "\r\n" };
        assert_eq!(
            format!("{stuff}{separator}.\r\n"),
            "line1\r\nline2\r\n.\r\n",
            "已以 CRLF 结尾时不得再补一个空行"
        );

        // 反例：未以 CRLF 结尾时**必须**补，否则 Dovecot 一直等这一行结束。
        let no_eol = dot_stuff("line1");
        let separator = if no_eol.ends_with("\r\n") { "" } else { "\r\n" };
        assert_eq!(format!("{no_eol}{separator}.\r\n"), "line1\r\n.\r\n");
    }

    /// 反例守卫：裸 LF 开头的句点行也必须转义，否则 Dovecot 在该行截断正文。
    #[test]
    fn a_bare_lf_dot_line_is_stuffed_too() {
        assert_eq!(
            dot_stuff("body\n.evil\nrest"),
            "body\r\n..evil\r\nrest",
            "裸 LF 后的句点行必须被加倍"
        );
        assert_eq!(dot_stuff("a\r\n.b\n.c"), "a\r\n..b\r\n..c");
    }
}
