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

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UnixStream};

use crate::error::{StoreError, StoreResult};

/// 默认的 Dovecot LMTP unix socket。
///
/// Dovecot 自带默认值（基线配置未覆盖 `service lmtp`），去掉 Postfix 之后不再有
/// `/var/spool/postfix/private/dovecot-lmtp` 这个 postfix 专属路径。
pub const DEFAULT_LMTP_SOCKET: &str = "/run/dovecot/lmtp";

/// 单行应答的长度上限。
///
/// 正常的 LMTP 应答远短于此（Dovecot 的应答几十字节）。对端失控 —— 或被替换成
/// 恶意实现 —— 时，一条永不出换行的应答原本可以让 `read_line` **无界**吃内存。
/// 超限按协议错误断开：截断出的半行会被上层当完整应答解析（状态码恰好在前
/// 3 字节），那比直接断开更危险。
const MAX_RESPONSE_LINE_BYTES: usize = 4096;

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
        Self::from_env_with_default(Self::default_unix())
    }

    /// 同 [`LmtpEndpoint::from_env`]，但把「都没有」的回落目标换成调用方给的默认。
    ///
    /// MailStack 自带 LMTP 服务端之后，`mailstackd` 的默认对端是**自己的** socket；
    /// 只有显式设置环境变量才指向别的实现（例如仍在运行的 Dovecot）。
    pub fn from_env_with_default(default: Self) -> Self {
        if let Ok(path) = std::env::var("MAILSTACK_LMTP_SOCKET") {
            if !path.trim().is_empty() {
                return LmtpEndpoint::Unix(PathBuf::from(path.trim()));
            }
        }
        if let Ok(addr) = std::env::var("MAILSTACK_LMTP_ADDR") {
            if let Some((host, port)) = parse_tcp_endpoint(&addr) {
                return LmtpEndpoint::Tcp(host, port);
            }
        }
        default
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
        // 信封地址会被 `format!` 直接拼进协议行（`MAIL FROM:<…>` / `RCPT TO:<…>`）。
        // 地址里的 CR/LF 等于在事务里**注入额外命令**（与入站走私同型的注入，
        // 只是方向相反）；NUL 则会让对端把命令截断成另一条。在入口统一拒绝，
        // 而不是相信每个上游生产者都校验过。
        if mail_from.contains(['\r', '\n', '\0'])
            || recipients
                .iter()
                .any(|recipient| recipient.contains(['\r', '\n', '\0']))
        {
            return Err(StoreError::Lmtp(
                "envelope address must not contain CR, LF or NUL (SMTP command injection)"
                    .to_string(),
            ));
        }
        // `LHLO <name>` 是**另一处**直接 `format!` 进协议行的地方（R2-010）。
        // 原先只校验了信封地址：`helo_name` 在 `bin/mailstackd` 里取自
        // `config.mail_host`，经 API 写入时已被 `validate_setup_identity` 约束，
        // 但 `setup.json` 是 root 可手改的，且 `LmtpClient::new` 是 `pub` 构造器 ——
        // 同一个入口统一拒绝，不信任任何上游生产者。
        let helo = self.helo_name.trim();
        if helo.is_empty()
            || helo.contains(['\r', '\n', '\0'])
            || helo.chars().any(|c| c.is_control() || c.is_whitespace())
        {
            return Err(StoreError::Lmtp(
                "LHLO name must be a non-empty host name without spaces, CR, LF or NUL (SMTP command injection)"
                    .to_string(),
            ));
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
        let (lhlo_code, lhlo_text) = self.command(&mut io, &format!("LHLO {helo}")).await?;
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
                LmtpEndpoint::Tcp(host, port) => {
                    // 端点可能来自配置或环境变量的「书写形式」：IPv6 字面量带方括号。
                    // `TcpStream::connect` 要的是**裸地址**，方括号不剥掉就永远连不上。
                    let host = strip_host_brackets(host);
                    TcpStream::connect((host, *port))
                        .await
                        .map(Stream::Tcp)
                        .map_err(|e| {
                            StoreError::Lmtp(format!("cannot connect to {host}:{port}: {e}"))
                        })
                }
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
            let line = self.read_line_bounded(io).await?;
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

    /// 读一行应答，**带长度上限**（[`MAX_RESPONSE_LINE_BYTES`]）。
    ///
    /// `BufReader::read_line` 没有上限：它会一直 append 到出现 `\n` 为止，对端
    /// 只要不发换行就能让内存无界增长。这里用 `fill_buf` + `consume` 手工实现
    /// 「读到换行、但累计不超过上限」—— 走的仍是 `BufReader` 的内部缓冲，
    /// 不会越过它读到底层流而丢掉已缓冲字节。超限按协议错误断开（不截断半行）。
    async fn read_line_bounded(&self, io: &mut BufReader<Stream>) -> StoreResult<String> {
        use tokio::io::AsyncBufReadExt;

        let mut line: Vec<u8> = Vec::new();
        loop {
            let available = tokio::time::timeout(self.timeout, io.fill_buf())
                .await
                .map_err(|_| StoreError::Lmtp("timed out waiting for LMTP response".to_string()))?
                .map_err(|e| StoreError::Lmtp(format!("read failed: {e}")))?;
            if available.is_empty() {
                if line.is_empty() {
                    return Err(StoreError::Lmtp(
                        "connection closed by LMTP server".to_string(),
                    ));
                }
                // EOF 前的残余（无结尾换行）：与 read_line 的行为一致，交给
                // 上层按「格式错误」处理。
                break;
            }
            match available.iter().position(|&byte| byte == b'\n') {
                Some(index) => {
                    if line.len() + index + 1 > MAX_RESPONSE_LINE_BYTES {
                        return Err(StoreError::Lmtp(format!(
                            "LMTP response line exceeds {MAX_RESPONSE_LINE_BYTES} bytes"
                        )));
                    }
                    line.extend_from_slice(&available[..=index]);
                    io.consume(index + 1);
                    break;
                }
                None => {
                    if line.len() + available.len() > MAX_RESPONSE_LINE_BYTES {
                        return Err(StoreError::Lmtp(format!(
                            "LMTP response line exceeds {MAX_RESPONSE_LINE_BYTES} bytes"
                        )));
                    }
                    line.extend_from_slice(available);
                    let filled = available.len();
                    io.consume(filled);
                }
            }
        }
        // 与 read_line 一致：非法 UTF-8 是读错误，而不是静默替换字节。
        String::from_utf8(line)
            .map_err(|e| StoreError::Lmtp(format!("read failed: invalid utf-8: {e}")))
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

/// 剥掉 IPv6 字面量的方括号（`[::1]` → `::1`）。
///
/// 方括号只是**书写形式**里的分隔标点（区分地址与端口）；`TcpStream::connect`
/// 要的是裸地址。放在连接点而不是只放在配置解析点：端点可能来自多处
/// （环境变量、配置文件、测试），任何一处带括号都不得让连接永远失败。
fn strip_host_brackets(host: &str) -> &str {
    let trimmed = host.trim();
    trimmed
        .strip_prefix('[')
        .and_then(|stripped| stripped.strip_suffix(']'))
        .unwrap_or(trimmed)
}

/// 解析 `host:port` 形式的地址（`MAILSTACK_LMTP_ADDR`）。
///
/// 用 `rsplit_once(':')` 取**最后一个**冒号，因此带方括号的 IPv6（`[::1]:24`）
/// 能正确分出地址与端口；方括号在此剥掉。无效端口 / 空主机返回 `None`，
/// 让调用方回落到默认端点，而不是拿着一个必然失败的端点继续。
fn parse_tcp_endpoint(addr: &str) -> Option<(String, u16)> {
    let (host, port) = addr.trim().rsplit_once(':')?;
    let port = port.parse::<u16>().ok()?;
    let host = strip_host_brackets(host);
    if host.is_empty() {
        return None;
    }
    Some((host.to_string(), port))
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
///
/// 实现是**单次扫描**、在输出缓冲上就地插入：原实现 `split('\n') → map →
/// collect → join` 会对整封邮件做约 4 次全量复制，而这是每封信的热路径。
/// 语义逐条对应原实现：`CRLF`/裸 `LF` 都归一为 `CRLF` 行尾；紧贴 `LF` 之前
/// （或数据末尾）的单个 `CR` 属于行终止符、被剥掉，其余 `CR` 原样保留；
/// 行首 `.` 加倍。多字节 UTF-8 不受影响（多字节序列不含 0x0A/0x0D 字节，
/// 复制与 ASCII 插入不破坏编码）。
fn dot_stuff(data: &str) -> String {
    let bytes = data.as_bytes();
    // 常见情形（无行首句点、行尾已归一）输出不比输入长，+16 免去正常邮件的重分配。
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len() + 16);
    let mut at_line_start = true;
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'\n' {
            out.extend_from_slice(b"\r\n");
            at_line_start = true;
            index += 1;
            continue;
        }
        if at_line_start && byte == b'.' {
            out.push(b'.');
        }
        at_line_start = false;
        if byte == b'\r' {
            // `CR` 只在「恰好在 `LF` 之前或数据末尾」时是行终止符的一部分：
            // 此时跳过它（由 `LF` 分支补成 `CRLF`，或在末尾剥掉）。
            let is_terminator = index + 1 == bytes.len() || bytes[index + 1] == b'\n';
            if is_terminator {
                index += 1;
                continue;
            }
        }
        out.push(byte);
        index += 1;
    }
    // 输入是 &str、插入的都是 ASCII 字节，输出必然是合法 UTF-8 —— 此处不可达。
    String::from_utf8(out).expect("dot_stuff 输出必然是合法 UTF-8")
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

    /// 与原实现逐条一致的边界：行内的裸 `CR` 不是行终止符，必须原样保留；
    /// 只有紧贴 `LF`（或数据末尾）的那个 `CR` 才被剥掉。
    #[test]
    fn lone_cr_inside_a_line_is_preserved() {
        assert_eq!(dot_stuff("a\r\rb"), "a\r\rb", "行内裸 CR 不是行尾");
        assert_eq!(dot_stuff("a\r\r\nb"), "a\r\r\nb", "只剥属于行尾的那一个 CR");
        assert_eq!(dot_stuff("x\r"), "x", "数据末尾的单个 CR 属于行尾");
        assert_eq!(dot_stuff("x\r\r"), "x\r");
        // 多字节内容不受逐字节扫描影响。
        assert_eq!(dot_stuff("正文\n.x"), "正文\r\n..x");
    }

    /// IPv6 字面量的方括号是书写标点：解析与连接两层都要剥掉，
    /// 否则 `[::1]:24` 永远连不上。
    #[test]
    fn tcp_endpoint_parsing_strips_ipv6_brackets() {
        assert_eq!(
            parse_tcp_endpoint("[::1]:24"),
            Some(("::1".to_string(), 24))
        );
        assert_eq!(
            parse_tcp_endpoint(" 127.0.0.1:24 "),
            Some(("127.0.0.1".to_string(), 24))
        );
        // 无效端口与空主机不产生端点：回落默认端点，而不是拿着必然失败的端点。
        assert_eq!(parse_tcp_endpoint("[::1]:lmtp"), None);
        assert_eq!(parse_tcp_endpoint(":24"), None);
    }

    #[test]
    fn host_brackets_are_stripped_at_the_connection_layer_too() {
        // 端点也可能绕过 parse_tcp_endpoint 直接构造（配置文件路径），
        // 所以连接点同样剥括号 —— 这里验证该纯函数本身。
        assert_eq!(strip_host_brackets("[::1]"), "::1");
        assert_eq!(strip_host_brackets(" 127.0.0.1 "), "127.0.0.1");
        assert_eq!(strip_host_brackets("::1"), "::1");
    }

    /// 信封地址直接 `format!` 进协议行：CR/LF/NUL 必须在任何 I/O 之前被拒绝。
    #[tokio::test]
    async fn envelope_addresses_with_crlf_or_nul_are_rejected_before_any_io() {
        // 用一个「连上必失败」的端点：若守卫未生效，错误将是连接错误而不是注入拒绝。
        let client = LmtpClient::new(
            LmtpEndpoint::Tcp("127.0.0.1".to_string(), 1),
            "mail.example.org",
            Duration::from_millis(200),
        );

        let injected = "r@example.org\r\nRCPT TO:<victim@x>";
        let error = client
            .deliver(
                "s@example.org",
                &[injected.to_string()],
                "Subject: t\r\n\r\nbody",
            )
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("CR, LF or NUL"),
            "收件人注入必须在入口被拒绝：{error}"
        );

        let error = client
            .deliver(
                "s@example.org\r\nBcc: evil@x",
                &["r@example.org".to_string()],
                "body",
            )
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("CR, LF or NUL"),
            "发件人注入必须在入口被拒绝：{error}"
        );
    }

    /// `LHLO` 的参数同样直接拼进协议行：CR/LF/NUL 必须在任何 I/O 之前被拒绝
    /// （R2-010：原先只守了信封地址，`helo_name` 是唯一漏网的拼接点）。
    #[tokio::test]
    async fn helo_names_with_crlf_or_nul_are_rejected_before_any_io() {
        // 同一条「连上必失败」的端点：若守卫未生效，错误会是连接错误而不是注入拒绝。
        let client = LmtpClient::new(
            LmtpEndpoint::Tcp("127.0.0.1".to_string(), 1),
            "mail.example.org\r\nRCPT TO:<victim@x>",
            Duration::from_millis(200),
        );
        let error = client
            .deliver("s@example.org", &["r@example.org".to_string()], "body")
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("CR, LF or NUL"),
            "LHLO 注入必须在入口被拒绝：{error}"
        );

        // NUL 与空名字同样拒绝；带空白的参数不是合法主机名（会拼出额外参数）。
        for bad in ["mail.example.org\0", "", "  ", "mail example.org"] {
            let client = LmtpClient::new(
                LmtpEndpoint::Tcp("127.0.0.1".to_string(), 1),
                bad,
                Duration::from_millis(200),
            );
            let error = client
                .deliver("s@example.org", &["r@example.org".to_string()], "body")
                .await
                .unwrap_err();
            assert!(
                error.to_string().contains("LHLO name"),
                "{bad:?} 必须在入口被拒绝：{error}"
            );
        }
    }

    /// 超长且不出换行的应答必须按协议错误断开，而不是无界吃内存
    /// （`BufReader::read_line` 没有上限，这里验证手工限长生效）。
    #[tokio::test]
    async fn an_oversized_response_line_is_a_protocol_error_not_unbounded_memory() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let Ok((socket, _)) = listener.accept().await else {
                return;
            };
            let (_, mut write) = socket.into_split();
            let _ = write.write_all(b"220 ready\r\n").await;
            let _ = write.flush().await;
            // 一条超出上限且永不出换行的「应答」。
            let junk = vec![b'x'; MAX_RESPONSE_LINE_BYTES + 64];
            let _ = write.write_all(&junk).await;
            let _ = write.flush().await;
            // 挂住连接，让客户端（而不是服务端关闭）触发超限判定。
            tokio::time::sleep(Duration::from_secs(5)).await;
        });

        let client = LmtpClient::new(
            LmtpEndpoint::Tcp("127.0.0.1".to_string(), port),
            "mail.example.org",
            Duration::from_secs(5),
        );
        let error = client
            .deliver(
                "s@example.org",
                &["r@example.org".to_string()],
                "Subject: t\r\n\r\nbody",
            )
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("exceeds"),
            "超长应答必须按协议错误断开：{error}"
        );
    }
}
