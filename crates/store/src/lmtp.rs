use std::path::PathBuf;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UnixStream};

use crate::error::{StoreError, StoreResult};

pub const DEFAULT_LMTP_SOCKET: &str = "/run/dovecot/lmtp";

const MAX_RESPONSE_LINE_BYTES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LmtpEndpoint {
    Unix(PathBuf),
    Tcp(String, u16),
}

impl LmtpEndpoint {
    pub fn default_unix() -> Self {
        LmtpEndpoint::Unix(PathBuf::from(DEFAULT_LMTP_SOCKET))
    }

    pub fn unix(path: impl Into<PathBuf>) -> Self {
        LmtpEndpoint::Unix(path.into())
    }

    pub fn loopback() -> Self {
        LmtpEndpoint::Tcp("127.0.0.1".to_string(), 24)
    }

    pub fn from_env() -> Self {
        Self::from_env_with_default(Self::default_unix())
    }

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

    pub fn describe(&self) -> String {
        match self {
            LmtpEndpoint::Unix(path) => path.display().to_string(),
            LmtpEndpoint::Tcp(host, port) => format!("{host}:{port}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientResult {
    pub recipient: String,

    pub code: u16,

    pub message: String,
}

impl RecipientResult {
    pub fn accepted(&self) -> bool {
        (200..300).contains(&self.code)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LmtpDelivery {
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

#[derive(Debug, Clone)]
pub struct LmtpClient {
    endpoint: LmtpEndpoint,

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

    pub async fn deliver(
        &self,
        mail_from: &str,
        recipients: &[String],
        data: &str,
    ) -> StoreResult<LmtpDelivery> {
        if recipients.is_empty() {
            return Err(StoreError::Lmtp("no recipients to deliver".to_string()));
        }

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

        let body = dot_stuff(data);
        let separator = if body.ends_with("\r\n") { "" } else { "\r\n" };
        let payload = format!("{body}{separator}.\r\n");
        self.write_all(&mut io, payload.as_bytes()).await?;

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

fn strip_host_brackets(host: &str) -> &str {
    let trimmed = host.trim();
    trimmed
        .strip_prefix('[')
        .and_then(|stripped| stripped.strip_suffix(']'))
        .unwrap_or(trimmed)
}

fn parse_tcp_endpoint(addr: &str) -> Option<(String, u16)> {
    let (host, port) = addr.trim().rsplit_once(':')?;
    let port = port.parse::<u16>().ok()?;
    let host = strip_host_brackets(host);
    if host.is_empty() {
        return None;
    }
    Some((host.to_string(), port))
}

fn collect(slots: Vec<Option<RecipientResult>>) -> StoreResult<Vec<RecipientResult>> {
    if slots.iter().any(Option::is_none) {
        return Err(StoreError::Lmtp(
            "LMTP server did not answer for every recipient".to_string(),
        ));
    }
    Ok(slots.into_iter().flatten().collect())
}

fn dot_stuff(data: &str) -> String {
    let bytes = data.as_bytes();

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
            let is_terminator = index + 1 == bytes.len() || bytes[index + 1] == b'\n';
            if is_terminator {
                index += 1;
                continue;
            }
        }
        out.push(byte);
        index += 1;
    }

    String::from_utf8(out).expect("dot_stuff 输出必然是合法 UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let no_eol = dot_stuff("line1");
        let separator = if no_eol.ends_with("\r\n") { "" } else { "\r\n" };
        assert_eq!(format!("{no_eol}{separator}.\r\n"), "line1\r\n.\r\n");
    }

    #[test]
    fn a_bare_lf_dot_line_is_stuffed_too() {
        assert_eq!(
            dot_stuff("body\n.evil\nrest"),
            "body\r\n..evil\r\nrest",
            "裸 LF 后的句点行必须被加倍"
        );
        assert_eq!(dot_stuff("a\r\n.b\n.c"), "a\r\n..b\r\n..c");
    }

    #[test]
    fn lone_cr_inside_a_line_is_preserved() {
        assert_eq!(dot_stuff("a\r\rb"), "a\r\rb", "行内裸 CR 不是行尾");
        assert_eq!(dot_stuff("a\r\r\nb"), "a\r\r\nb", "只剥属于行尾的那一个 CR");
        assert_eq!(dot_stuff("x\r"), "x", "数据末尾的单个 CR 属于行尾");
        assert_eq!(dot_stuff("x\r\r"), "x\r");

        assert_eq!(dot_stuff("正文\n.x"), "正文\r\n..x");
    }

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

        assert_eq!(parse_tcp_endpoint("[::1]:lmtp"), None);
        assert_eq!(parse_tcp_endpoint(":24"), None);
    }

    #[test]
    fn host_brackets_are_stripped_at_the_connection_layer_too() {
        assert_eq!(strip_host_brackets("[::1]"), "::1");
        assert_eq!(strip_host_brackets(" 127.0.0.1 "), "127.0.0.1");
        assert_eq!(strip_host_brackets("::1"), "::1");
    }

    #[tokio::test]
    async fn envelope_addresses_with_crlf_or_nul_are_rejected_before_any_io() {
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

    #[tokio::test]
    async fn helo_names_with_crlf_or_nul_are_rejected_before_any_io() {
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

            let junk = vec![b'x'; MAX_RESPONSE_LINE_BYTES + 64];
            let _ = write.write_all(&junk).await;
            let _ = write.flush().await;

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
