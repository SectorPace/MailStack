//! 带缓冲的行读取器（IMAP literal 与 POP3 多行应答共用）。
//!
//! ## 为什么缓冲区必须归会话所有，而不是每次包一层 `BufReader`
//!
//! 两条真实约束：
//!
//! 1. **STARTTLS 的明文注入**：客户端可以在 `STARTTLS` 后立刻拼接明文命令。若读
//!    缓冲区在升级时被丢弃，那些字节就随之消失（正确）；若每次从内核重读，攻击者
//!    可以把明文命令藏进 TLS 握手前的最后一次 `read` 里。会话层在升级时**主动丢弃**
//!    缓冲区内容（[`LineIo::into_inner`]），这是 TLS 剥离防护的一半。
//! 2. **流水线**：客户端常把 `A001 ...\r\nA002 ...\r\n` 一起发来。一次 `read` 可能
//!    读回两条命令，剩余字节必须留给下一次 `read_line`。
//!
//! ## 取消安全性
//!
//! [`LineIo::read_line`] 只在 `read` 上等待，而 `AsyncReadExt::read` 是取消安全的：
//! 被 `tokio::select!` 丢弃时，已读到的字节留在 `self.buffer`，下一层调用继续。
//! [`LineIo::read_exact`] **不是**取消安全的（它可能已消费一部分字节），因此只在
//! 「已经收到 literal 声明、直到读满之前不接受任何其他事件」的路径使用。

use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{MailError, Result};

const READ_CHUNK: usize = 4096;

/// `COMPRESS=DEFLATE`（RFC 4978）启用后的编解码状态。
///
/// RFC 4978 用的是**裸 DEFLATE**（无 zlib 头）。读取侧先把压缩字节攒进 `input`，
/// 再尽量解压进 [`LineIo::buffer`]；写入侧每次写都带 `Sync` flush，保证对端能立即
/// 解出完整应答（IMAP 是请求/响应式的，不能等下一次写再冲刷）。
struct DeflateState {
    decompress: flate2::Decompress,
    compress: flate2::Compress,
    /// 已从底层流读到、尚未被 inflate 消费的压缩字节。
    input: Vec<u8>,
}

pub struct LineIo<S> {
    io: S,
    buffer: Vec<u8>,
    compression: Option<DeflateState>,
}

impl<S> LineIo<S> {
    pub fn new(io: S) -> Self {
        Self {
            io,
            buffer: Vec::new(),
            compression: None,
        }
    }

    /// 启用 DEFLATE。调用方必须**先把切换应答写并 flush 出去**，再调用本方法：
    /// 应答本身是明文，之后的字节才压缩（RFC 4978 §3）。
    ///
    /// 会丢弃当前读缓冲：`COMPRESS` 之前客户端发来的字节按 RFC 4978 都是明文，
    /// 不能当作压缩流继续解析（与 STARTTLS 丢弃明文缓冲同理，避免注入）。
    pub fn enable_compression(&mut self) -> Result<()> {
        if self.compression.is_some() {
            return Err(MailError::protocol("compression is already enabled"));
        }
        self.buffer.clear();
        self.compression = Some(DeflateState {
            decompress: flate2::Decompress::new(false),
            compress: flate2::Compress::new(flate2::Compression::default(), false),
            input: Vec::new(),
        });
        Ok(())
    }

    /// 是否已启用压缩（测试与幂等检查用）。
    pub fn compression_enabled(&self) -> bool {
        self.compression.is_some()
    }

    /// 取回底层流。**缓冲区内容被丢弃** —— 这正是 STARTTLS 升级点需要的语义。
    pub fn into_inner(self) -> S {
        self.io
    }

    /// 当前已缓冲、尚未被消费的字节数（测试用）。
    pub fn buffered(&self) -> usize {
        self.buffer.len()
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> LineIo<S> {
    /// 读一行，去掉行尾 CRLF。EOF 且无残留时返回 `Ok(None)`。
    ///
    /// `max` 是**单行上限**；超过即协议错（长度耗尽攻击），并清空缓冲。
    pub async fn read_line(&mut self, max: usize) -> Result<Option<Vec<u8>>> {
        loop {
            if let Some(position) = self.buffer.iter().position(|&byte| byte == b'\n') {
                // 行长必须在**返回之前**校验：若只在「缓冲里还没有换行」时检查，
                // 一次 read 正好带回 `max + 几个字节 + CRLF` 时，超长行会从
                // 「发现换行」这条路径逃逸。
                let content_len =
                    position - usize::from(position > 0 && self.buffer[position - 1] == b'\r');
                if content_len > max {
                    self.buffer.clear();
                    return Err(MailError::protocol(format!("line exceeds {max} bytes")));
                }
                let mut line: Vec<u8> = self.buffer.drain(..=position).collect();
                line.pop();
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                return Ok(Some(line));
            }
            if self.buffer.len() > max {
                self.buffer.clear();
                return Err(MailError::protocol(format!("line exceeds {max} bytes")));
            }

            if !self.pump().await? {
                if self.buffer.is_empty() {
                    return Ok(None);
                }
                let mut line = std::mem::take(&mut self.buffer);
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                return Ok(Some(line));
            }
            // 没有换行时也要挡住无限增长（`max` 之外再留一点余量给即将出现的 LF）。
            if self.buffer.len() > max.saturating_add(READ_CHUNK) {
                self.buffer.clear();
                return Err(MailError::protocol(format!("line exceeds {max} bytes")));
            }
        }
    }

    /// 从底层流再取一些字节追加到 `buffer`；启用压缩时先解压。
    ///
    /// 返回 `Ok(false)` 表示底层流已 EOF 且没有更多可解压的内容。取消安全性：
    /// 只在 `io.read` 上等待，解压是同步的，因此被 `select!` 丢弃时已读到的原始
    /// 压缩字节仍留在 `state.input` 里，下次调用继续。
    async fn pump(&mut self) -> Result<bool> {
        let Self {
            io,
            buffer,
            compression,
        } = self;
        if compression.is_none() {
            let mut chunk = [0u8; READ_CHUNK];
            let read = io
                .read(&mut chunk)
                .await
                .map_err(|error| MailError::io(PathBuf::from("<stream>"), error))?;
            if read == 0 {
                return Ok(false);
            }
            buffer.extend_from_slice(&chunk[..read]);
            return Ok(true);
        }
        loop {
            let state = compression.as_mut().expect("checked above");
            if !state.input.is_empty() {
                let mut out = [0u8; READ_CHUNK];
                let before_in = state.decompress.total_in();
                let before_out = state.decompress.total_out();
                let status = state
                    .decompress
                    .decompress(&state.input, &mut out, flate2::FlushDecompress::None)
                    .map_err(|error| {
                        MailError::protocol(format!("corrupt DEFLATE stream: {error}"))
                    })?;
                let consumed = (state.decompress.total_in() - before_in) as usize;
                let produced = (state.decompress.total_out() - before_out) as usize;
                if consumed > 0 {
                    state.input.drain(..consumed);
                }
                if produced > 0 {
                    buffer.extend_from_slice(&out[..produced]);
                    return Ok(true);
                }
                if status == flate2::Status::StreamEnd {
                    return Ok(false);
                }
            }
            let mut chunk = [0u8; READ_CHUNK];
            let read = io
                .read(&mut chunk)
                .await
                .map_err(|error| MailError::io(PathBuf::from("<stream>"), error))?;
            if read == 0 {
                return Ok(false);
            }
            state.input.extend_from_slice(&chunk[..read]);
        }
    }

    /// 精确读取 `count` 字节（IMAP literal）。`max` 是硬上限。
    ///
    /// ## 不按 count 预分配
    ///
    /// `Vec::with_capacity(count)` + `resize(count, 0)` 会在**收到任何字节之前**
    /// 就提交并清零最多 32 MiB。攻击者只要声明 `{33554432}`、等服务器回 `+` 后
    /// 不再发送数据，就能让每条连接常驻 32 MiB；512 条连接 ≈ 16 GiB。这里按
    /// 64 KiB 分块读取，内存只随实际到达的字节增长。
    pub async fn read_exact(&mut self, count: usize, max: usize) -> Result<Vec<u8>> {
        if count > max {
            return Err(MailError::protocol(format!(
                "literal of {count} bytes exceeds limit {max}"
            )));
        }
        let mut out = Vec::with_capacity(count.min(READ_CHUNK));
        while out.len() < count {
            if !self.buffer.is_empty() {
                let take = (count - out.len()).min(self.buffer.len());
                out.extend(self.buffer.drain(..take));
                continue;
            }
            if !self.pump().await? {
                return Err(MailError::protocol(
                    "connection closed in the middle of a literal",
                ));
            }
        }
        Ok(out)
    }

    pub async fn write_all(&mut self, bytes: &[u8]) -> Result<()> {
        if self.compression.is_none() {
            return self
                .io
                .write_all(bytes)
                .await
                .map_err(|error| MailError::io(PathBuf::from("<stream>"), error));
        }
        let mut out: Vec<u8> = Vec::with_capacity(bytes.len() + 64);
        {
            let state = self.compression.as_mut().expect("checked above");
            state
                .compress
                .compress_vec(bytes, &mut out, flate2::FlushCompress::Sync)
                .map_err(|error| {
                    MailError::storage(format!("DEFLATE compression failed: {error}"))
                })?;
        }
        self.io
            .write_all(&out)
            .await
            .map_err(|error| MailError::io(PathBuf::from("<stream>"), error))
    }

    pub async fn flush(&mut self) -> Result<()> {
        self.io
            .flush()
            .await
            .map_err(|error| MailError::io(PathBuf::from("<stream>"), error))
    }
}

/// 原样透传给底层流的 `AsyncWrite` 实现（POP3 的传输编码用它）。
///
/// **不做压缩**：`COMPRESS=DEFLATE` 只经 [`LineIo::write_all`] 生效。IMAP 全部写
/// 走后者，POP3 不支持压缩，因此当前没有「压缩连接误用本实现」的路径。
impl<S: AsyncWrite + Unpin> AsyncWrite for LineIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn lines_survive_pipelining_and_crlf() {
        let (client, server) = tokio::io::duplex(64);
        let mut client = client;
        client.write_all(b"A1 NOOP\r\nA2 NOOP\nA3").await.unwrap();
        drop(client);

        let mut io = LineIo::new(server);
        assert_eq!(io.read_line(1024).await.unwrap().unwrap(), b"A1 NOOP");
        assert_eq!(io.read_line(1024).await.unwrap().unwrap(), b"A2 NOOP");
        // EOF 前的半行按行返回，随后才 None。
        assert_eq!(io.read_line(1024).await.unwrap().unwrap(), b"A3");
        assert!(io.read_line(1024).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn overlong_lines_are_refused_without_unbounded_growth() {
        let (client, server) = tokio::io::duplex(16 * 1024);
        let mut client = client;
        client.write_all(&vec![b'x'; 9000]).await.unwrap();
        drop(client);
        let mut io = LineIo::new(server);
        let error = io.read_line(100).await.expect_err("必须拒绝超长行");
        assert_eq!(error.kind(), "ProtocolError");
        assert_eq!(io.buffered(), 0, "拒绝后不得保留攻击者的字节");
    }

    #[tokio::test]
    async fn a_newline_does_not_let_an_overlong_line_through() {
        // 关键回归：换行与超长内容可能在同一次 read 里到达；只检查「没有换行
        // 且缓冲过大」会漏掉这条路径。
        let (mut client, server) = tokio::io::duplex(16 * 1024);
        client.write_all(&vec![b'x'; 9000]).await.unwrap();
        client.write_all(b"\r\n").await.unwrap();
        drop(client);
        let mut io = LineIo::new(server);
        let error = io
            .read_line(100)
            .await
            .expect_err("带换行的超长行同样必须被拒");
        assert_eq!(error.kind(), "ProtocolError");
        assert_eq!(io.buffered(), 0);
    }

    #[tokio::test]
    async fn literal_reads_span_buffer_boundaries() {
        let (client, server) = tokio::io::duplex(64);
        let mut client = client;
        client.write_all(b"{5}\r\nhello world\r\n").await.unwrap();
        drop(client);
        let mut io = LineIo::new(server);
        assert_eq!(io.read_line(1024).await.unwrap().unwrap(), b"{5}");
        assert_eq!(io.read_exact(5, 1024).await.unwrap(), b"hello");
        assert_eq!(io.read_line(1024).await.unwrap().unwrap(), b" world");
        assert!(io.read_exact(64, 16).await.is_err(), "超过上限必须拒绝");
    }

    #[tokio::test]
    async fn into_inner_drops_buffered_plaintext() {
        let (mut client, server) = tokio::io::duplex(64);
        client.write_all(b"A1 NOOP\r\nINJECTED\r\n").await.unwrap();
        let mut io = LineIo::new(server);
        assert_eq!(io.read_line(1024).await.unwrap().unwrap(), b"A1 NOOP");
        assert!(
            io.buffered() > 0,
            "第二条命令应已读入会话缓冲区（模拟明文夹带）"
        );
        // 升级点取回流时，`INJECTED` 随缓冲区一起被丢弃，而不是进入 TLS 会话。
        let raw = io.into_inner();
        drop(raw);
    }

    #[tokio::test]
    async fn deflate_round_trips_lines_and_literals() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let mut client = LineIo::new(client_io);
        let mut server = LineIo::new(server_io);
        client.enable_compression().unwrap();
        server.enable_compression().unwrap();
        assert!(client.compression_enabled());
        assert!(
            server.enable_compression().is_err(),
            "重复启用压缩必须被拒绝"
        );

        // 客户端 → 服务端：多条命令 + literal 在同一次压缩流里。
        client
            .write_all(b"A1 NOOP\r\nA2 APPEND {5}\r\n")
            .await
            .unwrap();
        client.flush().await.unwrap();
        assert_eq!(server.read_line(1024).await.unwrap().unwrap(), b"A1 NOOP");
        assert_eq!(
            server.read_line(1024).await.unwrap().unwrap(),
            b"A2 APPEND {5}"
        );
        client.write_all(b"hello").await.unwrap();
        client.flush().await.unwrap();
        assert_eq!(server.read_exact(5, 1024).await.unwrap(), b"hello");

        // 服务端 → 客户端：应答也走压缩。
        server.write_all(b"* OK done\r\n").await.unwrap();
        server.flush().await.unwrap();
        assert_eq!(client.read_line(1024).await.unwrap().unwrap(), b"* OK done");
    }

    #[tokio::test]
    async fn enabling_compression_discards_pre_handshake_plaintext() {
        let (mut client, server) = tokio::io::duplex(1024);
        // 客户端在 COMPRESS 同一段里夹带明文（RFC 4978 禁止，服务器必须丢掉）。
        client
            .write_all(b"A1 COMPRESS DEFLATE\r\nINJECTED\r\n")
            .await
            .unwrap();
        let mut io = LineIo::new(server);
        assert_eq!(
            io.read_line(1024).await.unwrap().unwrap(),
            b"A1 COMPRESS DEFLATE"
        );
        assert!(io.buffered() > 0, "夹带的明文应已进入缓冲区");
        io.enable_compression().unwrap();
        assert_eq!(io.buffered(), 0, "COMPRESS 之前的明文必须被丢弃");
    }
}
