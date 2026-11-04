use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{MailError, Result};

const READ_CHUNK: usize = 4096;

struct DeflateState {
    decompress: flate2::Decompress,
    compress: flate2::Compress,

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

    pub fn compression_enabled(&self) -> bool {
        self.compression.is_some()
    }

    pub fn into_inner(self) -> S {
        self.io
    }

    pub fn buffered(&self) -> usize {
        self.buffer.len()
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> LineIo<S> {
    pub async fn read_line(&mut self, max: usize) -> Result<Option<Vec<u8>>> {
        loop {
            if let Some(position) = self.buffer.iter().position(|&byte| byte == b'\n') {
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

            if self.buffer.len() > max.saturating_add(READ_CHUNK) {
                self.buffer.clear();
                return Err(MailError::protocol(format!("line exceeds {max} bytes")));
            }
        }
    }

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

        server.write_all(b"* OK done\r\n").await.unwrap();
        server.flush().await.unwrap();
        assert_eq!(client.read_line(1024).await.unwrap().unwrap(), b"* OK done");
    }

    #[tokio::test]
    async fn enabling_compression_discards_pre_handshake_plaintext() {
        let (mut client, server) = tokio::io::duplex(1024);

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
