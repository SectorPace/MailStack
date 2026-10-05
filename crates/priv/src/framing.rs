//! RPC 帧格式（规格书 §5.4.3）。
//!
//! 传输：Unix domain socket。
//! 帧：`uint32be(length)` + UTF-8 JSON，**双向**。
//!
//! 请求上限 256 KB（与 `mailstackctl.py` 一致），响应上限 16 MB
//! （超出报 `PRIVILEGED_OPERATION_FAILED`）。

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 通用帧最大字节数上限（用于服务端响应与客户端接收响应，规格书 §5.4.3）。
pub const MAX_FRAME_BYTES: u32 = 16 * 1024 * 1024;

/// 请求体上限 256 KB（与 `mailstackctl.py` 的 stdin 上限一致）。
pub const MAX_REQUEST_BYTES: usize = 256 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("frame length {0} exceeds maximum {MAX_FRAME_BYTES} bytes")]
    TooLarge(u32),
    #[error("request length {0} exceeds maximum {MAX_REQUEST_BYTES} bytes")]
    RequestTooLarge(u32),
    #[error("frame truncated: expected {expected} bytes, got {got}")]
    Truncated { expected: u32, got: usize },
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

/// 读取一帧：先读 4 字节长度前缀，再读负载。
///
/// 长度前缀为 big-endian `uint32`。超限时立即报错，**不**尝试读取负载
/// ——避免恶意对端用超大长度值诱导内存分配。
pub async fn read_frame<R>(reader: &mut R) -> Result<Vec<u8>, FrameError>
where
    R: AsyncReadExt + Unpin,
{
    read_frame_with_limit(reader, MAX_FRAME_BYTES as usize).await
}

async fn read_frame_with_limit<R>(reader: &mut R, max_bytes: usize) -> Result<Vec<u8>, FrameError>
where
    R: AsyncReadExt + Unpin,
{
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf);

    if len as usize > max_bytes {
        return Err(if max_bytes == MAX_REQUEST_BYTES {
            FrameError::RequestTooLarge(len)
        } else {
            FrameError::TooLarge(len)
        });
    }

    let mut payload = vec![0u8; len as usize];
    let got = read_fully(reader, &mut payload).await?;
    if got != len as usize {
        return Err(FrameError::Truncated { expected: len, got });
    }
    Ok(payload)
}

/// 读取一帧并反序列化为 `T`。
pub async fn read_json_frame<T, R>(reader: &mut R) -> Result<T, FrameError>
where
    T: serde::de::DeserializeOwned,
    R: AsyncReadExt + Unpin,
{
    let payload = read_frame(reader).await?;
    Ok(serde_json::from_slice(&payload)?)
}

/// 读取并解析 RPC 请求帧；在按声明长度分配内存前执行 256 KB 上限检查。
pub(crate) async fn read_json_request_frame<T, R>(reader: &mut R) -> Result<T, FrameError>
where
    T: serde::de::DeserializeOwned,
    R: AsyncReadExt + Unpin,
{
    let payload = read_frame_with_limit(reader, MAX_REQUEST_BYTES).await?;
    Ok(serde_json::from_slice(&payload)?)
}

/// 写入一帧：长度前缀 + 负载。
pub async fn write_frame<W>(writer: &mut W, payload: &[u8]) -> Result<(), FrameError>
where
    W: AsyncWriteExt + Unpin,
{
    if payload.len() > MAX_FRAME_BYTES as usize {
        return Err(FrameError::TooLarge(payload.len() as u32));
    }
    writer
        .write_all(&(payload.len() as u32).to_be_bytes())
        .await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}

/// 序列化并写入一帧。
pub async fn write_json_frame<W, T>(writer: &mut W, value: &T) -> Result<(), FrameError>
where
    W: AsyncWriteExt + Unpin,
    T: serde::Serialize,
{
    let payload = serde_json::to_vec(value)?;
    write_frame(writer, &payload).await
}

/// 读满整个缓冲区；返回实际读到的字节数（对端提前关闭时 < len）。
async fn read_fully<R>(reader: &mut R, buf: &mut [u8]) -> Result<usize, std::io::Error>
where
    R: AsyncReadExt + Unpin,
{
    let mut filled = 0usize;
    while filled < buf.len() {
        let n = reader.read(&mut buf[filled..]).await?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    Ok(filled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn round_trips_a_frame() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"hello world").await.unwrap();

        // 前 4 字节必须是 big-endian 长度。
        assert_eq!(&buf[..4], &11u32.to_be_bytes());
        assert_eq!(&buf[4..], b"hello world");

        let mut cursor = Cursor::new(buf);
        let got = read_frame(&mut cursor).await.unwrap();
        assert_eq!(got, b"hello world");
    }

    #[tokio::test]
    async fn round_trips_empty_frame() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"").await.unwrap();
        assert_eq!(buf.len(), 4);
        let mut cursor = Cursor::new(buf);
        assert!(read_frame(&mut cursor).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn round_trips_json_payload() {
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct Payload {
            action: String,
            n: u32,
        }
        let value = Payload {
            action: "domains.list".into(),
            n: 7,
        };
        let mut buf = Vec::new();
        write_json_frame(&mut buf, &value).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let got: Payload = read_json_frame(&mut cursor).await.unwrap();
        assert_eq!(got, value);
    }

    #[tokio::test]
    async fn rejects_oversized_length_prefix_without_allocating() {
        // 恶意长度值必须被立即拒绝，而不是先分配 4 GB。
        let mut buf = Vec::new();
        buf.extend_from_slice(&u32::MAX.to_be_bytes());
        let mut cursor = Cursor::new(buf);
        let err = read_frame(&mut cursor).await.unwrap_err();
        assert!(
            matches!(err, FrameError::TooLarge(_)),
            "应报 TooLarge，实际: {err:?}"
        );
    }

    #[tokio::test]
    async fn rejects_requests_above_256_kib_before_reading_or_allocating_the_payload() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&((MAX_REQUEST_BYTES as u32) + 1).to_be_bytes());
        let mut cursor = Cursor::new(buf);

        let error = read_json_request_frame::<serde_json::Value, _>(&mut cursor)
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            FrameError::RequestTooLarge(length) if length as usize == MAX_REQUEST_BYTES + 1
        ));
        assert_eq!(cursor.position(), 4, "不得读取超限帧的负载");
    }

    #[tokio::test]
    async fn reports_truncated_frame() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&100u32.to_be_bytes());
        buf.extend_from_slice(b"only-ten-b"); // 10 字节，声明 100
        let mut cursor = Cursor::new(buf);
        let err = read_frame(&mut cursor).await.unwrap_err();
        assert!(
            matches!(
                err,
                FrameError::Truncated {
                    expected: 100,
                    got: 10
                }
            ),
            "应报 Truncated，实际: {err:?}"
        );
    }

    #[tokio::test]
    async fn uses_big_endian_length_prefix() {
        let mut buf = Vec::new();
        write_frame(&mut buf, &[0u8; 256]).await.unwrap();
        assert_eq!(&buf[..4], &[0x00, 0x00, 0x01, 0x00]);
    }

    #[tokio::test]
    async fn handles_multibyte_utf8_payload_by_byte_length() {
        let payload = "域名已纳管".as_bytes();
        let mut buf = Vec::new();
        write_frame(&mut buf, payload).await.unwrap();
        assert_eq!(
            u32::from_be_bytes(buf[..4].try_into().unwrap()) as usize,
            payload.len(),
            "长度前缀必须是字节数，不是字符数"
        );
        let mut cursor = Cursor::new(buf);
        let got = read_frame(&mut cursor).await.unwrap();
        assert_eq!(got, payload);
    }
}
