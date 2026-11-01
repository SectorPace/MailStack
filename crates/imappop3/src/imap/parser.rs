//! IMAP 命令解析：tag、命令名、参数、literal（RFC 3501 §9）。
//!
//! ## 为什么需要自己的 tokenizer
//!
//! 通用「按空格切」在 IMAP 上会立刻出错，至少四处：
//!
//! * quoted string 里的空格与括号（`"a b(c)"`）；
//! * literal：`APPEND INBOX {310}\r\n<310 字节原始正文>` —— 长度是声明的，
//!   正文里可以出现任意字节，包括 CRLF 与畸形 UTF-8；
//! * FETCH 的 section：`BODY[HEADER.FIELDS (SUBJECT FROM)]<0.1024>` 里的括号与
//!   空格属于 section 语法，不能当成通用列表；
//! * `FETCH 1:* (UID FLAGS)` 的 `*` 是数据而不是通配。
//!
//! 本模块把「读到一条完整命令」与「把命令切成 token」分开：前者负责 literal 的
//! 继续读取（同步 literal 还要先发 `+`），后者在内存里建树。FETCH 的 section
//! 单独由 [`crate::imap::fetch`] 从原始参数文本解析（见 `raw_args`）。
//!
//! ## 防线
//!
//! * 单行、单条命令、literal、token 数各有上限；超限是协议错，不是内存问题；
//! * literal 声明 2 GiB 而实际只发 1 字节，会停在读满处等待，而不是分配 2 GiB
//!   （上限先拒绝）；
//! * 括号不平衡、引号未闭合、控制字符出现在 atom 里，都在进入会话状态机之前被拒。

use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::{MailError, Result};
use crate::lineio::LineIo;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParserLimits {
    pub max_line: usize,
    pub max_literal: usize,
    pub max_tokens: usize,
    pub max_command: usize,
}

impl Default for ParserLimits {
    fn default() -> Self {
        Self {
            max_line: 8 * 1024,
            max_literal: 32 * 1024 * 1024,
            max_tokens: 1024,
            // 多条 literal 拼接后的文本上限；正文本身不计入（另受 max_literal 约束）。
            max_command: 64 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    Atom(String),
    Quoted(String),
    Literal(Vec<u8>),
    List(Vec<Token>),
}

impl Token {
    pub fn as_atom(&self) -> Option<&str> {
        match self {
            Token::Atom(value) => Some(value),
            _ => None,
        }
    }

    /// Atom / Quoted / Literal 统一转成字符串（literal 按 UTF-8 lossy）。
    pub fn text(&self) -> Option<String> {
        match self {
            Token::Atom(value) | Token::Quoted(value) => Some(value.clone()),
            Token::Literal(bytes) => Some(String::from_utf8_lossy(bytes).to_string()),
            Token::List(_) => None,
        }
    }

    pub fn bytes(&self) -> Option<&[u8]> {
        match self {
            Token::Literal(bytes) => Some(bytes),
            _ => None,
        }
    }

    pub fn list(&self) -> Option<&[Token]> {
        match self {
            Token::List(items) => Some(items),
            _ => None,
        }
    }

    pub fn is_nil(&self) -> bool {
        matches!(self, Token::Atom(value) if value.eq_ignore_ascii_case("NIL"))
    }
}

#[derive(Debug, Clone)]
pub struct Command {
    pub tag: String,
    /// 已转大写。
    pub name: String,
    pub args: Vec<Token>,
    /// 不含 literal 时，命令名之后的原始参数文本（FETCH 的 section 语法靠它）；
    /// 含 literal 时为 `None`。
    pub raw_args: Option<String>,
}

enum Chunk {
    Text(Vec<u8>),
    Literal(Vec<u8>),
}

/// 读一条完整命令（含全部 literal）。EOF 且未读到任何字节时返回 `Ok(None)`。
pub async fn read_command<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut LineIo<S>,
    limits: ParserLimits,
) -> Result<Option<Command>> {
    let mut chunks: Vec<Chunk> = Vec::new();
    let mut literal_count = 0usize;
    let mut literal_total = 0usize;
    let mut total = 0usize;
    let mut first_line = true;

    loop {
        let line = match io.read_line(limits.max_line).await? {
            Some(line) => line,
            None if first_line => return Ok(None),
            None => {
                return Err(MailError::protocol(
                    "connection closed in the middle of a command",
                ))
            }
        };
        first_line = false;
        total = total.saturating_add(line.len());
        if total > limits.max_command {
            return Err(MailError::protocol("command is too long"));
        }

        let (content, marker) = split_literal_marker(&line, limits.max_literal)?;
        chunks.push(Chunk::Text(content.to_vec()));
        let Some((size, sync)) = marker else {
            break;
        };
        literal_count += 1;
        if literal_count > 32 {
            return Err(MailError::protocol("too many literals in one command"));
        }
        literal_total = literal_total.saturating_add(size);
        if literal_total > limits.max_literal {
            // 单条命令里的多个 literal 也要有总上限，否则 32 × max_literal
            // 可以在一瞬间吞掉接近 1 GiB 内存。
            return Err(MailError::protocol(
                "total literal size of a command exceeds the limit",
            ));
        }
        if sync {
            io.write_all(b"+ Ready for literal data\r\n").await?;
            io.flush().await?;
        }
        let data = io.read_exact(size, limits.max_literal).await?;
        chunks.push(Chunk::Literal(data));
    }

    // 原始参数文本必须在移动 chunks 之前取出：FETCH 的 section 语法依赖它。
    let raw_args = match chunks.as_slice() {
        [Chunk::Text(bytes)] => std::str::from_utf8(bytes)
            .ok()
            .and_then(raw_after_two_atoms),
        _ => None,
    };
    let tokens = tokenize(chunks, limits.max_tokens)?;
    finish(tokens, raw_args)
}

/// 行内 literal 标记的拆分结果：`(标记之前的文本, Some((字节数, 是否同步)))`。
type LiteralSplit<'a> = (&'a [u8], Option<(usize, bool)>);

/// 识别行尾的 `{n}`（同步）或 `{n+}`（LITERAL+，RFC 7888）。
fn split_literal_marker(line: &[u8], max_literal: usize) -> Result<LiteralSplit<'_>> {
    if line.last() != Some(&b'}') {
        return Ok((line, None));
    }
    let Some(open) = line.iter().rposition(|byte| *byte == b'{') else {
        return Ok((line, None));
    };
    // literal marker 必须处于 token 边界：前面是行首、空格或 '('。
    // 否则 `LOGIN user "{4}"` 这样的 quoted string 会被误判成 literal。
    let boundary = match open {
        0 => true,
        _ => matches!(line[open - 1], b' ' | b'('),
    };
    if !boundary {
        return Ok((line, None));
    }

    let inside = &line[open + 1..line.len() - 1];
    let (digits, sync) = match inside.strip_suffix(b"+") {
        Some(digits) => (digits, false),
        None => (inside, true),
    };
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return Err(MailError::protocol("malformed literal marker"));
    }
    let digits =
        std::str::from_utf8(digits).map_err(|_| MailError::protocol("malformed literal marker"))?;
    let size: usize = digits
        .parse()
        .map_err(|_| MailError::protocol("literal size out of range"))?;
    if size > max_literal {
        return Err(MailError::protocol(format!(
            "literal of {size} bytes exceeds limit {max_literal}"
        )));
    }
    Ok((&line[..open], Some((size, sync))))
}

fn tokenize(chunks: Vec<Chunk>, max_tokens: usize) -> Result<Vec<Token>> {
    let mut frames: Vec<Vec<Token>> = vec![Vec::new()];
    let mut count = 0usize;

    for chunk in chunks {
        match chunk {
            Chunk::Literal(bytes) => {
                // 移动而不是 clone：32 MiB 的 literal 再复制一份会让单条命令的
                // 峰值内存翻倍。
                push_token(&mut frames, Token::Literal(bytes), &mut count, max_tokens)?;
            }
            Chunk::Text(bytes) => tokenize_text(&bytes, &mut frames, &mut count, max_tokens)?,
        }
    }

    if frames.len() != 1 {
        return Err(MailError::protocol("unbalanced parentheses"));
    }
    Ok(frames.pop().unwrap_or_default())
}

fn push_token(
    frames: &mut [Vec<Token>],
    token: Token,
    count: &mut usize,
    max_tokens: usize,
) -> Result<()> {
    *count += 1;
    if *count > max_tokens {
        return Err(MailError::protocol("too many tokens in one command"));
    }
    if let Some(frame) = frames.last_mut() {
        frame.push(token);
    }
    Ok(())
}

fn tokenize_text(
    bytes: &[u8],
    frames: &mut Vec<Vec<Token>>,
    count: &mut usize,
    max_tokens: usize,
) -> Result<()> {
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            b' ' => index += 1,
            b'(' => {
                frames.push(Vec::new());
                index += 1;
            }
            b')' => {
                if frames.len() == 1 {
                    return Err(MailError::protocol("unexpected ')'"));
                }
                let items = frames.pop().unwrap_or_default();
                push_token(frames, Token::List(items), count, max_tokens)?;
                index += 1;
            }
            b'"' => {
                let (value, next) = parse_quoted(bytes, index + 1)?;
                push_token(frames, Token::Quoted(value), count, max_tokens)?;
                index = next;
            }
            byte if byte < 0x20 || byte == 0x7f => {
                return Err(MailError::protocol("control character in command"));
            }
            b'{' | b'}' => {
                return Err(MailError::protocol(
                    "unexpected brace outside of a literal marker",
                ));
            }
            _ => {
                let start = index;
                while index < bytes.len()
                    && !matches!(bytes[index], b' ' | b'(' | b')' | b'"' | b'{' | b'}')
                    && bytes[index] >= 0x20
                {
                    index += 1;
                }
                let atom = String::from_utf8_lossy(&bytes[start..index]).to_string();
                push_token(frames, Token::Atom(atom), count, max_tokens)?;
            }
        }
    }
    Ok(())
}

fn parse_quoted(bytes: &[u8], start: usize) -> Result<(String, usize)> {
    let mut out: Vec<u8> = Vec::new();
    let mut index = start;
    let mut escaped = false;
    while index < bytes.len() {
        let byte = bytes[index];
        index += 1;
        if escaped {
            escaped = false;
            // RFC 3501 禁止 quoted string 里出现 CR/LF，转义字节也不例外：
            // 否则 `"a\<CR>b"` 会从下面的检查绕过去。
            if byte == b'\r' || byte == b'\n' {
                return Err(MailError::protocol("CR/LF inside a quoted string"));
            }
            out.push(byte);
            continue;
        }
        match byte {
            b'\\' => escaped = true,
            b'"' => return Ok((String::from_utf8_lossy(&out).to_string(), index)),
            b'\r' | b'\n' => return Err(MailError::protocol("CR/LF inside a quoted string")),
            _ => out.push(byte),
        }
    }
    Err(MailError::protocol("unterminated quoted string"))
}

fn finish(tokens: Vec<Token>, raw_args: Option<String>) -> Result<Option<Command>> {
    if tokens.len() < 2 {
        return Err(MailError::protocol("command is missing a tag or name"));
    }
    let mut iter = tokens.into_iter();
    let tag = match iter.next() {
        Some(Token::Atom(tag)) => tag,
        _ => return Err(MailError::protocol("tag must be an atom")),
    };
    validate_tag(&tag)?;
    let name = match iter.next() {
        Some(Token::Atom(name)) => name.to_ascii_uppercase(),
        _ => return Err(MailError::protocol("command name must be an atom")),
    };
    let args: Vec<Token> = iter.collect();

    Ok(Some(Command {
        tag,
        name,
        args,
        raw_args,
    }))
}

fn validate_tag(tag: &str) -> Result<()> {
    if tag.is_empty() || tag.len() > 64 {
        return Err(MailError::protocol("tag must be 1-64 characters"));
    }
    let valid = tag.bytes().all(|byte| {
        byte.is_ascii_graphic()
            && byte != b'+'
            && !matches!(byte, b'(' | b')' | b'{' | b'"' | b'\\')
    });
    if !valid {
        return Err(MailError::protocol("invalid character in tag"));
    }
    Ok(())
}

fn raw_after_two_atoms(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut index = 0usize;
    let len = bytes.len();
    while index < len && bytes[index] == b' ' {
        index += 1;
    }
    while index < len && bytes[index] != b' ' {
        index += 1;
    }
    while index < len && bytes[index] == b' ' {
        index += 1;
    }
    while index < len && bytes[index] != b' ' {
        index += 1;
    }
    while index < len && bytes[index] == b' ' {
        index += 1;
    }
    Some(text[index..].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    async fn parse(input: &[u8]) -> Result<Option<Command>> {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        client.write_all(input).await.unwrap();
        drop(client);
        let mut io = LineIo::new(server);
        read_command(&mut io, ParserLimits::default()).await
    }

    #[tokio::test]
    async fn simple_command_with_quoted_and_list_arguments() {
        let command = parse(b"A1 login \"a b\" (\\Seen \"x\")\r\n")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(command.tag, "A1");
        assert_eq!(command.name, "LOGIN");
        assert_eq!(command.args[0], Token::Quoted("a b".into()));
        let list = command.args[1].list().unwrap();
        assert_eq!(list[0], Token::Atom("\\Seen".into()));
        assert_eq!(list[1], Token::Quoted("x".into()));
        assert!(command.raw_args.is_some());
    }

    #[tokio::test]
    async fn sync_literal_gets_a_continuation_and_is_read_exactly() {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let reader = tokio::spawn(async move {
            let mut io = LineIo::new(server);
            read_command(&mut io, ParserLimits::default()).await
        });
        let mut client = client;
        client.write_all(b"A1 LOGIN {3}\r\n").await.unwrap();
        let mut continuation = [0u8; 24];
        let read = tokio::io::AsyncReadExt::read(&mut client, &mut continuation)
            .await
            .unwrap();
        assert!(String::from_utf8_lossy(&continuation[..read]).starts_with("+ "));
        client.write_all(b"bob pass\r\n").await.unwrap();
        let command = reader.await.unwrap().unwrap().unwrap();
        assert_eq!(command.args[0], Token::Literal(b"bob".to_vec()));
        assert_eq!(command.args[1], Token::Atom("pass".into()));
        assert!(command.raw_args.is_none(), "含 literal 时不提供原始文本");
    }

    #[tokio::test]
    async fn literal_plus_does_not_wait_for_a_continuation() {
        let command = parse(b"A2 APPEND INBOX {5+}\r\nhello\r\n")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(command.name, "APPEND");
        assert_eq!(command.args[1], Token::Literal(b"hello".to_vec()));
    }

    #[tokio::test]
    async fn literal_bytes_may_contain_crlf_and_nul() {
        let command = parse(b"A3 APPEND INBOX {7+}\r\nab\r\nc\0d\r\n")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(command.args[1], Token::Literal(b"ab\r\nc\0d".to_vec()));
    }

    #[tokio::test]
    async fn braces_inside_quotes_are_not_literal_markers() {
        let command = parse(b"A4 LOGIN user \"{4}\"\r\n").await.unwrap().unwrap();
        assert_eq!(command.args[1], Token::Quoted("{4}".into()));
        assert_eq!(command.args.len(), 2);
    }

    #[tokio::test]
    async fn raw_args_preserve_fetch_section_syntax() {
        let command = parse(b"A5 FETCH 1:* (BODY.PEEK[HEADER.FIELDS (SUBJECT)]<0.10> UID)\r\n")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            command.raw_args.as_deref(),
            Some("1:* (BODY.PEEK[HEADER.FIELDS (SUBJECT)]<0.10> UID)")
        );
    }

    #[tokio::test]
    async fn malformed_input_is_rejected_without_panicking() {
        for input in [
            &b"A1\r\n"[..],
            b"A1 \"noop\"\r\n",
            b"A1 NOOP (a\r\n",
            b"A1 NOOP )\r\n",
            b"A1 NOOP \"unterminated\r\n",
            b"A1 LOGIN {99999999999999999999}\r\n",
            b"A1 LOGIN {4\r\n",
            b"A1 NOOP\x07\r\n",
            // 转义过的 CR 也算 quoted string 里的 CR/LF。
            b"A1 LOGIN \"a\\\rb\"\r\n",
        ] {
            assert!(
                parse(input).await.is_err(),
                "{:?}",
                String::from_utf8_lossy(input)
            );
        }
    }

    #[tokio::test]
    async fn literal_size_limit_is_enforced_before_reading() {
        let (mut client, server) = tokio::io::duplex(1024);
        client
            .write_all(b"A1 APPEND INBOX {1000}\r\n")
            .await
            .unwrap();
        let mut io = LineIo::new(server);
        let limits = ParserLimits {
            max_literal: 10,
            ..ParserLimits::default()
        };
        let error = read_command(&mut io, limits).await.err().unwrap();
        assert_eq!(error.kind(), "ProtocolError");
    }

    #[tokio::test]
    async fn the_total_literal_budget_caps_multiple_literals() {
        let (mut client, server) = tokio::io::duplex(1024);
        client
            .write_all(b"A1 LOGIN {6+}\r\nabcdef{6+}\r\nghijkl\r\n")
            .await
            .unwrap();
        drop(client);
        let mut io = LineIo::new(server);
        let limits = ParserLimits {
            max_literal: 10,
            ..ParserLimits::default()
        };
        let error = read_command(&mut io, limits).await.err().unwrap();
        assert_eq!(error.kind(), "ProtocolError");
    }

    #[tokio::test]
    async fn eof_before_any_command_is_not_an_error() {
        let (client, server) = tokio::io::duplex(16);
        drop(client);
        let mut io = LineIo::new(server);
        assert!(read_command(&mut io, ParserLimits::default())
            .await
            .unwrap()
            .is_none());
    }
}
