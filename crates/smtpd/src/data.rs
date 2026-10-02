//! DATA 阶段的字节流解析（RFC 5321 §4.1.1.4、§4.5.2；SMTP 走私防护）。
//!
//! ## 为什么按字节而不是按行
//!
//! I/O 层交上来的分块边界是**任意的**：结束标记 `CRLF.CRLF` 完全可能被切成
//! `...\r` / `\n.` / `\r\n` 三块，甚至逐字节到达。任何「先按行切开再判断」的写法
//! 都会在某些分块下漏判或误判，而漏判结束标记的后果是：后面的字节被当成 SMTP 命令
//! 执行。本模块因此只暴露 [`DataSink::feed`]，对**任意**分块序列都给出相同结果，
//! 并用「逐字节喂入」的测试把这条性质固定住。
//!
//! ## 返回已消费字节数不是可选项
//!
//! 客户端可以把 `DATA` 正文与后续命令**流水线**在同一个 TCP 段里发出来。
//! 若 `feed` 在结束标记处直接返回、磁盘上那半块字节被丢弃，后面几条真命令就丢了。
//! 因此 `feed` 返回 `(事件, 已消费字节数)`，由驱动把剩余字节推回命令缓冲。
//!
//! ## SMTP 走私（CVE-2023-51764 一类）
//!
//! 攻击形态：攻击者构造一封正文里含 `\n.\n` 的邮件，经由**接受裸 LF 的**上游服务器
//! 转发给**不接受的**本机。上游在那里切断了事务，本机却把后续字节当成正文，于是
//! 「正文里的 SMTP 命令」被当作真命令执行 —— 凭空多发一封钓鱼邮件。
//!
//! 本模块的防线是**不猜测**：
//!
//! * [`BareNewlinePolicy::Reject`]（默认）：正文里出现裸 LF 即拒收（550）并断开。
//! * [`BareNewlinePolicy::Normalize`]：把裸 LF 当作 CRLF 归一化，**但**如果归一化
//!   之后会产生一个「结束标记」，就拒绝而不是按自己的理解切分 —— 那正是走私的形态。
//!
//! 两条策略都保证：**本机对「事务边界在哪」的判断不会比上游更宽松**。

/// 正文里出现裸 LF（`\n` 前无 `\r`）时的处理策略。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BareNewlinePolicy {
    /// 拒收（默认）。最严格，也让走私在结构上不可能。
    #[default]
    Reject,
    /// 归一化为 CRLF，但拒绝「归一化后变成结束标记」的情形。
    Normalize,
}

/// [`DataSink::feed`] 的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataEvent {
    /// 还需要更多字节。
    NeedMore,
    /// 已收到结束标记（或超限后已丢弃完毕）。
    /// `data` 为 `None` 表示这封因超过大小上限被丢弃。
    Complete { data: Option<Vec<u8>> },
    /// 超过大小上限。**只报一次**，之后继续静默丢弃到结束标记 ——
    /// 否则客户端剩下的正文会被当成命令解析，直接造成会话错位。
    /// 调用方应立即回 552，并继续喂入直到 [`DataEvent::Complete`]。
    TooLarge,
    /// 裸 LF（仅 `Reject` 策略）。调用方必须立刻回 550 并**断开**，
    /// 不能继续用本连接解析命令。
    BareLineFeed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    InLine,
    SawCr,
}

/// DATA 正文接收器。
pub struct DataSink {
    max_size: usize,
    policy: BareNewlinePolicy,
    state: State,
    /// 当前行的已累积字节（不含行结束符）。
    line: Vec<u8>,
    out: Vec<u8>,
    /// 已超限：继续切行找结束标记，但不再保存内容。
    overflowed: bool,
}

impl DataSink {
    /// `max_size` 是正文（归一化后、未去点）的字节上限。
    pub fn new(max_size: usize, policy: BareNewlinePolicy) -> Self {
        Self {
            max_size,
            policy,
            state: State::InLine,
            line: Vec::with_capacity(1024),
            out: Vec::with_capacity(4096),
            overflowed: false,
        }
    }

    /// 本封是否已因超限被丢弃。
    pub fn overflowed(&self) -> bool {
        self.overflowed
    }

    /// 喂入一段字节，返回 `(事件, 已消费字节数)`。
    ///
    /// 事件不是 [`DataEvent::NeedMore`] 时，调用方**必须**从返回的偏移处继续处理
    /// 剩余字节（通常是推回命令缓冲），否则会丢数据。
    pub fn feed(&mut self, chunk: &[u8]) -> (DataEvent, usize) {
        for (index, &byte) in chunk.iter().enumerate() {
            let event = self.feed_byte(byte);
            if event != DataEvent::NeedMore {
                return (event, index + 1);
            }
        }
        (DataEvent::NeedMore, chunk.len())
    }

    fn feed_byte(&mut self, byte: u8) -> DataEvent {
        match self.state {
            State::InLine => match byte {
                b'\r' => {
                    self.state = State::SawCr;
                    DataEvent::NeedMore
                }
                b'\n' => self.complete_line(Terminator::BareLineFeed),
                other => self.push(other),
            },
            State::SawCr => {
                self.state = State::InLine;
                match byte {
                    b'\n' => self.complete_line(Terminator::CrLf),
                    // 连续两个 CR：第一个属于行内容（非法但不致命），
                    // 第二个继续当作可能的行结束前缀。
                    b'\r' => {
                        self.push(b'\r');
                        self.state = State::SawCr;
                        DataEvent::NeedMore
                    }
                    other => {
                        self.push(b'\r');
                        self.push(other)
                    }
                }
            }
        }
    }

    fn push(&mut self, byte: u8) -> DataEvent {
        self.line.push(byte);
        self.check_size()
    }

    /// 一行结束（含结束符）时的处理。
    fn complete_line(&mut self, terminator: Terminator) -> DataEvent {
        let line = std::mem::take(&mut self.line);
        self.state = State::InLine;

        // 1) 裸 LF：Reject 策略下无条件拒收。
        if terminator.is_bare_line_feed() && self.policy == BareNewlinePolicy::Reject {
            return DataEvent::BareLineFeed;
        }

        // 2) 结束标记。
        if line == b"." {
            return if terminator.is_bare_line_feed() {
                // 归一化由**裸 LF** 造出来的结束标记：上游很可能不认为这是结束。
                // 按自己的理解切分正是走私的形态，所以拒绝。
                DataEvent::BareLineFeed
            } else if self.overflowed {
                DataEvent::Complete { data: None }
            } else {
                DataEvent::Complete {
                    data: Some(std::mem::take(&mut self.out)),
                }
            };
        }

        // 3) 超限后只切行、不留内容。
        if self.overflowed {
            return DataEvent::NeedMore;
        }

        // 4) 去点：行首的单个 `.` 是转义出来的（RFC 5321 §4.5.2）。
        let content = line.strip_prefix(b".").unwrap_or(&line);
        self.out.extend_from_slice(content);
        self.out.extend_from_slice(b"\r\n");
        self.check_size()
    }

    fn check_size(&mut self) -> DataEvent {
        if self.overflowed {
            return DataEvent::NeedMore;
        }
        // 未完成的行也要计入：否则一个「永远不发 CRLF 的巨大行」可以无限占用内存。
        if self.out.len().saturating_add(self.line.len()) > self.max_size {
            self.overflowed = true;
            self.out = Vec::new();
            self.line = Vec::new();
            return DataEvent::TooLarge;
        }
        DataEvent::NeedMore
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Terminator {
    CrLf,
    BareLineFeed,
}

impl Terminator {
    fn is_bare_line_feed(&self) -> bool {
        matches!(self, Terminator::BareLineFeed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collect(chunks: &[&[u8]], policy: BareNewlinePolicy) -> Option<Vec<u8>> {
        let mut sink = DataSink::new(1 << 20, policy);
        for chunk in chunks {
            let (event, _) = sink.feed(chunk);
            match event {
                DataEvent::NeedMore => {}
                DataEvent::Complete { data } => return data,
                other => panic!("意外事件：{other:?}"),
            }
        }
        panic!("未收到结束标记");
    }

    #[test]
    fn a_simple_message_is_terminated_by_crlf_dot_crlf() {
        let message = collect(
            &[b"Subject: t\r\n\r\nbody\r\n.\r\n"],
            BareNewlinePolicy::Reject,
        )
        .unwrap();
        assert_eq!(message, b"Subject: t\r\n\r\nbody\r\n");
    }

    #[test]
    fn an_empty_message_is_terminated_immediately() {
        // 354 之后直接 `.` —— 起点等价于「刚过 CRLF」，必须识别为空邮件。
        let message = collect(&[b".\r\n"], BareNewlinePolicy::Reject).unwrap();
        assert!(message.is_empty());
    }

    #[test]
    fn leading_dots_are_unstuffed_exactly_once() {
        let message = collect(
            &[b"..leading\r\n...three\r\n.\r\n"],
            BareNewlinePolicy::Reject,
        )
        .unwrap();
        assert_eq!(message, b".leading\r\n..three\r\n");
    }

    #[test]
    fn dot_stuffing_round_trips_for_arbitrary_bodies() {
        // 反向验证：把一封正文按 RFC 5321 §4.5.2 转义后送进来，必须逐字还原。
        let original: Vec<u8> = b".\r\nnormal\r\n.\r\n..\r\n".to_vec();
        let mut stuffed = Vec::new();
        for line in original.split_inclusive(|&b| b == b'\n') {
            if line.starts_with(b".") {
                stuffed.push(b'.');
            }
            stuffed.extend_from_slice(line);
        }
        stuffed.extend_from_slice(b".\r\n");
        let got = collect(&[&stuffed], BareNewlinePolicy::Reject).unwrap();
        assert_eq!(got, original);
    }

    #[test]
    fn the_terminator_is_recognised_across_any_chunk_boundary() {
        // 逐字节喂入：分块边界落在结束标记的任何位置都必须得到同一结果。
        let wire = b"Subject: x\r\n\r\nhi\r\n.\r\n";
        let bytewise: Vec<&[u8]> = wire.iter().map(std::slice::from_ref).collect();
        let whole = collect(&[wire], BareNewlinePolicy::Reject).unwrap();
        let split = collect(&bytewise, BareNewlinePolicy::Reject).unwrap();
        assert_eq!(whole, split);
        assert_eq!(whole, b"Subject: x\r\n\r\nhi\r\n");
    }

    #[test]
    fn a_split_crlf_dot_crlf_is_not_mistaken_for_body_content() {
        // 攻击者常利用的正是「分块恰好切开结束标记」；这里把它切成 5 段。
        let message = collect(
            &[b"body\r", b"\n", b".", b"\r", b"\n"],
            BareNewlinePolicy::Reject,
        )
        .unwrap();
        assert_eq!(message, b"body\r\n");
    }

    #[test]
    fn a_bare_line_feed_is_rejected_under_the_reject_policy() {
        let mut sink = DataSink::new(1 << 20, BareNewlinePolicy::Reject);
        assert_eq!(sink.feed(b"body\nmore").0, DataEvent::BareLineFeed);
    }

    #[test]
    fn normalization_rejects_a_bare_lf_that_would_create_the_terminator() {
        // 这正是 SMTP 走私的形态：上游按裸 LF 切分、本机不切分，两边对
        // 「事务在哪结束」理解不一致。归一化策略必须拒绝而不是自行切分。
        let mut sink = DataSink::new(1 << 20, BareNewlinePolicy::Normalize);
        assert_eq!(
            sink.feed(b"body\n.\nRCPT TO:<victim@evil.test>\r\n").0,
            DataEvent::BareLineFeed
        );
    }

    #[test]
    fn normalization_converts_ordinary_bare_line_feeds_to_crlf() {
        let message = collect(
            &[b"Subject: t\n\nbody\n.\r\n"],
            BareNewlinePolicy::Normalize,
        )
        .unwrap();
        assert_eq!(message, b"Subject: t\r\n\r\nbody\r\n");
    }

    #[test]
    fn oversized_messages_are_reported_once_then_drained() {
        // 超限后必须继续找结束标记：否则剩下的正文会被当成命令解析，会话直接错位。
        let mut sink = DataSink::new(16, BareNewlinePolicy::Reject);
        assert_eq!(
            sink.feed(b"0123456789ABCDEFGHIJ\r\n").0,
            DataEvent::TooLarge
        );
        assert_eq!(sink.feed(b"more junk\r\n").0, DataEvent::NeedMore);
        assert_eq!(sink.feed(b".\r\n").0, DataEvent::Complete { data: None });
    }

    #[test]
    fn an_endless_line_cannot_exhaust_memory() {
        // 「永远不发 CRLF 的巨大行」不能让未完成行缓冲无限增长。
        let mut sink = DataSink::new(32, BareNewlinePolicy::Reject);
        let mut event = DataEvent::NeedMore;
        for _ in 0..1000 {
            event = sink.feed(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").0;
            if event == DataEvent::TooLarge {
                break;
            }
        }
        assert_eq!(event, DataEvent::TooLarge);
        assert_eq!(sink.feed(b".\r\n").0, DataEvent::Complete { data: None });
    }

    #[test]
    fn a_cr_not_followed_by_lf_is_kept_in_the_body() {
        let message = collect(&[b"a\rb\r\n.\r\n"], BareNewlinePolicy::Reject).unwrap();
        assert_eq!(message, b"a\rb\r\n");
    }

    #[test]
    fn bare_cr_at_end_of_chunk_is_not_treated_as_a_line_ending() {
        let message = collect(&[b"a\r", b"b\r\n.\r\n"], BareNewlinePolicy::Reject).unwrap();
        assert_eq!(message, b"a\rb\r\n");
    }

    #[test]
    fn bytes_after_the_terminator_are_left_for_the_caller() {
        // 流水线：正文与后续命令在同一个块里。结束标记之后的字节必须原样交回，
        // 否则那几条命令会被静默丢掉。
        let mut sink = DataSink::new(1 << 20, BareNewlinePolicy::Reject);
        let chunk = b"body\r\n.\r\nMAIL FROM:<x@y.test>\r\n";
        let (event, consumed) = sink.feed(chunk);
        assert_eq!(
            event,
            DataEvent::Complete {
                data: Some(b"body\r\n".to_vec())
            }
        );
        assert_eq!(&chunk[consumed..], b"MAIL FROM:<x@y.test>\r\n");
    }

    #[test]
    fn a_bare_lf_report_leaves_the_rest_of_the_chunk_to_the_caller() {
        let mut sink = DataSink::new(1 << 20, BareNewlinePolicy::Reject);
        let chunk = b"bad\nrest";
        let (event, consumed) = sink.feed(chunk);
        assert_eq!(event, DataEvent::BareLineFeed);
        // `bad\n` 共 4 字节：裸 LF 在索引 3，消费到它为止。
        assert_eq!(consumed, 4, "只消费到出问题的那一行的结束符");
        assert_eq!(&chunk[consumed..], b"rest");
    }
}
