#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BareNewlinePolicy {
    #[default]
    Reject,

    Normalize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataEvent {
    NeedMore,

    Complete { data: Option<Vec<u8>> },

    TooLarge,

    BareLineFeed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    InLine,
    SawCr,
}

pub struct DataSink {
    max_size: usize,
    policy: BareNewlinePolicy,
    state: State,

    line: Vec<u8>,
    out: Vec<u8>,

    overflowed: bool,

    line_len: u8,
}

impl DataSink {
    pub fn new(max_size: usize, policy: BareNewlinePolicy) -> Self {
        Self {
            max_size,
            policy,
            state: State::InLine,
            line: Vec::with_capacity(1024),
            out: Vec::with_capacity(4096),
            overflowed: false,
            line_len: 0,
        }
    }

    pub fn overflowed(&self) -> bool {
        self.overflowed
    }

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

                    b'\r' => {
                        let event = self.push(b'\r');
                        self.state = State::SawCr;
                        event
                    }
                    other => {
                        let first = self.push(b'\r');
                        let second = self.push(other);

                        if matches!(first, DataEvent::TooLarge)
                            || matches!(second, DataEvent::TooLarge)
                        {
                            DataEvent::TooLarge
                        } else {
                            DataEvent::NeedMore
                        }
                    }
                }
            }
        }
    }

    fn push(&mut self, byte: u8) -> DataEvent {
        self.line_len = match self.line_len {
            0 if byte == b'.' => 1,
            0 => 2,

            _ => 2,
        };

        if !self.overflowed {
            self.line.push(byte);
        }
        self.check_size()
    }

    fn complete_line(&mut self, terminator: Terminator) -> DataEvent {
        let line = std::mem::take(&mut self.line);

        let is_single_dot = self.line_len == 1;
        self.line_len = 0;
        self.state = State::InLine;

        if terminator.is_bare_line_feed() && self.policy == BareNewlinePolicy::Reject {
            return DataEvent::BareLineFeed;
        }

        if is_single_dot {
            return if terminator.is_bare_line_feed() {
                DataEvent::BareLineFeed
            } else if self.overflowed {
                DataEvent::Complete { data: None }
            } else {
                DataEvent::Complete {
                    data: Some(std::mem::take(&mut self.out)),
                }
            };
        }

        if self.overflowed {
            return DataEvent::NeedMore;
        }

        let content = line.strip_prefix(b".").unwrap_or(&line);
        self.out.extend_from_slice(content);
        self.out.extend_from_slice(b"\r\n");
        self.check_size()
    }

    fn check_size(&mut self) -> DataEvent {
        if self.overflowed {
            return DataEvent::NeedMore;
        }

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
    fn a_body_line_ending_with_a_single_dot_is_not_a_terminator() {
        let message = collect(
            &[b"Thanks.\r\nHi.\r\n1.\r\n.\r\n"],
            BareNewlinePolicy::Reject,
        )
        .unwrap();
        assert_eq!(message, b"Thanks.\r\nHi.\r\n1.\r\n");
    }

    #[test]
    fn oversized_data_reports_too_large_when_the_boundary_lands_after_cr() {
        let mut sink = DataSink::new(8, BareNewlinePolicy::Reject);
        let chunk: &[u8] = b"01234567\rX\r\n";
        let (event, consumed) = sink.feed(chunk);
        assert_eq!(event, DataEvent::TooLarge);
        let (event, _) = sink.feed(&chunk[consumed..]);
        assert_eq!(event, DataEvent::NeedMore);
        let (event, _) = sink.feed(b".\r\n");
        assert_eq!(event, DataEvent::Complete { data: None });
    }

    #[test]
    fn an_empty_message_is_terminated_immediately() {
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
        let wire = b"Subject: x\r\n\r\nhi\r\n.\r\n";
        let bytewise: Vec<&[u8]> = wire.iter().map(std::slice::from_ref).collect();
        let whole = collect(&[wire], BareNewlinePolicy::Reject).unwrap();
        let split = collect(&bytewise, BareNewlinePolicy::Reject).unwrap();
        assert_eq!(whole, split);
        assert_eq!(whole, b"Subject: x\r\n\r\nhi\r\n");
    }

    #[test]
    fn a_split_crlf_dot_crlf_is_not_mistaken_for_body_content() {
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
        let mut sink = DataSink::new(32, BareNewlinePolicy::Reject);
        let mut event = DataEvent::NeedMore;
        for _ in 0..1000 {
            event = sink.feed(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").0;
            if event == DataEvent::TooLarge {
                break;
            }
        }
        assert_eq!(event, DataEvent::TooLarge);

        assert_eq!(sink.feed(b"\r\n").0, DataEvent::NeedMore);
        assert_eq!(sink.feed(b".\r\n").0, DataEvent::Complete { data: None });
    }

    #[test]
    fn the_line_buffer_stops_growing_after_the_limit_is_hit() {
        const LIMIT: usize = 1024;
        let mut sink = DataSink::new(LIMIT, BareNewlinePolicy::Reject);

        let mut hit = false;
        for _ in 0..64 {
            if sink.feed(&[b'a'; 512]).0 == DataEvent::TooLarge {
                hit = true;
                break;
            }
        }
        assert!(hit, "本用例的前提是已经超限");

        assert!(
            sink.line.is_empty(),
            "超限后不应再缓冲未完成行（实际占 {} 字节）",
            sink.line.len()
        );
        let after_limit = sink.line.capacity();

        let chunk = vec![b'b'; 8192];
        for _ in 0..1024 {
            let event = sink.feed(&chunk).0;
            assert_ne!(
                event,
                DataEvent::Complete { data: None },
                "不该在超限后提前判定结束"
            );
        }
        assert_eq!(
            sink.line.capacity(),
            after_limit,
            "超限后继续喂入撑大了行缓冲：这是未认证的远程内存耗尽"
        );
        assert!(
            sink.line.is_empty(),
            "超限后 `line` 必须始终为空（实际占 {} 字节）",
            sink.line.len()
        );

        assert_eq!(sink.feed(b"\r\n").0, DataEvent::NeedMore);
        assert_eq!(sink.feed(b".\r\n").0, DataEvent::Complete { data: None });
    }

    #[test]
    fn a_line_starting_with_a_dot_is_not_mistaken_for_the_terminator() {
        let mut sink = DataSink::new(16, BareNewlinePolicy::Reject);

        for _ in 0..8 {
            if sink.feed(&[b'a'; 64]).0 == DataEvent::TooLarge {
                break;
            }
        }

        assert_eq!(
            sink.feed(b".foo\r\n").0,
            DataEvent::NeedMore,
            "`.foo` 被误判成结束标记：正文截断即走私"
        );

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

        assert_eq!(consumed, 4, "只消费到出问题的那一行的结束符");
        assert_eq!(&chunk[consumed..], b"rest");
    }
}
