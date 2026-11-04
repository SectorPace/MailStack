use crate::date;
use crate::maildir::MessageMeta;
use crate::mime;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadAlgorithm {
    OrderedSubject,
    References,
}

impl ThreadAlgorithm {
    pub fn parse(value: &str) -> Option<Self> {
        if value.eq_ignore_ascii_case("ORDEREDSUBJECT") {
            Some(Self::OrderedSubject)
        } else if value.eq_ignore_ascii_case("REFERENCES") {
            Some(Self::References)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone)]
pub struct ThreadMessage {
    pub number: u32,
    pub arrival: i64,
    pub date: i64,
    pub subject: String,
    pub message_id: Option<String>,
    pub references: Vec<String>,
    pub in_reply_to: Option<String>,
}

pub fn from_message(number: u32, meta: &MessageMeta, message: &[u8]) -> ThreadMessage {
    let headers = mime::parse_headers(message);
    let date = headers
        .get("date")
        .and_then(date::parse_header_date)
        .unwrap_or(meta.internal_date);
    ThreadMessage {
        number,
        arrival: meta.internal_date,
        date,
        subject: normalize_subject(headers.get("subject").unwrap_or("")),
        message_id: headers.get("message-id").and_then(normalize_id),
        references: parse_id_list(headers.get("references").unwrap_or("")),
        in_reply_to: headers.get("in-reply-to").and_then(normalize_id),
    }
}

fn normalize_id(value: &str) -> Option<String> {
    let value = value.trim().trim_matches(|ch| ch == '<' || ch == '>');
    (!value.is_empty()).then(|| value.to_string())
}

fn parse_id_list(value: &str) -> Vec<String> {
    value.split_whitespace().filter_map(normalize_id).collect()
}

fn normalize_subject(value: &str) -> String {
    let mut subject = value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase();
    loop {
        let trimmed = subject.trim_start();
        let mut stripped = false;
        for prefix in ["re:", "fwd:", "fw:", "aw:", "sv:"] {
            if let Some(rest) = trimmed.strip_prefix(prefix) {
                subject = rest.trim_start().to_string();
                stripped = true;
                break;
            }
        }
        if !stripped {
            break;
        }
    }
    subject
}

fn ordered(messages: &[ThreadMessage]) -> Vec<usize> {
    let mut indices: Vec<usize> = (0..messages.len()).collect();
    indices.sort_by(|&a, &b| {
        messages[a]
            .subject
            .cmp(&messages[b].subject)
            .then_with(|| messages[a].date.cmp(&messages[b].date))
            .then_with(|| messages[a].number.cmp(&messages[b].number))
    });
    indices
}

pub fn render(algorithm: ThreadAlgorithm, messages: &[ThreadMessage]) -> String {
    match algorithm {
        ThreadAlgorithm::OrderedSubject => render_ordered_subject(messages),
        ThreadAlgorithm::References => render_references(messages),
    }
}

fn render_ordered_subject(messages: &[ThreadMessage]) -> String {
    let indices = ordered(messages);
    let mut groups: Vec<Vec<usize>> = Vec::new();
    for index in indices {
        match groups.last_mut() {
            Some(group) if messages[group[0]].subject == messages[index].subject => {
                group.push(index);
            }
            _ => groups.push(vec![index]),
        }
    }

    groups.sort_by(|a, b| {
        let first = &messages[a[0]];
        let second = &messages[b[0]];
        first
            .date
            .cmp(&second.date)
            .then_with(|| first.number.cmp(&second.number))
    });
    let mut out = String::new();
    for group in groups {
        out.push('(');
        for (position, index) in group.iter().enumerate() {
            if position > 0 {
                out.push(' ');
            }
            out.push_str(&messages[*index].number.to_string());
        }
        out.push(')');
    }
    out
}

fn render_references(messages: &[ThreadMessage]) -> String {
    let mut by_id: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for (index, message) in messages.iter().enumerate() {
        if let Some(id) = &message.message_id {
            by_id.entry(id.as_str()).or_insert(index);
        }
    }
    let mut parents: Vec<Option<usize>> = vec![None; messages.len()];
    for (index, message) in messages.iter().enumerate() {
        let parent_id = message
            .references
            .iter()
            .rev()
            .find_map(|id| by_id.get(id.as_str()).copied())
            .or_else(|| {
                message
                    .in_reply_to
                    .as_ref()
                    .and_then(|id| by_id.get(id.as_str()).copied())
            });
        if let Some(parent) = parent_id {
            if parent != index {
                parents[index] = Some(parent);
            }
        }
    }
    let mut children: Vec<Vec<usize>> = vec![Vec::new(); messages.len()];

    for start in 0..messages.len() {
        let mut seen = std::collections::HashSet::new();
        let mut current = start;
        loop {
            if !seen.insert(current) {
                parents[start] = None;
                break;
            }
            match parents[current] {
                Some(parent) => current = parent,
                None => break,
            }
        }
    }
    let mut roots: Vec<usize> = Vec::new();
    for (index, parent) in parents.iter().enumerate() {
        match parent {
            Some(parent) => children[*parent].push(index),
            None => roots.push(index),
        }
    }
    roots.sort_by(|&a, &b| {
        messages[a]
            .date
            .cmp(&messages[b].date)
            .then_with(|| messages[a].number.cmp(&messages[b].number))
    });
    for list in &mut children {
        list.sort_by(|&a, &b| {
            messages[a]
                .date
                .cmp(&messages[b].date)
                .then_with(|| messages[a].number.cmp(&messages[b].number))
        });
    }

    let mut out = String::new();
    let mut stack: Vec<usize> = Vec::new();
    for root in roots {
        render_reference_node(&mut out, messages, &children, root, &mut stack);
    }
    out
}

const MAX_REFERENCE_DEPTH: usize = 512;

fn render_reference_node(
    out: &mut String,
    messages: &[ThreadMessage],
    children: &[Vec<usize>],
    index: usize,
    stack: &mut Vec<usize>,
) {
    if stack.contains(&index) || stack.len() > MAX_REFERENCE_DEPTH {
        out.push('(');
        out.push_str(&messages[index].number.to_string());
        out.push(')');
        return;
    }
    stack.push(index);
    out.push('(');
    out.push_str(&messages[index].number.to_string());
    for &child in &children[index] {
        out.push(' ');
        if children[child].is_empty() {
            out.push_str(&messages[child].number.to_string());
        } else {
            render_reference_node(out, messages, children, child, stack);
        }
    }
    out.push(')');
    stack.pop();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(number: u32, subject: &str, date: i64) -> ThreadMessage {
        ThreadMessage {
            number,
            arrival: date,
            date,
            subject: subject.to_string(),
            message_id: Some(format!("id{number}")),
            references: Vec::new(),
            in_reply_to: None,
        }
    }

    #[test]
    fn ordered_subject_groups_replies() {
        let messages = vec![
            message(1, "topic", 100),
            message(2, "re: topic", 200),
            message(3, "other", 300),
        ];
        let messages: Vec<ThreadMessage> = messages
            .into_iter()
            .map(|mut message| {
                message.subject = normalize_subject(&message.subject);
                message
            })
            .collect();
        assert_eq!(
            render(ThreadAlgorithm::OrderedSubject, &messages),
            "(1 2)(3)"
        );
    }

    #[test]
    fn references_nest_children() {
        let mut one = message(1, "topic", 100);
        one.message_id = Some("a".into());
        let mut two = message(2, "topic", 200);
        two.message_id = Some("b".into());
        two.in_reply_to = Some("a".into());
        let mut three = message(3, "other", 300);
        three.message_id = Some("c".into());
        let messages = vec![one, two, three];
        assert_eq!(render(ThreadAlgorithm::References, &messages), "(1 2)(3)");
    }

    #[test]
    fn references_cycles_do_not_loop_forever() {
        let mut one = message(1, "a", 100);
        one.message_id = Some("a".into());
        one.in_reply_to = Some("b".into());
        let mut two = message(2, "b", 200);
        two.message_id = Some("b".into());
        two.in_reply_to = Some("a".into());
        let rendered = render(ThreadAlgorithm::References, &[one, two]);
        assert!(rendered.contains('('), "{rendered}");
    }

    #[test]
    fn reference_rendering_is_depth_capped() {
        let messages: Vec<ThreadMessage> = (1u32..=600)
            .map(|number| {
                let mut message = message(number, "topic", number as i64);
                if number > 1 {
                    message.references = vec![format!("id{}", number - 1)];
                }
                message
            })
            .collect();
        let rendered = render(ThreadAlgorithm::References, &messages);
        assert!(rendered.contains("(514)"), "{rendered}");
        assert!(
            !rendered.contains("(515)"),
            "超限的更深层不应输出: {rendered}"
        );
    }
}
