//! 服务端 HTML 消毒器（allowlist）。
//!
//! 邮件 HTML 是**不可信输入**：它来自任何能往这个邮箱发信的人。契约 §2.2 要求
//! 服务端消毒后再交付，前端还会用 sandbox iframe 二次隔离——两层都要有，
//! 服务端这一层是唯一能保证「即使前端有 bug 也不执行脚本」的那层。
//!
//! ## 设计
//!
//! * 手写 tokenizer，不引 HTML 解析库（契约不允许新增依赖；且这里需要的语义比
//!   完整 HTML5 解析简单得多：**只输出 allowlist 内的结构**）；
//! * 白名单标签 / 属性；未列入的标签**剥离标签保留文本**，危险标签**连内容一起丢**；
//! * URL 只允许 `http: https: mailto: cid:`，相对 URL 一律剥离；HTML 实体先解码
//!   再判 scheme（`jav&#x61;script:` 这种写法必须在解码后才被认出来）；
//! * 远程图片默认阻断：`src` 改写成 `data-blocked-src` 并计数，只有显式
//!   `?images=1` 才保留（防追踪像素与远程内容）；
//! * `cid:` 图片改写为本站 API 部件 URL；
//! * 输出是**合法 HTML**：文本节点与属性值都转义，标签栈保证闭合。
//!
//! ## 为什么必须「输出合法 HTML」
//!
//! 消毒器自己拼接字符串时，一个没转义的 `"` 就能把属性值提前闭合、注入新属性
//! ——那和没消毒等价。因此这里的每个输出点都过 [`escape_text`] /
//! [`escape_attribute`]，测试里还有「消毒结果再消毒一次必须不变」的幂等守卫。

use std::collections::HashMap;

use crate::{MAX_HTML_BYTES, MAX_SANITIZE_INPUT_BYTES};

/// 允许保留的标签（契约 §2.2）。
const ALLOWED_TAGS: &[&str] = &[
    "a",
    "b",
    "strong",
    "i",
    "em",
    "u",
    "s",
    "p",
    "br",
    "hr",
    "div",
    "span",
    "blockquote",
    "pre",
    "code",
    "ul",
    "ol",
    "li",
    "table",
    "thead",
    "tbody",
    "tr",
    "td",
    "th",
    "caption",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "img",
    "font",
    "center",
    "big",
    "small",
    "sub",
    "sup",
    "dl",
    "dt",
    "dd",
];

/// 连内容一起丢弃的标签（契约 §2.2）。
///
/// 其中 `input/link/meta/base/embed` 是 void 元素：没有「内容」可丢，整标签丢弃。
/// 其余（`script/style/iframe/svg/math/template/...`）必须跳过其内部文本，否则
/// `<script>alert(1)</script>` 会退化成输出 `alert(1)`（不是脚本，但也不是邮件内容）。
const DROP_WITH_CONTENT_TAGS: &[&str] = &[
    "script", "style", "iframe", "frame", "frameset", "object", "embed", "applet", "form", "input",
    "button", "textarea", "select", "option", "link", "meta", "base", "svg", "math", "template",
    "noscript",
];

/// 没有结束标签的 void 元素（输出时不入栈、不补闭合）。
const VOID_TAGS: &[&str] = &["br", "hr", "img"];

/// HTML 规范里的全部 void 元素（用于判断「丢弃标签时有没有内容可跳」）。
///
/// 把 `input/link/meta/base` 当成有内容的标签去跳，会一直跳到 EOF——
/// 一个 `<input>` 就能让整封邮件后半段消失。这类标签本身就是空元素，丢标签即可。
const VOID_ELEMENTS: &[&str] = &[
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track",
    "wbr",
];

/// 允许保留的属性（契约 §2.2 + 消毒器自己产出的 `data-blocked-src`）。
const ALLOWED_ATTRIBUTES: &[&str] = &[
    "href",
    "src",
    "alt",
    "title",
    "width",
    "height",
    "colspan",
    "rowspan",
    "align",
    "valign",
    "dir",
    "lang",
    "style",
    "data-blocked-src",
];

/// `style` 里允许保留的 CSS 属性（安全子集）。
///
/// 排除 `position/display/z-index/top/left/right/bottom/background(-image)`：
/// 前一组能做出覆盖整个页面的钓鱼层，后一组能发起远程请求（追踪像素）。
const SAFE_STYLE_PROPERTIES: &[&str] = &[
    "color",
    "background-color",
    "font-family",
    "font-size",
    "font-style",
    "font-weight",
    "font-variant",
    "letter-spacing",
    "line-height",
    "text-align",
    "text-decoration",
    "text-indent",
    "text-transform",
    "vertical-align",
    "white-space",
    "word-break",
    "word-wrap",
    "border",
    "border-top",
    "border-right",
    "border-bottom",
    "border-left",
    "border-collapse",
    "border-spacing",
    "border-color",
    "border-style",
    "border-width",
    "margin",
    "margin-top",
    "margin-right",
    "margin-bottom",
    "margin-left",
    "padding",
    "padding-top",
    "padding-right",
    "padding-bottom",
    "padding-left",
    "width",
    "height",
    "max-width",
    "min-width",
];

/// 单个属性值的最大字符数。
const MAX_ATTRIBUTE_VALUE_CHARS: usize = 4_096;

/// 单个标签的属性个数上限。
const MAX_ATTRIBUTES_PER_TAG: usize = 64;

/// 消毒选项。
#[derive(Debug, Clone, Copy)]
pub struct SanitizeOptions<'a> {
    /// 是否保留远程图片（`?images=1`）。
    pub allow_remote_images: bool,
    /// `cid` 归一化值 → 本站部件 URL 的映射。
    pub cid_urls: &'a HashMap<String, String>,
}

impl Default for SanitizeOptions<'_> {
    fn default() -> Self {
        Self {
            allow_remote_images: false,
            cid_urls: &EMPTY_CID_URLS,
        }
    }
}

/// 静态空映射（`Default` 需要 `'static` 引用）。
static EMPTY_CID_URLS: std::sync::LazyLock<HashMap<String, String>> =
    std::sync::LazyLock::new(HashMap::new);

/// 消毒结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SanitizeOutcome {
    pub html: String,
    /// 被阻断的远程图片数（契约 `remoteImagesBlocked`）。
    pub remote_images_blocked: u32,
}

/// 消毒 HTML。
///
/// 输入先按字节上限截断（`MAX_HTML_BYTES`，见 [`MAX_SANITIZE_INPUT_BYTES`]），
/// 输出也有上限；超限后停止输出并闭合已打开标签，保证结果仍是合法 HTML。
pub fn sanitize_html(input: &str, options: &SanitizeOptions<'_>) -> SanitizeOutcome {
    let limit = MAX_SANITIZE_INPUT_BYTES.min(MAX_HTML_BYTES);
    let input = truncate_on_char_boundary(input, limit);
    let mut out = String::with_capacity(input.len().min(64 * 1024));
    let mut open: Vec<&'static str> = Vec::new();
    let mut blocked = 0u32;
    let mut skip: Option<SkipState> = None;
    let bytes = input.as_bytes();
    let mut index = 0usize;

    while index < bytes.len() {
        if out.len() >= MAX_SANITIZE_OUTPUT_BYTES {
            break;
        }
        if let Some(state) = skip.as_mut() {
            // 跳过模式只关心「标签结构」，但 index 此刻可能停在标签之间的文本上
            // （上一次 `tag.consumed_to` 指向 `>` 之后）。必须先推进到下一个 `<`，
            // 否则 `next_tag` 的 `debug_assert!(index at '<')` 会命中 —— 这正是
            // 本函数此前在「标签内嵌文本」输入上 panic 的原因。
            if bytes.get(index) != Some(&b'<') {
                match input[index..].find('<') {
                    Some(offset) => index += offset,
                    None => break,
                }
                continue;
            }
            match next_tag(input, index) {
                Some(tag) => {
                    if tag.is_end {
                        if tag.name == state.name {
                            state.depth -= 1;
                            if state.depth == 0 {
                                skip = None;
                            }
                        }
                    } else if tag.name == state.name && !tag.self_closing {
                        state.depth += 1;
                    }
                    index = tag.consumed_to;
                }
                None => break,
            }
            continue;
        }

        if bytes[index] != b'<' {
            let end = bytes[index..]
                .iter()
                .position(|byte| *byte == b'<')
                .map(|offset| index + offset)
                .unwrap_or(bytes.len());
            push_text(&mut out, &input[index..end]);
            index = end;
            continue;
        }

        // 注释 / doctype / CDATA / 处理指令：整段丢弃。
        if input[index..].starts_with("<!--") {
            match input[index + 4..].find("-->") {
                Some(end) => {
                    index = index + 4 + end + 3;
                    continue;
                }
                None => break,
            }
        }
        if input[index..].starts_with("<!") || input[index..].starts_with("<?") {
            match input[index..].find('>') {
                Some(end) => {
                    index += end + 1;
                    continue;
                }
                None => break,
            }
        }

        let Some(tag) = parse_tag(input, index) else {
            // 非标签的 `<`：按文本转义输出，越过这一个字符继续。
            push_text(&mut out, &input[index..index + 1]);
            index += 1;
            continue;
        };
        index = tag.consumed_to;

        if tag.is_end {
            if VOID_TAGS.contains(&tag.name.as_str()) {
                continue;
            }
            // 只在栈里找匹配项：未打开过的结束标签直接丢；不匹配的尾随标签
            // 一并关闭，避免输出 `<b><i></b>` 这种错嵌套。
            if let Some(position) = open.iter().rposition(|name| *name == tag.name) {
                while open.len() > position {
                    if let Some(name) = open.pop() {
                        out.push_str("</");
                        out.push_str(name);
                        out.push('>');
                    }
                }
            }
            continue;
        }

        if DROP_WITH_CONTENT_TAGS.contains(&tag.name.as_str()) {
            if !VOID_ELEMENTS.contains(&tag.name.as_str()) && !tag.self_closing {
                skip = Some(SkipState {
                    name: tag.name,
                    depth: 1,
                });
            }
            continue;
        }

        if !ALLOWED_TAGS.contains(&tag.name.as_str()) {
            // 非危险但不在 allowlist 的标签：剥离标签保留内容（不进入 skip）。
            continue;
        }

        let name: &'static str = match ALLOWED_TAGS.iter().find(|allowed| **allowed == tag.name) {
            Some(name) => name,
            None => continue,
        };
        if out.len() + 64 < MAX_SANITIZE_OUTPUT_BYTES {
            out.push('<');
            out.push_str(name);
            sanitize_attributes(name, &tag.attributes, options, &mut out, &mut blocked);
            if tag.self_closing && !VOID_TAGS.contains(&name) {
                // 非 void 标签的 `/>` 按普通开始标签处理（HTML 语义）。
            }
            out.push('>');
        }
        if !VOID_TAGS.contains(&name) {
            open.push(name);
        }
    }

    // 截断/结束时把还开着的标签按逆序闭合，保证输出合法。
    while let Some(name) = open.pop() {
        if out.len() + name.len() + 3 < MAX_SANITIZE_OUTPUT_BYTES {
            out.push_str("</");
            out.push_str(name);
            out.push('>');
        }
    }

    SanitizeOutcome {
        html: out,
        remote_images_blocked: blocked,
    }
}

/// 输出上限（字节）。
const MAX_SANITIZE_OUTPUT_BYTES: usize = MAX_SANITIZE_INPUT_BYTES + MAX_SANITIZE_INPUT_BYTES / 4;

/// 正在跳过的「连内容一起丢」标签的嵌套状态。
struct SkipState {
    name: String,
    depth: usize,
}

/// 一个解析出来的标签。
struct Tag {
    is_end: bool,
    name: String,
    attributes: Vec<(String, String)>,
    self_closing: bool,
    /// 该标签结束后的输入偏移。
    consumed_to: usize,
}

/// 从 `index` 起跳过一个完整的 HTML 标签（用于 skip 模式里只关心结构）。
fn next_tag(input: &str, index: usize) -> Option<Tag> {
    debug_assert!(input.as_bytes().get(index) == Some(&b'<'));
    parse_tag(input, index)
}

/// 解析 `<name attr=value ...>` / `</name>`。
///
/// 返回 `None` 表示「这里不是可解析的标签」——调用方会把 `<` 当文本输出。
/// 解析永远不会 panic：所有切片都在 ASCII 定界符上推进，遇到 EOF 就返回 `None`。
fn parse_tag(input: &str, start: usize) -> Option<Tag> {
    let bytes = input.as_bytes();
    let mut index = start;
    if bytes.get(index) != Some(&b'<') {
        return None;
    }
    index += 1;
    let is_end = bytes.get(index) == Some(&b'/');
    if is_end {
        index += 1;
    }
    let name_start = index;
    while let Some(byte) = bytes.get(index) {
        if byte.is_ascii_alphanumeric() || *byte == b'-' || *byte == b':' || *byte == b'_' {
            index += 1;
        } else {
            break;
        }
    }
    if index == name_start {
        return None;
    }
    let name = input[name_start..index].to_ascii_lowercase();
    let mut attributes: Vec<(String, String)> = Vec::new();
    let self_closing = false;

    loop {
        while bytes
            .get(index)
            .map(|byte| byte.is_ascii_whitespace())
            .unwrap_or(false)
        {
            index += 1;
        }
        match bytes.get(index) {
            None => return None,
            Some(b'>') => {
                return Some(Tag {
                    is_end,
                    name,
                    attributes,
                    self_closing,
                    consumed_to: index + 1,
                })
            }
            Some(b'/') if bytes.get(index + 1) == Some(&b'>') => {
                return Some(Tag {
                    is_end,
                    name,
                    attributes,
                    self_closing: true,
                    consumed_to: index + 2,
                })
            }
            Some(_) => {}
        }
        if is_end {
            // 结束标签允许出现多余属性（真实世界有），忽略直到 `>`。
            let end = input[index..].find('>')?;
            return Some(Tag {
                is_end,
                name,
                attributes,
                self_closing: false,
                consumed_to: index + end + 1,
            });
        }
        // 属性名。
        let name_start = index;
        while let Some(byte) = bytes.get(index) {
            if byte.is_ascii_whitespace() || *byte == b'=' || *byte == b'>' || *byte == b'/' {
                break;
            }
            index += 1;
        }
        if index == name_start {
            // 游离字符（如 `=`）：跳过它，避免死循环。
            index += 1;
            continue;
        }
        let attribute_name = input[name_start..index].to_ascii_lowercase();
        while bytes
            .get(index)
            .map(|byte| byte.is_ascii_whitespace())
            .unwrap_or(false)
        {
            index += 1;
        }
        if bytes.get(index) != Some(&b'=') {
            if attributes.len() < MAX_ATTRIBUTES_PER_TAG {
                attributes.push((attribute_name, String::new()));
            }
            continue;
        }
        index += 1;
        while bytes
            .get(index)
            .map(|byte| byte.is_ascii_whitespace())
            .unwrap_or(false)
        {
            index += 1;
        }
        let value;
        match bytes.get(index) {
            None => return None,
            Some(b'"') | Some(b'\'') => {
                let quote = bytes[index];
                index += 1;
                let value_start = index;
                while let Some(byte) = bytes.get(index) {
                    if *byte == quote {
                        break;
                    }
                    index += 1;
                }
                if bytes.get(index) != Some(&quote) {
                    return None;
                }
                value = input[value_start..index].to_string();
                index += 1;
            }
            Some(_) => {
                let value_start = index;
                while let Some(byte) = bytes.get(index) {
                    if byte.is_ascii_whitespace() || *byte == b'>' {
                        break;
                    }
                    index += 1;
                }
                value = input[value_start..index].to_string();
            }
        }
        if attributes.len() < MAX_ATTRIBUTES_PER_TAG {
            attributes.push((attribute_name, value));
        }
    }
}

/// 按标签名过滤属性并写进输出。
fn sanitize_attributes(
    tag: &'static str,
    attributes: &[(String, String)],
    options: &SanitizeOptions<'_>,
    out: &mut String,
    blocked: &mut u32,
) {
    let mut seen: Vec<&str> = Vec::new();
    for (name, raw_value) in attributes {
        if !ALLOWED_ATTRIBUTES.contains(&name.as_str()) {
            continue;
        }
        // 同名属性只保留第一个（后面的重名在浏览器里行为不一致，是绕过面）。
        if seen.contains(&name.as_str()) {
            continue;
        }
        seen.push(name.as_str());

        // 只对真正有 URL 语义的标签保留 URL 属性。
        match (tag, name.as_str()) {
            ("img", "src") => {
                let decoded = decode_entities_limited(raw_value);
                match classify_image_url(&decoded, options) {
                    ImageSource::Keep(url) => {
                        out.push_str(" src=\"");
                        out.push_str(&escape_attribute(&url));
                        out.push('"');
                    }
                    ImageSource::Blocked(url) => {
                        out.push_str(" data-blocked-src=\"");
                        out.push_str(&escape_attribute(&url));
                        out.push('"');
                        *blocked = blocked.saturating_add(1);
                    }
                    ImageSource::Drop => {}
                }
            }
            ("img", "data-blocked-src") => {
                // 幂等：消毒结果再次消毒时保留这个惰性属性（它没有 src 语义）。
                let decoded = decode_entities_limited(raw_value);
                out.push_str(" data-blocked-src=\"");
                out.push_str(&escape_attribute(&decoded));
                out.push('"');
            }
            ("a", "href") => {
                let decoded = decode_entities_limited(raw_value);
                if let Some(url) = safe_link_url(&decoded) {
                    out.push_str(" href=\"");
                    out.push_str(&escape_attribute(&url));
                    out.push('"');
                }
            }
            (_, "href") | (_, "src") => {
                // 其它标签上的 href/src 一律丢弃（没有渲染语义，保留只会扩大攻击面）。
            }
            (_, "style") => {
                let decoded = decode_entities_limited(raw_value);
                if let Some(style) = sanitize_style(&decoded) {
                    out.push_str(" style=\"");
                    out.push_str(&escape_attribute(&style));
                    out.push('"');
                }
            }
            (_, "width") | (_, "height") => {
                let decoded = decode_entities_limited(raw_value);
                if let Some(value) = sanitize_dimension(&decoded) {
                    out.push(' ');
                    out.push_str(name);
                    out.push_str("=\"");
                    out.push_str(&value);
                    out.push('"');
                }
            }
            (_, "colspan") | (_, "rowspan") => {
                let decoded = decode_entities_limited(raw_value);
                if let Ok(number) = decoded.trim().parse::<u32>() {
                    if (1..=1000).contains(&number) {
                        out.push(' ');
                        out.push_str(name);
                        out.push_str("=\"");
                        out.push_str(&number.to_string());
                        out.push('"');
                    }
                }
            }
            (_, "align") => {
                let decoded = decode_entities_limited(raw_value).to_ascii_lowercase();
                if matches!(
                    decoded.trim(),
                    "left" | "right" | "center" | "justify" | "top" | "middle" | "bottom"
                ) {
                    out.push(' ');
                    out.push_str(name);
                    out.push_str("=\"");
                    out.push_str(&escape_attribute(decoded.trim()));
                    out.push('"');
                }
            }
            (_, "valign") => {
                let decoded = decode_entities_limited(raw_value).to_ascii_lowercase();
                if matches!(decoded.trim(), "top" | "middle" | "bottom" | "baseline") {
                    out.push(' ');
                    out.push_str(name);
                    out.push_str("=\"");
                    out.push_str(&escape_attribute(decoded.trim()));
                    out.push('"');
                }
            }
            (_, "dir") => {
                let decoded = decode_entities_limited(raw_value).to_ascii_lowercase();
                if matches!(decoded.trim(), "ltr" | "rtl" | "auto") {
                    out.push_str(" dir=\"");
                    out.push_str(&escape_attribute(decoded.trim()));
                    out.push('"');
                }
            }
            (_, "lang") => {
                let decoded = decode_entities_limited(raw_value);
                let trimmed = decoded.trim();
                if !trimmed.is_empty()
                    && trimmed.len() <= 32
                    && trimmed
                        .chars()
                        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
                {
                    out.push_str(" lang=\"");
                    out.push_str(&escape_attribute(trimmed));
                    out.push('"');
                }
            }
            (_, "alt") | (_, "title") => {
                let decoded = decode_entities_limited(raw_value);
                let trimmed: String = decoded
                    .chars()
                    .filter(|ch| !ch.is_control())
                    .take(MAX_ATTRIBUTE_VALUE_CHARS)
                    .collect();
                if !trimmed.is_empty() {
                    out.push(' ');
                    out.push_str(name);
                    out.push_str("=\"");
                    out.push_str(&escape_attribute(&trimmed));
                    out.push('"');
                }
            }
            _ => {}
        }
    }

    if tag == "a" {
        // 契约 §2.2：`<a>` 统一加 rel/target。放在最后，覆盖不了（同名属性
        // 不在 allowlist 里，攻击者给的值已被丢弃）。
        out.push_str(" rel=\"noopener noreferrer nofollow\" target=\"_blank\"");
    }
}

/// 图片 `src` 的分类结果。
enum ImageSource {
    /// 保留原 URL。
    Keep(String),
    /// 阻断（改成 `data-blocked-src`）。
    Blocked(String),
    /// 直接丢弃（非法 scheme / 相对 URL / 未知 cid）。
    Drop,
}

/// 图片 URL 判定（契约 §2.2 第三条）。
fn classify_image_url(value: &str, options: &SanitizeOptions<'_>) -> ImageSource {
    let trimmed = trim_unsafe(value);
    if trimmed.is_empty() {
        return ImageSource::Drop;
    }
    if let Some(cid) = strip_scheme(trimmed, "cid:") {
        let key = cid.trim_matches(|ch| ch == '<' || ch == '>' || ch == '"');
        let normalized = key.to_ascii_lowercase();
        if let Some(url) = options.cid_urls.get(key) {
            return ImageSource::Keep(url.clone());
        }
        if let Some(url) = options.cid_urls.get(&normalized) {
            return ImageSource::Keep(url.clone());
        }
        return ImageSource::Drop;
    }
    if is_http_url(trimmed) {
        if options.allow_remote_images {
            return ImageSource::Keep(trimmed.to_string());
        }
        return ImageSource::Blocked(trimmed.to_string());
    }
    // 相对 URL、data:、javascript:、file: 等一律剥离。
    ImageSource::Drop
}

/// 链接 URL 判定：只允许 `http: https: mailto:`。
fn safe_link_url(value: &str) -> Option<String> {
    let trimmed = trim_unsafe(value);
    if trimmed.is_empty() {
        return None;
    }
    if is_http_url(trimmed) || has_scheme(trimmed, "mailto:") {
        return Some(trimmed.to_string());
    }
    None
}

/// URL 是否以 `http:` / `https:` 开头（大小写不敏感）。
fn is_http_url(value: &str) -> bool {
    has_scheme(value, "http://") || has_scheme(value, "https://")
}

/// 是否以指定 scheme 开头（大小写不敏感）。
fn has_scheme(value: &str, scheme: &str) -> bool {
    value.len() >= scheme.len() && value[..scheme.len()].eq_ignore_ascii_case(scheme)
}

/// 若以指定 scheme 开头则返回去掉 scheme 的剩余部分。
fn strip_scheme<'a>(value: &'a str, scheme: &str) -> Option<&'a str> {
    if has_scheme(value, scheme) {
        Some(&value[scheme.len()..])
    } else {
        None
    }
}

/// URL 清理：去掉首尾空白与控制字符（含 `\t\r\n`——`java\nscript:` 这种绕过）。
///
/// 中间的控制字符不是合法 URL 的一部分，直接整体判为不安全（返回空串）。
fn trim_unsafe(value: &str) -> &str {
    let value = value.trim();
    if value.chars().any(char::is_control) {
        return "";
    }
    value
}

/// `style` 属性清洗：只保留安全属性子集。
fn sanitize_style(value: &str) -> Option<String> {
    let mut declarations: Vec<String> = Vec::new();
    for declaration in value.split(';') {
        let Some((property, raw_value)) = declaration.split_once(':') else {
            continue;
        };
        let property = property.trim().to_ascii_lowercase();
        if !SAFE_STYLE_PROPERTIES.contains(&property.as_str()) {
            continue;
        }
        let raw_value = raw_value.trim();
        if raw_value.is_empty() || raw_value.len() > 256 {
            continue;
        }
        let lowered = raw_value.to_ascii_lowercase();
        // 远程请求 / 表达式 / 协议处理器：即使当前属性名安全，值里也不允许出现。
        if lowered.contains("url(")
            || lowered.contains("expression")
            || lowered.contains("javascript")
            || lowered.contains("@import")
            || lowered.contains('\\')
            || lowered.contains("/*")
            || lowered.contains("*/")
            || lowered.contains('<')
            || lowered.contains('>')
            || lowered.contains("behavior")
        {
            continue;
        }
        if raw_value.chars().any(char::is_control) {
            continue;
        }
        declarations.push(format!("{property}: {raw_value}"));
        if declarations.len() >= 32 {
            break;
        }
    }
    if declarations.is_empty() {
        None
    } else {
        Some(declarations.join("; "))
    }
}

/// `width` / `height`：只接受纯数字或百分比。
fn sanitize_dimension(value: &str) -> Option<String> {
    let trimmed = value.trim();
    let digits = trimmed.strip_suffix('%').unwrap_or(trimmed);
    if digits.is_empty() || digits.len() > 6 || !digits.chars().all(|ch| ch.is_ascii_digit()) {
        return None;
    }
    if trimmed.ends_with('%') {
        Some(format!("{digits}%"))
    } else {
        Some(digits.to_string())
    }
}

/// 文本节点转义。
///
/// 合法的 HTML 实体（`&amp;` 等）原样保留，其余 `&` 转义：否则输出会被浏览器
/// 二次解码（把用户文本里的 `&lt;b&gt;` 变成真的 `<b>`）。实体在**文本上下文**
/// 里没有 XSS 能力（`&#60;script&#62;` 仍是文本），因此保留是安全的。
fn push_text(out: &mut String, text: &str) {
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'<' => {
                out.push_str("&lt;");
                index += 1;
            }
            b'>' => {
                out.push_str("&gt;");
                index += 1;
            }
            b'&' => {
                if let Some(length) = entity_length(&text[index..]) {
                    out.push_str(&text[index..index + length]);
                    index += length;
                } else {
                    out.push_str("&amp;");
                    index += 1;
                }
            }
            _ => {
                let ch = text[index..].chars().next().unwrap_or(' ');
                out.push(ch);
                index += ch.len_utf8();
            }
        }
    }
}

/// 若 `value` 以合法 HTML 实体开头，返回它的字节长度。
fn entity_length(value: &str) -> Option<usize> {
    let bytes = value.as_bytes();
    if bytes.first() != Some(&b'&') {
        return None;
    }
    let semicolon = value.get(1..)?.find(';')?;
    if semicolon > 10 {
        return None;
    }
    let entity = &value[1..1 + semicolon];
    let valid = match entity {
        "amp" | "lt" | "gt" | "quot" | "apos" | "nbsp" => true,
        _ => {
            let number = entity.strip_prefix('#')?;
            let digits = number
                .strip_prefix('x')
                .or_else(|| number.strip_prefix('X'))
                .unwrap_or(number);
            !digits.is_empty() && digits.chars().all(|ch| ch.is_ascii_hexdigit())
        }
    };
    valid.then_some(semicolon + 2)
}

/// 属性值转义。
fn escape_attribute(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(ch),
        }
    }
    out
}

/// 解码常见 HTML 实体（判 scheme 之前必须做：`jav&#x61;script:` 是真实绕过）。
fn decode_entities_limited(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'&' {
            if let Some(semicolon) = value[index + 1..].find(';') {
                if semicolon <= 10 {
                    let entity = &value[index + 1..index + 1 + semicolon];
                    if let Some(decoded) = decode_one_entity(entity) {
                        out.push(decoded);
                        index += semicolon + 2;
                        continue;
                    }
                }
            }
        }
        let ch = value[index..].chars().next().unwrap_or(' ');
        out.push(ch);
        index += ch.len_utf8();
    }
    out
}

fn decode_one_entity(entity: &str) -> Option<char> {
    match entity {
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        "nbsp" => Some(' '),
        _ => {
            let number = entity.strip_prefix('#')?;
            if let Some(hex) = number
                .strip_prefix('x')
                .or_else(|| number.strip_prefix('X'))
            {
                u32::from_str_radix(hex, 16).ok().and_then(char::from_u32)
            } else {
                number.parse::<u32>().ok().and_then(char::from_u32)
            }
        }
    }
}

/// 在 char 边界上截断到 `limit` 字节。
fn truncate_on_char_boundary(value: &str, limit: usize) -> &str {
    if value.len() <= limit {
        return value;
    }
    let mut end = limit;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sanitize(input: &str) -> SanitizeOutcome {
        sanitize_html(input, &SanitizeOptions::default())
    }

    fn assert_no_active_content(html: &str) {
        let lower = html.to_ascii_lowercase();
        for needle in [
            "<script",
            "</script",
            "<iframe",
            "<object",
            "<embed",
            "<applet",
            "<form",
            "<input",
            "<button",
            "<textarea",
            "<select",
            "<link",
            "<meta",
            "<base",
            "<svg",
            "<math",
            "<template",
            "<style",
            "onerror",
            "onload",
            "onclick",
            "javascript:",
            "vbscript:",
            "data:text/html",
            "srcdoc",
            "formaction",
        ] {
            assert!(
                !lower.contains(needle),
                "输出仍含危险片段 {needle:?}：{html}"
            );
        }
    }

    /// 契约 §2.2 的 XSS 向量语料（也是不变量测试的语料来源）。
    const XSS_CORPUS: &[&str] = &[
        "<script>alert(1)</script>",
        "<SCRIPT SRC=//evil.example/x.js></SCRIPT>",
        "<img src=x onerror=alert(1)>",
        "<img src=\"x\" OnErRoR=\"alert(1)\">",
        "<a href=\"javascript:alert(1)\">click</a>",
        "<a href='jav&#x61;script:alert(1)'>click</a>",
        "<a href=\"data:text/html,<script>alert(1)</script>\">x</a>",
        "<iframe src=\"https://evil.example\"></iframe>",
        "<svg onload=alert(1)>",
        "<svg><script>alert(1)</script></svg>",
        "<math><mtext></mtext></math>",
        "<object data=\"x\"></object>",
        "<embed src=\"x\">",
        "<form action=\"https://evil.example\"><input name=x></form>",
        "<style>@import url(https://evil.example/x.css);</style>",
        "<div style=\"background:url(https://evil.example/pixel)\">x</div>",
        "<div style=\"position:fixed;top:0;left:0;width:100vw;height:100vh\">x</div>",
        "<p onclick=alert(1)>x</p>",
        "<scr<script>ipt>alert(1)</scr</script>ipt>",
        "<img src=\"https://evil.example/pixel.png\">",
        "<base href=\"https://evil.example/\">",
        "<meta http-equiv=\"refresh\" content=\"0;url=https://evil.example\">",
        "<video><source onerror=alert(1)></video>",
        "<textarea></textarea><script>alert(1)</script>",
        "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\"></noscript>",
        "<a href=\"  javascript:alert(1)\">x</a>",
        "<a href=\"java\nscript:alert(1)\">x</a>",
        "<img src=\"cid:unknown@example\">",
        "<p>&#60;script&#62;alert(1)&#60;/script&#62;</p>",
        "<div style=\"background-image: url(javascript:alert(1))\">x</div>",
        "<a href=\"https://ok.example\" rel=\"opener\">ok</a>",
    ];

    /// 反例守卫：消毒器必须剥掉脚本与事件处理器（不变量测试语料在这里）。
    #[test]
    fn webmail_html_sanitizer_strips_scripts_and_event_handlers() {
        for vector in XSS_CORPUS {
            let outcome = sanitize(vector);
            assert_no_active_content(&outcome.html);
            // 输出必须仍是合法 HTML：标签闭合、引号成对（简单结构性检查）。
            assert!(
                outcome.html.matches('<').count() == outcome.html.matches('>').count(),
                "输出标签不配平：{} ← {vector}",
                outcome.html
            );
        }

        // 具体向量的可读断言：script 内容整段丢弃、事件属性丢弃、危险 scheme 丢弃。
        assert!(!sanitize("<script>alert(1)</script>").html.contains("alert"));
        assert!(!sanitize("<img src=x onerror=alert(1)>")
            .html
            .contains("onerror"));
        assert!(!sanitize("<a href=\"javascript:alert(1)\">x</a>")
            .html
            .contains("javascript"));
        assert!(!sanitize("<iframe src=x></iframe>").html.contains("<iframe"));
    }

    #[test]
    fn allowlisted_markup_survives_with_escaped_text() {
        let outcome = sanitize("<p>Hello <b>world</b> &amp; &lt;friends&gt;</p>");
        assert_eq!(
            outcome.html,
            "<p>Hello <b>world</b> &amp; &lt;friends&gt;</p>"
        );
        // 文本里的裸尖括号被转义。
        assert_eq!(sanitize("1 < 2 > 0").html, "1 &lt; 2 &gt; 0");
    }

    #[test]
    fn links_get_target_and_rel_and_only_safe_schemes() {
        let outcome = sanitize("<a href=\"https://example.com/x\">x</a>");
        assert!(outcome.html.contains("href=\"https://example.com/x\""));
        assert!(outcome
            .html
            .contains("rel=\"noopener noreferrer nofollow\""));
        assert!(outcome.html.contains("target=\"_blank\""));

        // 相对 URL 按契约剥离，但保留链接文本。
        let relative = sanitize("<a href=\"/settings\">x</a>");
        assert!(!relative.html.contains("href="), "{}", relative.html);
        assert!(relative.html.contains(">x</a>"));

        // mailto 允许。
        assert!(sanitize("<a href=\"mailto:a@b.c\">m</a>")
            .html
            .contains("href=\"mailto:a@b.c\""));
    }

    /// 反例守卫：远程图片默认必须被阻断并计数（追踪像素防线）。
    #[test]
    fn webmail_html_sanitizer_blocks_remote_images_by_default() {
        let outcome = sanitize("<p><img src=\"https://evil.example/pixel.png\" alt=\"x\"></p>");
        // 注意：`data-blocked-src="https://…"` 里天然含有子串 `src="https`，
        // 因此断言必须带前导空格（真正的 ` src="` 才说明图片没被阻断）。
        assert!(
            !outcome.html.contains(" src=\"https://evil.example"),
            "默认必须阻断远程图片：{}",
            outcome.html
        );
        assert!(outcome
            .html
            .contains("data-blocked-src=\"https://evil.example/pixel.png\""));
        assert!(outcome.html.contains("alt=\"x\""));
        assert_eq!(outcome.remote_images_blocked, 1);

        // 显式允许（?images=1）时保留 src。
        let cid_urls = HashMap::new();
        let allowed = sanitize_html(
            "<img src=\"https://cdn.example/p.png\">",
            &SanitizeOptions {
                allow_remote_images: true,
                cid_urls: &cid_urls,
            },
        );
        assert!(allowed.html.contains("src=\"https://cdn.example/p.png\""));
        assert_eq!(allowed.remote_images_blocked, 0);

        // 内嵌 cid 图片改写为本站部件 URL。
        let mut cid_urls = HashMap::new();
        cid_urls.insert(
            "img1@example.com".to_string(),
            "/mail/api/messages/INBOX/7/parts/3".to_string(),
        );
        let rewritten = sanitize_html(
            "<img src=\"cid:img1@example.com\">",
            &SanitizeOptions {
                allow_remote_images: false,
                cid_urls: &cid_urls,
            },
        );
        assert!(rewritten
            .html
            .contains("src=\"/mail/api/messages/INBOX/7/parts/3\""));
    }

    #[test]
    fn unsafe_css_is_dropped_and_safe_subset_is_kept() {
        let outcome = sanitize(
            "<div style=\"color: red; position: fixed; background: url(https://evil.example/x)\">x</div>",
        );
        assert!(outcome.html.contains("color: red"), "{}", outcome.html);
        assert!(!outcome.html.contains("position"));
        assert!(!outcome.html.contains("url("));
        assert!(!outcome.html.contains("evil.example"));
    }

    #[test]
    fn attribute_injection_cannot_break_out_of_the_quotes() {
        let outcome = sanitize("<p title=\"x&quot; onmouseover=&quot;alert(1)\">hi</p>");
        assert_no_active_content(&outcome.html);
        // 值里的引号被转义，属性没有被提前闭合：整段内容仍在 title 的值里。
        assert!(outcome
            .html
            .contains("title=\"x&quot; onmouseover=&quot;alert(1)\""));
        let idempotent = sanitize(&outcome.html);
        assert_eq!(idempotent.html, outcome.html);
    }

    #[test]
    fn sanitization_is_idempotent_across_the_corpus() {
        for vector in XSS_CORPUS {
            let once = sanitize(vector).html;
            let twice = sanitize(&once).html;
            assert_eq!(twice, once, "消毒不幂等，输入：{vector}");
        }
    }

    #[test]
    fn malformed_markup_does_not_panic_or_loop() {
        for input in [
            "<",
            "<p",
            "<p attr=",
            "<p attr=\"unterminated",
            "<!-- unterminated",
            "<![CDATA[ x",
            ">>><<<",
            "<p><b><i>unclosed",
            "</p></div></b>",
            "<div><p></div></p>",
            "<img src=",
            "a < b && c > d",
            "<p style=\"color: red",
        ] {
            let outcome = sanitize(input);
            assert_no_active_content(&outcome.html);
        }
    }

    #[test]
    fn output_is_bounded_for_oversized_input() {
        let huge = format!("<p>{}</p>", "x".repeat(MAX_SANITIZE_INPUT_BYTES + 4096));
        let outcome = sanitize(&huge);
        assert!(outcome.html.len() <= MAX_SANITIZE_OUTPUT_BYTES + 64);
    }

    #[test]
    fn comments_and_doctype_are_removed() {
        let outcome = sanitize("<!DOCTYPE html><!-- hi --><p>ok</p>");
        assert_eq!(outcome.html, "<p>ok</p>");
    }
}
