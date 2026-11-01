//! AI 子系统（`ai.*`）：出站 HTTP 客户端 + SSRF / DNS-rebinding 防护。
//!
//! 从 `backend/mailstackctl/ai.py` 等价移植。除 `ai.config.get`（已在
//! `handlers.rs`）外，这里是其余六个动作的实现。
//!
//! ## 安全骨架（不得弱化）
//!
//! 1. **地址筛选复用 [`AddressPolicy`]**：它已覆盖私网 / 环回 / 链路本地 /
//!    CGNAT 100.64/10 / fake-IP 198.18/15 / 文档段，并会拆出 IPv6 里内嵌的
//!    IPv4（`::ffff:127.0.0.1` 之类）。**绝不另写一份 IP 黑名单** —— 两份规则
//!    迟早漂移，而漂移的那次就是 SSRF 缺口。
//! 2. **解析后固定第一个 IP，再按这个 IP 拨号，用原域名做 SNI/Host**：
//!    这是 DNS-rebinding 防护的落点。校验与连接必须针对**同一个** IP，
//!    否则两次 DNS 应答之间的窗口可以被换成一个内网地址。
//! 3. **`insecureTls` 一律拒绝**：允许关掉证书校验等于把上面全部保护连同
//!    中间人一起交出去。
//! 4. **重定向必须同源**：跨源重定向会绕过「解析→筛选→固定」整条链，
//!    因为新目标从未被筛选过。
//!
//! ## 可测试性
//!
//! 出站 HTTP 抽成 [`AiTransport`]（生产用 `PinnedDialer` + 手写 HTTP/1.1），
//! DNS 解析抽成 [`HostResolver`]。测试注入替身，**绝不发真实网络请求**。

use std::future::Future;
use std::net::{IpAddr, ToSocketAddrs};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use mailstack_core::atomic;
use mailstack_core::paths::Paths;
use mailstack_smtp::target::pinned_from_addresses;
use mailstack_smtp::{AddressPolicy, PinnedDialer, PinnedTarget};
use serde_json::{json, Value};

use crate::handlers::HandlerError;

/// 响应体上限：2 MB（基线 `resp.read(2_000_001)` + `> 2_000_000` 判据）。
const MAX_RESPONSE_BYTES: usize = 2_000_000;
/// 读取时多读 1 字节，用于区分「恰好 2MB」与「超过 2MB」。
const READ_PROBE_BYTES: usize = MAX_RESPONSE_BYTES + 1;
/// URL 长度上限（基线 `len(raw_url) > 2048`）。
const MAX_URL_LEN: usize = 2048;
/// 重定向次数上限（基线 `redirects > 3`）。
const MAX_REDIRECTS: usize = 3;
const USER_AGENT: &str = "MailStack-AI-Hub/1.0";

// ───────────────────────── 预设 ─────────────────────────

/// 供应商预设。
pub struct AiPreset {
    pub key: &'static str,
    pub name: &'static str,
    pub base_url: &'static str,
    pub model: &'static str,
    pub models: &'static [&'static str],
    pub default_key: &'static str,
    pub doc_url: &'static str,
    /// 请求协议：`openai` 或 `anthropic`。
    pub protocol: &'static str,
}

/// 内置预设（与基线 `AI_PRESETS` 逐字一致）。
pub const AI_PRESETS: &[AiPreset] = &[
    AiPreset {
        key: "bigmodel",
        name: "GLM (BigModel)",
        base_url: "https://open.bigmodel.cn/api/paas/v4",
        model: "glm-4-flash",
        models: &[
            "glm-4-flash",
            "glm-4-plus",
            "glm-4-air",
            "glm-4-long",
            "glm-4-0520",
        ],
        default_key: "",
        doc_url: "https://open.bigmodel.cn/usercenter/apikeys",
        protocol: "openai",
    },
    AiPreset {
        key: "deepseek",
        name: "DeepSeek",
        base_url: "https://api.deepseek.com/v1",
        model: "deepseek-chat",
        models: &["deepseek-chat", "deepseek-reasoner"],
        default_key: "",
        doc_url: "https://platform.deepseek.com/api_keys",
        protocol: "openai",
    },
    AiPreset {
        key: "openai",
        name: "OpenAI",
        base_url: "https://api.openai.com/v1",
        model: "gpt-4o-mini",
        models: &["gpt-4o-mini", "gpt-4o", "gpt-3.5-turbo", "o1-mini"],
        default_key: "",
        doc_url: "https://platform.openai.com/api-keys",
        protocol: "openai",
    },
    AiPreset {
        key: "anthropic",
        name: "Anthropic Claude",
        base_url: "https://api.anthropic.com/v1",
        model: "claude-3-5-sonnet-20241022",
        models: &[
            "claude-3-5-sonnet-20241022",
            "claude-3-5-haiku-20241022",
            "claude-3-opus-20240229",
        ],
        default_key: "",
        doc_url: "https://console.anthropic.com/settings/keys",
        protocol: "anthropic",
    },
    AiPreset {
        key: "custom",
        name: "Custom OpenAI-compatible provider",
        base_url: "",
        model: "",
        models: &[],
        default_key: "",
        doc_url: "",
        protocol: "openai",
    },
];

/// 按 key 精确查找预设。**大小写敏感**（基线用 `in AI_PRESETS`，键是小写字面量）。
pub fn preset(provider: &str) -> Option<&'static AiPreset> {
    AI_PRESETS.iter().find(|p| p.key == provider)
}

/// 默认预设 `bigmodel`（基线所有 `.get(provider, AI_PRESETS['bigmodel'])` 的落点）。
pub fn default_preset() -> &'static AiPreset {
    &AI_PRESETS[0]
}

/// 部署侧私网开关：`MAILSTACK_ALLOW_PRIVATE_AI=1`。
pub fn private_network_enabled() -> bool {
    std::env::var("MAILSTACK_ALLOW_PRIVATE_AI")
        .map(|v| v == "1")
        .unwrap_or(false)
}

// ───────────────────────── 注入点 ─────────────────────────

/// DNS 解析（同步，与基线的阻塞式 `getaddrinfo` 一致）。
pub trait HostResolver: Send + Sync {
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<IpAddr>, String>;
}

/// 生产解析器。
///
/// `resolve` 是**同步阻塞**调用（getaddrinfo）：不得钉在 tokio worker 上。
/// 出站路径（`models_list` / `request_custom`）统一经
/// `tokio::task::spawn_blocking` 挪进 blocking 线程池；同步入口 `config_set`
/// 则由 `Registry::dispatch` 对同步处理器的 spawn_blocking 兜底。
#[derive(Debug, Default)]
pub struct SystemResolver;

impl HostResolver for SystemResolver {
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<IpAddr>, String> {
        let addrs = (host, port).to_socket_addrs().map_err(|e| e.to_string())?;
        let mut out: Vec<IpAddr> = Vec::new();
        for addr in addrs {
            if !out.contains(&addr.ip()) {
                out.push(addr.ip());
            }
        }
        Ok(out)
    }
}

/// 一次出站 HTTP 请求（已完成 URL/头/体组装，尚未解析 DNS）。
#[derive(Debug, Clone)]
pub struct AiHttpRequest {
    pub url: String,
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
    pub timeout_secs: u64,
    pub allow_private: bool,
}

/// 出站 HTTP 响应（重定向与大小上限已由 transport 处理）。
#[derive(Debug, Clone)]
pub struct AiHttpResponse {
    pub status: u16,
    pub reason: String,
    pub body: Vec<u8>,
}

impl AiHttpResponse {
    /// 体按 UTF-8 有损解码（基线用 `errors='ignore'`）。
    pub fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// 出站 HTTP 传输：负责「解析 → 筛选 → 固定 IP → 拨号 → 发请求 → 跟随同源重定向」。
pub trait AiTransport: Send + Sync {
    fn send<'a>(
        &'a self,
        request: AiHttpRequest,
    ) -> Pin<Box<dyn Future<Output = Result<AiHttpResponse, String>> + Send + 'a>>;
}

/// `ai.*` 的运行环境。
#[derive(Clone)]
pub struct AiEnv {
    /// 部署侧私网开关（等价 `MAILSTACK_ALLOW_PRIVATE_AI`）。
    pub allow_private_ai: bool,
    pub resolver: Arc<dyn HostResolver>,
    pub transport: Arc<dyn AiTransport>,
}

impl std::fmt::Debug for AiEnv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AiEnv")
            .field("allow_private_ai", &self.allow_private_ai)
            .finish_non_exhaustive()
    }
}

impl Default for AiEnv {
    fn default() -> Self {
        Self {
            allow_private_ai: private_network_enabled(),
            resolver: Arc::new(SystemResolver),
            transport: Arc::new(SystemAiTransport::new()),
        }
    }
}

// ───────────────────────── URL / 端点校验 ─────────────────────────

/// 解析后的端点（含固定拨号 IP）。
#[derive(Debug, Clone, PartialEq, Eq)]
struct Endpoint {
    scheme: String,
    host: String,
    port: u16,
    path: String,
    query: String,
    pinned_ip: IpAddr,
    raw_url: String,
}

impl Endpoint {
    fn default_port(&self) -> u16 {
        if self.scheme == "https" {
            443
        } else {
            80
        }
    }
}

/// URL 语法拆解结果。
struct UrlParts {
    scheme: String,
    host: String,
    port: u16,
    path: String,
    query: String,
    has_userinfo: bool,
    has_fragment: bool,
}

/// 手写 URL 拆解（不引入 `url` crate）。
///
/// 只认 `http(s)://host[:port][/path][?query]`；刻意**不**做百分号解码与畸形
/// 容忍 —— 这个函数是 SSRF 的第一道门，宽容解析只会扩大攻击面。
fn parse_url(raw: &str) -> Result<UrlParts, String> {
    let (scheme, rest) = raw
        .split_once("://")
        .ok_or_else(|| "AI endpoint must use HTTP or HTTPS".to_string())?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err("AI endpoint must use HTTP or HTTPS".to_string());
    }

    let (rest, has_fragment) = match rest.split_once('#') {
        Some((before, _)) => (before, true),
        None => (rest, false),
    };
    let (authority, tail) = match rest.find(['/', '?']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    let has_userinfo = authority.contains('@');
    let hostport = authority
        .rsplit_once('@')
        .map(|(_, hp)| hp)
        .unwrap_or(authority);

    let default_port = if scheme == "https" { 443 } else { 80 };
    let (host, port) = split_host_port(hostport, default_port)?;

    let (path, query) = match tail.split_once('?') {
        Some((p, q)) => (p, q),
        None => (tail, ""),
    };
    let path = if path.is_empty() {
        "/".to_string()
    } else {
        path.to_string()
    };

    Ok(UrlParts {
        scheme,
        host,
        port,
        path,
        query: query.to_string(),
        has_userinfo,
        has_fragment,
    })
}

fn split_host_port(authority: &str, default_port: u16) -> Result<(String, u16), String> {
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        // IPv6 字面量：`[::1]:443`
        let end = rest
            .find(']')
            .ok_or_else(|| "AI endpoint must include a hostname".to_string())?;
        let host = &rest[..end];
        let after = &rest[end + 1..];
        let port = if let Some(p) = after.strip_prefix(':') {
            parse_port(p)?
        } else {
            default_port
        };
        (host.to_string(), port)
    } else if let Some((h, p)) = authority.rsplit_once(':') {
        if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) {
            (h.to_string(), parse_port(p)?)
        } else {
            (authority.to_string(), default_port)
        }
    } else {
        (authority.to_string(), default_port)
    };
    Ok((host.to_ascii_lowercase(), port))
}

fn parse_port(raw: &str) -> Result<u16, String> {
    raw.parse::<u16>()
        .map_err(|_| "Invalid AI endpoint URL".to_string())
}

/// 校验并固定一个出站端点（基线 `resolve_and_pin_endpoint` 第 1–8 步）。
///
/// **纯函数**（DNS 经 [`HostResolver`] 注入），因此规则本身可被独立单测。
fn validate_endpoint(
    url: &str,
    allow_private: bool,
    resolver: &dyn HostResolver,
) -> Result<Endpoint, String> {
    let raw_url = url.trim().trim_end_matches('/').to_string();
    if raw_url.is_empty()
        || raw_url.len() > MAX_URL_LEN
        || raw_url
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
    {
        return Err("Invalid AI endpoint URL".to_string());
    }
    let parts = parse_url(&raw_url)?;
    if parts.host.is_empty() {
        return Err("AI endpoint must include a hostname".to_string());
    }
    if parts.has_userinfo || parts.has_fragment {
        return Err("AI endpoint cannot include credentials or a URL fragment".to_string());
    }
    if parts.scheme == "http" {
        return Err("Public AI endpoints must use HTTPS".to_string());
    }

    let ips = resolver
        .resolve(&parts.host, parts.port)
        .map_err(|e| format!("Unable to resolve AI endpoint {}: {e}", parts.host))?;
    if ips.is_empty() {
        return Err(format!(
            "AI endpoint {} resolved to no usable IP address",
            parts.host
        ));
    }
    let public_policy = AddressPolicy::public_only();
    for ip in &ips {
        if allow_private {
            if !public_policy.accepts(*ip) && !mailstack_smtp::is_private_network_address(*ip) {
                return Err(format!(
                    "AI endpoint {} resolves to a restricted address ({ip})",
                    parts.host
                ));
            }
        } else if !public_policy.accepts(*ip) {
            return Err(format!(
                "AI endpoint {} resolves to restricted address ({ip}); private-network access must be explicitly enabled to reduce SSRF risk",
                parts.host
            ));
        }
    }

    Ok(Endpoint {
        scheme: parts.scheme,
        host: parts.host,
        port: parts.port,
        path: parts.path,
        query: parts.query,
        // 固定第一个地址：后续只连这个 IP。
        pinned_ip: ips[0],
        raw_url,
    })
}

/// 私网访问的部署策略判定（基线 `_effective_private_access`）。
fn effective_private_access(requested: bool, deployment: bool) -> Result<bool, String> {
    if requested && !deployment {
        return Err("Private AI network access is disabled by deployment policy".to_string());
    }
    Ok(deployment)
}

// ───────────────────────── HTTP 报文（纯函数，可单测） ─────────────────────────

/// 组请求字节：请求行 + Host + 其余头 + Content-Length + CRLFCRLF + body。
///
/// 额外补一个 `Connection: close`：服务端在应答后关闭连接，我们才能「读到 EOF」
/// 拿全响应体。这不是可观察到的 API 行为差异（客户端本就一次性请求）。
fn build_request_bytes(
    endpoint: &Endpoint,
    method: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
) -> Result<Vec<u8>, String> {
    let target = if endpoint.query.is_empty() {
        endpoint.path.clone()
    } else {
        format!("{}?{}", endpoint.path, endpoint.query)
    };
    if [method, target.as_str()].iter().any(|value| {
        value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
    }) || !method.bytes().all(|byte| byte.is_ascii_alphabetic())
    {
        return Err("AI request contains an invalid request line".to_string());
    }

    let mut out = String::new();
    out.push_str(&format!("{method} {target} HTTP/1.1\r\n"));

    let has = |name: &str| headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(name));
    if !has("host") {
        let host = if endpoint.port == endpoint.default_port() {
            endpoint.host.clone()
        } else {
            format!("{}:{}", endpoint.host, endpoint.port)
        };
        out.push_str(&format!("Host: {host}\r\n"));
    }
    for (k, v) in headers {
        if k.is_empty()
            || !k.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(
                        byte,
                        b'!' | b'#'
                            | b'$'
                            | b'%'
                            | b'&'
                            | b'\''
                            | b'*'
                            | b'+'
                            | b'-'
                            | b'.'
                            | b'^'
                            | b'_'
                            | b'`'
                            | b'|'
                            | b'~'
                    )
            })
            || v.bytes()
                .any(|byte| byte.is_ascii_control() && byte != b'\t')
        {
            return Err("AI request contains an invalid HTTP header".to_string());
        }
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    if !has("connection") {
        out.push_str("Connection: close\r\n");
    }
    if let Some(body) = body {
        out.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    out.push_str("\r\n");

    let mut bytes = out.into_bytes();
    if let Some(body) = body {
        bytes.extend_from_slice(body);
    }
    Ok(bytes)
}

/// 解析后的 HTTP 响应。
#[derive(Debug)]
struct ParsedResponse {
    status: u16,
    reason: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl ParsedResponse {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// 解析 HTTP/1.1 响应报文，支持 `Content-Length` 与 `chunked` 两种取体方式。
fn parse_http_response(raw: &[u8]) -> Result<ParsedResponse, String> {
    let head_end = find_subslice(raw, b"\r\n\r\n")
        .ok_or_else(|| "AI endpoint returned an invalid HTTP response".to_string())?;
    let head = String::from_utf8_lossy(&raw[..head_end]);
    let raw_body = &raw[head_end + 4..];

    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let mut parts = status_line.splitn(3, ' ');
    let _version = parts.next().unwrap_or("");
    let status: u16 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| "AI endpoint returned an invalid HTTP response".to_string())?;
    let reason = parts.next().unwrap_or("").trim().to_string();

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }

    let chunked = headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("transfer-encoding") && v.to_ascii_lowercase().contains("chunked")
    });
    let body = if chunked {
        decode_chunked(raw_body)?
    } else if let Some(len) = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse::<usize>().ok())
    {
        raw_body[..len.min(raw_body.len())].to_vec()
    } else {
        raw_body.to_vec()
    };

    if body.len() > MAX_RESPONSE_BYTES {
        return Err("AI endpoint response exceeded 2 MB".to_string());
    }

    Ok(ParsedResponse {
        status,
        reason,
        headers,
        body,
    })
}

fn decode_chunked(mut rest: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    loop {
        let line_end = find_subslice(rest, b"\r\n")
            .ok_or_else(|| "AI endpoint returned an invalid HTTP response".to_string())?;
        let size_line = String::from_utf8_lossy(&rest[..line_end]);
        let size_hex = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16)
            .map_err(|_| "AI endpoint returned an invalid HTTP response".to_string())?;
        rest = &rest[line_end + 2..];
        if size == 0 {
            break;
        }
        if rest.len() < size {
            return Err("AI endpoint returned an invalid HTTP response".to_string());
        }
        out.extend_from_slice(&rest[..size]);
        rest = &rest[size..];
        // 跳过块后的 CRLF。
        if rest.starts_with(b"\r\n") {
            rest = &rest[2..];
        }
        if out.len() > READ_PROBE_BYTES {
            return Err("AI endpoint response exceeded 2 MB".to_string());
        }
    }
    Ok(out)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// 重定向决策结果。
#[derive(Debug)]
struct Follow {
    url: String,
    method: String,
    keep_body: bool,
}

/// 判定一次响应是否为需要跟随的重定向，并做同源校验与次数限制。
///
/// **为什么必须同源**：跨源重定向的目标从未经过「解析→筛选→固定 IP」这条链，
/// 直接跟随等于把 SSRF 防护整个绕开。基线的判据是 `(scheme, hostname, port)` 完全一致。
fn follow_redirect(
    current: &Endpoint,
    status: u16,
    location: Option<&str>,
    method: &str,
    redirects: usize,
) -> Result<Option<Follow>, String> {
    if !matches!(status, 301 | 302 | 303 | 307 | 308) {
        return Ok(None);
    }
    if redirects >= MAX_REDIRECTS {
        return Err("AI endpoint redirected too many times".to_string());
    }
    let location = location
        .filter(|l| !l.trim().is_empty())
        .ok_or_else(|| "AI endpoint returned an invalid redirect".to_string())?;

    let new_url = resolve_location(&current.raw_url, location);
    let parts =
        parse_url(&new_url).map_err(|_| "AI endpoint returned an invalid redirect".to_string())?;
    let old_port = if current.port == 0 {
        current.default_port()
    } else {
        current.port
    };
    if (parts.scheme.as_str(), parts.host.as_str(), parts.port)
        != (current.scheme.as_str(), current.host.as_str(), old_port)
    {
        return Err("Cross-origin AI endpoint redirect was rejected".to_string());
    }

    let next_method = if status == 303 {
        "GET".to_string()
    } else {
        method.to_string()
    };
    let keep_body = next_method != "GET";
    Ok(Some(Follow {
        url: new_url,
        method: next_method,
        keep_body,
    }))
}

/// 相对 Location 的解析（等价 `urllib.parse.urljoin` 的常见情形）。
fn resolve_location(base: &str, location: &str) -> String {
    if location.starts_with("http://") || location.starts_with("https://") {
        return location.to_string();
    }
    let (scheme, rest) = base.split_once("://").unwrap_or(("", base));
    let origin_end = rest.find(['/', '?']).unwrap_or(rest.len());
    let origin = &rest[..origin_end];
    if location.starts_with('/') {
        format!("{scheme}://{origin}{location}")
    } else {
        format!("{scheme}://{origin}/{location}")
    }
}

// ───────────────────────── 生产 transport ─────────────────────────

/// 生产传输：`PinnedDialer` + 手写 HTTP/1.1。
pub struct SystemAiTransport {
    dialer: Option<PinnedDialer>,
    reason: Option<String>,
}

impl Default for SystemAiTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemAiTransport {
    pub fn new() -> Self {
        match PinnedDialer::with_webpki_roots(Duration::from_secs(35)) {
            Ok(dialer) => Self {
                dialer: Some(dialer),
                reason: None,
            },
            Err(error) => {
                mailstack_core::warn::warn_with_detail(
                    "build AI outbound TLS configuration",
                    &error.to_string(),
                );
                Self {
                    dialer: None,
                    reason: Some(error.to_string()),
                }
            }
        }
    }

    async fn perform(&self, request: AiHttpRequest) -> Result<AiHttpResponse, String> {
        let Some(dialer) = self.dialer.clone() else {
            return Err(self
                .reason
                .clone()
                .unwrap_or_else(|| "no TLS backend available".to_string()));
        };

        let mut url = request.url.clone();
        let mut method = request.method.clone();
        let mut body = request.body.clone();
        let mut redirects = 0usize;
        loop {
            let endpoint = validate_endpoint(&url, request.allow_private, &SystemResolver)?;
            let target = pinned_from_addresses(
                &endpoint.host,
                endpoint.port,
                vec![endpoint.pinned_ip],
                if request.allow_private {
                    AddressPolicy::allow_private()
                } else {
                    AddressPolicy::public_only()
                },
            )
            .map_err(|e| e.to_string())?;

            let bytes = build_request_bytes(&endpoint, &method, &request.headers, body.as_deref())?;
            let raw = self
                .exchange(
                    &dialer,
                    &target,
                    &endpoint.scheme,
                    &bytes,
                    request.timeout_secs,
                )
                .await?;
            let parsed = parse_http_response(&raw)?;

            let location = parsed.header("location").map(str::to_string);
            match follow_redirect(
                &endpoint,
                parsed.status,
                location.as_deref(),
                &method,
                redirects,
            )? {
                Some(next) => {
                    redirects += 1;
                    url = next.url;
                    method = next.method;
                    if !next.keep_body {
                        body = None;
                    }
                }
                None => {
                    return Ok(AiHttpResponse {
                        status: parsed.status,
                        reason: parsed.reason,
                        body: parsed.body,
                    })
                }
            }
        }
    }

    /// 拨号（http 明文 / https 走 TLS）→ 写请求 → 读到 EOF，整体受 `timeout_secs` 约束。
    async fn exchange(
        &self,
        dialer: &PinnedDialer,
        target: &PinnedTarget,
        scheme: &str,
        request: &[u8],
        timeout_secs: u64,
    ) -> Result<Vec<u8>, String> {
        use tokio::io::AsyncWriteExt;

        let timeout = Duration::from_secs(timeout_secs.max(1));
        let work = async {
            if scheme == "https" {
                let tcp = dialer.connect(target).await.map_err(|e| e.to_string())?;
                let mut tls = dialer
                    .start_tls(tcp, target)
                    .await
                    .map_err(|e| e.to_string())?;
                tls.write_all(request).await.map_err(|e| e.to_string())?;
                tls.flush().await.map_err(|e| e.to_string())?;
                read_all(&mut tls).await
            } else {
                let mut tcp = dialer.connect(target).await.map_err(|e| e.to_string())?;
                tcp.write_all(request).await.map_err(|e| e.to_string())?;
                tcp.flush().await.map_err(|e| e.to_string())?;
                read_all(&mut tcp).await
            }
        };
        tokio::time::timeout(timeout, work)
            .await
            .map_err(|_| format!("AI endpoint request timed out after {timeout_secs}s"))?
    }
}

/// 读到 EOF 或超过上限（多读 1 字节以便区分「恰好 2MB」与「超限」）。
async fn read_all<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>, String> {
    use tokio::io::AsyncReadExt;

    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = stream.read(&mut chunk).await.map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > READ_PROBE_BYTES {
            break;
        }
    }
    Ok(buf)
}

impl AiTransport for SystemAiTransport {
    fn send<'a>(
        &'a self,
        request: AiHttpRequest,
    ) -> Pin<Box<dyn Future<Output = Result<AiHttpResponse, String>> + Send + 'a>> {
        Box::pin(async move { self.perform(request).await })
    }
}

// ───────────────────────── Ai 动作执行体 ─────────────────────────

/// `ai.*` 的执行体。
pub struct Ai {
    paths: Paths,
    env: AiEnv,
}

impl Ai {
    pub fn new(paths: Paths, env: AiEnv) -> Self {
        Self { paths, env }
    }

    /// 生产构造。
    pub fn system(paths: Paths) -> Self {
        Self::new(paths, AiEnv::default())
    }

    /// 覆盖运行环境（测试用）。
    pub fn with_env(mut self, env: AiEnv) -> Self {
        self.env = env;
        self
    }

    fn resolver(&self) -> &dyn HostResolver {
        self.env.resolver.as_ref()
    }

    // ── ai.config.set ──

    /// `ai.config.set`：校验并落盘 AI 供应商配置。
    pub fn config_set(&self, data: &Value) -> Result<Value, HandlerError> {
        let provider = str_field(data, "provider").trim();
        // 缺字段时基线默认 `bigmodel`；空串则落到「不支持的供应商」。
        let provider = if data.get("provider").is_none() {
            "bigmodel"
        } else {
            provider
        };
        let preset =
            preset(provider).ok_or_else(|| HandlerError::new("Unsupported AI provider"))?;

        let current = read_ai_config(&self.paths);
        let api_key = first_truthy([
            Some(str_field(data, "apiKey").trim().to_string()),
            cfg_str(&current, "apiKey"),
            Some(preset.default_key.to_string()),
        ]);
        let allow_private = effective_private_access(
            truthy(data.get("allowPrivateNetwork")) || truthy(current.get("allowPrivateNetwork")),
            self.env.allow_private_ai,
        )
        .map_err(HandlerError::new)?;
        if truthy(data.get("insecureTls")) || truthy(current.get("insecureTls")) {
            return Err(HandlerError::new(
                "TLS verification cannot be disabled for AI requests",
            ));
        }

        let base_url_input = first_truthy([
            Some(str_field(data, "baseUrl").trim().to_string()),
            Some(preset.base_url.to_string()),
        ]);
        validate_endpoint(&base_url_input, allow_private, self.resolver())
            .map_err(HandlerError::new)?;

        let model = first_truthy([
            Some(str_field(data, "model").trim().to_string()),
            Some(preset.model.to_string()),
        ]);
        let cfg = json!({
            "provider": provider,
            "model": model,
            "baseUrl": base_url_input.trim_end_matches('/'),
            "apiKey": api_key,
            "fallbackProvider": str_field(data, "fallbackProvider").trim(),
            "allowPrivateNetwork": allow_private,
            "insecureTls": false,
            "updatedAt": mailstack_core::now_iso8601_utc(),
        });
        let text = format!("{}\n", serde_json::to_string_pretty(&cfg)?);
        atomic::atomic_as(&self.paths.ai_config, text.as_bytes(), 0o600, None)?;
        // 镜像一份到 `etc/ai.json`（0600）；失败只告警。
        if let Err(error) = atomic::atomic_as(
            &self.paths.etc.join("ai.json"),
            text.as_bytes(),
            0o600,
            None,
        ) {
            mailstack_core::warn::warn_with_detail(
                "mirror AI config to ai.json",
                &error.to_string(),
            );
        }
        Ok(ai_public_config(&self.paths, allow_private))
    }

    // ── ai.models.list ──

    /// `ai.models.list`：拉取供应商的模型清单。
    pub async fn models_list(&self, _data: &Value) -> Result<Value, HandlerError> {
        let cfg = read_ai_config(&self.paths);
        if truthy(cfg.get("insecureTls")) {
            return Err(HandlerError::new(
                "TLS verification cannot be disabled for AI requests",
            ));
        }

        let provider = cfg_str(&cfg, "provider").and_then(|provider| preset(&provider));
        let allow_private = self.effective_private(&json!({}), &cfg)?;
        let base_url = cfg_str(&cfg, "baseUrl")
            .or_else(|| provider.map(|p| p.base_url.to_string()))
            .unwrap_or_default()
            .trim()
            .trim_end_matches('/')
            .to_string();
        if base_url.is_empty() {
            return Err(HandlerError::new(
                "AI provider API base URL is not configured",
            ));
        }
        // 端点校验内含同步 DNS 解析（getaddrinfo），必须离开异步 worker：
        // 挪进 blocking 线程池。`HostResolver` 是 Send + Sync，Arc 可安全跨线程。
        let resolver = Arc::clone(&self.env.resolver);
        let base_url_for_check = base_url.clone();
        tokio::task::spawn_blocking(move || {
            validate_endpoint(&base_url_for_check, allow_private, resolver.as_ref())
        })
        .await
        .map_err(|error| HandlerError::new(format!("AI endpoint validation task failed: {error}")))?
        .map_err(HandlerError::new)?;

        let api_key = first_truthy([
            cfg_str(&cfg, "apiKey"),
            provider.map(|p| p.default_key.to_string()),
        ]);

        let mut headers = vec![
            ("content-type".to_string(), "application/json".to_string()),
            ("User-Agent".to_string(), USER_AGENT.to_string()),
        ];
        if !api_key.is_empty() {
            headers.push(("authorization".to_string(), format!("Bearer {api_key}")));
        }
        let response = self
            .send(AiHttpRequest {
                url: format!("{base_url}/models"),
                method: "GET".to_string(),
                headers,
                body: None,
                timeout_secs: 15,
                allow_private,
            })
            .await?;

        if response.status != 200 {
            return Err(HandlerError::new(format!(
                "AI model list request failed: HTTP {} ({})",
                response.status, response.reason
            )));
        }

        let parsed: Value = serde_json::from_str(&response.body_text()).unwrap_or(Value::Null);
        let mut models = collect_models(&parsed);
        models.sort();
        models.dedup();
        Ok(json!({
            "models": models,
            "count": models.len(),
            "baseUrl": base_url,
        }))
    }

    // ── ai.chat ──

    /// `ai.chat`：发一次对话补全（带可选 fallback）。
    pub async fn chat(&self, data: &Value) -> Result<Value, HandlerError> {
        let messages = match data.get("messages") {
            Some(Value::Array(a)) if !a.is_empty() => a.clone(),
            _ => return Err(HandlerError::new("messages must be a non-empty list")),
        };
        let cfg = read_ai_config(&self.paths);
        let provider = first_truthy([
            Some(str_field(data, "provider").trim().to_string()),
            cfg_str(&cfg, "provider"),
            Some("bigmodel".to_string()),
        ]);
        let preset = preset(&provider).unwrap_or_else(default_preset);
        let allow_private = self.effective_private(data, &cfg)?;
        if truthy(data.get("insecureTls")) || truthy(cfg.get("insecureTls")) {
            return Err(HandlerError::new(
                "TLS verification cannot be disabled for AI requests",
            ));
        }

        // 4.18/4.19 同款纪律（见 `models_list`）：base_url 与 api_key **只认持久化
        // 配置**，请求体里的同名字段一律忽略。若采信 body 的 baseUrl，存储的 apiKey
        // 就会被发送到调用方指定的任意 URL（密钥外带）；采信 body 的 apiKey 则把
        // 「用谁的凭据」交给了调用方。provider / model 不是机密，仍允许按请求覆写。
        let params = ChatParams {
            messages,
            provider: provider.clone(),
            base_url: cfg_str(&cfg, "baseUrl")
                .map(|url| url.trim().to_string())
                .unwrap_or_else(|| preset.base_url.to_string()),
            api_key: cfg_str(&cfg, "apiKey")
                .unwrap_or_else(|| preset.default_key.to_string()),
            model: first_truthy([
                Some(str_field(data, "model").trim().to_string()),
                cfg_str(&cfg, "model"),
                Some(preset.model.to_string()),
            ]),
            max_tokens: data
                .get("maxTokens")
                .and_then(Value::as_u64)
                .unwrap_or(1500),
            temperature: data
                .get("temperature")
                .and_then(Value::as_f64)
                .unwrap_or(0.2),
            allow_private,
        };
        if params.api_key.is_empty() {
            return Err(HandlerError::new(format!(
                "AI API key is not configured for {}",
                preset.name
            )));
        }
        if params.base_url.is_empty() {
            // 与 `models_list` 同一文案：custom 预设没有自带 base_url，
            // 未配置时宁可报「没配置」也不得拿空串去拼请求。
            return Err(HandlerError::new(
                "AI provider API base URL is not configured",
            ));
        }

        let started = Instant::now();
        match self.request_custom(&params).await {
            Ok((content, usage)) => Ok(json!({
                "status": "ok",
                "provider": params.provider,
                "model": params.model,
                "reply": content,
                "latencyMs": elapsed_ms(started),
                "usage": usage,
            })),
            Err(error) => {
                // fallback 仅当请求**未显式指定** provider 时才尝试。
                if !truthy(data.get("provider")) {
                    if let Some(result) = self.try_fallback(data, &cfg, &params, started).await? {
                        return Ok(result);
                    }
                }
                Err(error)
            }
        }
    }

    async fn try_fallback(
        &self,
        data: &Value,
        cfg: &Value,
        params: &ChatParams,
        started: Instant,
    ) -> Result<Option<Value>, HandlerError> {
        let fallback = cfg_str(cfg, "fallbackProvider").unwrap_or_default();
        if fallback.is_empty() || fallback == params.provider {
            return Ok(None);
        }
        let Some(fb_preset) = preset(&fallback) else {
            return Ok(None);
        };
        let fb_key = first_truthy([
            cfg_str(cfg, "fallbackApiKey"),
            Some(fb_preset.default_key.to_string()),
        ]);
        if fb_key.is_empty() {
            return Ok(None);
        }

        let fb_params = ChatParams {
            messages: params.messages.clone(),
            provider: fallback,
            base_url: fb_preset.base_url.to_string(),
            api_key: fb_key,
            model: fb_preset.model.to_string(),
            max_tokens: params.max_tokens,
            temperature: params.temperature,
            allow_private: params.allow_private,
        };
        let _ = data;
        let (content, usage) = self.request_custom(&fb_params).await?;
        Ok(Some(json!({
            "status": "ok",
            "provider": fb_params.provider,
            "model": fb_params.model,
            "reply": content,
            "latencyMs": elapsed_ms(started),
            "usage": usage,
            "fallbackUsed": true,
        })))
    }

    // ── ai.test ──

    /// 连接自检：固定一条 hello 消息，不走 fallback。
    pub async fn test(&self, data: &Value) -> Result<Value, HandlerError> {
        let cfg = read_ai_config(&self.paths);
        let provider = first_truthy([
            Some(str_field(data, "provider").trim().to_string()),
            cfg_str(&cfg, "provider"),
            Some("bigmodel".to_string()),
        ]);
        let preset = preset(&provider).unwrap_or_else(default_preset);
        let allow_private = self.effective_private(data, &cfg)?;
        if truthy(data.get("insecureTls")) || truthy(cfg.get("insecureTls")) {
            return Err(HandlerError::new(
                "TLS verification cannot be disabled for AI requests",
            ));
        }

        // 与 `chat` / `models_list` 同一纪律：base_url 与 api_key 只认持久化配置，
        // 请求体里的同名字段一律忽略（否则自检也能把存储的密钥送到任意 URL）。
        let params = ChatParams {
            messages: vec![json!({ "role": "user", "content": "Hello, test connection." })],
            provider: provider.clone(),
            base_url: cfg_str(&cfg, "baseUrl")
                .map(|url| url.trim().to_string())
                .unwrap_or_else(|| preset.base_url.to_string()),
            api_key: cfg_str(&cfg, "apiKey")
                .unwrap_or_else(|| preset.default_key.to_string()),
            model: first_truthy([
                Some(str_field(data, "model").trim().to_string()),
                cfg_str(&cfg, "model"),
                Some(preset.model.to_string()),
            ]),
            max_tokens: 20,
            temperature: 0.1,
            allow_private,
        };
        if params.api_key.is_empty() {
            return Err(HandlerError::new(format!(
                "AI API key is not configured for {}",
                preset.name
            )));
        }
        if params.base_url.is_empty() {
            return Err(HandlerError::new(
                "AI provider API base URL is not configured",
            ));
        }

        let started = Instant::now();
        let (content, usage) = self.request_custom(&params).await?;
        let reply: String = content.chars().take(100).collect();
        Ok(json!({
            "status": "ok",
            "provider": params.provider,
            "model": params.model,
            "reply": reply,
            "latencyMs": elapsed_ms(started),
            "usage": usage,
        }))
    }

    // ── ai.diagnose / ai.parse ──

    pub async fn diagnose(&self, data: &Value) -> Result<Value, HandlerError> {
        let logs = str_field(data, "logs").trim();
        let prompt = format!(
            "Analyze these Linux mail-server logs and return prioritized findings.\n\n{logs}"
        );
        // 基线传的是一个**新 dict**：只带 messages，故 data 里的 provider 等不参与。
        self.chat(&json!({ "messages": [{ "role": "user", "content": prompt }] }))
            .await
    }

    pub async fn parse(&self, data: &Value) -> Result<Value, HandlerError> {
        let text = str_field(data, "text").trim();
        let prompt = format!(
            "Parse the following mail configuration and return strict JSON diagnostics.\n\n{text}"
        );
        self.chat(&json!({ "messages": [{ "role": "user", "content": prompt }] }))
            .await
    }

    // ── 内部 ──

    fn effective_private(&self, data: &Value, cfg: &Value) -> Result<bool, HandlerError> {
        effective_private_access(
            truthy(data.get("allowPrivateNetwork")) || truthy(cfg.get("allowPrivateNetwork")),
            self.env.allow_private_ai,
        )
        .map_err(HandlerError::new)
    }

    async fn send(&self, request: AiHttpRequest) -> Result<AiHttpResponse, HandlerError> {
        self.env
            .transport
            .send(request)
            .await
            .map_err(HandlerError::new)
    }

    /// 按供应商协议发一次补全请求，返回 `(正文, usage)`。
    async fn request_custom(&self, params: &ChatParams) -> Result<(String, Value), HandlerError> {
        let preset = preset(&params.provider).unwrap_or_else(default_preset);
        let base = params.base_url.trim_end_matches('/').to_string();
        // 端点校验内含同步 DNS 解析（getaddrinfo），必须离开异步 worker（见
        // `models_list` 的同款处理）。
        let resolver = Arc::clone(&self.env.resolver);
        let base_for_check = base.clone();
        let allow_private = params.allow_private;
        tokio::task::spawn_blocking(move || {
            validate_endpoint(&base_for_check, allow_private, resolver.as_ref())
        })
        .await
        .map_err(|error| HandlerError::new(format!("AI endpoint validation task failed: {error}")))?
        .map_err(HandlerError::new)?;

        if preset.protocol == "anthropic" {
            let (system_prompt, user_msgs) = split_anthropic_messages(&params.messages);
            let mut payload = json!({
                "model": params.model,
                "max_tokens": params.max_tokens,
                "temperature": params.temperature,
                "messages": user_msgs,
            });
            let system = system_prompt.trim();
            if !system.is_empty() {
                payload["system"] = Value::String(system.to_string());
            }
            let headers = vec![
                ("content-type".to_string(), "application/json".to_string()),
                ("x-api-key".to_string(), params.api_key.clone()),
                ("anthropic-version".to_string(), "2023-06-01".to_string()),
                ("User-Agent".to_string(), USER_AGENT.to_string()),
            ];
            let response = self
                .send(AiHttpRequest {
                    url: format!("{base}/messages"),
                    method: "POST".to_string(),
                    headers,
                    body: Some(payload.to_string().into_bytes()),
                    timeout_secs: 35,
                    allow_private: params.allow_private,
                })
                .await?;
            if response.status != 200 {
                return Err(HandlerError::new(format!(
                    "Claude API request failed: HTTP {}: {}",
                    response.status,
                    truncate_for_error(&response.body_text())
                )));
            }
            let result: Value = serde_json::from_str(&response.body_text()).unwrap_or(Value::Null);
            let content = collect_anthropic_text(&result);
            Ok((content.trim().to_string(), usage_of(&result)))
        } else {
            let payload = json!({
                "model": params.model,
                "messages": params.messages,
                "temperature": params.temperature,
                "max_tokens": params.max_tokens,
            });
            let headers = vec![
                ("content-type".to_string(), "application/json".to_string()),
                (
                    "authorization".to_string(),
                    format!("Bearer {}", params.api_key),
                ),
                ("User-Agent".to_string(), USER_AGENT.to_string()),
            ];
            let response = self
                .send(AiHttpRequest {
                    url: format!("{base}/chat/completions"),
                    method: "POST".to_string(),
                    headers,
                    body: Some(payload.to_string().into_bytes()),
                    timeout_secs: 35,
                    allow_private: params.allow_private,
                })
                .await?;
            if response.status != 200 {
                return Err(HandlerError::new(format!(
                    "AI completion request failed: HTTP {}: {}",
                    response.status,
                    truncate_for_error(&response.body_text())
                )));
            }
            let result: Value = serde_json::from_str(&response.body_text()).unwrap_or(Value::Null);
            let content = result
                .get("choices")
                .and_then(Value::as_array)
                .and_then(|c| c.first())
                .and_then(|c| c.get("message"))
                .and_then(|m| m.get("content"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim()
                .to_string();
            Ok((content, usage_of(&result)))
        }
    }
}

/// 一次补全请求的参数（避免 `ai_request_custom` 的参数列表过长）。
struct ChatParams {
    messages: Vec<Value>,
    provider: String,
    base_url: String,
    api_key: String,
    model: String,
    max_tokens: u64,
    temperature: f64,
    allow_private: bool,
}

// ───────────────────────── 辅助 ─────────────────────────

/// 读 `ai-provider.json`（缺失/损坏 → 空对象）。
fn read_ai_config(paths: &Paths) -> Value {
    let Ok(text) = std::fs::read_to_string(&paths.ai_config) else {
        return json!({});
    };
    match serde_json::from_str::<Value>(&text) {
        Ok(value) => value,
        Err(_) => {
            mailstack_core::warn::warn(&format!(
                "parse ai provider config {}",
                paths.ai_config.display()
            ));
            json!({})
        }
    }
}

/// 公开配置（与 `ai.config.get` 同一份；**绝不返回 apiKey 明文**）。
pub fn ai_public_config(paths: &Paths, allow_private: bool) -> Value {
    let cfg = read_ai_config(paths);
    let provider = cfg_str(&cfg, "provider").unwrap_or_else(|| "bigmodel".to_string());
    let preset = preset(&provider).unwrap_or_else(default_preset);
    let key = cfg_str(&cfg, "apiKey").unwrap_or_default();
    let masked_key = mask_key(&key);

    let mut available = serde_json::Map::new();
    for p in AI_PRESETS {
        available.insert(
            p.key.to_string(),
            json!({
                "name": p.name,
                "model": p.model,
                "models": p.models,
                "baseUrl": p.base_url,
                "docUrl": p.doc_url,
            }),
        );
    }

    json!({
        "provider": provider,
        "providerName": preset.name,
        "model": cfg_str(&cfg, "model").unwrap_or_else(|| preset.model.to_string()),
        "baseUrl": cfg_str(&cfg, "baseUrl").unwrap_or_else(|| preset.base_url.to_string()),
        "hasKey": !key.is_empty(),
        "maskedKey": masked_key,
        "docUrl": preset.doc_url,
        "availablePresets": Value::Object(available),
        "fallbackProvider": cfg_str(&cfg, "fallbackProvider").unwrap_or_default(),
        "allowPrivateNetwork": allow_private,
        "insecureTls": false,
        "configured": !key.is_empty() || !preset.default_key.is_empty(),
    })
}

/// 密钥打码：长度 ≥ 8 保留前 4 位，否则整体 `****`（空 key 打空串）。
fn mask_key(key: &str) -> String {
    if key.chars().count() >= 8 {
        let head: String = key.chars().take(4).collect();
        format!("{head}****")
    } else if key.is_empty() {
        String::new()
    } else {
        "****".to_string()
    }
}

/// 取字符串字段（缺失/非字符串 → 空串）。
fn str_field<'a>(data: &'a Value, key: &str) -> &'a str {
    data.get(key).and_then(Value::as_str).unwrap_or("")
}

/// 错误文案里内嵌的上游响应体截到**前 500 字符**。
///
/// 上游响应体可达 2 MB（[`MAX_RESPONSE_BYTES`]），此前会原样进 `HandlerError`、
/// 再一路进错误信封、日志与前端 —— 一次上游故障就能把一整个页面塞进管理台。
/// 500 字符足够看清供应商的错误 JSON（与 `acme.rs` 的 `detail[-500:]` 同一纪律）。
fn truncate_for_error(body: &str) -> String {
    body.chars().take(500).collect()
}

fn cfg_str(cfg: &Value, key: &str) -> Option<String> {
    cfg.get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .filter(|s| !s.is_empty())
}

/// 取第一个非空的候选项。
fn first_truthy(candidates: impl IntoIterator<Item = Option<String>>) -> String {
    candidates
        .into_iter()
        .flatten()
        .find(|s| !s.is_empty())
        .unwrap_or_default()
}

/// 宽松真值判定（对应 Python 的真值语义的常见情形）。
fn truthy(value: Option<&Value>) -> bool {
    match value {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Number(n)) => n.as_f64().map(|v| v != 0.0).unwrap_or(false),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
        _ => false,
    }
}

fn elapsed_ms(started: Instant) -> u64 {
    started.elapsed().as_millis().max(1) as u64
}

fn usage_of(result: &Value) -> Value {
    result.get("usage").cloned().unwrap_or_else(|| json!({}))
}

/// 从 `{data:[...]}` / 裸数组里收集模型 id（基线 `ai_models_list` 的形状兼容）。
fn collect_models(parsed: &Value) -> Vec<String> {
    let items = parsed
        .get("data")
        .and_then(Value::as_array)
        .or_else(|| parsed.as_array());
    let Some(items) = items else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|m| match m {
            Value::String(s) => Some(s.clone()),
            Value::Object(_) => m.get("id").and_then(Value::as_str).map(str::to_string),
            _ => None,
        })
        .collect()
}

/// 抽出 anthropic 的 `system` 消息，并返回（system 文本, 其余消息）。
fn split_anthropic_messages(messages: &[Value]) -> (String, Vec<Value>) {
    let mut system = String::new();
    let mut user = Vec::new();
    for m in messages {
        let role = m.get("role").and_then(Value::as_str).unwrap_or("user");
        let content = m.get("content").and_then(Value::as_str).unwrap_or("");
        if role == "system" {
            system.push_str(content);
            system.push('\n');
        } else {
            user.push(json!({ "role": role, "content": content }));
        }
    }
    (system, user)
}

/// 拼接 anthropic `content[].type=="text"` 的正文。
fn collect_anthropic_text(result: &Value) -> String {
    result
        .get("content")
        .and_then(Value::as_array)
        .map(|blocks| {
            blocks
                .iter()
                .filter(|b| b.get("type").and_then(Value::as_str) == Some("text"))
                .filter_map(|b| b.get("text").and_then(Value::as_str))
                .collect::<String>()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, VecDeque};
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Mutex;

    // ── 替身 ──

    #[derive(Default)]
    struct FakeResolver {
        map: BTreeMap<String, Vec<IpAddr>>,
        error: Option<String>,
    }

    impl FakeResolver {
        fn with(host: &str, ips: &[&str]) -> Self {
            let mut resolver = Self::default();
            resolver.map.insert(
                host.to_string(),
                ips.iter().map(|s| s.parse().unwrap()).collect(),
            );
            resolver
        }

        fn add(mut self, host: &str, ips: &[&str]) -> Self {
            self.map.insert(
                host.to_string(),
                ips.iter().map(|s| s.parse().unwrap()).collect(),
            );
            self
        }
    }

    impl HostResolver for FakeResolver {
        fn resolve(&self, host: &str, _port: u16) -> Result<Vec<IpAddr>, String> {
            if let Some(error) = &self.error {
                return Err(error.clone());
            }
            Ok(self.map.get(host).cloned().unwrap_or_default())
        }
    }

    #[derive(Default)]
    struct FakeTransport {
        responses: Mutex<VecDeque<Result<AiHttpResponse, String>>>,
        requests: Mutex<Vec<AiHttpRequest>>,
    }

    impl FakeTransport {
        fn with(responses: Vec<Result<AiHttpResponse, String>>) -> Arc<Self> {
            Arc::new(Self {
                responses: Mutex::new(responses.into()),
                requests: Mutex::new(Vec::new()),
            })
        }

        fn requests(&self) -> Vec<AiHttpRequest> {
            self.requests.lock().unwrap().clone()
        }
    }

    impl AiTransport for FakeTransport {
        fn send<'a>(
            &'a self,
            request: AiHttpRequest,
        ) -> Pin<Box<dyn Future<Output = Result<AiHttpResponse, String>> + Send + 'a>> {
            self.requests.lock().unwrap().push(request);
            let reply = self
                .responses
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| Err("no scripted AI response".to_string()));
            Box::pin(async move { reply })
        }
    }

    fn json_response(status: u16, reason: &str, body: Value) -> AiHttpResponse {
        AiHttpResponse {
            status,
            reason: reason.to_string(),
            body: serde_json::to_vec(&body).unwrap(),
        }
    }

    struct Fixture {
        root: PathBuf,
        paths: Paths,
    }

    impl Fixture {
        fn new(tag: &str) -> Self {
            let mut root = std::env::temp_dir();
            root.push(format!(
                "mailstack-ai-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir_all(&root).unwrap();
            let paths = Paths::rooted(&root);
            Self { root, paths }
        }

        fn ai(
            &self,
            resolver: Arc<FakeResolver>,
            transport: Arc<FakeTransport>,
            allow_private_ai: bool,
        ) -> Ai {
            Ai::new(
                self.paths.clone(),
                AiEnv {
                    allow_private_ai,
                    resolver,
                    transport,
                },
            )
        }

        fn write_config(&self, value: Value) {
            fs::create_dir_all(self.paths.etc.clone()).unwrap();
            fs::write(
                &self.paths.ai_config,
                format!("{}\n", serde_json::to_string_pretty(&value).unwrap()),
            )
            .unwrap();
        }

        fn raw_config(&self) -> Value {
            serde_json::from_str(&fs::read_to_string(&self.paths.ai_config).unwrap()).unwrap()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn no_transport() -> Arc<FakeTransport> {
        FakeTransport::with(Vec::new())
    }

    // ── 1. URL 形态校验 ──

    #[test]
    fn validate_endpoint_rejects_malformed_urls() {
        let resolver = FakeResolver::default();
        let err = |url: &str| validate_endpoint(url, false, &resolver).unwrap_err();
        assert_eq!(err(""), "Invalid AI endpoint URL");
        assert_eq!(
            err(&format!("https://{}", "a".repeat(3000))),
            "Invalid AI endpoint URL"
        );
        assert_eq!(
            err("ftp://example.com"),
            "AI endpoint must use HTTP or HTTPS"
        );
        assert_eq!(
            err("https:///only-path"),
            "AI endpoint must include a hostname"
        );
        assert_eq!(
            err("https://user:pass@example.com"),
            "AI endpoint cannot include credentials or a URL fragment"
        );
        assert_eq!(
            err("https://example.com/x#frag"),
            "AI endpoint cannot include credentials or a URL fragment"
        );
        // http 且未允许私网 → 必须 HTTPS。
        assert_eq!(
            err("http://example.com"),
            "Public AI endpoints must use HTTPS"
        );
    }

    #[test]
    fn url_without_scheme_is_rejected_as_http_or_https() {
        let resolver = FakeResolver::default();
        assert_eq!(
            validate_endpoint("example.com/path", false, &resolver).unwrap_err(),
            "AI endpoint must use HTTP or HTTPS"
        );
    }

    // ── 2. 地址筛选（SSRF） ──

    #[test]
    fn every_resolved_address_is_screened_for_ssrf() {
        for ip in [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.169.254",
            "::ffff:127.0.0.1",
        ] {
            let resolver = FakeResolver::with("ai.example.com", &[ip]);
            let err = validate_endpoint("https://ai.example.com", false, &resolver).unwrap_err();
            assert!(
                err.contains("resolves to restricted address") && err.contains(ip),
                "{ip}: {err}"
            );
        }
    }

    #[test]
    fn a_host_mixing_public_and_private_addresses_is_rejected() {
        // 只筛第一个地址是不够的：A 记录里混入一个私网地址就能绕过。
        let resolver = FakeResolver::with("ai.example.com", &["8.8.8.8", "127.0.0.1"]);
        let err = validate_endpoint("https://ai.example.com", false, &resolver).unwrap_err();
        assert!(
            err.contains("resolves to restricted address (127.0.0.1)"),
            "{err}"
        );
    }

    #[test]
    fn resolution_failure_is_reported_with_the_host() {
        let resolver = FakeResolver {
            map: BTreeMap::new(),
            error: Some("name resolution failed".to_string()),
        };
        let err = validate_endpoint("https://ai.example.com", false, &resolver).unwrap_err();
        assert_eq!(
            err,
            "Unable to resolve AI endpoint ai.example.com: name resolution failed"
        );
    }

    #[test]
    fn an_allowed_private_endpoint_pins_the_address() {
        let resolver = FakeResolver::with("internal.corp", &["10.0.0.5"]);
        let ep = validate_endpoint("https://internal.corp/api", true, &resolver).unwrap();
        assert_eq!(ep.pinned_ip, "10.0.0.5".parse::<IpAddr>().unwrap());
        assert_eq!(ep.host, "internal.corp");
        assert_eq!(ep.port, 443);
    }

    #[test]
    fn private_access_requires_the_deployment_switch() {
        let f = Fixture::new("privswitch");
        let resolver = Arc::new(FakeResolver::with("internal.corp", &["10.0.0.5"]));

        // 部署未开：请求 allowPrivateNetwork:true 必须被拒。
        let ai = f.ai(Arc::clone(&resolver), no_transport(), false);
        let err = ai
            .config_set(&json!({ "provider": "custom", "baseUrl": "https://internal.corp", "apiKey": "k123456789", "allowPrivateNetwork": true }))
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "Private AI network access is disabled by deployment policy"
        );

        // 部署已开：同一请求应通过。
        let ai = f.ai(resolver, no_transport(), true);
        let out = ai
            .config_set(&json!({ "provider": "custom", "baseUrl": "https://internal.corp", "apiKey": "k123456789", "allowPrivateNetwork": true }))
            .unwrap();
        assert_eq!(out["allowPrivateNetwork"], true);

        assert_eq!(
            validate_endpoint(
                "http://internal.corp",
                true,
                &FakeResolver::with("internal.corp", &["10.0.0.5"])
            )
            .unwrap_err(),
            "Public AI endpoints must use HTTPS"
        );
        assert!(validate_endpoint(
            "https://mixed.corp",
            true,
            &FakeResolver::with("mixed.corp", &["8.8.8.8", "10.0.0.5"])
        )
        .is_ok());
        assert!(validate_endpoint(
            "https://metadata.corp",
            true,
            &FakeResolver::with("metadata.corp", &["169.254.169.254"])
        )
        .unwrap_err()
        .contains("restricted address"));
    }

    // ── 3. insecureTls 一律拒绝 ──

    #[test]
    fn insecure_tls_is_rejected_everywhere() {
        let f = Fixture::new("insecure");
        let resolver = Arc::new(
            FakeResolver::with("api.deepseek.com", &["8.8.8.8"])
                .add("ai.example.com", &["8.8.8.8"]),
        );
        let expected = "TLS verification cannot be disabled for AI requests";

        let ai = f.ai(Arc::clone(&resolver), no_transport(), false);
        assert_eq!(
            ai.config_set(&json!({ "provider": "deepseek", "insecureTls": true }))
                .unwrap_err()
                .to_string(),
            expected
        );

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        // 注意：`ai.models.list` 不在这里 —— 自 4.18 修复起它**完全忽略请求体**
        // （`models_list(&self, _data)`），目标 URL 与凭据只来自持久化配置。
        // 它的 insecureTls 判定改由 `models_list_reads_insecure_tls_only_from_config` 覆盖。
        assert_eq!(
            rt.block_on(ai.chat(
                &json!({ "messages": [{ "role": "user", "content": "hi" }], "insecureTls": true })
            ))
            .unwrap_err()
            .to_string(),
            expected
        );
        assert_eq!(
            rt.block_on(ai.test(&json!({ "insecureTls": true })))
                .unwrap_err()
                .to_string(),
            expected
        );
    }

    // ── 4. ai.config.set ──

    #[test]
    fn config_set_rejects_an_unknown_provider() {
        let f = Fixture::new("cfgbad");
        let ai = f.ai(Arc::new(FakeResolver::default()), no_transport(), false);
        assert_eq!(
            ai.config_set(&json!({ "provider": "nope" }))
                .unwrap_err()
                .to_string(),
            "Unsupported AI provider"
        );
    }

    #[test]
    fn config_set_writes_0600_mirrors_and_masks_the_key() {
        let f = Fixture::new("cfgset");
        let resolver = Arc::new(FakeResolver::with("api.deepseek.com", &["8.8.8.8"]));
        let ai = f.ai(resolver, no_transport(), false);

        let out = ai
            .config_set(&json!({
                "provider": "deepseek",
                "apiKey": "sk-super-secret-value",
                "baseUrl": "https://api.deepseek.com/v1",
                "model": "deepseek-chat",
            }))
            .unwrap();

        assert_eq!(out["provider"], "deepseek");
        assert_eq!(out["hasKey"], true);
        assert_eq!(out["maskedKey"], "sk-s****");
        let text = serde_json::to_string(&out).unwrap();
        assert!(
            !text.contains("sk-super-secret-value"),
            "公开配置不得含明文 key"
        );
        assert!(!text.contains("apiKey"));

        // 镜像到 etc/ai.json。
        assert!(f.paths.etc.join("ai.json").is_file());
        assert_eq!(f.raw_config()["apiKey"], "sk-super-secret-value");

        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let mode = |p: &std::path::Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&f.paths.ai_config), 0o600);
            assert_eq!(mode(&f.paths.etc.join("ai.json")), 0o600);
            assert_eq!(fs::metadata(&f.paths.ai_config).unwrap().gid(), unsafe {
                libc::getegid()
            });
            assert_eq!(
                fs::metadata(f.paths.etc.join("ai.json")).unwrap().gid(),
                unsafe { libc::getegid() }
            );
        }
    }

    #[test]
    fn config_set_reuses_the_previous_key_when_none_is_supplied() {
        let f = Fixture::new("cfgkeep");
        f.write_config(json!({
            "provider": "openai",
            "apiKey": "old-secret-key",
            "baseUrl": "https://api.openai.com/v1",
            "model": "gpt-4o-mini",
        }));
        let resolver = Arc::new(FakeResolver::with("api.openai.com", &["8.8.8.8"]));
        let ai = f.ai(resolver, no_transport(), false);

        ai.config_set(&json!({ "provider": "openai" })).unwrap();
        assert_eq!(f.raw_config()["apiKey"], "old-secret-key");
    }

    // ── 5. ai.models.list ──

    #[test]
    fn models_list_requires_a_configured_base_url() {
        let f = Fixture::new("modelsnourl");
        f.write_config(json!({ "provider": "custom", "apiKey": "secret-key" }));
        let ai = f.ai(Arc::new(FakeResolver::default()), no_transport(), false);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        assert_eq!(
            rt.block_on(ai.models_list(&json!({})))
                .unwrap_err()
                .to_string(),
            "AI provider API base URL is not configured"
        );
    }

    #[test]
    fn models_list_reports_a_non_200_and_parses_both_shapes() {
        let f = Fixture::new("models");
        let resolver = Arc::new(
            FakeResolver::with("api.example.com", &["8.8.8.8"])
                .add("attacker.example", &["9.9.9.9"]),
        );
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        // 非 200。
        f.write_config(json!({
            "provider": "custom",
            "baseUrl": "https://api.example.com",
            "apiKey": "stored-key",
        }));
        let transport = FakeTransport::with(vec![Ok(json_response(500, "Boom", json!({})))]);
        let ai = f.ai(Arc::clone(&resolver), transport, false);
        assert_eq!(
            rt.block_on(ai.models_list(&json!({})))
                .unwrap_err()
                .to_string(),
            "AI model list request failed: HTTP 500 (Boom)"
        );

        // `{data:[...]}` 形状 + 去重排序。
        let transport = FakeTransport::with(vec![Ok(json_response(
            200,
            "OK",
            json!({ "data": [{ "id": "b" }, "c", { "id": "a" }, { "id": "a" }] }),
        ))]);
        let ai = f.ai(Arc::clone(&resolver), transport, false);
        let out = rt.block_on(ai.models_list(&json!({}))).unwrap();
        assert_eq!(out["models"], json!(["a", "b", "c"]));
        assert_eq!(out["count"], 3);
        assert_eq!(out["baseUrl"], "https://api.example.com");

        // 裸数组形状。
        let transport = FakeTransport::with(vec![Ok(json_response(
            200,
            "OK",
            json!([{ "id": "x" }, "y"]),
        ))]);
        let ai = f.ai(resolver, transport, false);
        let out = rt.block_on(ai.models_list(&json!({}))).unwrap();
        assert_eq!(out["models"], json!(["x", "y"]));
        assert_eq!(out["baseUrl"], "https://api.example.com");
    }

    #[test]
    fn models_list_sends_a_bearer_token_and_the_documented_headers() {
        let f = Fixture::new("modelsreq");
        let resolver = Arc::new(FakeResolver::with("api.example.com", &["8.8.8.8"]));
        f.write_config(json!({
            "provider": "custom",
            "baseUrl": "https://api.example.com",
            "apiKey": "stored-key",
        }));
        let transport =
            FakeTransport::with(vec![Ok(json_response(200, "OK", json!({ "data": [] })))]);
        let ai = f.ai(resolver, Arc::clone(&transport), false);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(ai.models_list(&json!({
            "baseUrl": "https://attacker.example",
            "apiKey": "attacker-controlled",
        })))
        .unwrap();
        let requests = transport.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, "GET");
        assert_eq!(requests[0].url, "https://api.example.com/models");
        assert!(requests[0]
            .headers
            .iter()
            .any(|(k, v)| k == "authorization" && v == "Bearer stored-key"));
        assert!(requests[0]
            .headers
            .iter()
            .any(|(k, v)| k == "User-Agent" && v == "MailStack-AI-Hub/1.0"));
        assert_eq!(requests[0].timeout_secs, 15);
        assert_eq!(requests[0].url, "https://api.example.com/models");
    }

    #[test]
    fn models_list_rejects_a_persisted_private_endpoint_without_deployment_permission() {
        let f = Fixture::new("modelsprivate");
        f.write_config(json!({
            "provider": "custom",
            "baseUrl": "https://internal.example",
            "apiKey": "stored-key",
            "allowPrivateNetwork": true,
        }));
        let transport = FakeTransport::with(vec![]);
        let ai = f.ai(
            Arc::new(FakeResolver::with("internal.example", &["10.0.0.5"])),
            Arc::clone(&transport),
            false,
        );
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        assert_eq!(
            rt.block_on(ai.models_list(&json!({})))
                .unwrap_err()
                .to_string(),
            "Private AI network access is disabled by deployment policy"
        );
        assert!(transport.requests().is_empty());
    }

    /// `insecureTls` 只认持久化配置：请求体里的同名字段既不能关掉 TLS 校验，
    /// 也不会被当成拒绝理由（4.18 之后请求体整体不被信任）。
    #[test]
    fn models_list_reads_insecure_tls_only_from_config() {
        let expected = "TLS verification cannot be disabled for AI requests";
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        // (a) 配置里的 insecureTls → 拒绝，且一次请求都不许发出去。
        let configured = Fixture::new("modelstlsbad");
        configured.write_config(json!({
            "provider": "custom",
            "baseUrl": "https://api.example.com",
            "apiKey": "stored-key",
            "insecureTls": true,
        }));
        let transport = FakeTransport::with(vec![]);
        let ai = configured.ai(
            Arc::new(FakeResolver::with("api.example.com", &["8.8.8.8"])),
            Arc::clone(&transport),
            false,
        );

        assert_eq!(
            rt.block_on(ai.models_list(&json!({ "insecureTls": false })))
                .unwrap_err()
                .to_string(),
            expected
        );
        assert!(transport.requests().is_empty());

        // (b) 请求体里的 insecureTls → 被忽略，正常出站（目标仍取自配置）。
        let ignored = Fixture::new("modelstlsbody");
        ignored.write_config(json!({
            "provider": "custom",
            "baseUrl": "https://api.example.com",
            "apiKey": "stored-key",
        }));
        let transport =
            FakeTransport::with(vec![Ok(json_response(200, "OK", json!({ "data": [] })))]);
        let ai = ignored.ai(
            Arc::new(FakeResolver::with("api.example.com", &["8.8.8.8"])),
            Arc::clone(&transport),
            false,
        );

        rt.block_on(ai.models_list(&json!({
            "insecureTls": true,
            "baseUrl": "https://attacker.example",
        })))
        .unwrap();
        let requests = transport.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].url, "https://api.example.com/models");
    }

    // ── 6. ai.chat ──

    fn chat_config() -> Value {
        json!({
            "provider": "openai",
            "apiKey": "sk-chat-key-12345",
            "baseUrl": "https://api.openai.com/v1",
            "model": "gpt-4o-mini",
        })
    }

    #[test]
    fn chat_requires_a_non_empty_message_list() {
        let f = Fixture::new("chatmsgs");
        let ai = f.ai(Arc::new(FakeResolver::default()), no_transport(), false);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        for bad in [
            json!({}),
            json!({ "messages": [] }),
            json!({ "messages": "hi" }),
        ] {
            assert_eq!(
                rt.block_on(ai.chat(&bad)).unwrap_err().to_string(),
                "messages must be a non-empty list",
                "{bad}"
            );
        }
    }

    #[test]
    fn chat_requires_an_api_key() {
        let f = Fixture::new("chatnokey");
        let ai = f.ai(Arc::new(FakeResolver::default()), no_transport(), false);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = rt
            .block_on(ai.chat(&json!({
                "messages": [{ "role": "user", "content": "hi" }],
                "provider": "bigmodel",
                "baseUrl": "https://example.com",
            })))
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "AI API key is not configured for GLM (BigModel)"
        );
    }

    #[test]
    fn chat_openai_shape_and_reply_parsing() {
        let f = Fixture::new("chatopenai");
        f.write_config(chat_config());
        let resolver = Arc::new(FakeResolver::with("api.openai.com", &["8.8.8.8"]));
        let transport = FakeTransport::with(vec![Ok(json_response(
            200,
            "OK",
            json!({ "choices": [{ "message": { "content": "  hello there  " } }], "usage": { "total_tokens": 7 } }),
        ))]);
        let ai = f.ai(resolver, Arc::clone(&transport), false);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let out = rt
            .block_on(ai.chat(&json!({ "messages": [{ "role": "user", "content": "hi" }] })))
            .unwrap();
        assert_eq!(out["status"], "ok");
        assert_eq!(out["provider"], "openai");
        assert_eq!(out["reply"], "hello there");
        assert_eq!(out["usage"]["total_tokens"], 7);
        assert!(out["latencyMs"].as_u64().unwrap() >= 1);

        let requests = transport.requests();
        assert_eq!(
            requests[0].url,
            "https://api.openai.com/v1/chat/completions"
        );
        let body: Value = serde_json::from_slice(requests[0].body.as_ref().unwrap()).unwrap();
        assert_eq!(body["model"], "gpt-4o-mini");
        assert_eq!(body["max_tokens"], 1500);
        assert_eq!(body["temperature"], 0.2);
        assert_eq!(body["messages"][0]["content"], "hi");
    }

    #[test]
    fn chat_and_test_ignore_base_url_and_api_key_from_the_request_body() {
        // 4.19：base_url / api_key 只认持久化配置（与 `models_list` 同款）。请求体里
        // 塞攻击者 URL 不得改变出站目标 —— 否则「发一次对话」就能把存储的密钥
        // 原样送到攻击者指定的端点；塞攻击者 key 也不得替换存储的凭据。
        let f = Fixture::new("chaigroup");
        f.write_config(json!({
            "provider": "custom",
            "apiKey": "stored-key",
            "baseUrl": "https://api.example.com/v1",
            "model": "m",
        }));
        let resolver = Arc::new(FakeResolver::with("api.example.com", &["8.8.8.8"]));
        let transport = FakeTransport::with(vec![
            Ok(json_response(
                200,
                "OK",
                json!({ "choices": [{ "message": { "content": "ok" } }] }),
            )),
            Ok(json_response(
                200,
                "OK",
                json!({ "choices": [{ "message": { "content": "ok" } }] }),
            )),
        ]);
        let ai = f.ai(resolver, Arc::clone(&transport), false);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let body = json!({
            "messages": [{ "role": "user", "content": "hi" }],
            "baseUrl": "https://attacker.example",
            "apiKey": "attacker-controlled",
        });
        rt.block_on(ai.chat(&body)).unwrap();
        rt.block_on(ai.test(&body)).unwrap();

        for request in transport.requests() {
            assert_eq!(request.url, "https://api.example.com/v1/chat/completions");
            assert!(
                request
                    .headers
                    .iter()
                    .any(|(k, v)| k == "authorization" && v == "Bearer stored-key"),
                "必须携带存储的凭据: {:?}",
                request.headers
            );
            assert!(
                !request
                    .headers
                    .iter()
                    .any(|(_, v)| v.contains("attacker-controlled")),
                "请求体指定的 key 不得被采信"
            );
        }
    }

    #[test]
    fn upstream_error_bodies_are_truncated_in_error_messages() {
        // 上游响应体可达 2 MB，错误文案必须截断，否则一次上游故障就能把
        // 一整个页面塞进错误信封 / 日志 / 前端。
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let f = Fixture::new("chatbigerr");
        f.write_config(chat_config());
        let long_body = "x".repeat(4000);
        let transport =
            FakeTransport::with(vec![Ok(json_response(500, "Err", json!(long_body)))]);
        let ai = f.ai(
            Arc::new(FakeResolver::with("api.openai.com", &["8.8.8.8"])),
            transport,
            false,
        );

        let err = rt
            .block_on(ai.chat(&json!({ "messages": [{ "role": "user", "content": "hi" }] })))
            .unwrap_err()
            .to_string();
        assert!(
            err.starts_with("AI completion request failed: HTTP 500:"),
            "{err}"
        );
        assert!(
            err.chars().count() < 600,
            "错误文案必须截断（{} chars）",
            err.chars().count()
        );
        // 纯函数口径：按字符截断到 500（不按字节，避免切进多字节字符中间）。
        assert_eq!(truncate_for_error(&"a".repeat(600)).chars().count(), 500);
    }

    #[test]
    fn chat_anthropic_extracts_system_and_parses_text_blocks() {
        let f = Fixture::new("chatanthropic");
        f.write_config(json!({
            "provider": "anthropic",
            "apiKey": "sk-ant-key-123456",
            "baseUrl": "https://api.anthropic.com/v1",
            "model": "claude-3-5-sonnet-20241022",
        }));
        let resolver = Arc::new(FakeResolver::with("api.anthropic.com", &["8.8.8.8"]));
        let transport = FakeTransport::with(vec![Ok(json_response(
            200,
            "OK",
            json!({ "content": [{ "type": "text", "text": "Hel" }, { "type": "text", "text": "lo" }], "usage": {} }),
        ))]);
        let ai = f.ai(resolver, Arc::clone(&transport), false);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let out = rt
            .block_on(ai.chat(&json!({
                "messages": [
                    { "role": "system", "content": "be terse" },
                    { "role": "user", "content": "hi" },
                ],
            })))
            .unwrap();
        assert_eq!(out["reply"], "Hello");
        assert_eq!(out["provider"], "anthropic");

        let requests = transport.requests();
        assert_eq!(requests[0].url, "https://api.anthropic.com/v1/messages");
        assert!(requests[0].headers.iter().any(|(k, _)| k == "x-api-key"));
        assert!(requests[0]
            .headers
            .iter()
            .any(|(k, v)| k == "anthropic-version" && v == "2023-06-01"));
        assert!(!requests[0]
            .headers
            .iter()
            .any(|(k, _)| k == "authorization"));
        let body: Value = serde_json::from_slice(requests[0].body.as_ref().unwrap()).unwrap();
        assert_eq!(body["system"], "be terse");
        assert_eq!(body["messages"].as_array().unwrap().len(), 1);
        assert_eq!(body["messages"][0]["role"], "user");
    }

    #[test]
    fn chat_reports_both_protocol_error_texts() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let f = Fixture::new("chatopenai");
        f.write_config(chat_config());
        let resolver = Arc::new(FakeResolver::with("api.openai.com", &["8.8.8.8"]));
        let transport = FakeTransport::with(vec![err_response("HTTP 500: bad".to_string())]);
        let ai = f.ai(resolver, transport, false);
        assert_eq!(
            rt.block_on(ai.chat(&json!({ "messages": [{ "role": "user", "content": "hi" }] })))
                .unwrap_err()
                .to_string(),
            "HTTP 500: bad"
        );

        // 真正返回非 200（transport 层成功、协议层失败）。
        let transport = FakeTransport::with(vec![Ok(json_response(
            500,
            "Err",
            json!({ "error": "nope" }),
        ))]);
        let ai = f.ai(
            Arc::new(FakeResolver::with("api.openai.com", &["8.8.8.8"])),
            transport,
            false,
        );
        let err = rt
            .block_on(ai.chat(&json!({ "messages": [{ "role": "user", "content": "hi" }] })))
            .unwrap_err();
        assert!(
            err.to_string()
                .starts_with("AI completion request failed: HTTP 500:"),
            "{err}"
        );

        let f = Fixture::new("chatanth");
        f.write_config(json!({
            "provider": "anthropic",
            "apiKey": "sk-ant-key-123456",
            "baseUrl": "https://api.anthropic.com/v1",
            "model": "claude-3-5-sonnet-20241022",
        }));
        let transport = FakeTransport::with(vec![Ok(json_response(
            500,
            "Err",
            json!({ "error": "nope" }),
        ))]);
        let ai = f.ai(
            Arc::new(FakeResolver::with("api.anthropic.com", &["8.8.8.8"])),
            transport,
            false,
        );
        let err = rt
            .block_on(ai.chat(&json!({ "messages": [{ "role": "user", "content": "hi" }] })))
            .unwrap_err();
        assert!(
            err.to_string()
                .starts_with("Claude API request failed: HTTP 500:"),
            "{err}"
        );
    }

    /// 便于构造 transport 层错误。
    fn err_response(message: String) -> Result<AiHttpResponse, String> {
        Err(message)
    }

    // ── 7. fallback ──

    #[test]
    fn chat_uses_the_fallback_when_the_primary_fails() {
        let f = Fixture::new("fallback");
        f.write_config(json!({
            "provider": "openai",
            "apiKey": "sk-primary-key-123",
            "baseUrl": "https://api.openai.com/v1",
            "model": "gpt-4o-mini",
            "fallbackProvider": "deepseek",
            "fallbackApiKey": "sk-fallback-key-1",
        }));
        let resolver = Arc::new(
            FakeResolver::with("api.openai.com", &["8.8.8.8"])
                .add("api.deepseek.com", &["8.8.8.8"]),
        );
        let transport = FakeTransport::with(vec![
            Err("primary down".to_string()),
            Ok(json_response(
                200,
                "OK",
                json!({ "choices": [{ "message": { "content": "fb reply" } }] }),
            )),
        ]);
        let ai = f.ai(resolver, Arc::clone(&transport), false);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let out = rt
            .block_on(ai.chat(&json!({ "messages": [{ "role": "user", "content": "hi" }] })))
            .unwrap();
        assert_eq!(out["provider"], "deepseek");
        assert_eq!(out["reply"], "fb reply");
        assert_eq!(out["fallbackUsed"], true);
        assert_eq!(transport.requests().len(), 2);
    }

    #[test]
    fn an_explicit_provider_disables_the_fallback() {
        let f = Fixture::new("fallbackexplicit");
        f.write_config(json!({
            "provider": "openai",
            "apiKey": "sk-primary-key-123",
            "baseUrl": "https://api.openai.com/v1",
            "model": "gpt-4o-mini",
            "fallbackProvider": "deepseek",
            "fallbackApiKey": "sk-fallback-key-1",
        }));
        let resolver = Arc::new(FakeResolver::with("api.openai.com", &["8.8.8.8"]));
        let transport = FakeTransport::with(vec![Err("primary down".to_string())]);
        let ai = f.ai(resolver, Arc::clone(&transport), false);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let err = rt
            .block_on(ai.chat(&json!({
                "provider": "openai",
                "messages": [{ "role": "user", "content": "hi" }],
            })))
            .unwrap_err();
        assert_eq!(err.to_string(), "primary down");
        assert_eq!(
            transport.requests().len(),
            1,
            "显式指定 provider 时不得 fallback"
        );
    }

    // ── 8. diagnose / parse 的 prompt ──

    #[test]
    fn diagnose_and_parse_build_the_exact_prompt() {
        let f = Fixture::new("prompts");
        f.write_config(chat_config());
        let resolver = Arc::new(FakeResolver::with("api.openai.com", &["8.8.8.8"]));
        let transport = FakeTransport::with(vec![
            Ok(json_response(
                200,
                "OK",
                json!({ "choices": [{ "message": { "content": "ok" } }] }),
            )),
            Ok(json_response(
                200,
                "OK",
                json!({ "choices": [{ "message": { "content": "ok" } }] }),
            )),
        ]);
        let ai = f.ai(resolver, Arc::clone(&transport), false);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(ai.diagnose(&json!({ "logs": "line1\nline2" })))
            .unwrap();
        rt.block_on(ai.parse(&json!({ "text": "key=value" })))
            .unwrap();

        let requests = transport.requests();
        let first: Value = serde_json::from_slice(requests[0].body.as_ref().unwrap()).unwrap();
        assert_eq!(
            first["messages"][0]["content"],
            "Analyze these Linux mail-server logs and return prioritized findings.\n\nline1\nline2"
        );
        let second: Value = serde_json::from_slice(requests[1].body.as_ref().unwrap()).unwrap();
        assert_eq!(
            second["messages"][0]["content"],
            "Parse the following mail configuration and return strict JSON diagnostics.\n\nkey=value"
        );
        // diagnose/parse 只带 messages，不携带请求里的 provider。
        assert_eq!(
            requests[0].url,
            "https://api.openai.com/v1/chat/completions"
        );
    }

    // ── 9. HTTP 报文解析（纯函数） ──

    #[test]
    fn response_body_over_two_megabytes_is_rejected() {
        let mut raw = b"HTTP/1.1 200 OK\r\nContent-Length: 2000001\r\n\r\n".to_vec();
        raw.resize(raw.len() + 2_000_001, b'x');
        assert_eq!(
            parse_http_response(&raw).unwrap_err(),
            "AI endpoint response exceeded 2 MB"
        );
    }

    #[test]
    fn chunked_responses_are_decoded() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHello\r\n6\r\n World\r\n0\r\n\r\n";
        let parsed = parse_http_response(raw).unwrap();
        assert_eq!(parsed.status, 200);
        assert_eq!(parsed.body, b"Hello World");
    }

    #[test]
    fn content_length_limits_the_body() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHelloWorld";
        let parsed = parse_http_response(raw).unwrap();
        assert_eq!(parsed.body, b"Hello");
    }

    fn endpoint(url: &str, resolver: &FakeResolver) -> Endpoint {
        validate_endpoint(url, false, resolver).unwrap()
    }

    #[test]
    fn redirects_must_be_same_origin() {
        let resolver = FakeResolver::with("ai.example.com", &["8.8.8.8"]);
        let current = endpoint("https://ai.example.com/api", &resolver);

        // 同源相对路径 → 允许。
        let follow = follow_redirect(&current, 302, Some("/next"), "POST", 0)
            .unwrap()
            .unwrap();
        assert_eq!(follow.url, "https://ai.example.com/next");
        assert_eq!(follow.method, "POST");

        // 跨源 → 拒绝（新目标从未被筛选）。
        let err =
            follow_redirect(&current, 302, Some("https://evil.example/x"), "POST", 0).unwrap_err();
        assert_eq!(err, "Cross-origin AI endpoint redirect was rejected");

        // 端口不同也算跨源。
        let err = follow_redirect(
            &current,
            302,
            Some("https://ai.example.com:8443/x"),
            "POST",
            0,
        )
        .unwrap_err();
        assert_eq!(err, "Cross-origin AI endpoint redirect was rejected");
    }

    #[test]
    fn redirects_are_limited_and_303_becomes_a_bodyless_get() {
        let resolver = FakeResolver::with("ai.example.com", &["8.8.8.8"]);
        let current = endpoint("https://ai.example.com/api", &resolver);

        for redirects in 0..MAX_REDIRECTS {
            assert!(
                follow_redirect(&current, 302, Some("/next"), "POST", redirects)
                    .unwrap()
                    .is_some(),
                "redirects={redirects} 应允许"
            );
        }
        assert_eq!(
            follow_redirect(&current, 302, Some("/next"), "POST", MAX_REDIRECTS).unwrap_err(),
            "AI endpoint redirected too many times"
        );

        let follow = follow_redirect(&current, 303, Some("/next"), "POST", 0)
            .unwrap()
            .unwrap();
        assert_eq!(follow.method, "GET");
        assert!(!follow.keep_body);

        // 302 不是 303：方法保持不变。
        let follow = follow_redirect(&current, 302, Some("/next"), "POST", 0)
            .unwrap()
            .unwrap();
        assert_eq!(follow.method, "POST");
        assert!(follow.keep_body);
    }

    #[test]
    fn a_redirect_without_location_is_invalid() {
        let resolver = FakeResolver::with("ai.example.com", &["8.8.8.8"]);
        let current = endpoint("https://ai.example.com/api", &resolver);
        assert_eq!(
            follow_redirect(&current, 301, None, "GET", 0).unwrap_err(),
            "AI endpoint returned an invalid redirect"
        );
    }

    #[test]
    fn request_bytes_carry_host_and_content_length() {
        let resolver = FakeResolver::with("ai.example.com", &["8.8.8.8"]);
        let ep = endpoint("https://ai.example.com/v1/chat?x=1", &resolver);
        let bytes = build_request_bytes(
            &ep,
            "POST",
            &[("content-type".to_string(), "application/json".to_string())],
            Some(b"{}"),
        );
        let text = String::from_utf8(bytes.unwrap()).unwrap();
        assert!(text.starts_with("POST /v1/chat?x=1 HTTP/1.1\r\n"));
        assert!(text.contains("Host: ai.example.com\r\n"));
        assert!(text.contains("content-type: application/json\r\n"));
        assert!(text.contains("Content-Length: 2\r\n"));
        assert!(text.contains("Connection: close\r\n"));
        assert!(text.ends_with("\r\n\r\n{}"));
    }

    #[test]
    fn request_bytes_reject_crlf_injection_in_method_target_and_headers() {
        let resolver = FakeResolver::with("ai.example.com", &["8.8.8.8"]);
        let ep = endpoint("https://ai.example.com/v1/chat?x=1", &resolver);
        let invalid_headers = [
            vec![(
                "authorization".to_string(),
                "Bearer secret\r\nX-Evil: 1".to_string(),
            )],
            vec![("x-safe\r\nX-Evil".to_string(), "value".to_string())],
            vec![("x-safe".to_string(), "value\nInjected: yes".to_string())],
        ];
        for headers in invalid_headers {
            assert!(build_request_bytes(&ep, "GET", &headers, None).is_err());
        }
        assert!(build_request_bytes(&ep, "GET\r\nX-Evil: 1", &[], None).is_err());

        let mut injected_target = ep;
        injected_target.query = "x=1\r\nX-Evil: yes".to_string();
        assert!(build_request_bytes(&injected_target, "GET", &[], None).is_err());
    }

    #[test]
    fn endpoint_urls_reject_control_characters_and_spaces() {
        let resolver = FakeResolver::with("ai.example.com", &["8.8.8.8"]);
        for url in [
            "https://ai.example.com/path\r\nX-Evil: 1",
            "https://ai.example.com/path\nX-Evil: 1",
            "https://ai.example.com/a path",
            "https://ai.example.com/?key=value\tInjected",
        ] {
            assert!(validate_endpoint(url, false, &resolver).is_err(), "{url:?}");
        }
    }

    // ── 10. 密钥不出现在错误文案里 ──

    #[test]
    fn the_api_key_never_leaks_into_an_error_message() {
        let f = Fixture::new("noleak");
        f.write_config(chat_config());
        let resolver = Arc::new(FakeResolver::with("api.openai.com", &["8.8.8.8"]));
        let transport = FakeTransport::with(vec![Err("upstream refused".to_string())]);
        let ai = f.ai(resolver, transport, false);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let err = rt
            .block_on(ai.chat(&json!({ "messages": [{ "role": "user", "content": "hi" }] })))
            .unwrap_err();
        assert!(
            !err.to_string().contains("sk-chat-key-12345"),
            "错误文案不得含密钥"
        );
    }
}
