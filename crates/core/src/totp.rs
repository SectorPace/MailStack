//! TOTP（RFC 6238）与 2FA 信封（规格书 §5.5；INV-5、INV-29、INV-32）。
//!
//! ## 三条不可动摇的性质
//!
//! * **INV-5**：TOTP secret **绝不明文落盘**。secret 以 AES-256-GCM 信封写进
//!   `admin.json` 的 `totp` 块，主密钥单独放在 `0600 root:root` 的
//!   [`Paths::totp_key`]。于是即便 `admin.json` 被读到（它是 `0640 root:mailstack-admin`），
//!   没有 `totp.key` 也解不出 secret —— 两件东西分属两个权限域才有意义。
//! * **INV-29**：一张恢复码只能被消费一次。消费失败不得改动既有码。
//! * **INV-32**：整个「读 → 判定 → 改 → 写」都在 [`crate::atomic::locked`] 临界区内。
//!   `atomic()` 只保证最后写入那一瞬是原子的；若各自 read 之后再 write，
//!   两次并发消费会各自基于「码还在」的同一份快照写回 —— 同一张码被用两次。
//! * **重放保护（RFC 6238 §5.2 建议的 lastUsedStep）**：6 位动态码一旦被接受，
//!   同一个 step **不得**再被接受。不记这一步的话，±1 的偏移窗口（±30 秒）把
//!   一个 6 位码的有效期拉长到约 90 秒，攻击者在窗口内可以**无限次重放**同一个码
//!   —— 恢复码有一张一消费（INV-29），动态码却没有，这个不对称是真实缺口。
//!
//! ## 为什么自己实现而不引第三方 TOTP crate
//!
//! 需要的东西只有 HMAC-SHA1 与 6 位动态截断，标准是明确的（RFC 4226 §5.4），
//! 而 `HMAC` / `SHA1` / `AES-GCM` 都由 RustCrypto 提供且是纯 Rust（不违反 §3.4
//! 的无 C 依赖约束）。引一个「TOTP 全家桶」只会扩大审计面。

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::config::{update_admin_config, AdminConfig};
use crate::error::{CoreError, CoreResult};
use crate::paths::Paths;

/// 时间步长（RFC 6238 §4.1 默认 30 秒）。
pub const TOTP_PERIOD_SECS: u64 = 30;
/// 动态截断后的位数（RFC 4226 §5.4 的 6 位）。
pub const TOTP_DIGITS: u32 = 6;
/// 时钟偏移容忍步数：接受 `step-1 / step / step+1` 三步。
pub const TOTP_WINDOW_STEPS: i64 = 1;
/// secret 长度：RFC 4226 §4 建议 160 位。
pub const TOTP_SECRET_BYTES: usize = 20;
/// 主密钥长度：AES-256 ⇒ 32 字节。
pub const TOTP_KEY_BYTES: usize = 32;
/// 恢复码张数。
pub const RECOVERY_CODE_COUNT: usize = 8;
/// 单张恢复码字符数（32 符号表 ⇒ 约 50 位熵，且登录侧另有失败限流）。
pub const RECOVERY_CODE_LEN: usize = 10;
/// 信封格式版本。读到未知版本一律拒绝（fail-closed），不做「尽力解析」。
pub const ENVELOPE_VERSION: u32 = 1;
/// 已消费 step 记账保留的条数。
///
/// 取 8 而不是 1：只记「最后一个」的话，攻击者只要在 ±1 窗口里交替提交
/// `step-1` 与 `step+1` 两个码，就能把中间那一步反复绕过。窗口内最多 3 个 step，
/// 记不下 3 个就等于没记。8 有余量，代价只是 admin.json 里多几个整数。
pub const USED_STEPS_KEPT: usize = 8;

/// AEAD 附加认证数据：把信封绑定到它唯一的用途，避免密文被搬到别处复用。
const AEAD_AAD: &[u8] = b"mailstack.totp.v1";

/// 恢复码字母表：去掉 `0/O`、`1/I` 等易混字符，便于人工抄录。
const RECOVERY_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

/// `otpauth://` URI 的签发者名。
pub const DEFAULT_ISSUER: &str = "MailStack";

/// AES-256-GCM 信封（`admin.json` 里 `enc` / `nonce` / `tag` 三个字段）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// base64(密文，不含 tag)。
    pub enc: String,
    /// base64(12 字节随机 nonce)。
    pub nonce: String,
    /// base64(16 字节 GCM tag)。
    pub tag: String,
}

/// `admin.json` 的 `totp` 块状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TotpState {
    /// 没有 `totp` 块：从未启用。
    Disabled,
    /// 有块但 `enabled: false`：已 `begin` 但尚未用验证码确认。
    Pending,
    /// 已启用。
    Enabled,
}

impl TotpState {
    pub fn as_str(self) -> &'static str {
        match self {
            TotpState::Disabled => "disabled",
            TotpState::Pending => "pending",
            TotpState::Enabled => "enabled",
        }
    }
}

/// 校验通过时用的因子。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyMethod {
    Totp,
    Recovery,
}

impl VerifyMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            VerifyMethod::Totp => "totp",
            VerifyMethod::Recovery => "recovery",
        }
    }
}

/// 校验结论。**「码不对」是结论而不是错误** —— 用户名/口令/验证码三者失败必须
/// 对外不可区分（INV-23），故这里返回 `valid: false` 而不是 `Err`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifyResult {
    pub valid: bool,
    pub method: Option<VerifyMethod>,
}

impl VerifyResult {
    fn rejected() -> Self {
        Self {
            valid: false,
            method: None,
        }
    }
}

/// `begin` 的产出：只在这一刻把 secret 交给用户，之后再也取不回明文。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enrollment {
    /// base32 编码的 secret。
    pub secret: String,
    /// 可直接交给验证器 App 的 `otpauth://` URI。
    pub otpauth_url: String,
    pub issuer: String,
    pub account: String,
}

// ─────────────────────────── 主密钥 ───────────────────────────

/// 只读加载主密钥；不存在时返回 [`CoreError::NotFound`]。
///
/// **读路径绝不创建密钥**：登录校验走这条路，若它顺手造一个主密钥，
/// 那么「密钥文件被运维删掉」这一故障会被静默掩盖成一个空密钥。
pub fn load_master_key(paths: &Paths) -> CoreResult<[u8; TOTP_KEY_BYTES]> {
    match std::fs::read_to_string(&paths.totp_key) {
        Ok(text) => decode_master_key(text.trim()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err(CoreError::NotFound(paths.totp_key.clone()))
        }
        Err(e) => Err(CoreError::io(&paths.totp_key, e)),
    }
}

/// 加载主密钥，缺失则生成并以 `0600 root:root` 落盘。
///
/// 只在**写路径**（`begin` / `enable`）使用：那里确实需要一把密钥。
pub fn load_or_create_master_key(paths: &Paths) -> CoreResult<[u8; TOTP_KEY_BYTES]> {
    if paths.totp_key.exists() {
        return load_master_key(paths);
    }
    let key = random_bytes::<TOTP_KEY_BYTES>();
    let body = format!("{}\n", BASE64.encode(key));
    // group = None ⇒ 只 chown 到 root（不落到 mailstack-admin）：这个密钥的读者
    // 只有特权进程，web 进程读不到它正是 INV-5 的立足点。
    crate::atomic::atomic_as(&paths.totp_key, body.as_bytes(), 0o600, None)?;
    Ok(key)
}

fn decode_master_key(text: &str) -> CoreResult<[u8; TOTP_KEY_BYTES]> {
    let raw = BASE64
        .decode(text)
        .map_err(|_| CoreError::invalid("totp master key is not valid base64"))?;
    raw.as_slice().try_into().map_err(|_| {
        CoreError::invalid(format!(
            "totp master key must decode to {TOTP_KEY_BYTES} bytes"
        ))
    })
}

// ─────────────────────────── 信封 ───────────────────────────

/// 用主密钥封装明文（AES-256-GCM）。
pub fn seal(key: &[u8; TOTP_KEY_BYTES], plaintext: &[u8]) -> CoreResult<Envelope> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce_bytes = random_bytes::<12>();
    let sealed = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad: AEAD_AAD,
            },
        )
        .map_err(|_| CoreError::invalid("totp envelope encryption failed"))?;

    // GCM 的 tag 固定 16 字节，`encrypt` 把它拼在密文尾部；拆开是为了让
    // `admin.json` 的字段形状与既有 2FA 块保持一致（enc / nonce / tag）。
    let (ciphertext, tag) = sealed.split_at(sealed.len() - 16);
    Ok(Envelope {
        enc: BASE64.encode(ciphertext),
        nonce: BASE64.encode(nonce_bytes),
        tag: BASE64.encode(tag),
    })
}

/// 解开信封。任何不一致（字段缺失、base64 非法、长度不对、tag 不匹配）
/// 都返回错误，**绝不返回部分明文**。
pub fn open(key: &[u8; TOTP_KEY_BYTES], envelope: &Envelope) -> CoreResult<Vec<u8>> {
    let ciphertext = BASE64
        .decode(&envelope.enc)
        .map_err(|_| CoreError::invalid("totp envelope ciphertext is not valid base64"))?;
    let nonce = BASE64
        .decode(&envelope.nonce)
        .map_err(|_| CoreError::invalid("totp envelope nonce is not valid base64"))?;
    let tag = BASE64
        .decode(&envelope.tag)
        .map_err(|_| CoreError::invalid("totp envelope tag is not valid base64"))?;
    if nonce.len() != 12 || tag.len() != 16 {
        return Err(CoreError::invalid(
            "totp envelope has malformed nonce or tag",
        ));
    }

    let mut body = ciphertext;
    body.extend_from_slice(&tag);
    Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key))
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &body,
                aad: AEAD_AAD,
            },
        )
        .map_err(|_| CoreError::invalid("totp envelope failed authentication"))
}

// ─────────────────────────── 生成与编码 ───────────────────────────

fn random_bytes<const N: usize>() -> [u8; N] {
    use rand::RngCore;
    let mut buf = [0u8; N];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

/// 新 secret（20 随机字节）。
pub fn new_secret() -> [u8; TOTP_SECRET_BYTES] {
    random_bytes()
}

/// RFC 4648 base32 编码（无填充）。
///
/// 验证器 App 的 `otpauth://` 一律用 base32，且普遍不接受 `=` 填充。
pub fn base32_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

/// 组装 `otpauth://totp/...` URI。
pub fn otpauth_uri(issuer: &str, account: &str, secret_base32: &str) -> String {
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits={}&period={}",
        percent_encode(issuer),
        percent_encode(account),
        secret_base32,
        percent_encode(issuer),
        TOTP_DIGITS,
        TOTP_PERIOD_SECS,
    )
}

/// URI 组件的百分号编码（RFC 3986 unreserved 之外一律转义）。
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

// ─────────────────────────── TOTP ───────────────────────────

/// RFC 4226 的 HMAC-SHA1 + 动态截断（6 位）。
pub fn hotp(secret: &[u8], counter: u64) -> u32 {
    // 限定到 `Mac`：`aes_gcm::aead::KeyInit` 也有同名的 `new_from_slice`，
    // 不限定会产生歧义。
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(secret).expect("HMAC 接受任意长度密钥");
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();

    // 20 字节输出取最后一个字节的低 4 位作偏移量，再取 4 字节并抹掉符号位。
    let offset = (digest[19] & 0x0f) as usize;
    let truncated = ((u32::from(digest[offset]) & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    truncated % 10u32.pow(TOTP_DIGITS)
}

/// `unix_time` 对应的步数。
fn step_at(unix_time: u64) -> i64 {
    (unix_time / TOTP_PERIOD_SECS) as i64
}

/// 输入形状是否可参与比较（6 位纯数字）。
///
/// 单独拎出来是为了让「形状不对」不必进偏移窗口循环：**8** 个字符的畸形输入
/// 会白算 3 次 HMAC，而它本来就绝不可能是任何一步的动态码。
fn code_shape_ok(code: &str) -> bool {
    let code = code.trim();
    code.len() == TOTP_DIGITS as usize && code.bytes().all(|b| b.is_ascii_digit())
}

/// 在 `step ± TOTP_WINDOW_STEPS` 里找出与 `code` 匹配的那个 step。
///
/// 返回 `None` 表示不匹配。**返回 step 而不只是 bool 是重放保护的前提**：
/// 只有知道「命中的是哪一步」，才能把它记进已消费集合。
///
/// ## 为什么保留 step=0
///
/// `step.checked_add(offset).filter(|s| *s >= 0)` 会把 `step=0` 的 `step-1`
/// 直接跳过。这本身是对的（负 step 不存在），但**记账时必须把 0 当作正常值**：
/// 一旦用 `if step > 0` 之类的真值判断去写 `usedSteps`，step 0 就永远记不上，
/// 于是「epoch 后第一分钟」那个码可以被无限重放。
pub fn matching_step(secret: &[u8], code: &str, unix_time: u64) -> Option<i64> {
    let code = code.trim();
    if !code_shape_ok(code) {
        return None;
    }
    let step = step_at(unix_time);
    for offset in -TOTP_WINDOW_STEPS..=TOTP_WINDOW_STEPS {
        let Some(candidate) = step.checked_add(offset).filter(|s| *s >= 0) else {
            continue;
        };
        let expected = format!(
            "{:0width$}",
            hotp(secret, candidate as u64),
            width = TOTP_DIGITS as usize
        );
        if ct_eq(expected.as_bytes(), code.as_bytes()) {
            return Some(candidate);
        }
    }
    None
}

/// 校验 6 位动态码，容忍前后各一步的时钟偏移。
pub fn verify_code(secret: &[u8], code: &str, unix_time: u64) -> bool {
    matching_step(secret, code, unix_time).is_some()
}

/// 常数时间比较（长度不同直接判否；长度本身不是秘密）。
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ─────────────────────────── 恢复码 ───────────────────────────

/// 生成一批恢复码（明文，**只在 enable 那一刻返回一次**）。
pub fn generate_recovery_codes() -> Vec<String> {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..RECOVERY_CODE_COUNT)
        .map(|_| {
            (0..RECOVERY_CODE_LEN)
                .map(|_| RECOVERY_ALPHABET[rng.gen_range(0..RECOVERY_ALPHABET.len())] as char)
                .collect()
        })
        .collect()
}

/// 归一化：去掉空白与连字符、转大写。
///
/// 用户抄写时习惯加连字符或空格，若不归一化，一张正确的码会因为输入格式被拒。
pub fn normalize_recovery_code(code: &str) -> String {
    code.chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .flat_map(char::to_uppercase)
        .collect()
}

/// 恢复码的存储形态：SHA-256 十六进制。
///
/// 恢复码本身是 50 位随机量，不需要加盐或慢哈希；这里要防的是「文件被读到
/// 就直接得到可用的码」，而不是防离线爆破。
pub fn hash_recovery_code(code: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(normalize_recovery_code(code).as_bytes());
    hex::encode(hasher.finalize())
}

// ─────────────────────────── admin.json 的 totp 块 ───────────────────────────

fn totp_block(config: &AdminConfig) -> Option<&Value> {
    config.totp.as_ref().filter(|value| value.is_object())
}

/// 读 `admin.json` 判定 2FA 状态。
pub fn state(config: &AdminConfig) -> TotpState {
    let Some(block) = totp_block(config) else {
        return TotpState::Disabled;
    };
    if block
        .get("enabled")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        TotpState::Enabled
    } else {
        TotpState::Pending
    }
}

/// 读磁盘上的 2FA 状态。
pub fn state_at(paths: &Paths) -> TotpState {
    crate::config::read_admin_config(paths)
        .as_ref()
        .map(state)
        .unwrap_or(TotpState::Disabled)
}

fn envelope_from_block(block: &Value) -> CoreResult<Envelope> {
    if let Some(version) = block.get("version").and_then(Value::as_u64) {
        if version != u64::from(ENVELOPE_VERSION) {
            return Err(CoreError::invalid(format!(
                "unsupported totp envelope version {version}"
            )));
        }
    }
    let field = |key: &str| -> CoreResult<String> {
        block
            .get(key)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| CoreError::invalid(format!("totp block is missing `{key}`")))
    };
    Ok(Envelope {
        enc: field("enc")?,
        nonce: field("nonce")?,
        tag: field("tag")?,
    })
}

fn recovery_hashes(block: &Value) -> Vec<String> {
    block
        .get("recovery")
        .and_then(Value::as_array)
        .map(|codes| {
            codes
                .iter()
                .filter_map(|c| c.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// 读已消费 step 记账。
///
/// **只认非负整数**：手改过 `admin.json`（或降级到旧版本再回来）可能塞进字符串、
/// 浮点或负数；把它们当成有效记账会让某个 step 永久被拒，而那正是攻击者要的
/// 「让合法管理员进不来」。宁可当作没有记账（退化成可重放）也不伪造拒绝 ——
/// 但注意退化的方向是**不再拦合法用户**，不是**放行攻击者**：匹配上的码仍要过一次
/// 真正的 HMAC 比对。
fn used_steps(block: &Value) -> Vec<i64> {
    block
        .get("usedSteps")
        .and_then(Value::as_array)
        .map(|steps| {
            steps
                .iter()
                .filter_map(Value::as_i64)
                .filter(|s| *s >= 0)
                .collect()
        })
        .unwrap_or_default()
}

/// 已消费 step 记账里是否已有 `step`。
fn step_already_used(block: &Value, step: i64) -> bool {
    used_steps(block).contains(&step)
}

/// 把 `step` 记进已消费集合并返回新的块。
///
/// 记账**只增不减**（直到超出 `USED_STEPS_KEPT` 才淘汰最旧的），
/// 因此时钟回拨不会让旧码复活：回拨后 `last` 可能变小，但集合里那个 step 仍在，
/// 于是同一个码第二次提交照样被拒。
fn block_with_step_used(block: &Value, step: i64) -> Value {
    let mut steps = used_steps(block);
    if !steps.contains(&step) {
        steps.push(step);
    }
    // 降序去重：同一步只留一个，且最新的排在前面 —— 淘汰时丢的是最旧的那些。
    steps.sort_unstable_by(|a, b| b.cmp(a));
    steps.dedup();
    steps.truncate(USED_STEPS_KEPT);
    let mut next = block.clone();
    next["usedSteps"] = Value::Array(steps.into_iter().map(Value::from).collect());
    next
}

// ─────────────────────────── 生命周期操作 ───────────────────────────

/// `admin.totp.begin`：生成新 secret 并写入**未启用**的信封。
///
/// 已启用时拒绝：静默替换在用的 secret 会立刻把真正的管理员锁在门外。
pub fn begin(paths: &Paths, account: &str) -> CoreResult<Enrollment> {
    let key = load_or_create_master_key(paths)?;
    let secret = new_secret();
    let envelope = seal(&key, &secret)?;
    let secret_base32 = base32_encode(&secret);
    let account = if account.trim().is_empty() {
        "admin".to_string()
    } else {
        account.trim().to_string()
    };

    update_admin_config(&paths.admin_config, |current| {
        if state(current) == TotpState::Enabled {
            return Err(CoreError::invalid(
                "two-factor authentication is already enabled; disable it first",
            ));
        }
        let mut next = current.clone();
        next.totp = Some(json!({
            "version": ENVELOPE_VERSION,
            "enabled": false,
            "enc": envelope.enc,
            "nonce": envelope.nonce,
            "tag": envelope.tag,
            "recovery": [],
        }));
        Ok((next, ()))
    })?;

    Ok(Enrollment {
        otpauth_url: otpauth_uri(DEFAULT_ISSUER, &account, &secret_base32),
        secret: secret_base32,
        issuer: DEFAULT_ISSUER.to_string(),
        account,
    })
}

/// `admin.totp.enable`：校验一次动态码，成功后置位并签发恢复码。
///
/// 返回的恢复码是**明文且仅此一次**；磁盘上只留 SHA-256。
pub fn enable(paths: &Paths, code: &str, unix_time: u64) -> CoreResult<Vec<String>> {
    let key = load_or_create_master_key(paths)?;
    let codes = generate_recovery_codes();
    let hashed: Vec<String> = codes.iter().map(|c| hash_recovery_code(c)).collect();

    update_admin_config(&paths.admin_config, |current| {
        let block = totp_block(current)
            .ok_or_else(|| CoreError::invalid("no pending two-factor enrollment"))?;
        if block
            .get("enabled")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            return Err(CoreError::invalid(
                "two-factor authentication is already enabled",
            ));
        }
        let secret = open(&key, &envelope_from_block(block)?)?;
        if !verify_code(&secret, code, unix_time) {
            // 未通过就不置位、也不签发恢复码 —— 否则一次打错的确认码就会
            // 把账号锁在一个用户拿不到恢复码的 2FA 状态里。
            return Err(CoreError::invalid("invalid verification code"));
        }

        let mut next = current.clone();
        next.totp = Some(json!({
            "version": ENVELOPE_VERSION,
            "enabled": true,
            "enc": block.get("enc").cloned().unwrap_or(Value::Null),
            "nonce": block.get("nonce").cloned().unwrap_or(Value::Null),
            "tag": block.get("tag").cloned().unwrap_or(Value::Null),
            "recovery": hashed,
        }));
        Ok((next, ()))
    })?;

    Ok(codes)
}

/// `admin.totp.disable`：整块移除（secret 与恢复码一并作废）。返回是否原本启用。
///
/// ## 为什么必须带二次因子
///
/// 拆 2FA 是**削弱**账号安全性的动作，而会话是被劫持时攻击者最先拿到的东西。
/// 若这一动作零验证，攻击者拿到会话就能静默拆掉 2FA，之后 `admin.set` 改密、
/// 改域名、发信全都畅通 —— 而管理员自己再也进不去（恢复码此时也已被一并作废）。
/// 恢复码有「一张一消费」（INV-29），唯独这里曾是敞开的，这个不对称必须补上。
///
/// ## 复用 `verify` 而不是另写一套
///
/// 走的是登录/关 2FA 完全相同的那条路径，于是顺带拿到两件事：
/// 动态码**记重放账**（同一 step 不能既用来登录又用来拆 2FA），恢复码**被消费**。
/// 单独再实现一份比对，等于多一个「忘记记重放」的地方。
///
/// ## 只有已启用时才要求码
///
/// `Pending`（已 `begin` 未确认）与从未启用都**没有第二个因子可交**，用户在
/// 这一步多半正是「验证器丢了 / 输错了码」的状态。若此时也要码，唯一的出路
/// 就是手改 `admin.json` —— 那等于把一个可自助恢复的状态变成死锁。
pub fn disable(paths: &Paths, code: &str, unix_time: u64) -> CoreResult<bool> {
    // 状态判定故意放在锁外、且允许与下面持锁的那次不一致：
    // 两次之间发生的唯一可能是「另一个请求抢先关掉了 2FA」，此时第二次
    // 拿不到码而拒绝，代价只是「重复点一次按钮」，换来的是不为纯读付一次锁。
    if state_at(paths) == TotpState::Enabled {
        let outcome = verify(paths, code, unix_time)?;
        if !outcome.valid {
            // **与「码不对」刻意用同一句话**：区分「这个码曾经有效」与
            // 「这个码从没有效」会把 6 位空间的搜索效率提高一个量级，
            // 而这正是重放保护要挡的探测方式。
            return Err(CoreError::invalid(
                "a valid two-factor code is required to disable two-factor authentication",
            ));
        }
    }

    update_admin_config(&paths.admin_config, |current| {
        let was_enabled = state(current) != TotpState::Disabled;
        let mut next = current.clone();
        next.totp = None;
        Ok((next, was_enabled))
    })
}

/// 消费一张恢复码。**命中即移除，且整个过程在一次锁内完成**（INV-29 / INV-32）。
pub fn consume_recovery(paths: &Paths, code: &str) -> CoreResult<bool> {
    let normalized = normalize_recovery_code(code);
    // 形状不对就没必要进临界区；这不是「拒绝一次尝试」，只是省一次写盘。
    if normalized.len() != RECOVERY_CODE_LEN
        || !normalized.bytes().all(|b| RECOVERY_ALPHABET.contains(&b))
    {
        return Ok(false);
    }
    let target = hash_recovery_code(&normalized);

    update_admin_config(&paths.admin_config, |current| {
        let Some(block) = totp_block(current) else {
            return Ok((current.clone(), false));
        };
        if state(current) != TotpState::Enabled {
            return Ok((current.clone(), false));
        }
        let stored = recovery_hashes(block);
        let mut remaining: Vec<String> = Vec::with_capacity(stored.len());
        let mut consumed = false;
        for hash in stored {
            // 常数时间比较，并且**只移除一张**：命中后再出现同值也只会在
            // 生成端被去重掉，这里保守起见不依赖该前提。
            if !consumed && ct_eq(hash.as_bytes(), target.as_bytes()) {
                consumed = true;
                continue;
            }
            remaining.push(hash);
        }
        if !consumed {
            return Ok((current.clone(), false));
        }

        let mut new_block = block.clone();
        new_block["recovery"] = Value::Array(remaining.into_iter().map(Value::String).collect());
        let mut next = current.clone();
        next.totp = Some(new_block);
        Ok((next, true))
    })
}

/// 消费一个动态码：命中且**尚未被消费过**的 step 才算通过，并就地记账。
///
/// 整个「读块 → 判是否已用 → 记账 → 写回」都在 [`update_admin_config`] 的
/// `locked()` 临界区内（INV-32）：若锁外读、锁外判，两个并发请求会各自看到
/// 「这一步还没用过」并双双放行 —— 那等于没有重放保护。
///
/// 记账的写入是一次真实的 `admin.json` 覆写，因此**只在形状像动态码时才进临界区**：
/// 恢复码与畸形输入根本不可能命中任何一步，让它们也去改一次配置文件毫无意义。
fn consume_totp_step(paths: &Paths, secret: &[u8], code: &str, unix_time: u64) -> CoreResult<bool> {
    // 形状先判：非 6 位数字既不可能是动态码，也不值得一次写盘。
    if !code_shape_ok(code) {
        return Ok(false);
    }
    // secret / 时间都不随配置变，所以「命中哪一步」可以锁外算；真正需要串行化的
    // 是「这一步是否已被消费过」的判定与记账，那部分在锁内。
    let Some(step) = matching_step(secret, code, unix_time) else {
        return Ok(false);
    };

    update_admin_config(&paths.admin_config, |current| {
        let Some(block) = totp_block(current) else {
            return Ok((current.clone(), false));
        };
        if state(current) != TotpState::Enabled {
            return Ok((current.clone(), false));
        }
        if step_already_used(block, step) {
            // **刻意与「码不对」返回同一个结论、同一段文案**：若这里给一个
            // 「该码已被使用」的错误，攻击者就能用它区分「我猜的码曾经有效过」
            // 与「这个码从没有效过」，从而把 6 位空间的搜索效率提高一个量级。
            // 重放保护的效果必须完全落在「这个码现在无效」这一事实上。
            return Ok((current.clone(), false));
        }
        let mut next = current.clone();
        next.totp = Some(block_with_step_used(block, step));
        Ok((next, true))
    })
}

/// 校验一次 2FA 输入：先试动态码（记账后不可重放），再试恢复码（有消费副作用）。
///
/// 顺序是刻意的：动态码是常态路径，不能因为「顺便试一下恢复码」而在每次登录
/// 都去改写 `admin.json`；而恢复码必须留到最后 —— 它是一次性物资，被动态码的
/// 试探误伤（形状恰好不匹配时不会，但语义上必须「动态码优先」）就成了一次
/// 无谓的损失。
pub fn verify(paths: &Paths, code: &str, unix_time: u64) -> CoreResult<VerifyResult> {
    let Some(config) = crate::config::read_admin_config(paths) else {
        return Ok(VerifyResult::rejected());
    };
    let Some(block) = totp_block(&config) else {
        return Ok(VerifyResult::rejected());
    };
    if state(&config) != TotpState::Enabled {
        return Ok(VerifyResult::rejected());
    }

    let key = load_master_key(paths)?;
    let secret = open(&key, &envelope_from_block(block)?)?;
    if consume_totp_step(paths, &secret, code, unix_time)? {
        return Ok(VerifyResult {
            valid: true,
            method: Some(VerifyMethod::Totp),
        });
    }

    if consume_recovery(paths, code)? {
        return Ok(VerifyResult {
            valid: true,
            method: Some(VerifyMethod::Recovery),
        });
    }
    Ok(VerifyResult::rejected())
}

/// 当前 Unix 时间（秒）。
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 测试与排障用：某个时刻该 secret 的正确动态码。
pub fn code_at(secret: &[u8], unix_time: u64) -> String {
    format!(
        "{:0width$}",
        hotp(secret, step_at(unix_time) as u64),
        width = TOTP_DIGITS as usize
    )
}

/// 供测试构造一个信封块。
#[cfg(test)]
fn block_with(envelope: &Envelope, enabled: bool, recovery: Vec<String>) -> Value {
    json!({
        "version": ENVELOPE_VERSION,
        "enabled": enabled,
        "enc": envelope.enc,
        "nonce": envelope.nonce,
        "tag": envelope.tag,
        "recovery": recovery,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    struct Fixture {
        root: PathBuf,
        paths: Paths,
    }

    impl Fixture {
        fn new(tag: &str) -> Self {
            let mut root = std::env::temp_dir();
            root.push(format!(
                "mailstack-totp-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir_all(&root).unwrap();
            let paths = Paths::rooted(&root);
            fs::create_dir_all(&paths.etc).unwrap();
            // 2FA 只能长在已有管理员凭证之上（update_admin_config 要求配置存在）。
            crate::config::admin_set(&paths, "admin", "Tr0ubadour9x").unwrap();
            Self { root, paths }
        }

        fn admin_json(&self) -> Value {
            serde_json::from_str(&fs::read_to_string(&self.paths.admin_config).unwrap()).unwrap()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    // ── base32 / otpauth ──

    #[test]
    fn base32_matches_rfc4648_vectors() {
        // RFC 4648 §10 的测试向量。
        assert_eq!(base32_encode(b""), "");
        assert_eq!(base32_encode(b"f"), "MY");
        assert_eq!(base32_encode(b"fo"), "MZXQ");
        assert_eq!(base32_encode(b"foo"), "MZXW6");
        assert_eq!(base32_encode(b"foob"), "MZXW6YQ");
        assert_eq!(base32_encode(b"fooba"), "MZXW6YTB");
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
    }

    #[test]
    fn otpauth_uri_escapes_group_and_account() {
        let uri = otpauth_uri("MailStack", "admin@example.com", "MZXW6YTBOI");
        assert!(uri.starts_with("otpauth://totp/MailStack:admin%40example.com?"));
        assert!(uri.contains("secret=MZXW6YTBOI"));
        assert!(uri.contains("issuer=MailStack"));
        assert!(uri.contains("algorithm=SHA1"));
        assert!(uri.contains(&format!("digits={TOTP_DIGITS}")));
        assert!(uri.contains(&format!("period={TOTP_PERIOD_SECS}")));
    }

    // ── RFC 4226 Appendix D 测试向量 ──

    #[test]
    fn hotp_matches_the_rfc4226_vectors() {
        let secret = b"12345678901234567890";
        let expected = [
            755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489,
        ];
        for (counter, want) in expected.iter().enumerate() {
            assert_eq!(hotp(secret, counter as u64), *want, "counter={counter}");
        }
    }

    #[test]
    fn verify_accepts_the_current_step_and_rejects_neighbours_outside_the_window() {
        let secret = b"12345678901234567890";
        let now = 1_700_000_000u64; // 与 30 秒格点对齐与否都不影响本断言
        let current = code_at(secret, now);

        assert!(verify_code(secret, &current, now), "当前步必须通过");
        assert!(
            verify_code(secret, &current, now - TOTP_PERIOD_SECS),
            "前一步必须通过（时钟偏移窗口）"
        );
        assert!(
            verify_code(secret, &current, now + TOTP_PERIOD_SECS),
            "后一步必须通过（时钟偏移窗口）"
        );
        assert!(
            !verify_code(secret, &current, now + 2 * TOTP_PERIOD_SECS),
            "窗口之外必须拒绝"
        );
    }

    #[test]
    fn verify_rejects_malformed_codes_without_panicking() {
        let secret = b"12345678901234567890";
        let now = 1_700_000_000u64;
        for bad in [
            "", "12345", "1234567", "abcdef", "12 456", "-12345", "12345a",
        ] {
            assert!(!verify_code(secret, bad, now), "{bad:?} 不应通过");
        }
    }

    // ── INV-5：信封 ──

    #[test]
    fn envelope_round_trips_and_binds_to_the_master_key() {
        let key = [7u8; TOTP_KEY_BYTES];
        let other = [8u8; TOTP_KEY_BYTES];
        let secret = new_secret();

        let envelope = seal(&key, &secret).unwrap();
        assert_eq!(open(&key, &envelope).unwrap(), secret.to_vec());
        // 换一把密钥必须失败（这正是「两件东西分属两个权限域」的意义）。
        assert!(open(&other, &envelope).is_err());
    }

    #[test]
    fn envelope_rejects_tampering_of_any_component() {
        let key = [7u8; TOTP_KEY_BYTES];
        let envelope = seal(&key, &new_secret()).unwrap();

        let mut flipped = envelope.clone();
        let mut raw = BASE64.decode(&flipped.enc).unwrap();
        raw[0] ^= 0x01;
        flipped.enc = BASE64.encode(raw);
        assert!(open(&key, &flipped).is_err(), "密文被改必须失败");

        let mut bad_tag = envelope.clone();
        let mut tag = BASE64.decode(&bad_tag.tag).unwrap();
        tag[0] ^= 0x01;
        bad_tag.tag = BASE64.encode(tag);
        assert!(open(&key, &bad_tag).is_err(), "tag 被改必须失败");

        let mut bad_nonce = envelope.clone();
        bad_nonce.nonce = BASE64.encode([0u8; 12]);
        assert!(open(&key, &bad_nonce).is_err(), "nonce 被改必须失败");

        let mut short_nonce = envelope.clone();
        short_nonce.nonce = BASE64.encode([0u8; 8]);
        assert!(open(&key, &short_nonce).is_err(), "长度不对必须失败");

        let mut garbage = envelope;
        garbage.enc = "not base64!!".to_string();
        assert!(open(&key, &garbage).is_err());
    }

    #[test]
    fn master_key_is_created_once_and_only_readable_by_its_owner() {
        let f = Fixture::new("masterkey");
        assert!(!f.paths.totp_key.exists());

        // 纯读路径不得顺手造密钥。
        assert!(load_master_key(&f.paths).is_err());

        let first = load_or_create_master_key(&f.paths).unwrap();
        let second = load_or_create_master_key(&f.paths).unwrap();
        assert_eq!(first, second, "已有密钥不得被覆盖");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&f.paths.totp_key)
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "主密钥必须 0600");
        }
    }

    // ── 生命周期 ──

    #[test]
    fn begin_writes_a_pending_envelope_and_never_the_plaintext_secret() {
        let f = Fixture::new("begin");
        let enrollment = begin(&f.paths, "admin").unwrap();

        assert_eq!(state_at(&f.paths), TotpState::Pending);
        let raw = fs::read_to_string(&f.paths.admin_config).unwrap();
        assert!(
            !raw.contains(&enrollment.secret),
            "INV-5: admin.json 里绝不能出现明文 secret"
        );
        assert!(raw.contains("\"enc\""));

        let block = f.admin_json()["totp"].clone();
        assert_eq!(block["enabled"], false);
        assert_eq!(block["version"], ENVELOPE_VERSION);

        // 信封能被解开，且解出的就是用户拿到的那串 base32。
        let key = load_master_key(&f.paths).unwrap();
        let secret = open(&key, &envelope_from_block(&block).unwrap()).unwrap();
        assert_eq!(base32_encode(&secret), enrollment.secret);
    }

    #[test]
    fn begin_is_refused_while_already_enabled() {
        let f = Fixture::new("beginagain");
        let enrollment = begin(&f.paths, "admin").unwrap();
        let secret = decode_secret_from_enrollment(&f, &enrollment);
        let now = now_unix();
        enable(&f.paths, &code_at(&secret, now), now).unwrap();

        let err = begin(&f.paths, "admin").unwrap_err();
        assert!(
            err.to_string().contains("already enabled"),
            "已启用时必须拒绝重新 begin：{err}"
        );
    }

    fn decode_secret_from_enrollment(f: &Fixture, enrollment: &Enrollment) -> Vec<u8> {
        let block = f.admin_json()["totp"].clone();
        let key = load_master_key(&f.paths).unwrap();
        let secret = open(&key, &envelope_from_block(&block).unwrap()).unwrap();
        assert_eq!(base32_encode(&secret), enrollment.secret);
        secret
    }

    #[test]
    fn enable_requires_a_correct_code_and_only_then_issues_recovery_codes() {
        let f = Fixture::new("enable");
        let enrollment = begin(&f.paths, "admin").unwrap();
        let secret = decode_secret_from_enrollment(&f, &enrollment);
        let now = now_unix();

        // 打错一次：不得置位，也不得签发恢复码（否则账号会被锁死）。
        let err = enable(&f.paths, "000000", now).unwrap_err();
        assert!(err.to_string().contains("invalid verification code"));
        assert_eq!(state_at(&f.paths), TotpState::Pending);
        assert!(recovery_hashes(&f.admin_json()["totp"]).is_empty());

        let codes = enable(&f.paths, &code_at(&secret, now), now).unwrap();
        assert_eq!(codes.len(), RECOVERY_CODE_COUNT);
        assert_eq!(state_at(&f.paths), TotpState::Enabled);

        let block = f.admin_json()["totp"].clone();
        let stored = recovery_hashes(&block);
        assert_eq!(stored.len(), RECOVERY_CODE_COUNT);
        for code in &codes {
            assert!(
                !stored.contains(code),
                "恢复码必须只以哈希形态落盘，不得明文"
            );
            assert!(stored.contains(&hash_recovery_code(code)));
        }
    }

    #[test]
    fn enable_without_a_pending_enrollment_is_refused() {
        let f = Fixture::new("enablenone");
        let err = enable(&f.paths, "123456", now_unix()).unwrap_err();
        assert!(err.to_string().contains("no pending two-factor enrollment"));
    }

    #[test]
    fn disable_removes_the_block_and_invalidates_recovery_codes() {
        let f = Fixture::new("disable");
        let enrollment = begin(&f.paths, "admin").unwrap();
        let secret = decode_secret_from_enrollment(&f, &enrollment);
        let now = now_unix();
        let codes = enable(&f.paths, &code_at(&secret, now), now).unwrap();

        assert!(disable(&f.paths, &code_at(&secret, now), now).unwrap());
        assert_eq!(state_at(&f.paths), TotpState::Disabled);
        assert!(f.admin_json().get("totp").is_none(), "整块必须被移除");
        assert!(!verify(&f.paths, &codes[0], now).unwrap().valid);
        // 再次 disable 是幂等的（整块已不在，没有第二个因子可要）。
        assert!(!disable(&f.paths, "", now).unwrap());
    }

    // ── 校验路径 ──

    #[test]
    fn verify_rejects_everything_when_two_factor_is_not_enabled() {
        let f = Fixture::new("verifyoff");
        assert!(!verify(&f.paths, "123456", now_unix()).unwrap().valid);

        // pending 状态同样不得放行。
        let enrollment = begin(&f.paths, "admin").unwrap();
        let secret = decode_secret_from_enrollment(&f, &enrollment);
        let now = now_unix();
        assert!(!verify(&f.paths, &code_at(&secret, now), now).unwrap().valid);
    }

    #[test]
    fn verify_accepts_totp_and_recovery_but_reports_which_was_used() {
        let f = Fixture::new("verifyok");
        let enrollment = begin(&f.paths, "admin").unwrap();
        let secret = decode_secret_from_enrollment(&f, &enrollment);
        let now = now_unix();
        let codes = enable(&f.paths, &code_at(&secret, now), now).unwrap();

        let totp = verify(&f.paths, &code_at(&secret, now), now).unwrap();
        assert!(totp.valid);
        assert_eq!(totp.method, Some(VerifyMethod::Totp));
        assert_eq!(
            recovery_hashes(&f.admin_json()["totp"]).len(),
            RECOVERY_CODE_COUNT,
            "走动态码不得消费恢复码"
        );

        // 恢复码不受「同 step 只能用一次」的影响：它是一次性物资，
        // 语义上就是「用过即废」，与动态码的重放账是两套独立规则。
        let recovery = verify(&f.paths, &codes[0], now).unwrap();
        assert!(recovery.valid);
        assert_eq!(recovery.method, Some(VerifyMethod::Recovery));

        let wrong = verify(&f.paths, "000000", now).unwrap();
        assert!(!wrong.valid);
        assert_eq!(wrong.method, None);
    }

    // ── INV-29 / INV-32 ──

    #[test]
    fn a_recovery_code_can_only_be_consumed_once() {
        let f = Fixture::new("once");
        let enrollment = begin(&f.paths, "admin").unwrap();
        let secret = decode_secret_from_enrollment(&f, &enrollment);
        let now = now_unix();
        let codes = enable(&f.paths, &code_at(&secret, now), now).unwrap();

        assert!(consume_recovery(&f.paths, &codes[0]).unwrap());
        assert!(
            !consume_recovery(&f.paths, &codes[0]).unwrap(),
            "INV-29: 同一张恢复码不得被用第二次"
        );
        assert_eq!(
            recovery_hashes(&f.admin_json()["totp"]).len(),
            RECOVERY_CODE_COUNT - 1
        );
    }

    #[test]
    fn recovery_codes_tolerate_human_formatting() {
        let f = Fixture::new("format");
        let enrollment = begin(&f.paths, "admin").unwrap();
        let secret = decode_secret_from_enrollment(&f, &enrollment);
        let now = now_unix();
        let codes = enable(&f.paths, &code_at(&secret, now), now).unwrap();

        let pretty: String = codes[0]
            .chars()
            .enumerate()
            .flat_map(|(i, c)| if i == 0 { vec![c] } else { vec!['-', c] })
            .collect();
        assert_eq!(
            pretty.chars().filter(|c| *c != '-').count(),
            RECOVERY_CODE_LEN
        );
        assert!(
            consume_recovery(&f.paths, &pretty.to_lowercase()).unwrap(),
            "带连字符且小写的输入必须被接受"
        );
    }

    #[test]
    fn malformed_recovery_input_never_touches_the_stored_codes() {
        let f = Fixture::new("malformed");
        let enrollment = begin(&f.paths, "admin").unwrap();
        let secret = decode_secret_from_enrollment(&f, &enrollment);
        let now = now_unix();
        enable(&f.paths, &code_at(&secret, now), now).unwrap();

        for bad in ["", "SHORT", "!!!!!!", "AAAAAAAAAAAAAAAAAAA", "123456"] {
            assert!(!consume_recovery(&f.paths, bad).unwrap());
        }
        assert_eq!(
            recovery_hashes(&f.admin_json()["totp"]).len(),
            RECOVERY_CODE_COUNT
        );
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_recovery_consumption_spends_exactly_one() {
        // INV-32：整个读-改-写必须在同一把锁内。若退化成「各自 read 后 write」，
        // 两个线程会各自看到「码还在」并把同一张码都判为有效（double spend）。
        let f = Fixture::new("race");
        let enrollment = begin(&f.paths, "admin").unwrap();
        let secret = decode_secret_from_enrollment(&f, &enrollment);
        let now = now_unix();
        let codes = enable(&f.paths, &code_at(&secret, now), now).unwrap();

        let successes = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let paths = f.paths.clone();
            let code = codes[0].clone();
            let successes = Arc::clone(&successes);
            handles.push(std::thread::spawn(move || {
                if consume_recovery(&paths, &code).unwrap() {
                    successes.fetch_add(1, Ordering::SeqCst);
                }
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(
            successes.load(Ordering::SeqCst),
            1,
            "并发消费同一张恢复码只能有一次成功"
        );
        assert_eq!(
            recovery_hashes(&f.admin_json()["totp"]).len(),
            RECOVERY_CODE_COUNT - 1,
            "其余恢复码不得被连带消耗"
        );
    }

    // ── 与 admin_set 的协同（INV-30 的另一面） ──

    #[test]
    fn changing_the_password_keeps_two_factor_working() {
        let f = Fixture::new("keep2fa");
        let enrollment = begin(&f.paths, "admin").unwrap();
        let secret = decode_secret_from_enrollment(&f, &enrollment);
        let now = now_unix();
        enable(&f.paths, &code_at(&secret, now), now).unwrap();

        crate::config::admin_set(&f.paths, "admin", "An0therGood1").unwrap();
        assert_eq!(state_at(&f.paths), TotpState::Enabled);
        assert!(verify(&f.paths, &code_at(&secret, now), now).unwrap().valid);
    }

    // ── 重放保护（RFC 6238 §5.2 的 lastUsedStep） ──

    /// 已启用 2FA 并返回 secret 与恢复码。
    fn enabled(tag: &str) -> (Fixture, Vec<u8>, Vec<String>) {
        let f = Fixture::new(tag);
        let enrollment = begin(&f.paths, "admin").unwrap();
        let secret = decode_secret_from_enrollment(&f, &enrollment);
        let now = now_unix();
        let codes = enable(&f.paths, &code_at(&secret, now), now).unwrap();
        (f, secret, codes)
    }

    #[test]
    fn a_totp_code_cannot_be_used_twice_in_the_same_step() {
        // 反例守卫：±1 窗口（约 90 秒）曾让一个 6 位码可以被无限重放。
        let (f, secret, _) = enabled("replay");
        let now = now_unix();
        let code = code_at(&secret, now);

        let first = verify(&f.paths, &code, now).unwrap();
        assert!(first.valid, "第一次必须通过");
        assert_eq!(first.method, Some(VerifyMethod::Totp));

        // 同一个 step 再来一次（哪怕间隔 29 秒，仍落在同一个 30 秒格里）。
        let second = verify(&f.paths, &code, now + 29).unwrap();
        assert!(
            !second.valid,
            "同一个 step 的同一个码不得被接受第二次（重放）"
        );
        assert_eq!(second.method, None, "重放必须与「码不对」给同一个结论");
    }

    #[test]
    fn a_wrong_guess_does_not_burn_the_real_code_of_the_current_step() {
        // 记账必须**只在命中时**发生。若实现改成「每次尝试都记一步」，
        // 攻击者只要先猜错一次就能把管理员自己那一步作废 —— 把重放保护
        // 变成了拒绝服务。这条断言把「记账的触发条件」钉死。
        let (f, secret, _) = enabled("wrongguess");
        let now = now_unix();
        let real = code_at(&secret, now);

        // 一个**不匹配窗口内任何步**的 6 位码：在本地算出来（不在循环里调
        // `verify` —— 那是持锁的文件操作，跑一百万次纯属浪费）。
        let step_now = (now / TOTP_PERIOD_SECS) as i64;
        let window: Vec<String> = (step_now - TOTP_WINDOW_STEPS..=step_now + TOTP_WINDOW_STEPS)
            .map(|s| code_at(&secret, (s * TOTP_PERIOD_SECS as i64) as u64))
            .collect();
        let wrong = (0..=999_999u32)
            .map(|c| format!("{c:06}"))
            .find(|c| !window.contains(c))
            .expect("6 位空间里必然有不匹配窗口的码");
        for _ in 0..5 {
            assert!(!verify(&f.paths, &wrong, now).unwrap().valid);
        }
        assert!(
            used_steps(&f.admin_json()["totp"]).is_empty(),
            "猜错不得写进记账：{:?}",
            f.admin_json()["totp"]["usedSteps"]
        );

        // 真正的码仍然能用 —— 说明上面的失败没有把它顶掉。
        assert!(verify(&f.paths, &real, now).unwrap().valid);
    }

    #[test]
    fn the_ledger_records_steps_so_a_neighbouring_step_is_not_blocked() {
        // 记 step（而不是「记一个码」或「记一个时间戳」）的语义锚：
        // 消费掉当前步之后，**窗口内相邻步**的码必须照常可用。
        let (f, secret, _) = enabled("ledgerstep");
        let now = now_unix() + 10 * TOTP_PERIOD_SECS;
        let base = now - (now % TOTP_PERIOD_SECS);

        assert!(
            verify(&f.paths, &code_at(&secret, base), base)
                .unwrap()
                .valid
        );
        let recorded = used_steps(&f.admin_json()["totp"]);
        assert_eq!(
            recorded,
            vec![(base / TOTP_PERIOD_SECS) as i64],
            "记账里必须是 step 本身，而不是码或时间戳"
        );

        for neighbour in [base - TOTP_PERIOD_SECS, base + TOTP_PERIOD_SECS] {
            assert!(
                verify(&f.paths, &code_at(&secret, neighbour), neighbour)
                    .unwrap()
                    .valid,
                "相邻步不得因为中心步被消费而被连带拒绝"
            );
        }
    }

    #[test]
    fn each_step_in_the_window_may_be_used_once_but_neighbouring_steps_still_work() {
        // 防的是「只记最后一个 step」这种实现：那样 `step-1` 与 `step+1`
        // 就能交替提交，把中间那一步反复绕过。
        let (f, secret, _) = enabled("replaywindow");
        let now = now_unix() + 10 * TOTP_PERIOD_SECS;
        let base = now - (now % TOTP_PERIOD_SECS);

        for (i, step) in [base - TOTP_PERIOD_SECS, base, base + TOTP_PERIOD_SECS]
            .into_iter()
            .enumerate()
        {
            let code = code_at(&secret, step);
            assert!(
                verify(&f.paths, &code, step).unwrap().valid,
                "窗口内第 {i} 个 step 必须各能用一次"
            );
            assert!(
                !verify(&f.paths, &code, step).unwrap().valid,
                "窗口内第 {i} 个 step 用第二次必须被拒"
            );
        }
        assert_eq!(
            used_steps(&f.admin_json()["totp"]).len(),
            3,
            "三个 step 都必须被记账"
        );
    }

    #[test]
    fn a_clock_rollback_does_not_revive_a_previously_used_code() {
        // 反例守卫：把「上次成功校验的 step」当成唯一判据的话，
        // 时钟回拨（`last` 变小）后同一个码会重新可用。记账必须**只增不减**。
        let (f, secret, _) = enabled("rollback");
        let now = now_unix() + 20 * TOTP_PERIOD_SECS;
        let base = now - (now % TOTP_PERIOD_SECS);
        let code = code_at(&secret, base);
        assert!(verify(&f.paths, &code, base).unwrap().valid);

        // 时钟被拨回 5 分钟：同一个码在一个「更早」的时刻再次提交。
        let earlier = base - 10 * TOTP_PERIOD_SECS;
        assert!(!verify(&f.paths, &code, earlier).unwrap().valid);
        // 再拨回 10 分钟仍然不行（哪怕此时 `step` 已经小于记账里的任何值）。
        let much_earlier = base - 20 * TOTP_PERIOD_SECS;
        assert!(!verify(&f.paths, &code, much_earlier).unwrap().valid);
    }

    #[test]
    fn step_zero_is_recorded_like_any_other_step() {
        // 反例守卫：step=0 是**合法值**，不是「没有值」。
        // 若记账用真值判断（`if step > 0`）或 `Option<i64>` 默认值来跳，
        // epoch 后第一分钟的那个码就会被无限重放。
        let f = Fixture::new("stepzero");
        let enrollment = begin(&f.paths, "admin").unwrap();
        let secret = decode_secret_from_enrollment(&f, &enrollment);
        enable(&f.paths, &code_at(&secret, 0), 0).unwrap();

        let code = code_at(&secret, 0);
        assert!(verify(&f.paths, &code, 0).unwrap().valid, "step 0 必须能用");
        assert!(
            used_steps(&f.admin_json()["totp"]).contains(&0),
            "step 0 必须被记账，实际: {:?}",
            f.admin_json()["totp"]["usedSteps"]
        );
        assert!(
            !verify(&f.paths, &code, 0).unwrap().valid,
            "step 0 的码不得被重放"
        );
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_totp_verifications_of_one_step_yield_exactly_one_success() {
        // 与恢复码的 double-spend 同理：如果「判已用」与「记账」不在同一把锁内，
        // 两个并发请求会各自看到「还没用过」并双双放行。
        let (f, secret, _) = enabled("replayrace");
        let now = now_unix();
        let code = code_at(&secret, now);

        let successes = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let paths = f.paths.clone();
            let code = code.clone();
            let successes = Arc::clone(&successes);
            handles.push(std::thread::spawn(move || {
                if verify(&paths, &code, now).unwrap().valid {
                    successes.fetch_add(1, Ordering::SeqCst);
                }
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }
        assert_eq!(
            successes.load(Ordering::SeqCst),
            1,
            "并发用同一个 step 的同一个码只能有一次成功"
        );
    }

    #[test]
    fn used_steps_ledger_is_bounded_and_drops_the_oldest_first() {
        // 记账不得无限增长（admin.json 是每次登录都要覆写的文件）。
        let (f, secret, _) = enabled("usedledger");
        let start = now_unix() + 100 * TOTP_PERIOD_SECS;
        for i in 0..(USED_STEPS_KEPT as u64 * 3) {
            let t = start + i * TOTP_PERIOD_SECS;
            assert!(verify(&f.paths, &code_at(&secret, t), t).unwrap().valid);
        }
        let steps = used_steps(&f.admin_json()["totp"]);
        assert_eq!(steps.len(), USED_STEPS_KEPT, "记账必须有界：{steps:?}");
        assert_eq!(
            steps[0],
            ((start + (USED_STEPS_KEPT as u64 * 3 - 1) * TOTP_PERIOD_SECS) / TOTP_PERIOD_SECS)
                as i64,
            "最新的 step 必须排在最前（淘汰时丢最旧的）"
        );
    }

    #[test]
    fn a_corrupt_used_steps_ledger_does_not_lock_the_admin_out() {
        // 记账是**防御性数据**，不是安全根：它被手改成垃圾时，代价最多是
        // 退化成「无重放保护」，而**绝不能**是把所有 step 都判成已用、
        // 让管理员再也进不来。因此非整数/负数一律当没有记账。
        let (f, secret, _) = enabled("corruptledger");
        let now = now_unix();
        let code = code_at(&secret, now);
        let this_step = (now / TOTP_PERIOD_SECS) as i64;

        let mut value = f.admin_json();
        value["totp"]["usedSteps"] = json!([this_step, -1, "x", 1.5, null]);
        fs::write(
            &f.paths.admin_config,
            serde_json::to_string_pretty(&value).unwrap(),
        )
        .unwrap();

        // `this_step` 是个合法的非负整数 —— 它必须被认作「已消费」，
        // 而旁边的垃圾项不得被当成「全都用过」。
        assert!(!verify(&f.paths, &code, now).unwrap().valid);
        // 但**下一个** step 必须仍能用（说明垃圾项没有被当成「全都用过」）。
        let next = now + TOTP_PERIOD_SECS;
        assert!(
            verify(&f.paths, &code_at(&secret, next), next)
                .unwrap()
                .valid,
            "垃圾记账不得把合法管理员锁在门外"
        );
    }

    // ── 关 2FA 的二次因子 ──

    #[test]
    fn disable_requires_a_valid_second_factor_and_leaves_no_side_effect_on_failure() {
        let (f, secret, _) = enabled("disableauth");
        let now = now_unix();

        for bad in ["", "000000", "nope", "12345", "already-spent"] {
            let err = disable(&f.paths, bad, now).unwrap_err();
            assert!(
                err.to_string()
                    .contains("a valid two-factor code is required"),
                "{bad:?} 实际: {err}"
            );
            assert_eq!(
                state_at(&f.paths),
                TotpState::Enabled,
                "拒绝后 2FA 必须还在"
            );
        }
        assert_eq!(
            recovery_hashes(&f.admin_json()["totp"]).len(),
            RECOVERY_CODE_COUNT,
            "被拒绝的 disable 不得消耗恢复码"
        );

        assert!(disable(&f.paths, &code_at(&secret, now), now).unwrap());
        assert_eq!(state_at(&f.paths), TotpState::Disabled);
    }

    #[test]
    fn disable_accepts_a_recovery_code_because_it_never_had_a_second_factor() {
        // 这一条是「为什么恢复码路径也走 verify」的锚：丢了验证器的人
        // 还能靠恢复码自救，不必手改 admin.json。
        let (f, _, codes) = enabled("disablerecovery");
        let now = now_unix();
        assert!(disable(&f.paths, &codes[3], now).unwrap());
        assert_eq!(state_at(&f.paths), TotpState::Disabled);
    }

    #[test]
    fn disable_does_not_demand_a_code_when_nothing_was_enabled() {
        // 从未启用 / 只 begin 未确认的状态**没有第二个因子可交**；
        // 用户在这个阶段多半正是「验证器丢了」的人。若也要码，
        // 唯一的出路就是手改 admin.json —— 把可自助恢复变成死锁。
        let f = Fixture::new("disablepending");
        // 从未启用。返回 `was_enabled == false`（原先就没有块）。
        assert!(!disable(&f.paths, "", now_unix()).unwrap());
        // 已 begin 未确认：**不要求码**就把 pending 块撤掉。
        begin(&f.paths, "admin").unwrap();
        assert_eq!(state_at(&f.paths), TotpState::Pending);
        assert!(
            disable(&f.paths, "", now_unix()).unwrap(),
            "pending 块原先存在，was_enabled 应为 true"
        );
        assert_eq!(state_at(&f.paths), TotpState::Disabled);
    }

    #[test]
    fn disabling_twice_never_succeeds_twice_and_never_burns_a_second_factor() {
        let (f, _, codes) = enabled("disableidempotent");
        let now = now_unix();
        assert!(disable(&f.paths, &codes[0], now).unwrap());
        // 第二次：整块已不在，因此不再要求码（也不该把码吃掉）。
        assert!(!disable(&f.paths, "", now).unwrap());
    }

    #[test]
    fn unknown_envelope_version_is_refused_instead_of_guessed() {
        let f = Fixture::new("version");
        let enrollment = begin(&f.paths, "admin").unwrap();
        let secret = decode_secret_from_enrollment(&f, &enrollment);
        let now = now_unix();

        let mut value = f.admin_json();
        value["totp"]["version"] = json!(999);
        fs::write(
            &f.paths.admin_config,
            serde_json::to_string_pretty(&value).unwrap(),
        )
        .unwrap();

        // pending 状态下 enable 会走到版本检查。
        let err = enable(&f.paths, &code_at(&secret, now), now).unwrap_err();
        assert!(
            err.to_string()
                .contains("unsupported totp envelope version"),
            "实际: {err}"
        );
    }

    /// `block_with` 仅用于保证测试辅助函数不被误删（信封字段形状的回归锚）。
    #[test]
    fn envelope_block_shape_is_stable() {
        let envelope = Envelope {
            enc: "E".into(),
            nonce: "N".into(),
            tag: "T".into(),
        };
        let block = block_with(&envelope, true, vec!["H".into()]);
        assert_eq!(block["enabled"], true);
        assert_eq!(block["recovery"][0], "H");
        assert_eq!(envelope_from_block(&block).unwrap(), envelope);
    }
}
