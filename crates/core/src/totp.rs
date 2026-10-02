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

/// 校验 6 位动态码，容忍前后各一步的时钟偏移。
pub fn verify_code(secret: &[u8], code: &str, unix_time: u64) -> bool {
    let code = code.trim();
    if code.len() != TOTP_DIGITS as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
        return false;
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
            return true;
        }
    }
    false
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
pub fn disable(paths: &Paths) -> CoreResult<bool> {
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

/// 校验一次 2FA 输入：先试动态码（无写副作用），再试恢复码（有消费副作用）。
///
/// 顺序是刻意的：动态码是常态路径，不能因为「顺便试一下恢复码」而在每次登录
/// 都去改写 `admin.json`。
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
    if verify_code(&secret, code, unix_time) {
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

        assert!(disable(&f.paths).unwrap());
        assert_eq!(state_at(&f.paths), TotpState::Disabled);
        assert!(f.admin_json().get("totp").is_none(), "整块必须被移除");
        assert!(!verify(&f.paths, &codes[0], now).unwrap().valid);
        // 再次 disable 是幂等的。
        assert!(!disable(&f.paths).unwrap());
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
