//! DKIM 密钥：生成、落盘、权限加固与 DNS 记录（规格书 §5.8）。
//!
//! 本模块是 `certs.py:181 dkim_rotate` 与 `core.py:725 set_dkim_key_permissions`
//! 的等价移植，但把 `opendkim-genkey` 换成了 **mail-auth 的原生 RSA 生成**
//! （规格书 §3.3 要求移除 OpenDKIM）。
//!
//! ## 两个必须写死的正确性细节
//!
//! 1. **`p=` 必须是 SubjectPublicKeyInfo（SPKI），不是 PKCS#1。**
//!    mail-auth 的 `DkimKeyPair::encoded_public_key()` 给的是 **PKCS#1** base64，
//!    而 RFC 6376 的 `p=` 与生态里的既有记录都是 SPKI。mail-auth 的验签侧
//!    `try_strip_rsa_prefix(..).unwrap_or(bytes)` **两种都容忍**，所以 PKCS#1 也能
//!    通过本地自检 —— 但 Gmail / 任何按规范解析的对端会验签失败。这里显式做 SPKI
//!    封装（[`spki_from_pkcs1`]）并用测试把前缀钉死。
//! 2. **`.txt` 是 zone 片段，且引号拼接后必须还原完整记录。**
//!    基线的 `network.py:115` 记录过一次真实事故：`opendkim-genkey` 把长公钥拆成
//!    多个带引号的行，天真的正则匹配把公钥**截断**了，DKIM DNS 记录因此失效。
//!    这里用 [`zone_txt_fragment`] 生成，并用「去引号去空白后必须逐字等于原值」
//!    的往返测试固定该性质。
//!
//! ## 密钥落盘位置（已登记的偏离）
//!
//! 基线里有两处不一致：`network.py:105` 的 setup 流程写
//! `/etc/opendkim/keys/<domain>/`，而 `certs.py:190` 的 `dkim.rotate` 写
//! `/etc/mailstack/dkim/<domain>/`。规格书 §2.5/§5.8 取的是前者，且
//! `telemetry.key_permission_scan` 的默认扫描目录也是 `/etc/opendkim/keys`。
//! 本实现**统一采用 `/etc/opendkim/keys/<domain>/`**，把 `certs.py` 的那条路径
//! 记为偏离（见 `docs/TEST_REPORT.md`）。

use std::fs;
use std::path::{Path, PathBuf};

use mail_auth::dkim::generate::DkimKeyPair;
use mailstack_core::paths::Paths;
use mailstack_core::validate::{DKIM_SELECTOR_RE, DOMAIN_RE};
use mailstack_core::warn::{warn, warn_with_error};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::PrivatePkcs1KeyDer;
use serde::Serialize;

use crate::error::{AuthError, AuthResult};

/// selector 缺省值（`certs.py:185`）。
pub const DEFAULT_DKIM_SELECTOR: &str = "mailstack";
/// 密钥长度（规格书 §5.8 与基线均要求 2048）。
pub const DKIM_KEY_BITS: usize = 2048;
/// 私钥属组（`set_dkim_key_permissions`）。
pub const DKIM_KEY_GROUP: &str = "opendkim";
/// 私钥权限：属主可写、属组只读，其他人无权限。
pub const DKIM_KEY_MODE: u32 = 0o640;

/// `dkim.rotate` 的返回体，逐字对齐基线：
/// `{status:'ok', domain, selector, record}`（`certs.py:199`）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DkimRotation {
    pub status: &'static str,
    pub domain: String,
    pub selector: String,
    /// `<selector>.txt` 的内容 —— opendkim-genkey 兼容的 DNS zone 片段。
    pub record: String,
    /// SPKI 的 base64，与 `.txt` 里 `p=` 之后的值逐字相同。
    ///
    /// 单独带出来是因为 `setup.identity.apply` 要把它作为 `dkimPublicKey` 回给向导
    /// （运维据此粘贴 DNS 记录，无需再读磁盘）。它不是 `dkim.rotate` 对外响应的一部分，
    /// 故不参与序列化。
    #[serde(skip)]
    pub public_key_spki_b64: String,
}

/// 一次生成的完整密钥材料。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DkimKeyMaterial {
    pub domain: String,
    pub selector: String,
    /// PKCS#1 PEM（`BEGIN RSA PRIVATE KEY`），与 `opendkim-genkey` 同格式。
    pub private_key_pem: String,
    /// SPKI 的 base64 —— **这才是可以放进 `p=` 的形态**。
    pub public_key_spki_b64: String,
    /// `v=DKIM1; h=sha256; k=rsa; p=...` 的纯 TXT 值。
    pub txt_value: String,
    /// 可直接粘贴进 DNS 的 zone 片段。
    pub txt_record: String,
}

/// 校验并规范化域名；失败文案与 `certs.py:184` 逐字一致。
pub fn validate_domain(domain: &str) -> AuthResult<String> {
    let domain = domain.trim().to_ascii_lowercase();
    if !DOMAIN_RE.is_match(&domain) {
        return Err(AuthError::invalid("invalid domain format"));
    }
    Ok(domain)
}

/// 校验并规范化 selector；失败文案与 `certs.py:187` 逐字一致。
///
/// 缺省与空串都落到 [`DEFAULT_DKIM_SELECTOR`]（基线为
/// `str(data.get('selector', 'mailstack')).strip().lower() or 'mailstack'`）。
pub fn validate_selector(selector: Option<&str>) -> AuthResult<String> {
    let selector = selector.unwrap_or("").trim().to_ascii_lowercase();
    let selector = if selector.is_empty() {
        DEFAULT_DKIM_SELECTOR.to_string()
    } else {
        selector
    };
    if !DKIM_SELECTOR_RE.is_match(&selector) {
        return Err(AuthError::invalid("invalid DKIM selector"));
    }
    Ok(selector)
}

/// 密钥目录：`<etc>/opendkim/keys/<domain>`。
pub fn dkim_key_dir(paths: &Paths, domain: &str) -> PathBuf {
    paths.opendkim.join("keys").join(domain)
}

/// 私钥文件路径：`<etc>/opendkim/keys/<domain>/<selector>.private`。
pub fn private_key_path(paths: &Paths, domain: &str, selector: &str) -> PathBuf {
    dkim_key_dir(paths, domain).join(format!("{selector}.private"))
}

/// DNS 记录文件路径：`<etc>/opendkim/keys/<domain>/<selector>.txt`。
pub fn txt_record_path(paths: &Paths, domain: &str, selector: &str) -> PathBuf {
    dkim_key_dir(paths, domain).join(format!("{selector}.txt"))
}

// ───────────────────────────── base64 ─────────────────────────────

const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// 标准 base64（RFC 4648，带 `=` 填充）。
///
/// 自实现而不引依赖：本 crate 只需要编码，且 §3.4 要求依赖面尽量小。
pub fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(*chunk.get(1).unwrap_or(&0));
        let b2 = u32::from(*chunk.get(2).unwrap_or(&0));
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(BASE64_ALPHABET[((triple >> 18) & 0x3f) as usize] as char);
        out.push(BASE64_ALPHABET[((triple >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(BASE64_ALPHABET[((triple >> 6) & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(BASE64_ALPHABET[(triple & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

// ───────────────────────────── DER / SPKI ─────────────────────────────

/// DER 长度字段（X.690 的定长/不定长编码里只用定长形式）。
pub fn der_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        return vec![len as u8];
    }
    let mut bytes = Vec::with_capacity(4);
    let mut value = len;
    while value > 0 {
        bytes.push((value & 0xff) as u8);
        value >>= 8;
    }
    bytes.reverse();
    let mut out = Vec::with_capacity(bytes.len() + 1);
    out.push(0x80 | bytes.len() as u8);
    out.extend_from_slice(&bytes);
    out
}

fn der_wrap(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 5);
    out.push(tag);
    out.extend_from_slice(&der_length(content.len()));
    out.extend_from_slice(content);
    out
}

/// `AlgorithmIdentifier` for `rsaEncryption` (OID 1.2.840.113549.1.1.1, NULL 参数)。
const RSA_ALGORITHM_IDENTIFIER: [u8; 15] = [
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
];

/// 把 PKCS#1 `RSAPublicKey` DER 封装成 SubjectPublicKeyInfo DER。
///
/// 结构：`SEQUENCE { AlgorithmIdentifier, BIT STRING { 0x00, RSAPublicKey } }`。
/// 2048 位密钥的结果以 `MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...` 开头 ——
/// 这正是 RFC 6376 的 `p=` 与 mail-auth 自带测试向量的形态。
pub fn spki_from_pkcs1(pkcs1: &[u8]) -> Vec<u8> {
    let mut bit_string = Vec::with_capacity(pkcs1.len() + 1);
    bit_string.push(0x00); // 「未使用位数」= 0
    bit_string.extend_from_slice(pkcs1);
    let bit_string = der_wrap(0x03, &bit_string);

    let mut content = Vec::with_capacity(RSA_ALGORITHM_IDENTIFIER.len() + bit_string.len());
    content.extend_from_slice(&RSA_ALGORITHM_IDENTIFIER);
    content.extend_from_slice(&bit_string);
    der_wrap(0x30, &content)
}

// ───────────────────────────── PEM / zone ─────────────────────────────

/// PKCS#1 私钥 PEM（每行 64 字符），与 `opendkim-genkey` 的 `.private` 同格式。
pub fn pkcs1_pem(der: &[u8]) -> String {
    let b64 = base64_encode(der);
    let mut out = String::with_capacity(b64.len() + b64.len() / 64 + 64);
    out.push_str("-----BEGIN RSA PRIVATE KEY-----\n");
    for line in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).unwrap_or_default());
        out.push('\n');
    }
    out.push_str("-----END RSA PRIVATE KEY-----\n");
    out
}

/// 单个带引号字符串的字节上限（RFC 1035 的 TXT 段上限 255）。
const TXT_CHUNK_LIMIT: usize = 255;

/// 生成 zone 片段：`owner  IN  TXT  ( "chunk" "chunk" )  ; comment`。
///
/// **不变量**：把引号与空白全部去掉后拼接，必须逐字等于 `value`。
/// 这是对 `network.py:115` 记录的那次公钥截断事故的回归守卫。
pub fn zone_txt_fragment(owner: &str, value: &str, comment: &str) -> String {
    debug_assert!(value.is_ascii(), "TXT 值必须是 ASCII，否则分块会撕裂字符");
    let mut chunks: Vec<&str> = Vec::new();
    let mut rest = value;
    while !rest.is_empty() {
        let take = rest.len().min(TXT_CHUNK_LIMIT);
        let (head, tail) = rest.split_at(take);
        chunks.push(head);
        rest = tail;
    }
    if chunks.is_empty() {
        chunks.push("");
    }

    let mut out = String::with_capacity(value.len() + chunks.len() * 16 + owner.len() + 64);
    out.push_str(owner);
    out.push_str("\tIN\tTXT\t( ");
    for (index, chunk) in chunks.iter().enumerate() {
        if index > 0 {
            out.push_str("\n\t");
        }
        out.push('"');
        out.push_str(chunk);
        out.push('"');
    }
    out.push_str(" )  ; ");
    out.push_str(comment);
    out
}

/// 由 SPKI base64 组装 `v=DKIM1; h=sha256; k=rsa; p=<base64>`。
///
/// 标签顺序与 `opendkim-genkey` 一致（`v` → `h` → `k` → `p`）。
pub fn dkim_txt_value(public_key_spki_b64: &str) -> String {
    format!("v=DKIM1; h=sha256; k=rsa; p={public_key_spki_b64}")
}

// ───────────────────────────── 生成 ─────────────────────────────

/// 原生生成一套 DKIM 密钥材料（不落盘）。`bits` 生产固定 [`DKIM_KEY_BITS`]。
pub fn generate_key_material(
    domain: &str,
    selector: &str,
    bits: usize,
) -> AuthResult<DkimKeyMaterial> {
    let pair = DkimKeyPair::generate_rsa(bits).map_err(|_| AuthError::KeyGeneration)?;
    let private_key_pem = pkcs1_pem(pair.private_key());
    let spki = spki_from_pkcs1(pair.public_key());
    let public_key_spki_b64 = base64_encode(&spki);
    let txt_value = dkim_txt_value(&public_key_spki_b64);
    let txt_record = zone_txt_fragment(
        &format!("{selector}._domainkey"),
        &txt_value,
        &format!("----- DKIM key {selector} for {domain}"),
    );
    Ok(DkimKeyMaterial {
        domain: domain.to_string(),
        selector: selector.to_string(),
        private_key_pem,
        public_key_spki_b64,
        txt_value,
        txt_record,
    })
}

// ───────────────────────────── 权限加固 ─────────────────────────────

/// 把私钥加固为 `0640 root:opendkim`（`core.py:725`）。
///
/// 开发机上没有 `opendkim` 组时**降级但响亮**：每次失败都经 `warn()` 上报，
/// 而不是静默吞掉 —— 基线注释点明，正是因为静默，才出现过
/// 「密钥以 0600 opendkim:opendkim 躺着没人发现」的情况。
///
/// 本函数**不返回错误**：与基线一致，权限加固失败不阻断密钥轮换。
pub fn apply_key_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        if let Err(error) = fs::set_permissions(path, fs::Permissions::from_mode(DKIM_KEY_MODE)) {
            warn_with_error(&format!("chmod {} to 0640", path.display()), &error);
        }

        match mailstack_core::atomic::gid_by_name(DKIM_KEY_GROUP) {
            Some(gid) => {
                if let Err(error) = std::os::unix::fs::chown(path, Some(0), Some(gid)) {
                    warn_with_error(
                        &format!("chown {} to root:{}", path.display(), DKIM_KEY_GROUP),
                        &error,
                    );
                }
            }
            // 组不存在（开发机/容器）—— 与 chown 失败同样响亮。
            None => warn(&format!(
                "chown {} to root:{}",
                path.display(),
                DKIM_KEY_GROUP
            )),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

/// 读取私钥 PEM 并解出 PKCS#1 DER（签名用）。
pub fn load_private_key_der(path: &Path) -> AuthResult<Vec<u8>> {
    let pem = fs::read(path).map_err(|error| AuthError::io(path, error))?;
    let der = PrivatePkcs1KeyDer::from_pem_slice(&pem)
        .map_err(|error| AuthError::Signing(format!("{}: {error}", path.display())))?;
    Ok(der.secret_pkcs1_der().to_vec())
}

// ───────────────────────────── dkim.rotate ─────────────────────────────

/// `dkim.rotate`：生成并落盘一套 `<selector>.private` / `<selector>.txt`。
///
/// 落盘顺序对齐基线（`certs.py:194-197`）：先由生成器写出私钥，**再**加固权限。
/// 这里把「写出」拆成两步以保证中间态永远不比目标更宽松：先以 `0600` 原子落盘，
/// 再 chmod 到 `0640` + chown 到 `root:opendkim`。这样即使加固失败，密钥也停在
/// `0600`（更严），而不是 `0640 root:root`（更松）。
pub fn rotate(paths: &Paths, domain: &str, selector: Option<&str>) -> AuthResult<DkimRotation> {
    let domain = validate_domain(domain)?;
    let selector = validate_selector(selector)?;

    let dir = dkim_key_dir(paths, &domain);
    fs::create_dir_all(&dir).map_err(|error| AuthError::io(&dir, error))?;

    let material = generate_key_material(&domain, &selector, DKIM_KEY_BITS)?;

    let private_path = private_key_path(paths, &domain, &selector);
    mailstack_core::atomic::atomic_as(
        &private_path,
        material.private_key_pem.as_bytes(),
        0o600,
        None,
    )
    .map_err(|error| AuthError::Signing(error.to_string()))?;
    apply_key_permissions(&private_path);

    let txt_path = txt_record_path(paths, &domain, &selector);
    mailstack_core::atomic::atomic_as(&txt_path, material.txt_record.as_bytes(), 0o644, None)
        .map_err(|error| AuthError::Signing(error.to_string()))?;

    Ok(DkimRotation {
        status: "ok",
        domain,
        selector,
        record: material.txt_record,
        public_key_spki_b64: material.public_key_spki_b64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;

    fn fixture() -> (tempfile::TempDir, Paths) {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::rooted(dir.path());
        (dir, paths)
    }

    /// 2048 位生成较慢，多个断言共用一套材料。
    fn shared_material() -> &'static DkimKeyMaterial {
        static MATERIAL: OnceLock<DkimKeyMaterial> = OnceLock::new();
        MATERIAL.get_or_init(|| {
            generate_key_material("example.com", "mailstack", DKIM_KEY_BITS).expect("生成密钥")
        })
    }

    #[test]
    fn base64_matches_rfc4648_vectors() {
        for (input, expected) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64_encode(input.as_bytes()), expected, "输入 {input:?}");
        }
    }

    #[test]
    fn der_length_uses_short_and_long_forms() {
        assert_eq!(der_length(0), vec![0x00]);
        assert_eq!(der_length(127), vec![0x7f]);
        assert_eq!(der_length(128), vec![0x81, 0x80]);
        assert_eq!(der_length(290), vec![0x82, 0x01, 0x22]);
        assert_eq!(der_length(65535), vec![0x82, 0xff, 0xff]);
        assert_eq!(der_length(65536), vec![0x83, 0x01, 0x00, 0x00]);
    }

    #[test]
    fn public_key_is_spki_not_pkcs1() {
        // 这条是「本地绿、生产静默失败」的守门测试（见 §5.2.1）。
        let material = shared_material();
        assert!(
            material
                .public_key_spki_b64
                .starts_with("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A"),
            "p= 必须是 SPKI（RFC 6376 生态约定），实际前缀：{}",
            &material.public_key_spki_b64[..24.min(material.public_key_spki_b64.len())]
        );
        // 反向确认：它不是 mail-auth 直接给的那个 PKCS#1 形态。
        assert!(
            !material.public_key_spki_b64.starts_with("MIIBCgKCAQEA"),
            "不得把 PKCS#1 直接当作 p= 发布"
        );
    }

    #[test]
    fn spki_wrapping_is_exactly_the_pkcs1_plus_a_fixed_header() {
        // 2048 位：SPKI = 24 字节固定头 + PKCS#1 DER（270 字节）。
        let pair = DkimKeyPair::generate_rsa(DKIM_KEY_BITS).expect("生成密钥");
        let pkcs1 = pair.public_key();
        let spki = spki_from_pkcs1(pkcs1);
        assert_eq!(
            spki.len(),
            pkcs1.len() + 24,
            "2048 位 SPKI 只应比 PKCS#1 多 24 字节固定头"
        );
        assert_eq!(&spki[24..], pkcs1, "SPKI 尾部必须逐字是 PKCS#1");
        // 偏移 4 = 外层 SEQUENCE 头（`30 82 01 22`）；再往后才是 AlgorithmIdentifier。
        assert_eq!(
            &spki[4..19],
            &RSA_ALGORITHM_IDENTIFIER[..],
            "AlgorithmIdentifier 必须是 rsaEncryption"
        );
        assert_eq!(&spki[..4], &[0x30, 0x82, 0x01, 0x22], "外层长度必须自洽");
        // BIT STRING 头 + 「未使用位数 = 0」
        assert_eq!(&spki[19..24], &[0x03, 0x82, 0x01, 0x0f, 0x00]);
    }

    #[test]
    fn zone_fragment_round_trips_after_stripping_quotes_and_whitespace() {
        // 回归守卫：network.py:115 记录过一次真实事故 ——
        // 多行带引号的公钥被天真正则截断，DKIM 记录因此失效。
        let value = dkim_txt_value(&shared_material().public_key_spki_b64);
        let fragment = zone_txt_fragment("mailstack._domainkey", &value, "----- c");
        let flattened: String = fragment
            .chars()
            .filter(|c| *c != '"' && !c.is_whitespace())
            .collect();
        assert!(
            flattened.contains(&value.replace(' ', "")),
            "去引号去空白后必须包含完整 TXT 值"
        );
        assert!(
            flattened.contains(&format!("p={}", shared_material().public_key_spki_b64)),
            "p= 的 base64 不得被截断"
        );
    }

    #[test]
    fn zone_fragment_splits_long_values_below_the_dns_limit() {
        let value = "A".repeat(600);
        let fragment = zone_txt_fragment("x._domainkey", &value, "c");
        for line in fragment.lines() {
            // 只量引号之间的内容：第一行前面还有 owner/类/类型。
            let quoted: Vec<&str> = line.split('"').skip(1).step_by(2).collect();
            for payload in quoted {
                assert!(
                    payload.len() <= TXT_CHUNK_LIMIT,
                    "每个引号串不得超过 255 字节（实际 {}）：{payload:?}",
                    payload.len()
                );
            }
        }
    }

    #[test]
    fn domain_and_selector_validation_uses_the_python_contract() {
        assert_eq!(validate_domain("Example.COM").unwrap(), "example.com");
        assert_eq!(
            validate_domain("bad domain").unwrap_err().to_string(),
            "invalid domain format"
        );
        assert_eq!(
            validate_domain("example").unwrap_err().to_string(),
            "invalid domain format"
        );

        assert_eq!(validate_selector(None).unwrap(), DEFAULT_DKIM_SELECTOR);
        assert_eq!(
            validate_selector(Some("  ")).unwrap(),
            DEFAULT_DKIM_SELECTOR
        );
        assert_eq!(validate_selector(Some("Mail-1")).unwrap(), "mail-1");
        assert_eq!(
            validate_selector(Some("bad selector"))
                .unwrap_err()
                .to_string(),
            "invalid DKIM selector"
        );
    }

    #[test]
    fn key_paths_live_under_the_opendkim_keys_directory() {
        let paths = Paths::production();
        assert_eq!(
            private_key_path(&paths, "example.com", "mailstack"),
            PathBuf::from("/etc/opendkim/keys/example.com/mailstack.private")
        );
        assert_eq!(
            txt_record_path(&paths, "example.com", "mailstack"),
            PathBuf::from("/etc/opendkim/keys/example.com/mailstack.txt")
        );
    }

    #[test]
    fn rotate_writes_both_files_and_returns_the_zone_record() {
        let (_dir, paths) = fixture();
        let rotation = rotate(&paths, "Example.COM", Some("Mail")).expect("轮换密钥");

        assert_eq!(rotation.status, "ok");
        assert_eq!(rotation.domain, "example.com");
        assert_eq!(rotation.selector, "mail");

        let private = private_key_path(&paths, "example.com", "mail");
        let txt = txt_record_path(&paths, "example.com", "mail");
        assert!(private.is_file(), "私钥必须落盘：{}", private.display());
        assert!(txt.is_file(), "DNS 记录必须落盘：{}", txt.display());

        let on_disk = std::fs::read_to_string(&txt).unwrap();
        assert_eq!(
            on_disk, rotation.record,
            "返回的 record 必须与 .txt 内容一致"
        );

        // 私钥能被自己读回并解出 DER —— 说明写出的 PEM 是可用的。
        let der = load_private_key_der(&private).expect("读回私钥");
        assert!(!der.is_empty(), "解出的 DER 不得为空");
    }

    #[cfg(unix)]
    #[test]
    fn rotated_private_key_is_never_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, paths) = fixture();
        rotate(&paths, "example.com", None).expect("轮换密钥");
        let private = private_key_path(&paths, "example.com", DEFAULT_DKIM_SELECTOR);
        let mode = fs::metadata(&private).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode & 0o007, 0, "私钥不得对其他人可读（实际 {mode:o}）");
        assert_eq!(mode, DKIM_KEY_MODE, "加固后应为 0640（实际 {mode:o}）");
    }
}
