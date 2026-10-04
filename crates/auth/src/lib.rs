//! MailStack 认证与签名（规格书 §3.3、§5.8）—— 替代 OpenDKIM。
//!
//! | 模块 | 职责 |
//! |---|---|
//! | [`keys`] | DKIM 密钥：原生生成、落盘、`0640 root:opendkim` 加固、SPKI 形态的 DNS 记录 |
//! | [`dkim`] | DKIM 签名（RFC 6376）与验签自检 |
//! | [`spf`] | SPF 校验（RFC 7208） |
//! | [`dmarc`] | DMARC 对齐评估（RFC 7489）—— SPF + DKIM 的唯一编排点 |
//! | [`arc`] | ARC 链校验**与封印**（RFC 8617） |
//! | [`policy`] | 从 `setup.json` 推导「该不该签、用哪把钥匙」 |
//! | [`cache`] | 可注入的 TXT 缓存 —— 让上述校验能在无网络环境下被真实验证 |
//!
//! ## 依赖边界（§3.4）
//!
//! 全部密码学与协议逻辑由 `mail-auth` 承担，且**必须**按
//! `features = ["ring", "arc", "generate"]` 引入：默认特性会拉入 `aws-lc-rs`
//! （需 cmake/nasm）与 `zip`（默认含 zstd/xz/bzip2，三者都编译 C），直接违反
//! 「禁止 C 依赖链」的硬约束。理由与实测见 `docs/TEST_REPORT.md` §5.2。
//!
//! ## 两处容易静默出错的地方（都有守门测试）
//!
//! 1. `p=` 必须是 **SPKI** 而不是 PKCS#1。mail-auth 的验签侧两种都容忍，
//!    因此这个错误**不会**被本地验签发现 —— 见 [`keys::spki_from_pkcs1`]。
//! 2. `.txt` 是多行带引号的 zone 片段，拼接后必须还原完整公钥。
//!    基线曾因天真正则截断公钥导致 DKIM DNS 记录失效（`network.py:115`）
//!    —— 见 [`keys::zone_txt_fragment`]。
//!
//! ## 尚未接线（诚实披露）
//!
//! * **ARC 封印已实现，但管线里还没有消费者**：`arc::seal_with` 能独立完成
//!   「校验现有链 → 产出 ARC 三件套 + `Authentication-Results` → 逐字保留原报文」，
//!   并有自封自验、二次续封、篡改反例三组测试。但 MailStack 目前**没有转发路径**
//!   （入站邮件要么投本地 LMTP，要么由认证用户提交外发 —— 两种情形下本机都不是
//!   「中转 MTA」，按 RFC 8617 §5 不该盖章）。等别名/转发到外域的功能落地时，
//!   在那一跳调用 `seal_with` 即可；现在接线会盖出语义错误的集合。
//! * **DKIM 过期签名（`x=`）与 `l=`（正文长度）**：当前签名模板用 mail-auth 的
//!   默认值（无过期、不写 `l=`）。`l=` 会削弱签名覆盖范围，本实现刻意不开启。

pub mod arc;
pub mod cache;
pub mod dkim;
pub mod dmarc;
pub mod error;
pub mod keys;
pub mod policy;
pub mod spf;

pub use arc::{seal, seal_with, ArcStatus, ArcVerdict, SealContext, ARC_SIGNED_HEADERS};
// 把解析器类型再导出，让调用方（入站 MTA）不必为了存一个字段而重复声明 mail-auth
// 那组**必须精确一致**的特性开关（见下方 §3.4 说明）。
pub use cache::{system_resolver, TxtCache};
pub use dkim::{
    from_domain, sign, sign_with_default_headers, DkimStatus, DkimVerdict, DEFAULT_SIGNED_HEADERS,
};
pub use dmarc::{DmarcCheck, DmarcPolicy, DmarcStatus};
pub use error::{AuthError, AuthResult};
pub use keys::{
    apply_key_permissions, dkim_key_dir, dkim_txt_value, generate_key_material,
    load_private_key_der, private_key_path, rotate, spki_from_pkcs1, txt_record_path,
    validate_domain, validate_selector, zone_txt_fragment, DkimKeyMaterial, DkimRotation,
    DEFAULT_DKIM_SELECTOR, DKIM_KEY_BITS, DKIM_KEY_GROUP, DKIM_KEY_MODE,
};
pub use mail_auth::MessageAuthenticator;
pub use policy::{signing_policy, DkimSigningPolicy, SigningPolicyOutcome};
pub use spf::{SpfCheck, SpfStatus};
