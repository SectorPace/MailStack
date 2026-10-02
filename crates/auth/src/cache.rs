//! 可注入的 TXT 记录缓存。
//!
//! 存在的理由：mail-auth 的联网解析器没法在测试里喂假记录，而
//! `common::resolver::mock_resolve` 是 `cfg(any(test, feature="test"))` 的、
//! **只返回错误**的桩（它连库外测试都进不去）。但 `txt_lookup` 的顺序是
//! **先查缓存、再走网络**（`common/resolver.rs:119-126`），所以只要把记录塞进
//! 缓存，就能在完全离线的情况下跑完整的验签路径。
//!
//! 这不是「为测试而测试」的脚手架：`verify_with` 系列函数正是靠它实现
//! 「同一密钥对发出的邮件做验签自检」——那条自检在生产上也不该依赖外部 DNS。
//!
//! 生产路径（收信时校验对端）仍然走系统解析器：见 [`system_resolver`]。

use std::borrow::Borrow;
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Mutex;
use std::time::Instant;

use mail_auth::common::parse::TxtRecordParser;
use mail_auth::common::resolver::ToFqdn;
use mail_auth::common::verify::DomainKey;
use mail_auth::dmarc::Dmarc;
use mail_auth::spf::Spf;
use mail_auth::{MessageAuthenticator, ResolverCache, Txt};

use crate::error::{AuthError, AuthResult};

/// 内存 TXT 缓存。键在写入时按 mail-auth 的 `ToFqdn` 规则规范化
/// （小写 + 末尾点），否则查询必然落空。
#[derive(Default)]
pub struct TxtCache {
    entries: Mutex<HashMap<Box<str>, Txt>>,
}

impl TxtCache {
    pub fn new() -> Self {
        Self::default()
    }

    fn key(name: &str) -> Box<str> {
        name.to_fqdn().into_owned().into_boxed_str()
    }

    fn store(&self, name: &str, value: Txt) {
        let mut guard = match self.entries.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.insert(Self::key(name), value);
    }

    /// 只在键不存在时写入。
    fn store_if_absent(&self, name: &str, value: Txt) {
        let mut guard = match self.entries.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.entry(Self::key(name)).or_insert(value);
    }

    /// 放入一条 DKIM 公钥记录（`v=DKIM1; ... p=...`）。
    pub fn add_domain_key(&self, name: &str, record: &[u8]) -> AuthResult<()> {
        let parsed = DomainKey::parse(record).map_err(|error| AuthError::Dns(error.to_string()))?;
        self.store(name, parsed.into());
        Ok(())
    }

    /// 放入一条 SPF 记录。
    pub fn add_spf(&self, name: &str, record: &[u8]) -> AuthResult<()> {
        let parsed = Spf::parse(record).map_err(|error| AuthError::Dns(error.to_string()))?;
        self.store(name, parsed.into());
        Ok(())
    }

    /// 放入一条 DMARC 记录。
    pub fn add_dmarc(&self, name: &str, record: &[u8]) -> AuthResult<()> {
        let parsed = Dmarc::parse(record).map_err(|error| AuthError::Dns(error.to_string()))?;
        self.store(name, parsed.into());
        Ok(())
    }

    /// 让 DMARC 的 **DNS 树走查**在缓存内终止（RFC 9989 §4.10）。
    ///
    /// mail-auth 0.13 起不再只查 `_dmarc.<From 域>` 一条：它会从 From 域**逐级向上**
    /// 查到顶级域，每级都查一次。因此只把 `_dmarc.example.com` 放进缓存是不够的 ——
    /// 走查到 `_dmarc.com` 时缓存未命中，就会去发真实 DNS 查询，整条 DMARC 判定
    /// 随之在离线或网络抖动时退化成 `temperror`。
    ///
    /// 这里把每一级祖先都钉成「本级有 TXT 但不是 DMARC 记录」
    /// （[`TxtCache::pin_absent`]）：树走查会把这种错误当成「本级无记录」继续向上，
    /// 于是走查留在缓存内结束，不发一个包。
    ///
    /// 已存在的键不会被覆盖，所以显式注入的 DMARC 记录始终优先，调用顺序无关。
    pub fn pin_dmarc_walk(&self, from_domain: &str) {
        let labels: Vec<&str> = from_domain
            .trim_matches('.')
            .split('.')
            .filter(|label| !label.is_empty())
            .collect();
        // 从「去掉最左一个标签」开始：From 域那一级由调用方自己注入真实记录。
        for start in 1..labels.len() {
            self.pin_absent(&format!("_dmarc.{}", labels[start..].join(".")));
        }
    }

    /// 把某个名字钉成「此处有 TXT、但不是被查询的那一类记录」，使该名字的 TXT
    /// 查询**在缓存内结束**，绝不发真实 DNS。
    ///
    /// 与 [`TxtCache::pin_dmarc_walk`] 同一个理由：只要有一条查询路径没被钉住，
    /// 在离线或网络抖动时整条判定就会退化成 `temperror` / 超时。
    ///
    /// **SPF 尤其隐蔽**：`SpfParameters::verify` 是「EHLO + MAIL FROM 双身份」语义,
    /// 它**先查 HELO 域**（`spf/verify.rs` 的 `Sender::Full` 分支），只有 HELO
    /// 判定为 `Fail` 才不回看 MAIL FROM。因此只注入 MAIL FROM 域的 SPF 记录是不够的
    /// —— HELO 域（测试里常是 `client.test` 这类不存在的名字）仍会去打真实 DNS。
    ///
    /// 用 `Txt::Error(DnsError::InvalidRecordType)` 而不是「一条别的类型的合法记录」：
    /// 前者经 `unwrap_txt` 原样成为 `Err`，SPF / DMARC 都把它折算成「无记录」；
    /// 后者会变成 `Error::Io("Invalid record type")`，语义完全不同（见
    /// [`TxtCache::pin_dmarc_walk`] 的说明）。已存在的键不会被覆盖。
    pub fn pin_absent(&self, name: &str) {
        self.store_if_absent(
            name,
            Txt::Error(mail_auth::Error::Dns(
                mail_auth::DnsError::InvalidRecordType,
            )),
        );
    }
}

impl ResolverCache<Box<str>, Txt> for TxtCache {
    fn get<Q>(&self, name: &Q) -> Option<Txt>
    where
        Box<str>: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let guard = match self.entries.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.get(name).cloned()
    }

    fn remove<Q>(&self, name: &Q) -> Option<Txt>
    where
        Box<str>: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let mut guard = match self.entries.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.remove(name)
    }

    fn insert(&self, key: Box<str>, value: Txt, _valid_until: Instant) {
        let mut guard = match self.entries.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.insert(key, value);
    }
}

/// 系统 DNS 解析器（生产路径；读取 `/etc/resolv.conf`）。
pub fn system_resolver() -> AuthResult<MessageAuthenticator> {
    MessageAuthenticator::new_system_conf().map_err(|error| AuthError::Dns(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mail_auth::common::resolver::UnwrapTxtRecord;

    #[test]
    fn keys_are_normalised_to_fqdn_on_insert_and_lookup() {
        let cache = TxtCache::new();
        cache
            .add_domain_key(
                "Mailstack._domainkey.Example.COM",
                b"v=DKIM1; k=rsa; p=AAAA",
            )
            .expect("解析公钥记录");

        // 查询侧：mail-auth 会先把名字过一遍 ToFqdn，所以这里必须命中。
        assert!(
            cache
                .get::<str>("mailstack._domainkey.example.com.")
                .is_some(),
            "缓存键必须与 mail-auth 的 FQDN 规范化一致，否则永远查不到"
        );
        assert!(cache.get::<str>("other._domainkey.example.com.").is_none());
    }

    #[test]
    fn malformed_records_are_rejected_instead_of_cached() {
        let cache = TxtCache::new();
        assert!(cache
            .add_domain_key("x._domainkey.example.com", b"not a dkim record")
            .is_err());
        assert!(cache.add_spf("example.com", b"not an spf record").is_err());
        assert!(cache
            .add_dmarc("_dmarc.example.com", b"not a dmarc record")
            .is_err());
    }

    #[test]
    fn pinning_the_dmarc_walk_blocks_every_ancestor_level() {
        let cache = TxtCache::new();
        cache.pin_dmarc_walk("sub.example.com");

        // From 域那一级留给调用方；祖先各级必须都已钉住，走查才不会漏到网络。
        assert!(cache.get::<str>("_dmarc.example.com.").is_some());
        assert!(cache.get::<str>("_dmarc.com.").is_some());
        assert!(cache.get::<str>("_dmarc.sub.example.com.").is_none());

        // 钉住的必须是**树走查认得的那种错误**：它只把
        // `DnsError::InvalidRecordType` / `DnsError::RecordNotFound` 当作「本级无记录」，
        // 换成别的形态（或别的类型但合法的记录）整条判定就会变成 permerror。
        let pinned = cache.get::<str>("_dmarc.com.").unwrap();
        assert!(matches!(
            Dmarc::unwrap_txt(pinned),
            Err(mail_auth::Error::Dns(
                mail_auth::DnsError::InvalidRecordType
            ))
        ));
    }

    #[test]
    fn pinning_a_name_absent_terminates_spf_and_dmarc_lookups_in_cache() {
        // SPF 的「EHLO + MAIL FROM 双身份」会先查 HELO 域，而 HELO 域常常是
        // `client.test` 这类不存在的名字 —— 不钉住它，整条入站认证就会去发真实 DNS。
        let cache = TxtCache::new();
        cache.pin_absent("client.test");

        let pinned = cache.get::<str>("client.test.").expect("钉住的键必须存在");
        // SPF 与 DMARC 都把这条错误折算成「此处无记录」，所以查询在缓存内结束。
        assert!(matches!(
            Spf::unwrap_txt(pinned.clone()),
            Err(mail_auth::Error::Dns(
                mail_auth::DnsError::InvalidRecordType
            ))
        ));
        assert!(matches!(
            Dmarc::unwrap_txt(pinned),
            Err(mail_auth::Error::Dns(
                mail_auth::DnsError::InvalidRecordType
            ))
        ));

        // 与 `pin_dmarc_walk` 同一条纪律：显式注入的记录永远优先。
        cache
            .add_spf("example.com", b"v=spf1 ip4:203.0.113.10 -all")
            .expect("装载 SPF 记录");
        cache.pin_absent("example.com");
        assert!(matches!(
            cache.get::<str>("example.com.").unwrap(),
            Txt::Spf(_)
        ));
    }

    #[test]
    fn pinning_never_overwrites_an_explicit_record() {
        // 不管调用顺序如何，显式注入的 DMARC 记录都必须胜出。
        let cache = TxtCache::new();
        cache.pin_dmarc_walk("example.com");
        cache
            .add_dmarc("_dmarc.com", b"v=DMARC1; p=reject")
            .expect("装载 DMARC 记录");
        assert!(matches!(
            cache.get::<str>("_dmarc.com.").unwrap(),
            Txt::Dmarc(_)
        ));

        let other = TxtCache::new();
        other
            .add_dmarc("_dmarc.com", b"v=DMARC1; p=reject")
            .expect("装载 DMARC 记录");
        other.pin_dmarc_walk("example.com");
        assert!(matches!(
            other.get::<str>("_dmarc.com.").unwrap(),
            Txt::Dmarc(_)
        ));
    }
}
