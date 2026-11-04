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

pub const MAX_TTL: std::time::Duration = std::time::Duration::from_secs(3600);

pub const MAX_ENTRIES: usize = 4096;

type CacheEntry = (Txt, Option<Instant>);

type DmarcRaw = Box<str>;

#[derive(Default)]
struct Inner {
    entries: HashMap<Box<str>, CacheEntry>,
    dmarc_raw: HashMap<Box<str>, DmarcRaw>,
}

#[derive(Default)]
pub struct TxtCache {
    inner: Mutex<Inner>,
}

impl TxtCache {
    pub fn new() -> Self {
        Self::default()
    }

    fn key(name: &str) -> Box<str> {
        name.to_fqdn().into_owned().into_boxed_str()
    }

    fn lock_inner(&self) -> std::sync::MutexGuard<'_, Inner> {
        match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn store(&self, name: &str, value: Txt, raw: Option<&str>) {
        let mut guard = self.lock_inner();
        let key = Self::key(name);
        Self::enforce_capacity(&mut guard, Some(key.as_ref()));

        guard.entries.insert(key.clone(), (value, None));
        match raw {
            Some(raw) => {
                guard.dmarc_raw.insert(key, raw.into());
            }

            None => {
                guard.dmarc_raw.remove(key.as_ref());
            }
        }
    }

    fn store_if_absent(&self, name: &str, value: Txt) {
        let mut guard = self.lock_inner();
        let key = Self::key(name);
        if guard.entries.contains_key(key.as_ref()) {
            return;
        }
        Self::enforce_capacity(&mut guard, Some(key.as_ref()));
        guard.entries.insert(key, (value, None));
    }

    fn enforce_capacity(guard: &mut Inner, keep: Option<&str>) {
        let now = Instant::now();
        guard.entries.retain(|key, (_, until)| {
            if Some(key.as_ref()) == keep {
                return true;
            }

            match until {
                None => true,
                Some(expiry) => *expiry > now,
            }
        });

        guard
            .dmarc_raw
            .retain(|key, _| guard.entries.contains_key(key.as_ref()));

        while guard.entries.len() > MAX_ENTRIES.saturating_sub(1) {
            let victim = guard
                .entries
                .iter()
                .filter(|(key, (_, until))| Some(key.as_ref()) != keep && until.is_some())
                .min_by_key(|(_, (_, until))| *until)
                .or_else(|| {
                    guard
                        .entries
                        .iter()
                        .find(|(key, _)| Some(key.as_ref()) != keep)
                })
                .map(|(k, _)| k.clone());
            match victim {
                Some(victim) => {
                    guard.entries.remove(&victim);

                    guard.dmarc_raw.remove(victim.as_ref());
                }
                None => break,
            }
        }
    }

    pub fn add_domain_key(&self, name: &str, record: &[u8]) -> AuthResult<()> {
        let parsed = DomainKey::parse(record).map_err(|error| AuthError::Dns(error.to_string()))?;
        self.store(name, parsed.into(), None);
        Ok(())
    }

    pub fn add_spf(&self, name: &str, record: &[u8]) -> AuthResult<()> {
        let parsed = Spf::parse(record).map_err(|error| AuthError::Dns(error.to_string()))?;
        self.store(name, parsed.into(), None);
        Ok(())
    }

    pub fn add_dmarc(&self, name: &str, record: &[u8]) -> AuthResult<()> {
        let parsed = Dmarc::parse(record).map_err(|error| AuthError::Dns(error.to_string()))?;

        let raw = String::from_utf8_lossy(record).into_owned();
        self.store(name, parsed.into(), Some(&raw));
        Ok(())
    }

    pub fn pin_dmarc_walk(&self, from_domain: &str) {
        let labels: Vec<&str> = from_domain
            .trim_matches('.')
            .split('.')
            .filter(|label| !label.is_empty())
            .collect();

        for start in 1..labels.len() {
            self.pin_absent(&format!("_dmarc.{}", labels[start..].join(".")));
        }
    }

    pub fn pin_absent(&self, name: &str) {
        self.store_if_absent(
            name,
            Txt::Error(mail_auth::Error::Dns(
                mail_auth::DnsError::InvalidRecordType,
            )),
        );
    }

    pub fn raw_dmarc_record(&self, domain: &str) -> Option<String> {
        let labels: Vec<&str> = domain
            .trim_matches('.')
            .split('.')
            .filter(|label| !label.is_empty())
            .collect();
        if labels.len() < 2 {
            return None;
        }
        let guard = self.lock_inner();
        for start in 0..labels.len() - 1 {
            let key = Self::key(&format!("_dmarc.{}", labels[start..].join(".")));
            if let Some(raw) = guard.dmarc_raw.get(key.as_ref()) {
                if guard.entries.contains_key(key.as_ref()) {
                    return Some(raw.to_string());
                }
            }
        }
        None
    }
}

impl ResolverCache<Box<str>, Txt> for TxtCache {
    fn get<Q>(&self, name: &Q) -> Option<Txt>
    where
        Box<str>: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let mut guard = self.lock_inner();
        let key = name.borrow();

        let expired = match guard.entries.get(key) {
            None => return None,
            Some((_, Some(expiry))) => *expiry <= Instant::now(),
            Some(_) => false,
        };
        if expired {
            guard.entries.remove(key);

            guard.dmarc_raw.remove(key);
            return None;
        }
        guard.entries.get(key).map(|(value, _)| value.clone())
    }

    fn remove<Q>(&self, name: &Q) -> Option<Txt>
    where
        Box<str>: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let mut guard = self.lock_inner();
        let removed = guard.entries.remove(name.borrow()).map(|(value, _)| value);
        if removed.is_some() {
            guard.dmarc_raw.remove(name.borrow());
        }
        removed
    }

    fn insert(&self, key: Box<str>, value: Txt, valid_until: Instant) {
        let mut guard = self.lock_inner();
        Self::enforce_capacity(&mut guard, Some(key.as_ref()));
        let expiry = Some(std::cmp::min(valid_until, Instant::now() + MAX_TTL));

        guard.entries.insert(key.clone(), (value, expiry));
        guard.dmarc_raw.remove(key.as_ref());
    }
}

pub fn system_resolver() -> AuthResult<MessageAuthenticator> {
    MessageAuthenticator::new_system_conf().map_err(|error| AuthError::Dns(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mail_auth::common::resolver::UnwrapTxtRecord;
    use std::time::Duration;

    #[test]
    fn keys_are_normalised_to_fqdn_on_insert_and_lookup() {
        let cache = TxtCache::new();
        cache
            .add_domain_key(
                "Mailstack._domainkey.Example.COM",
                b"v=DKIM1; k=rsa; p=AAAA",
            )
            .expect("解析公钥记录");

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

        assert!(cache.get::<str>("_dmarc.example.com.").is_some());
        assert!(cache.get::<str>("_dmarc.com.").is_some());
        assert!(cache.get::<str>("_dmarc.sub.example.com.").is_none());

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
        let cache = TxtCache::new();
        cache.pin_absent("client.test");

        let pinned = cache.get::<str>("client.test.").expect("钉住的键必须存在");

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

    #[test]
    fn an_expired_lookup_result_is_no_longer_served() {
        let cache = TxtCache::new();
        cache.insert(
            "mailstack._domainkey.example.com.".into(),
            Txt::Error(mail_auth::Error::Dns(
                mail_auth::DnsError::InvalidRecordType,
            )),
            Instant::now() - Duration::from_secs(1),
        );
        assert!(
            cache
                .get::<str>("mailstack._domainkey.example.com.")
                .is_none(),
            "已过期的结果不得继续被服务：安全判定会一直停在旧答案上"
        );
    }

    #[test]
    fn a_fresh_lookup_result_is_still_served() {
        let cache = TxtCache::new();
        cache.insert(
            "mailstack._domainkey.example.com.".into(),
            Txt::Error(mail_auth::Error::Dns(
                mail_auth::DnsError::InvalidRecordType,
            )),
            Instant::now() + Duration::from_secs(600),
        );
        assert!(cache
            .get::<str>("mailstack._domainkey.example.com.")
            .is_some());
    }

    #[test]
    fn an_absurdly_large_ttl_is_capped() {
        let cache = TxtCache::new();

        cache.insert(
            "mailstack._domainkey.example.com.".into(),
            Txt::Error(mail_auth::Error::Dns(
                mail_auth::DnsError::InvalidRecordType,
            )),
            Instant::now() + Duration::from_secs(315_360_000),
        );
        let guard = cache.inner.lock().unwrap();
        let (_, until) = guard
            .entries
            .get("mailstack._domainkey.example.com.")
            .expect("条目应存在");
        let expiry = until.expect("走 insert 的条目必须带过期时间");
        let remaining = expiry.saturating_duration_since(Instant::now());
        assert!(
            remaining <= MAX_TTL + Duration::from_secs(1),
            "TTL 应被压到 {MAX_TTL:?} 附近，实际还剩 {remaining:?}"
        );
    }

    #[test]
    fn injected_records_outlive_ttl_bound_ones_under_pressure() {
        let cache = TxtCache::new();

        cache
            .add_domain_key("pinned._domainkey.example.com", b"v=DKIM1; k=rsa; p=AAAA")
            .expect("装载公钥记录");

        for i in 0..(MAX_ENTRIES + 64) {
            cache.insert(
                format!("sel{i}._domainkey.example.com.").into(),
                Txt::Error(mail_auth::Error::Dns(
                    mail_auth::DnsError::InvalidRecordType,
                )),
                Instant::now() + Duration::from_secs(1),
            );
        }

        let guard = cache.inner.lock().unwrap();
        assert!(
            guard.entries.len() <= MAX_ENTRIES,
            "缓存必须有界（实际 {} 条）",
            guard.entries.len()
        );
        assert!(
            guard.entries.contains_key("pinned._domainkey.example.com."),
            "注入条目被带 TTL 的条目挤掉了：淘汰顺序反了"
        );
    }

    #[test]
    fn raw_dmarc_text_is_retained_and_reachable_up_the_tree() {
        let cache = TxtCache::new();
        cache
            .add_dmarc("_dmarc.example.com", b"v=DMARC1; p=reject; pct=10")
            .expect("装载 DMARC 记录");

        assert_eq!(
            cache.raw_dmarc_record("example.com").as_deref(),
            Some("v=DMARC1; p=reject; pct=10"),
            "原始文本必须原样保留：pct= 只能从这里取回"
        );

        assert!(cache.raw_dmarc_record("EXAMPLE.com.").is_some());

        assert!(cache.raw_dmarc_record("sub.example.com").is_some());

        cache
            .add_spf("other.test", b"v=spf1 -all")
            .expect("装载 SPF 记录");
        assert!(cache.raw_dmarc_record("other.test").is_none());

        assert!(cache.raw_dmarc_record("localhost").is_none());
    }

    #[test]
    fn a_fresh_ttl_insert_supersedes_the_injected_raw_text() {
        let cache = TxtCache::new();
        cache
            .add_dmarc("_dmarc.example.com", b"v=DMARC1; p=reject; pct=10")
            .expect("装载 DMARC 记录");

        let fresh: Txt = Dmarc::parse(b"v=DMARC1; p=quarantine")
            .expect("解析新记录")
            .into();
        cache.insert(
            "_dmarc.example.com.".into(),
            fresh,
            Instant::now() + Duration::from_secs(60),
        );

        assert!(
            cache.raw_dmarc_record("example.com").is_none(),
            "新结构配旧原始文本是 pct 张冠李戴：宁可按未公布 pct 处理（fail-closed）"
        );
    }

    #[test]
    fn the_raw_twin_never_outlives_its_parsed_entry() {
        let cache = TxtCache::new();
        cache
            .add_dmarc("_dmarc.example.com", b"v=DMARC1; p=reject")
            .expect("装载 DMARC 记录");

        assert!(cache.remove::<str>("_dmarc.example.com.").is_some());
        assert!(cache.raw_dmarc_record("example.com").is_none());

        let cache = TxtCache::new();
        cache
            .add_dmarc("_dmarc.pinned.example.com", b"v=DMARC1; p=reject; pct=10")
            .expect("装载 DMARC 记录");
        for i in 0..(MAX_ENTRIES + 64) {
            cache.insert(
                format!("sel{i}._domainkey.example.com.").into(),
                Txt::Error(mail_auth::Error::Dns(
                    mail_auth::DnsError::InvalidRecordType,
                )),
                Instant::now() + Duration::from_secs(1),
            );
        }
        let parsed_twin_survived = {
            let guard = cache.inner.lock().unwrap();
            guard.entries.contains_key("_dmarc.pinned.example.com.")
        };
        if parsed_twin_survived {
            assert!(
                cache.raw_dmarc_record("pinned.example.com").is_some(),
                "解析孪生幸存时旁表必须同样幸存"
            );
        } else {
            assert!(
                cache.raw_dmarc_record("pinned.example.com").is_none(),
                "解析孪生被淘汰后旁表不得残留"
            );
        }
    }
}
