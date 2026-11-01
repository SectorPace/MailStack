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

/// 单条缓存记录的存活期上限。
///
/// mail-auth 通过 `valid_until` 传入的 TTL 直接来自对端应答里的 `TTL` 字段，
/// 而那个值可以是任意大（甚至 `0`，含义是「不要缓存」）。不设上界的话，
/// 一条声称 TTL = 31536000 的记录会把结果钉住一年 —— 对一个**安全判定**来说，
/// 「永久记住旧答案」和「永远不接受新答案」是同一种失效。
pub const MAX_TTL: std::time::Duration = std::time::Duration::from_secs(3600);

/// 缓存条目数上界。
///
/// 键来自邮件里的域名（`_dmarc.<from 域>` / `<selector>._domainkey.<域>`）。
/// 没有上界时，攻击者只要在发件域上放一个通配 TXT，就能让每个随机
/// `_domainkey` 查询都留下一条**永不过期**的条目 —— 未认证的内存增长。
pub const MAX_ENTRIES: usize = 4096;

/// 缓存表的值类型：`记录本身 + 过期时刻`。
///
/// `None` 表示不过期（注入条目），`Some(t)` 表示 `t` 之后失效。
/// 抽成别名是为了让 `enforce_capacity` 的签名读得出来 —— 直接写
/// `HashMap<Box<str>, (Txt, Option<Instant>)>` 会触发 `clippy::type_complexity`。
type CacheEntry = (Txt, Option<Instant>);

/// DMARC 原始记录旁表的值类型：原始记录文本。
///
/// 旁表存在的原因：mail-auth 0.13 解析 `Dmarc` 时直接丢弃 `pct=` 标签
/// （RFC 7489 §6.6.4 的抽样参数），解析后的结构永远取不回它；而
/// [`crate::dmarc::evaluate`] 的 pct 抽样只能从原始文本解析（见
/// [`TxtCache::add_dmarc`] 的说明）。
type DmarcRaw = Box<str>;

/// 主表（解析后的 TXT）与 DMARC 原始文本旁表共用一把锁、同步增删。
///
/// 镜像不变量：旁表里的每一条都必须有主表里同键的解析孪生；反之不然
/// （非 DMARC 记录没有旁表条目）。所有对主表的生命周期操作（写入 / 覆盖 /
/// 删除 / 过期清理 / 容量淘汰）都必须同步维护旁表 —— 见各方法内的说明。
#[derive(Default)]
struct Inner {
    entries: HashMap<Box<str>, CacheEntry>,
    dmarc_raw: HashMap<Box<str>, DmarcRaw>,
}

/// 内存 TXT 缓存。键在写入时按 mail-auth 的 `ToFqdn` 规则规范化
/// （小写 + 末尾点），否则查询必然落空。
///
/// ## 为什么每条记录带一个 `Option<Instant>`
///
/// 这个缓存有两种来源，语义**相反**，不能混成一种：
///
/// * [`TxtCache::insert`]（`ResolverCache` 回调，**生产路径**）—— 由 mail-auth
///   在每次 TXT 查询后调用，**包括失败结果**。它带一个 `valid_until`。
///   原实现把 `valid_until` 命名成 `_valid_until` **直接丢弃**，`get` 也不查
///   过期 ⇒ TTL 完全失效：发件方轮换 DKIM 密钥、撤销 selector、把 DMARC 从
///   `p=none` 提到 `p=reject`，本机在**重启前**永远看不到。对端的一次瞬时 DNS
///   错误也会把负结果**永久**钉住。
/// * [`TxtCache::store`] 系列（**注入路径**，本模块存在的理由）—— 显式塞入，
///   用来离线跑完整验签。这里**不能**加 TTL：注入的目的正是绕开 DNS，
///   一旦过期，测试与「同密钥对自签自验」会变成与墙钟赛跑的 flaky。
///
/// 所以用 `None`（不过期）显式表达「注入」，`Some(t)` 表达「有 TTL」。
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

    /// 拿锁。毒化的锁照常取内值：某个持锁线程 panic 过不代表整张表作废，
    /// 与本文件原有的处理方式一致。
    fn lock_inner(&self) -> std::sync::MutexGuard<'_, Inner> {
        match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// 写入一条解析记录；`raw` 是配套的原始文本（仅 DMARC 记录有）。
    ///
    /// 原始文本与解析结构必须在**同一个临界区**内成对写入：拆成两次加锁的话，
    /// 两次之间并发的带 TTL 写入（`insert`）可能插进来清掉/换掉同一键的记录，
    /// 旁表就会留下一条与主表配错对的原始文本。
    fn store(&self, name: &str, value: Txt, raw: Option<&str>) {
        let mut guard = self.lock_inner();
        let key = Self::key(name);
        Self::enforce_capacity(&mut guard, Some(key.as_ref()));
        // `None` = 注入条目，永不过期（理由见类型文档）。
        guard.entries.insert(key.clone(), (value, None));
        match raw {
            Some(raw) => {
                guard.dmarc_raw.insert(key, raw.into());
            }
            // 该键现在存放的不是带原始文本的 DMARC 记录：旁表不得残留旧值。
            None => {
                guard.dmarc_raw.remove(key.as_ref());
            }
        }
    }

    /// 只在键不存在时写入。
    fn store_if_absent(&self, name: &str, value: Txt) {
        let mut guard = self.lock_inner();
        let key = Self::key(name);
        if guard.entries.contains_key(key.as_ref()) {
            return;
        }
        Self::enforce_capacity(&mut guard, Some(key.as_ref()));
        guard.entries.insert(key, (value, None));
    }

    /// 丢掉过期的条目；仍超上界时按「过期时间最近」淘汰 —— 留最久不过期的。
    ///
    /// 注入条目（`None`）没有过期时间，排在最后：只要还有带 TTL 的条目可丢，
    /// 就不会动它们，因此离线注入的稳定性不受容量压力影响。
    ///
    /// `keep` 是调用方即将写入、必须留住的键（`retain` 不看值，得单独传下来）。
    fn enforce_capacity(guard: &mut Inner, keep: Option<&str>) {
        let now = Instant::now();
        guard.entries.retain(|key, (_, until)| {
            if Some(key.as_ref()) == keep {
                return true;
            }
            // 注入条目：保留。
            match until {
                None => true,
                Some(expiry) => *expiry > now,
            }
        });
        // 镜像同步：惰性过期只动了主表，主表里已消失的键旁表不得残留
        // （下面的容量淘汰分支自己成对删除，不经这里）。
        guard
            .dmarc_raw
            .retain(|key, _| guard.entries.contains_key(key.as_ref()));
        // 上界为 0 时留不出空间给 `keep`，此时直接不淘汰（退化但不会 panic）。
        while guard.entries.len() > MAX_ENTRIES.saturating_sub(1) {
            // 淘汰顺序：**先丢最接近过期的带 TTL 条目**。
            //
            // 关键在 `Option` 的序是 `None < Some(_)`，所以朴素的
            // `min_by_key(|(_, (_, until))| *until)` 会把**注入条目**（`None`）
            // 排在最前并优先淘汰它 —— 与意图正好相反。因此分两步：
            // 先只在「带 TTL 且未过期」的条目里挑最接近过期的；实在没有可丢的
            // （表里全是注入条目）才退回到任意淘汰。
            let victim = guard
                .entries
                .iter()
                .filter(|(key, (_, until))| Some(key.as_ref()) != keep && until.is_some())
                .min_by_key(|(_, (_, until))| *until)
                .or_else(|| guard.entries.iter().find(|(key, _)| Some(key.as_ref()) != keep))
                .map(|(k, _)| k.clone());
            match victim {
                Some(victim) => {
                    guard.entries.remove(&victim);
                    // 主表淘汰谁，旁表的孪生就跟着走 —— 旁表不允许比主表活得久。
                    guard.dmarc_raw.remove(victim.as_ref());
                }
                None => break,
            }
        }
    }

    /// 放入一条 DKIM 公钥记录（`v=DKIM1; ... p=...`）。
    pub fn add_domain_key(&self, name: &str, record: &[u8]) -> AuthResult<()> {
        let parsed = DomainKey::parse(record).map_err(|error| AuthError::Dns(error.to_string()))?;
        self.store(name, parsed.into(), None);
        Ok(())
    }

    /// 放入一条 SPF 记录。
    pub fn add_spf(&self, name: &str, record: &[u8]) -> AuthResult<()> {
        let parsed = Spf::parse(record).map_err(|error| AuthError::Dns(error.to_string()))?;
        self.store(name, parsed.into(), None);
        Ok(())
    }

    /// 放入一条 DMARC 记录。
    ///
    /// 与其他 `add_*` 不同，这里还要把**原始文本**一并存进旁表：mail-auth 0.13
    /// 解析 `Dmarc` 时直接丢弃 `pct=` 标签（RFC 7489 §6.6.4 的抽样参数），解析
    /// 后的结构永远取不回它，而 [`crate::dmarc::evaluate`] 的 pct 抽样只能从
    /// 原始文本解析 —— 旁表是它唯一的来源。
    pub fn add_dmarc(&self, name: &str, record: &[u8]) -> AuthResult<()> {
        let parsed = Dmarc::parse(record).map_err(|error| AuthError::Dns(error.to_string()))?;
        // TXT 记录允许多段字符串拼接，原始字节可能不是 UTF-8；pct 解析只关心
        // ASCII 标签，有损转换不影响语义。
        let raw = String::from_utf8_lossy(record).into_owned();
        self.store(name, parsed.into(), Some(&raw));
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

    /// 取某域可用的**原始** DMARC 记录文本（`pct=` 只能从这里取回）。
    ///
    /// 查找顺序与 mail-auth 的 DMARC 树走查一致（RFC 9989 §4.10）：从本域的
    /// `_dmarc.<域>` 起逐级向上，返回找到的第一条 —— 本域记录优先，其次各级
    /// 祖先。键规范化与主表相同（小写 + 末尾点），所以大小写与末尾点写法无关。
    ///
    /// ## `None` 的语义必须读对
    ///
    /// 只有经 [`TxtCache::add_dmarc`] 注入的记录才有原始文本 —— mail-auth 联网
    /// 解析时把原始字节消费在解析器内部，[`ResolverCache::insert`] 回调里只有
    /// 解析后的结构（`pct` 已被丢弃）。因此 **`None` 不等于「无 DMARC 记录」**，
    /// 只等于「拿不到原始文本」：调用方必须把它当「未公布 `pct`」处理
    /// （全量执行已公布策略，fail-closed），绝不能当成「该域无策略」。
    pub fn raw_dmarc_record(&self, domain: &str) -> Option<String> {
        let labels: Vec<&str> = domain
            .trim_matches('.')
            .split('.')
            .filter(|label| !label.is_empty())
            .collect();
        if labels.len() < 2 {
            // 单标签域不可能是 DMARC 的适用对象（树走查也从这里起步）。
            return None;
        }
        let guard = self.lock_inner();
        for start in 0..labels.len() - 1 {
            let key = Self::key(&format!("_dmarc.{}", labels[start..].join(".")));
            if let Some(raw) = guard.dmarc_raw.get(key.as_ref()) {
                // 镜像不变量要求旁表条目必有主表孪生；这里多看一眼主表，
                // 防御未来演化不小心破坏镜像时把 pct 配到不存在的记录上。
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
        // 过期即视为「没查到」—— 交给上层走一次真实 DNS，而不是拿旧答案当现状。
        // 这里**顺带**删除：否则过期条目会一直留在表里。
        let expired = match guard.entries.get(key) {
            None => return None,
            Some((_, Some(expiry))) => *expiry <= Instant::now(),
            Some(_) => false,
        };
        if expired {
            guard.entries.remove(key);
            // 主表过期被清，旁表孪生跟着清（旁表不允许比主表活得久）。
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

    /// 写入一条**带 TTL** 的查询结果（mail-auth 在每次 TXT 查询后调用，
    /// **失败结果也包括在内**）。
    ///
    /// 原实现把 `valid_until` 命名成 `_valid_until` 并丢弃，`get` 也不查过期，
    /// 于是 TTL 完全失效。现在按它兑现，并把上界压到 [`MAX_TTL`]。
    fn insert(&self, key: Box<str>, value: Txt, valid_until: Instant) {
        let mut guard = self.lock_inner();
        Self::enforce_capacity(&mut guard, Some(key.as_ref()));
        let expiry = Some(std::cmp::min(valid_until, Instant::now() + MAX_TTL));
        // 联网解析路径拿到的只有解析后的结构（原始字节留在了 mail-auth 内部）。
        // 同一键写入**任何**新鲜 TTL 条目都使旧的注入原始文本失效 —— 它描述的
        // 可能已不是 DNS 当前的状态（非 DMARC 条目同样会顶掉同名键）。
        // 宁可丢掉（pct 按未公布处理，全量执行已公布策略）也不能拿旧文本配新结构。
        guard.entries.insert(key.clone(), (value, expiry));
        guard.dmarc_raw.remove(key.as_ref());
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

    /// 反例守卫：**过期的查询结果必须被丢弃**。
    ///
    /// `insert` 原先把 `valid_until` 命名成 `_valid_until` 直接丢弃，`get` 也不查
    /// 过期，于是 TTL 完全失效：发件方轮换 DKIM 密钥、撤销 selector、把 DMARC
    /// 从 `p=none` 提到 `p=reject`，本机在**重启前**永远看不到旧答案 —— 而
    /// `sink.rs` 的 reject 分支依赖这个判定。
    ///
    /// 用 `ResolverCache::insert` 而不是 `store`：这才是生产路径
    /// （mail-auth 查完 DNS 后回调），也是唯一会带 TTL 的入口。
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

    /// 反例守卫：未过期的结果**仍**要被服务（TTL 不是「一律不用缓存」）。
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

    /// 反例守卫：TTL 上界生效 —— 对端自称 TTL 极大时也不得永久钉住。
    #[test]
    fn an_absurdly_large_ttl_is_capped() {
        let cache = TxtCache::new();
        // 十年：远超 MAX_TTL（1 小时）。
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

    /// 反例守卫：注入条目**优先于**带 TTL 的条目被保留下来。
    ///
    /// `enforce_capacity` 优先淘汰「最接近过期」的条目，而注入条目的过期时间是
    /// `None`、排在最后。这条钉住那个顺序：如果它排前面，离线注入的 DKIM 记录
    /// 就会在生产收信的压力下随机消失，「同密钥对自签自验」变成与流量相关的
    /// flaky —— 那才是最难查的一类故障。
    #[test]
    fn injected_records_outlive_ttl_bound_ones_under_pressure() {
        let cache = TxtCache::new();
        // 一条注入记录（永不过期）。
        cache
            .add_domain_key("pinned._domainkey.example.com", b"v=DKIM1; k=rsa; p=AAAA")
            .expect("装载公钥记录");

        // 再灌满容量 —— 全部走 `insert`（带 TTL），且 TTL 极短。
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
            guard
                .entries
                .contains_key("pinned._domainkey.example.com."),
            "注入条目被带 TTL 的条目挤掉了：淘汰顺序反了"
        );
    }

    /// pct= 接线的地基：`add_dmarc` 必须把**原始文本**留在旁表里，且键规范化
    /// 与主表一致（`raw_dmarc_record` 按树走查方向从本域向上找）。
    #[test]
    fn raw_dmarc_text_is_retained_and_reachable_up_the_tree() {
        let cache = TxtCache::new();
        cache
            .add_dmarc(
                "_dmarc.example.com",
                b"v=DMARC1; p=reject; pct=10",
            )
            .expect("装载 DMARC 记录");

        assert_eq!(
            cache.raw_dmarc_record("example.com").as_deref(),
            Some("v=DMARC1; p=reject; pct=10"),
            "原始文本必须原样保留：pct= 只能从这里取回"
        );
        // 大小写与末尾点不得影响命中（与主表同一套键规范化）。
        assert!(cache.raw_dmarc_record("EXAMPLE.com.").is_some());
        // 树走查方向：从子域向上也能找到（本域记录优先，其次祖先）。
        assert!(cache.raw_dmarc_record("sub.example.com").is_some());
        // 只有 DMARC 记录有原始文本旁表：放一条别的类型的记录也不产生原始文本。
        cache
            .add_spf("other.test", b"v=spf1 -all")
            .expect("装载 SPF 记录");
        assert!(cache.raw_dmarc_record("other.test").is_none());
        // 单标签域不适用 DMARC，直接无原始文本。
        assert!(cache.raw_dmarc_record("localhost").is_none());
    }

    /// 反例守卫：生产路径的带 TTL 写入（mail-auth 联网解析后的回调）只有
    /// 解析后的结构 —— 同一键残留的注入原始文本必须被清掉，绝不能拿旧文本
    /// 去配新结构（pct 张冠李戴比没有 pct 更糟）。
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

    /// 反例守卫：主表条目被删除 / 被容量淘汰时，旁表孪生必须跟着走。
    #[test]
    fn the_raw_twin_never_outlives_its_parsed_entry() {
        let cache = TxtCache::new();
        cache
            .add_dmarc("_dmarc.example.com", b"v=DMARC1; p=reject")
            .expect("装载 DMARC 记录");

        // 显式删除。
        assert!(cache.remove::<str>("_dmarc.example.com.").is_some());
        assert!(cache.raw_dmarc_record("example.com").is_none());

        // 容量压力：注入条目在其解析孪生幸存时同样幸存（镜像淘汰顺序），
        // 孪生被淘汰时旁表不得残留。
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
