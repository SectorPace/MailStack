use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use mailstack_smtp::{select_outbound_route, OutboundRoute, RelayEndpoint, RelayPolicy};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::backoff::BackoffPolicy;
use crate::delivery::{DeliveryFailure, DeliveryTarget, FailureClass, Transport};
use crate::dsn::{build_dsn, dsn_envelope_from, dsn_recipient, DsnRequest};
use crate::entry::{EntryKind, QueueEntry};
use crate::error::QueueResult;
use crate::signing::{MessageSigner, SigningTransport};
use crate::store::{OutboundHealthState, QueueStore};

#[derive(Debug, Clone)]
pub struct QueueConfig {
    pub relay_concurrency: u32,
    pub backoff: BackoffPolicy,

    pub reporting_mta: String,

    pub managed_domains: Vec<String>,

    pub blocked_threshold: u32,
}

impl Default for QueueConfig {
    fn default() -> Self {
        Self {
            relay_concurrency: 20,
            backoff: BackoffPolicy::default(),
            reporting_mta: "localhost".to_string(),

            managed_domains: Vec::new(),
            blocked_threshold: DEFAULT_BLOCKED_THRESHOLD,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundHealth {
    pub consecutive_failures: u32,

    pub blocked: bool,

    pub needs_relay: bool,

    pub message: String,
}

pub const DEFAULT_BLOCKED_THRESHOLD: u32 = 10;

pub fn outbound_health_from(
    failures: u32,
    blocked_threshold: u32,
    relay_host: Option<&str>,
) -> OutboundHealth {
    let threshold = blocked_threshold.max(1);
    let blocked = failures >= threshold;
    let needs_relay = blocked && relay_host.is_none();

    let message = if !blocked {
        "outbound delivery is healthy".to_string()
    } else if needs_relay {
        format!(
            "Outbound port 25 is blocked ({failures} consecutive delivery failures); \
             configure a relay (smarthost)"
        )
    } else {
        format!(
            "Relay {} is failing repeatedly ({failures} consecutive delivery failures); \
             verify credentials and TLS mode",
            relay_host.unwrap_or_default()
        )
    };

    OutboundHealth {
        consecutive_failures: failures,
        blocked,
        needs_relay,
        message,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueRunReport {
    pub considered: usize,

    pub delivered: usize,

    pub deferred: usize,

    pub bounced: usize,

    pub discarded: usize,

    pub fast_failed: bool,

    pub backlog: usize,

    pub failed: usize,

    pub relay_concurrency: u32,
    pub outbound_health: OutboundHealth,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueMetrics {
    pub backlog: usize,

    pub relay_concurrency: u32,
    pub outbound_health: OutboundHealth,
}

#[derive(Debug, Default, Clone, Copy)]
struct EntryOutcome {
    delivered: usize,
    bounced: usize,
    discarded: usize,
    deferred: usize,
    fast_failed: bool,
}

#[derive(Debug)]
struct PendingBounce {
    failed: Vec<String>,

    diagnostic: String,

    code: Option<u16>,
}

impl EntryOutcome {
    fn merge(&mut self, other: EntryOutcome) {
        self.delivered += other.delivered;
        self.bounced += other.bounced;
        self.discarded += other.discarded;
        self.deferred += other.deferred;
        self.fast_failed |= other.fast_failed;
    }
}

pub struct QueueRunner {
    store: QueueStore,
    local: Arc<dyn Transport>,
    remote: Arc<dyn Transport>,
    config: QueueConfig,
    relay: Option<RelayEndpoint>,
    health: Mutex<OutboundHealthState>,

    half_open_used: AtomicBool,

    round_in_flight: AtomicBool,
    semaphore: Semaphore,
}

impl QueueRunner {
    pub fn new(
        store: QueueStore,
        local: Arc<dyn Transport>,
        remote: Arc<dyn Transport>,
        config: QueueConfig,
        relay: Option<RelayEndpoint>,
        signer: Arc<dyn MessageSigner>,
    ) -> Self {
        let health = store.load_health().unwrap_or_default();
        let permits = config.relay_concurrency.max(1) as usize;
        let remote: Arc<dyn Transport> = Arc::new(SigningTransport::new(remote, signer));
        Self {
            store,
            local,
            remote,
            config,
            relay,
            health: Mutex::new(health),
            half_open_used: AtomicBool::new(false),
            round_in_flight: AtomicBool::new(false),
            semaphore: Semaphore::new(permits),
        }
    }

    pub fn store(&self) -> &QueueStore {
        &self.store
    }

    pub fn outbound_route(&self) -> OutboundRoute {
        select_outbound_route(self.relay.as_ref())
    }

    pub fn outbound_health(&self) -> OutboundHealth {
        outbound_health_from(
            self.health_snapshot().consecutive_failures,
            self.config.blocked_threshold,
            self.relay.as_ref().map(|r| r.relayhost()).as_deref(),
        )
    }

    pub async fn run_once(self: &Arc<Self>, now_unix: i64) -> QueueResult<QueueRunReport> {
        if self
            .round_in_flight
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(crate::error::QueueError::busy(
                "overlapping run_once would re-deliver the same entries",
            ));
        }

        let _round_guard = RoundGuard(&self.round_in_flight);

        self.half_open_used.store(false, Ordering::SeqCst);

        let store = self.store.clone();
        let (entries, claimed) = tokio::task::spawn_blocking(
            move || -> QueueResult<(Vec<QueueEntry>, std::collections::HashSet<String>)> {
                store.prune_claims(now_unix)?;
                let claimed = store.claimed_ids(now_unix)?;
                let entries = store.load_due(now_unix)?;
                Ok((entries, claimed))
            },
        )
        .await
        .map_err(|e| crate::error::QueueError::Storage(format!("queue load task failed: {e}")))??;
        let due: Vec<QueueEntry> = entries
            .into_iter()
            .filter(|entry| entry.is_due(now_unix) && !claimed.contains(&entry.id))
            .collect();

        let policy = RelayPolicy::new(self.config.managed_domains.iter().cloned());

        let mut totals = EntryOutcome::default();
        let mut considered = 0usize;
        let mut failed = 0usize;
        let mut join_error: Option<crate::error::QueueError> = None;
        let mut tasks = JoinSet::new();
        for entry in due.iter().cloned() {
            match self.store.try_claim(&entry.id, now_unix) {
                Ok(true) => {
                    let runner = Arc::clone(self);
                    let policy = policy.clone();
                    tasks.spawn(async move { runner.process(entry, now_unix, &policy).await });
                }
                Ok(false) => {}
                Err(error) => {
                    mailstack_core::warn::warn_with_detail(
                        "queue claim",
                        &format!("entry {}: {error}", entry.id),
                    );
                    failed += 1;
                }
            }
        }

        while let Some(joined) = tasks.join_next().await {
            match joined {
                Ok(Ok(outcome)) => {
                    considered += 1;
                    totals.merge(outcome);
                }
                Ok(Err(e)) => {
                    mailstack_core::warn::warn_with_detail(
                        "queue entry processing",
                        &e.to_string(),
                    );
                    failed += 1;
                    join_error.get_or_insert(e);
                }
                Err(e) => {
                    mailstack_core::warn::warn_with_detail("queue task join", &e.to_string());
                }
            }
        }

        let snapshot = self.health_snapshot();
        self.store.save_health(&snapshot)?;

        if let Some(err) = join_error {
            mailstack_core::warn::warn_with_detail("queue run had failures", &err.to_string());
        }

        let store = self.store.clone();
        let backlog = tokio::task::spawn_blocking(move || store.len())
            .await
            .map_err(|e| {
                crate::error::QueueError::Storage(format!("queue backlog task failed: {e}"))
            })??;

        Ok(QueueRunReport {
            considered,
            delivered: totals.delivered,
            deferred: totals.deferred,
            bounced: totals.bounced,
            discarded: totals.discarded,
            failed,
            fast_failed: totals.fast_failed,
            backlog,
            relay_concurrency: self.config.relay_concurrency.max(1),
            outbound_health: self.outbound_health(),
        })
    }

    pub async fn metrics_snapshot(&self) -> QueueMetrics {
        let store = self.store.clone();
        let backlog = tokio::task::spawn_blocking(move || store.len().unwrap_or(0))
            .await
            .unwrap_or(0);
        QueueMetrics {
            backlog,
            relay_concurrency: self.config.relay_concurrency.max(1),
            outbound_health: self.outbound_health(),
        }
    }

    async fn process(
        &self,
        mut entry: QueueEntry,
        now_unix: i64,
        policy: &RelayPolicy,
    ) -> QueueResult<EntryOutcome> {
        let _claim = ClaimGuard {
            store: self.store.clone(),
            id: entry.id.clone(),
        };

        let mut outcome = EntryOutcome::default();

        let mut mutated = false;

        let mut pending_bounces: Vec<PendingBounce> = Vec::new();
        let route = self.outbound_route();
        let (local_recipients, remote_recipients) = self.partition(&entry, policy);

        let _permit = self.semaphore.acquire().await;

        if !local_recipients.is_empty() {
            match self
                .local
                .deliver(&entry, DeliveryTarget::Local, &local_recipients)
                .await
            {
                Ok(receipt) => {
                    if receipt.accepted != local_recipients.len() {
                        return Err(crate::error::QueueError::invalid(format!(
                            "local transport reported {} accepted of {} attempted recipients \
                             (entry {}); refusing to drop the remainder silently",
                            receipt.accepted,
                            local_recipients.len(),
                            entry.id
                        )));
                    }
                    outcome.delivered += receipt.accepted;
                    remove_recipients(&mut entry, &local_recipients);
                    mutated = true;
                    entry.last_error = None;
                    entry.last_code = None;
                }
                Err(failure) => {
                    mutated = true;
                    self.apply_failure(
                        &mut entry,
                        &mut outcome,
                        &local_recipients,
                        failure,
                        now_unix,
                        &mut pending_bounces,
                    );
                }
            }
        }

        if !remote_recipients.is_empty() {
            if self.may_attempt_remote() {
                match self
                    .remote
                    .deliver(
                        &entry,
                        DeliveryTarget::Remote(route.clone()),
                        &remote_recipients,
                    )
                    .await
                {
                    Ok(receipt) => {
                        if receipt.accepted != remote_recipients.len() {
                            if mutated {
                                self.persist_best_effort(&entry);
                            }

                            if !pending_bounces.is_empty() {
                                if let Err(error) = self.flush_bounces(
                                    &mut entry,
                                    &mut outcome,
                                    pending_bounces,
                                    now_unix,
                                ) {
                                    mailstack_core::warn::warn_with_detail(
                                        "queue bounce write-back",
                                        &error.to_string(),
                                    );
                                }
                            }
                            return Err(crate::error::QueueError::invalid(format!(
                                "remote transport reported {} accepted of {} attempted \
                                 recipients (entry {}); refusing to drop the remainder silently",
                                receipt.accepted,
                                remote_recipients.len(),
                                entry.id
                            )));
                        }
                        outcome.delivered += receipt.accepted;
                        remove_recipients(&mut entry, &remote_recipients);
                        mutated = true;
                        entry.last_error = None;
                        entry.last_code = None;
                        self.record_remote_success();
                    }
                    Err(failure) => {
                        self.record_remote_failure(&failure);
                        mutated = true;
                        self.apply_failure(
                            &mut entry,
                            &mut outcome,
                            &remote_recipients,
                            failure,
                            now_unix,
                            &mut pending_bounces,
                        );
                    }
                }
            } else {
                outcome.fast_failed = true;
                outcome.deferred += 1;
            }
        }

        if entry.recipients.is_empty() {
            self.store.remove(&entry.id)?;
        } else if mutated {
            entry.validate()?;
            self.store.enqueue(&entry)?;
        }

        self.flush_bounces(&mut entry, &mut outcome, pending_bounces, now_unix)?;

        Ok(outcome)
    }

    fn persist_best_effort(&self, entry: &QueueEntry) {
        if let Err(error) = self.store.enqueue(entry) {
            mailstack_core::warn::warn_with_detail("queue entry write-back", &error.to_string());
        }
    }

    fn flush_bounces(
        &self,
        entry: &mut QueueEntry,
        outcome: &mut EntryOutcome,
        pending: Vec<PendingBounce>,
        now_unix: i64,
    ) -> QueueResult<()> {
        let mut first_error: Option<crate::error::QueueError> = None;
        for bounce in pending {
            let PendingBounce {
                failed,
                diagnostic,
                code,
            } = bounce;
            match self.bounce(entry, &failed, &diagnostic, code, now_unix) {
                Ok(true) => outcome.bounced += failed.len(),
                Ok(false) => outcome.discarded += failed.len(),
                Err(error) => {
                    for recipient in &failed {
                        if !entry.recipients.contains(recipient) {
                            entry.recipients.push(recipient.clone());
                        }
                    }
                    first_error.get_or_insert(error);
                }
            }
        }
        if first_error.is_some() {
            self.persist_best_effort(entry);
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn apply_failure(
        &self,
        entry: &mut QueueEntry,
        outcome: &mut EntryOutcome,
        attempted: &[String],
        failure: DeliveryFailure,
        now_unix: i64,
        pending: &mut Vec<PendingBounce>,
    ) {
        let accepted = failure.accepted.clone();
        if !accepted.is_empty() {
            outcome.delivered += accepted.len();
            remove_recipients(entry, &accepted);
        }
        let failed: Vec<String> = attempted
            .iter()
            .filter(|recipient| !accepted.contains(recipient))
            .cloned()
            .collect();
        if failed.is_empty() {
            return;
        }

        match failure.class {
            FailureClass::Permanent => {
                remove_recipients(entry, &failed);
                pending.push(PendingBounce {
                    failed,
                    diagnostic: failure.message.clone(),
                    code: failure.code,
                });
            }
            FailureClass::Transient => {
                let exhausted = self.config.backoff.on_failure(
                    entry,
                    now_unix,
                    Some(failure.message.clone()),
                    failure.code,
                );
                if exhausted {
                    remove_recipients(entry, &failed);
                    pending.push(PendingBounce {
                        failed,
                        diagnostic: failure.message,
                        code: failure.code,
                    });
                } else {
                    outcome.deferred += 1;
                }
            }
        }
    }

    fn bounce(
        &self,
        entry: &QueueEntry,
        failed: &[String],
        diagnostic: &str,
        code: Option<u16>,
        now_unix: i64,
    ) -> QueueResult<bool> {
        if entry.kind == EntryKind::Bounce || entry.is_null_sender() {
            return Ok(false);
        }
        let Some(recipient) = dsn_recipient(entry) else {
            return Ok(false);
        };

        let message = build_dsn(&DsnRequest {
            reporting_mta: &self.config.reporting_mta,
            original: entry,
            failed_recipients: failed,
            diagnostic,
            status_code: code,
        });

        let mut dsn = QueueEntry::new(
            EntryKind::Bounce,
            dsn_envelope_from(),
            vec![recipient.to_string()],
            message,
            now_unix,
        )?;

        self.store.enqueue_new(&mut dsn)?;
        Ok(true)
    }

    fn partition(&self, entry: &QueueEntry, policy: &RelayPolicy) -> (Vec<String>, Vec<String>) {
        let mut local = Vec::new();
        let mut remote = Vec::new();
        for recipient in &entry.recipients {
            let domain = recipient
                .rsplit_once('@')
                .map(|(_, domain)| domain)
                .unwrap_or("");
            if policy.is_managed(domain) {
                local.push(recipient.clone());
            } else {
                remote.push(recipient.clone());
            }
        }
        (local, remote)
    }

    fn health_snapshot(&self) -> OutboundHealthState {
        match self.health.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    fn record_remote_success(&self) {
        let mut guard = self
            .health
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.consecutive_failures = 0;
        guard.last_success_at = Some(mailstack_core::now_iso8601_utc());
        guard.last_failure = None;
    }

    fn record_remote_failure(&self, failure: &DeliveryFailure) {
        if failure.local_fault {
            return;
        }

        if failure.class != crate::delivery::FailureClass::Transient {
            return;
        }

        let mut guard = self
            .health
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.consecutive_failures = guard.consecutive_failures.saturating_add(1);
        guard.last_failure = Some(failure.message.clone());
    }

    fn may_attempt_remote(&self) -> bool {
        let failures = self.health_snapshot().consecutive_failures;
        if failures < self.config.blocked_threshold.max(1) {
            return true;
        }
        !self.half_open_used.swap(true, Ordering::SeqCst)
    }
}

fn remove_recipients(entry: &mut QueueEntry, done: &[String]) {
    entry.recipients.retain(|r| !done.contains(r));
}

struct RoundGuard<'a>(&'a AtomicBool);

impl Drop for RoundGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

struct ClaimGuard {
    store: QueueStore,
    id: String,
}

impl Drop for ClaimGuard {
    fn drop(&mut self) {
        if let Err(error) = self.store.release_claim(&self.id) {
            mailstack_core::warn::warn_with_detail("release queue claim", &error.to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delivery::{DeliveryFuture, DeliveryReceipt};
    use crate::signing::SigningOutcome;
    use mailstack_smtp::{validate_relay, RelayValidationRequest};
    use std::collections::VecDeque;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    struct ScriptedTransport {
        script: Mutex<VecDeque<Result<DeliveryReceipt, DeliveryFailure>>>,
        default: Mutex<Result<DeliveryReceipt, DeliveryFailure>>,
        calls: Mutex<Vec<(String, DeliveryTarget, Vec<String>)>>,
        inflight: AtomicUsize,
        max_inflight: AtomicUsize,
        hold: Duration,
    }

    impl ScriptedTransport {
        fn new(default: Result<DeliveryReceipt, DeliveryFailure>) -> Self {
            Self {
                script: Mutex::new(VecDeque::new()),
                default: Mutex::new(default),
                calls: Mutex::new(Vec::new()),
                inflight: AtomicUsize::new(0),
                max_inflight: AtomicUsize::new(0),
                hold: Duration::ZERO,
            }
        }

        fn ok() -> Arc<Self> {
            Arc::new(Self::new(Ok(DeliveryReceipt { accepted: 0 })))
        }

        fn failing(failure: DeliveryFailure) -> Arc<Self> {
            Arc::new(Self::new(Err(failure)))
        }

        fn with_hold(mut self: Arc<Self>, hold: Duration) -> Arc<Self> {
            if let Some(inner) = Arc::get_mut(&mut self) {
                inner.hold = hold;
            }
            self
        }

        fn calls(&self) -> Vec<(String, DeliveryTarget, Vec<String>)> {
            self.calls.lock().unwrap().clone()
        }

        fn observed_max_inflight(&self) -> usize {
            self.max_inflight.load(Ordering::SeqCst)
        }
    }

    impl Transport for ScriptedTransport {
        fn deliver<'a>(
            &'a self,
            entry: &'a QueueEntry,
            target: DeliveryTarget,
            recipients: &'a [String],
        ) -> DeliveryFuture<'a> {
            Box::pin(async move {
                let now = self
                    .inflight
                    .fetch_add(1, Ordering::SeqCst)
                    .saturating_add(1);
                self.max_inflight.fetch_max(now, Ordering::SeqCst);

                self.calls
                    .lock()
                    .unwrap()
                    .push((entry.id.clone(), target, recipients.to_vec()));

                if !self.hold.is_zero() {
                    tokio::time::sleep(self.hold).await;
                }

                self.inflight.fetch_sub(1, Ordering::SeqCst);

                let next = self.script.lock().unwrap().pop_front();
                match next {
                    Some(result) => result,
                    None => {
                        let fallback = self.default.lock().unwrap().clone();
                        match fallback {
                            Ok(receipt) => Ok(DeliveryReceipt {
                                accepted: if receipt.accepted == 0 {
                                    recipients.len()
                                } else {
                                    receipt.accepted
                                },
                            }),
                            Err(failure) => Err(failure),
                        }
                    }
                }
            })
        }
    }

    struct Harness {
        _dir: tempfile::TempDir,
        store: QueueStore,
        local: Arc<ScriptedTransport>,
        remote: Arc<ScriptedTransport>,
    }

    impl Harness {
        fn new(local: Arc<ScriptedTransport>, remote: Arc<ScriptedTransport>) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let store = QueueStore::new(dir.path().join("queue"));
            Self {
                _dir: dir,
                store,
                local,
                remote,
            }
        }

        fn runner(&self, config: QueueConfig, relay: Option<RelayEndpoint>) -> Arc<QueueRunner> {
            self.runner_with_signer(config, relay, Arc::new(NoSigning))
        }

        fn runner_with_signer(
            &self,
            config: QueueConfig,
            relay: Option<RelayEndpoint>,
            signer: Arc<dyn MessageSigner>,
        ) -> Arc<QueueRunner> {
            Arc::new(QueueRunner::new(
                self.store.clone(),
                self.local.clone(),
                self.remote.clone(),
                config,
                relay,
                signer,
            ))
        }
    }

    struct NoSigning;

    impl MessageSigner for NoSigning {
        fn sign(&self, _message: &str) -> SigningOutcome {
            SigningOutcome::NotApplicable
        }
    }

    struct FailingSigner;

    impl MessageSigner for FailingSigner {
        fn sign(&self, _message: &str) -> SigningOutcome {
            SigningOutcome::Failed("key is unreadable".to_string())
        }
    }

    fn config() -> QueueConfig {
        QueueConfig {
            relay_concurrency: 4,
            backoff: BackoffPolicy {
                base_secs: 10,
                factor: 2,
                max_secs: 100,
                max_attempts: 3,
            },
            reporting_mta: "mail.example.org".to_string(),
            managed_domains: vec!["example.org".to_string()],
            blocked_threshold: 3,
        }
    }

    fn enqueue_outbound(store: &QueueStore, id: &str, recipients: &[&str]) -> QueueEntry {
        enqueue_from(store, id, "sender@example.org", recipients)
    }

    fn enqueue_from(
        store: &QueueStore,
        id: &str,
        mail_from: &str,
        recipients: &[&str],
    ) -> QueueEntry {
        let mut entry = QueueEntry::new(
            EntryKind::Outbound,
            mail_from,
            recipients.iter().map(|r| r.to_string()).collect(),
            "Subject: t\r\n\r\nbody",
            1_000,
        )
        .unwrap();
        entry.id = id.to_string();
        store.enqueue(&entry).unwrap();
        entry
    }

    fn relay() -> RelayEndpoint {
        validate_relay(
            &RelayValidationRequest {
                host: "smtp.sendgrid.net".to_string(),
                port: 587,
                tls_mode: "STARTTLS".to_string(),
                username: "apikey".to_string(),
                password: "secret".to_string(),
                allow_private_network: false,
            },
            false,
        )
        .unwrap()
    }

    #[test]
    fn default_concurrency_matches_the_settings_schema() {
        assert_eq!(QueueConfig::default().relay_concurrency, 20);
        assert_eq!(
            QueueConfig::default().relay_concurrency,
            mailstack_core::config::Settings::default().relay_concurrency
        );
    }

    #[tokio::test]
    async fn metrics_snapshot_exposes_backlog_concurrency_and_health() {
        let harness = Harness::new(ScriptedTransport::ok(), ScriptedTransport::ok());
        let mut cfg = config();
        cfg.relay_concurrency = 7;

        let mut entry = enqueue_outbound(&harness.store, "00000000001-0001", &["bob@example.net"]);
        entry.next_attempt_unix = 9_999_999;
        harness.store.enqueue(&entry).unwrap();

        let runner = harness.runner(cfg, None);
        let metrics = runner.metrics_snapshot().await;
        assert_eq!(metrics.relay_concurrency, 7, "并发上限必须可观测");
        assert_eq!(metrics.backlog, 1, "积压量必须可观测");
        assert!(!metrics.outbound_health.blocked);

        let report = runner.run_once(1_000).await.unwrap();
        assert_eq!(report.relay_concurrency, 7);
        assert_eq!(report.backlog, 1, "未到期条目仍算积压");
        assert_eq!(report.considered, 0);
    }

    #[tokio::test]
    async fn zero_concurrency_is_clamped_instead_of_deadlocking() {
        let harness = Harness::new(ScriptedTransport::ok(), ScriptedTransport::ok());
        enqueue_outbound(&harness.store, "00000000001-0001", &["bob@example.net"]);
        let mut cfg = config();
        cfg.relay_concurrency = 0;
        let runner = harness.runner(cfg, None);

        let report = tokio::time::timeout(Duration::from_secs(5), runner.run_once(1_000))
            .await
            .expect("并发上限为 0 时不得死锁")
            .unwrap();
        assert_eq!(report.delivered, 1);
        assert_eq!(report.relay_concurrency, 1, "生效值应被夹到 1");
    }

    #[tokio::test]
    async fn delivered_entry_is_removed_from_the_queue() {
        let harness = Harness::new(ScriptedTransport::ok(), ScriptedTransport::ok());
        enqueue_outbound(&harness.store, "00000000001-0001", &["bob@example.net"]);
        let runner = harness.runner(config(), None);

        let report = runner.run_once(1_000).await.unwrap();
        assert_eq!(report.delivered, 1);
        assert_eq!(report.deferred, 0);
        assert!(
            harness.store.is_empty().unwrap(),
            "投递成功后条目必须从队列移除"
        );

        let calls = harness.remote.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].1, DeliveryTarget::Remote(OutboundRoute::Direct));
    }

    #[tokio::test]
    async fn local_recipients_use_the_local_transport_and_remote_use_the_remote_one() {
        let harness = Harness::new(ScriptedTransport::ok(), ScriptedTransport::ok());
        enqueue_outbound(
            &harness.store,
            "00000000001-0001",
            &["alice@example.org", "bob@example.net"],
        );
        let runner = harness.runner(config(), None);

        runner.run_once(1_000).await.unwrap();

        let local_calls = harness.local.calls();
        assert_eq!(local_calls.len(), 1, "本地收件人应走 LMTP 传输");
        assert_eq!(local_calls[0].2, vec!["alice@example.org".to_string()]);
        assert_eq!(local_calls[0].1, DeliveryTarget::Local);

        let remote_calls = harness.remote.calls();
        assert_eq!(remote_calls.len(), 1, "外域收件人应走出站传输");
        assert_eq!(remote_calls[0].2, vec!["bob@example.net".to_string()]);

        assert!(harness.store.is_empty().unwrap());
    }

    #[tokio::test]
    async fn recipients_accepted_by_a_partial_delivery_are_not_retried_or_bounced() {
        let harness = Harness::new(ScriptedTransport::ok(), ScriptedTransport::ok());
        enqueue_outbound(
            &harness.store,
            "00000000001-0001",
            &["alice@example.net", "bob@example.net"],
        );
        *harness.remote.default.lock().unwrap() = Err(DeliveryFailure::transient(
            "LmtpPartial",
            "452 4.2.2 over quota",
        )
        .with_accepted(vec!["alice@example.net".to_string()]));
        let runner = harness.runner(config(), None);

        let report = runner.run_once(1_000).await.unwrap();
        assert_eq!(report.delivered, 1, "已投递的收件人应计入 delivered");
        assert_eq!(report.deferred, 1);
        assert_eq!(report.bounced, 0, "已投递的收件人不得被退信");

        let entries = harness.store.load_all().unwrap();
        assert_eq!(entries.len(), 1, "只剩未投递的收件人需要重试");
        assert_eq!(entries[0].recipients, vec!["bob@example.net".to_string()]);

        harness.remote.calls.lock().unwrap().clear();
        *harness.remote.default.lock().unwrap() = Ok(DeliveryReceipt { accepted: 0 });
        runner.run_once(1_000_000).await.unwrap();
        let calls = harness.remote.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].2, vec!["bob@example.net".to_string()]);
        assert!(harness.store.is_empty().unwrap());
    }

    #[tokio::test]
    async fn a_fully_accepted_but_failed_batch_does_not_retry_anything() {
        let harness = Harness::new(ScriptedTransport::ok(), ScriptedTransport::ok());
        enqueue_outbound(&harness.store, "00000000001-0001", &["alice@example.net"]);
        *harness.remote.default.lock().unwrap() = Err(DeliveryFailure::transient(
            "LmtpPartial",
            "connection closed after delivery",
        )
        .with_accepted(vec!["alice@example.net".to_string()]));
        let runner = harness.runner(config(), None);

        let report = runner.run_once(1_000).await.unwrap();
        assert_eq!(report.delivered, 1);
        assert_eq!(report.deferred, 0, "没有剩余收件人就不该重试");
        assert_eq!(report.bounced, 0);
        assert!(
            harness.store.is_empty().unwrap(),
            "不得留下一条无从投递的空条目"
        );
    }

    #[tokio::test]
    async fn empty_managed_domains_treat_every_recipient_as_remote() {
        let harness = Harness::new(ScriptedTransport::ok(), ScriptedTransport::ok());
        enqueue_outbound(&harness.store, "00000000001-0001", &["alice@example.org"]);
        let mut cfg = config();
        cfg.managed_domains.clear();
        let runner = harness.runner(cfg, None);

        runner.run_once(1_000).await.unwrap();

        assert!(harness.local.calls().is_empty(), "不得走本地投递");
        assert_eq!(harness.remote.calls().len(), 1);
    }

    #[tokio::test]
    async fn permanent_failure_bounces_immediately_without_retry() {
        let local = ScriptedTransport::ok();
        let remote = ScriptedTransport::failing(
            DeliveryFailure::permanent("SmtpRejected", "550 no such user").with_code(550),
        );
        let harness = Harness::new(local, remote);
        let original = enqueue_outbound(&harness.store, "00000000001-0001", &["bob@example.net"]);
        let runner = harness.runner(config(), None);

        let report = runner.run_once(1_000).await.unwrap();
        assert_eq!(report.bounced, 1);
        assert_eq!(report.deferred, 0, "5xx 不得进入重试");

        let entries = harness.store.load_all().unwrap();
        assert_eq!(entries.len(), 1, "应恰好生成一封退信");
        let dsn = &entries[0];
        assert_eq!(dsn.kind, EntryKind::Bounce);
        assert!(
            dsn.is_null_sender(),
            "DSN 必须使用 null sender，否则退信自身失败会形成回环"
        );
        assert_eq!(dsn.recipients, vec!["sender@example.org".to_string()]);
        assert!(dsn.data.contains("550 no such user"));
        assert!(dsn.data.contains(&original.id), "退信应回附原邮件用以定位");
    }

    #[tokio::test]
    async fn transient_failures_retry_then_bounce_after_the_retry_limit() {
        let harness = Harness::new(
            ScriptedTransport::ok(),
            ScriptedTransport::failing(DeliveryFailure::transient(
                "ConnectionError",
                "connection refused",
            )),
        );
        enqueue_outbound(&harness.store, "00000000001-0001", &["bob@example.net"]);
        let runner = harness.runner(config(), None);

        let first = runner.run_once(1_000).await.unwrap();
        assert_eq!(first.deferred, 1);
        assert_eq!(first.bounced, 0);
        let entries = harness.store.load_all().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].attempts, 1);
        assert!(
            !entries[0].recipients.is_empty(),
            "临时失败必须保留收件人，否则重试无从谈起"
        );
        let after_first = entries[0].next_attempt_unix;
        assert!(after_first > 1_000, "必须推迟到未来");

        let too_early = runner.run_once(1_000).await.unwrap();
        assert_eq!(too_early.considered, 0, "未到退避时间不应被调度");

        runner.run_once(after_first).await.unwrap();
        let third = runner.run_once(after_first + 10_000).await.unwrap();
        assert_eq!(third.bounced, 1, "超过阈值必须退信，而不是无限重试");

        let entries = harness.store.load_all().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].kind, EntryKind::Bounce);
        assert!(
            entries[0].data.contains("connection refused"),
            "退信应说明最后一次失败原因"
        );
    }

    #[tokio::test]
    async fn bounce_is_never_generated_for_a_null_sender() {
        let harness = Harness::new(
            ScriptedTransport::ok(),
            ScriptedTransport::failing(DeliveryFailure::permanent("SmtpRejected", "550 nope")),
        );
        let mut entry = QueueEntry::new(
            EntryKind::Outbound,
            "",
            vec!["bob@example.net".to_string()],
            "body",
            1_000,
        )
        .unwrap();
        entry.id = "00000000001-0001".to_string();
        harness.store.enqueue(&entry).unwrap();
        let runner = harness.runner(config(), None);

        let report = runner.run_once(1_000).await.unwrap();
        assert_eq!(report.bounced, 0);
        assert_eq!(report.discarded, 1);
        assert!(
            harness.store.is_empty().unwrap(),
            "不得生成退信，也不得把 null sender 的邮件永远挂在队列里"
        );
    }

    #[tokio::test]
    async fn dsn_entries_are_never_bounced_again() {
        let harness = Harness::new(
            ScriptedTransport::ok(),
            ScriptedTransport::failing(DeliveryFailure::permanent(
                "SmtpRejected",
                "550 mailbox unavailable",
            )),
        );
        let mut dsn = QueueEntry::new(
            EntryKind::Bounce,
            "",
            vec!["sender@example.net".to_string()],
            "Subject: Undelivered Mail\r\n\r\nbody",
            1_000,
        )
        .unwrap();
        dsn.id = "00000000001-0001".to_string();
        harness.store.enqueue(&dsn).unwrap();
        let runner = harness.runner(config(), None);

        let report = runner.run_once(1_000).await.unwrap();
        assert_eq!(report.bounced, 0, "退信不得再退信");
        assert_eq!(report.discarded, 1);
        assert!(harness.store.is_empty().unwrap());
    }

    #[tokio::test]
    async fn bounces_use_the_same_outbound_route_as_user_mail() {
        let harness = Harness::new(ScriptedTransport::ok(), ScriptedTransport::ok());
        let endpoint = relay();
        enqueue_from(
            &harness.store,
            "00000000001-0001",
            "sender@remote.example",
            &["bob@example.net"],
        );
        let runner = harness.runner(config(), Some(endpoint.clone()));

        let expected = OutboundRoute::ViaRelay {
            host: endpoint.host.clone(),
            port: endpoint.port,
            wrappermode: endpoint.requires_wrappermode(),
        };
        assert_eq!(runner.outbound_route(), expected);

        runner.run_once(1_000).await.unwrap();
        let user_call = harness.remote.calls();
        assert_eq!(user_call.len(), 1);
        assert_eq!(user_call[0].1, DeliveryTarget::Remote(expected.clone()));

        *harness.remote.default.lock().unwrap() =
            Err(DeliveryFailure::permanent("SmtpRejected", "550 nope"));
        enqueue_from(
            &harness.store,
            "00000000001-0002",
            "sender@remote.example",
            &["carol@example.net"],
        );
        runner.run_once(2_000).await.unwrap();

        let dsn_entry = harness
            .store
            .load_all()
            .unwrap()
            .into_iter()
            .find(|e| e.kind == EntryKind::Bounce)
            .expect("应生成退信");
        assert_eq!(
            dsn_entry.recipients,
            vec!["sender@remote.example".to_string()],
            "退信应收给原信封发件人"
        );

        *harness.remote.default.lock().unwrap() = Ok(DeliveryReceipt { accepted: 0 });
        harness.remote.calls.lock().unwrap().clear();
        runner.run_once(3_000).await.unwrap();

        let dsn_calls: Vec<_> = harness
            .remote
            .calls()
            .into_iter()
            .filter(|(id, _, _)| *id == dsn_entry.id)
            .collect();
        assert_eq!(dsn_calls.len(), 1, "退信必须经同一出站传输投递");
        assert_eq!(
            dsn_calls[0].1,
            DeliveryTarget::Remote(expected),
            "INV-21：退信与用户邮件不得走不同路径"
        );
        assert!(
            harness
                .local
                .calls()
                .iter()
                .all(|(id, _, _)| *id != dsn_entry.id),
            "退信不得走本地投递旁路"
        );
    }

    #[tokio::test]
    async fn a_bounce_addressed_to_a_local_sender_is_delivered_locally() {
        let harness = Harness::new(ScriptedTransport::ok(), ScriptedTransport::ok());
        enqueue_from(
            &harness.store,
            "00000000001-0001",
            "sender@example.org",
            &["bob@example.net"],
        );
        *harness.remote.default.lock().unwrap() =
            Err(DeliveryFailure::permanent("SmtpRejected", "550 nope"));
        let runner = harness.runner(config(), Some(relay()));

        runner.run_once(1_000).await.unwrap();
        let dsn_entry = harness
            .store
            .load_all()
            .unwrap()
            .into_iter()
            .find(|e| e.kind == EntryKind::Bounce)
            .expect("应生成退信");

        *harness.remote.default.lock().unwrap() = Ok(DeliveryReceipt { accepted: 0 });
        harness.local.calls.lock().unwrap().clear();
        runner.run_once(2_000).await.unwrap();

        let local_calls: Vec<_> = harness
            .local
            .calls()
            .into_iter()
            .filter(|(id, _, _)| *id == dsn_entry.id)
            .collect();
        assert_eq!(local_calls.len(), 1, "本域发件人的退信应走本地投递");
        assert_eq!(local_calls[0].1, DeliveryTarget::Local);
    }

    #[tokio::test]
    async fn consecutive_outbound_failures_produce_the_blocked_verdict() {
        let harness = Harness::new(
            ScriptedTransport::ok(),
            ScriptedTransport::failing(DeliveryFailure::transient(
                "ConnectionError",
                "connection timed out",
            )),
        );
        enqueue_outbound(&harness.store, "00000000001-0001", &["bob@example.net"]);
        let runner = harness.runner(config(), None);

        let mut now = 1_000;
        for _ in 0..3 {
            runner.run_once(now).await.unwrap();
            now += 1_000_000;
        }

        let health = runner.outbound_health();
        assert!(health.blocked, "连续失败 3 次后必须判定出站不可用");
        assert!(health.needs_relay, "未配置中继时应明确要求配置中继");
        assert!(
            health.message.contains("Outbound port 25 is blocked"),
            "文案必须让运维一眼看出结论，实际：{}",
            health.message
        );
    }

    #[tokio::test]
    async fn permanent_failures_never_trip_the_outbound_blocked_verdict() {
        let harness = Harness::new(
            ScriptedTransport::ok(),
            ScriptedTransport::failing(DeliveryFailure::permanent(
                "RcptRejected",
                "550 5.1.1 no such user",
            )),
        );
        let runner = harness.runner(config(), None);

        for round in 0..12 {
            enqueue_outbound(
                &harness.store,
                &format!("000000{:05}-0001", round + 1),
                &[&format!("ghost{round}@example.net")],
            );
            runner
                .run_once(1_000 + round as i64 * 1_000_000)
                .await
                .unwrap();
        }

        let health = runner.outbound_health();
        assert_eq!(
            health.consecutive_failures, 0,
            "永久失败说明链路是通的，不得计入出站健康"
        );
        assert!(
            !health.blocked,
            "正常退信不得把出站判成被封（否则停止全部外域投递）"
        );
    }

    #[tokio::test]
    async fn an_entry_under_a_live_claim_is_skipped_and_delivered_after_expiry() {
        let harness = Harness::new(ScriptedTransport::ok(), ScriptedTransport::ok());
        let entry = enqueue_outbound(&harness.store, "00000000001-0001", &["bob@example.net"]);
        let runner = harness.runner(config(), None);

        let claimed_at = 1_000;
        assert!(harness.store.try_claim(&entry.id, claimed_at).unwrap());

        let report = runner
            .run_once(claimed_at + 60)
            .await
            .expect("本轮应当正常完成（只是跳过被租约持有的条目）");
        assert_eq!(report.considered, 0, "被租约持有的条目不应被处理");
        assert!(
            harness.remote.calls().is_empty(),
            "被租约持有的条目不得被投递 —— 否则就是重复投递"
        );
        assert_eq!(
            harness.store.load_all().unwrap().len(),
            1,
            "条目本身必须原样留在队列里，不能因为跳过而被删"
        );

        let after_expiry = claimed_at + crate::store::CLAIM_TTL_SECONDS + 1;
        let report = runner.run_once(after_expiry).await.unwrap();
        assert_eq!(report.considered, 1, "租约过期后应正常处理");
        assert_eq!(harness.remote.calls().len(), 1);
        assert!(
            harness.store.load_all().unwrap().is_empty(),
            "投递成功后条目应被移除"
        );

        assert!(
            harness.store.claimed_ids(after_expiry).unwrap().is_empty(),
            "投递完成后租约必须被释放"
        );
    }

    #[tokio::test]
    async fn overlapping_rounds_are_refused_instead_of_double_delivering() {
        let harness = Harness::new(ScriptedTransport::ok(), ScriptedTransport::ok());
        enqueue_outbound(&harness.store, "00000000001-0001", &["bob@example.net"]);
        let runner = harness.runner(config(), None);

        use std::sync::atomic::Ordering;
        assert!(runner
            .round_in_flight
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok());

        let error = runner
            .run_once(1_000)
            .await
            .expect_err("重叠轮次必须被拒绝");
        assert!(
            error.is_busy(),
            "必须是可识别的「跳过」而不是普通故障：{error}"
        );

        assert_eq!(
            harness.remote.calls().len(),
            0,
            "被拒绝的那一轮不得投递任何条目"
        );

        runner.round_in_flight.store(false, Ordering::SeqCst);
        runner.run_once(1_000).await.unwrap();
        assert_eq!(harness.remote.calls().len(), 1);
    }

    #[tokio::test]
    async fn blocked_verdict_survives_restart() {
        let harness = Harness::new(
            ScriptedTransport::ok(),
            ScriptedTransport::failing(DeliveryFailure::transient(
                "ConnectionError",
                "connection timed out",
            )),
        );
        enqueue_outbound(&harness.store, "00000000001-0001", &["bob@example.net"]);
        let runner = harness.runner(config(), None);
        runner.run_once(1_000).await.unwrap();
        runner.run_once(1_000_000).await.unwrap();
        runner.run_once(2_000_000).await.unwrap();
        assert!(runner.outbound_health().blocked);

        let restarted = harness.runner(config(), None);
        let health = restarted.outbound_health();
        assert!(health.blocked, "出站不可用的结论必须跨重启保留");
        assert!(health.needs_relay);
    }

    #[tokio::test]
    async fn blocked_queue_fast_fails_instead_of_hammering() {
        let harness = Harness::new(
            ScriptedTransport::ok(),
            ScriptedTransport::failing(DeliveryFailure::transient(
                "ConnectionError",
                "connection timed out",
            )),
        );
        let runner = harness.runner(config(), None);

        for i in 0..3 {
            enqueue_outbound(
                &harness.store,
                &format!("0000000000{i}-0001"),
                &["bob@example.net"],
            );
            runner.run_once(1_000 + i as i64).await.unwrap();
        }
        assert!(runner.outbound_health().blocked);

        for i in 0..5 {
            enqueue_outbound(
                &harness.store,
                &format!("000000000A{i}-0001"),
                &["bob@example.net"],
            );
        }
        harness.remote.calls.lock().unwrap().clear();
        let report = runner.run_once(10_000_000).await.unwrap();

        assert!(report.fast_failed, "判定出站不可用后必须走快速失败");
        assert_eq!(
            harness.remote.calls().len(),
            1,
            "快速失败期间每轮只允许一次探测投递，不得逐条重试"
        );
        assert!(report.deferred >= 5, "其余条目应原样留在队列里等待");
    }

    #[tokio::test]
    async fn a_successful_probe_clears_the_blocked_verdict() {
        let harness = Harness::new(
            ScriptedTransport::ok(),
            ScriptedTransport::failing(DeliveryFailure::transient(
                "ConnectionError",
                "connection timed out",
            )),
        );
        enqueue_outbound(&harness.store, "00000000001-0001", &["bob@example.net"]);
        let runner = harness.runner(config(), None);
        for i in 0..3 {
            runner.run_once(1_000 + i as i64 * 1_000_000).await.unwrap();
        }
        assert!(runner.outbound_health().blocked);

        *harness.remote.default.lock().unwrap() = Ok(DeliveryReceipt { accepted: 0 });
        enqueue_outbound(&harness.store, "00000000001-0002", &["bob@example.net"]);
        let report = runner.run_once(10_000_000).await.unwrap();

        assert!(!report.outbound_health.blocked, "成功投递应清除不可用判定");
        assert_eq!(report.outbound_health.consecutive_failures, 0);
        assert!(harness
            .store
            .load_all()
            .unwrap()
            .iter()
            .all(|e| !e.recipients.is_empty()));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrency_is_bounded_by_relay_concurrency() {
        let remote =
            ScriptedTransport::with_hold(ScriptedTransport::ok(), Duration::from_millis(30));
        let harness = Harness::new(ScriptedTransport::ok(), remote);
        let mut cfg = config();
        cfg.relay_concurrency = 2;

        for i in 0..8 {
            enqueue_outbound(
                &harness.store,
                &format!("0000000000{i}-0001"),
                &["bob@example.net"],
            );
        }
        let runner = harness.runner(cfg, None);
        let report = runner.run_once(1_000).await.unwrap();

        assert_eq!(report.delivered, 8);
        assert!(
            harness.remote.observed_max_inflight() <= 2,
            "并发峰值 {} 超过了 relayConcurrency=2",
            harness.remote.observed_max_inflight()
        );
        assert!(
            harness.remote.observed_max_inflight() > 1,
            "并发完全没有发生，限流测试没有验证到任何东西"
        );
    }

    #[tokio::test]
    async fn a_local_transport_failure_does_not_trip_the_outbound_verdict() {
        let harness = Harness::new(
            ScriptedTransport::failing(DeliveryFailure::transient(
                "LmtpUnavailable",
                "connection refused",
            )),
            ScriptedTransport::ok(),
        );
        enqueue_outbound(&harness.store, "00000000001-0001", &["alice@example.org"]);
        let runner = harness.runner(config(), None);

        runner.run_once(1_000).await.unwrap();
        assert_eq!(
            runner.outbound_health().consecutive_failures,
            0,
            "本地投递失败不得计入出站健康"
        );
        let entries = harness.store.load_all().unwrap();
        assert_eq!(entries[0].attempts, 1, "本地失败仍应触发退避重试");
        assert!(!entries[0].recipients.is_empty());
    }

    #[tokio::test]
    async fn entry_processing_errors_are_counted_in_the_report() {
        let harness = Harness::new(ScriptedTransport::ok(), ScriptedTransport::ok());
        enqueue_outbound(&harness.store, "00000000001-0001", &["bob@example.net"]);

        harness
            .remote
            .script
            .lock()
            .unwrap()
            .push_back(Ok(DeliveryReceipt { accepted: 0 }));
        let runner = harness.runner(config(), None);

        let report = runner.run_once(1_000).await.unwrap();
        assert_eq!(report.considered, 0, "失败的条目不计入 considered");
        assert_eq!(report.failed, 1, "Ok(Err) 必须被计数");

        assert_eq!(harness.store.load_all().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn local_progress_is_persisted_before_a_remote_mismatch_error() {
        let harness = Harness::new(ScriptedTransport::ok(), ScriptedTransport::ok());
        enqueue_outbound(
            &harness.store,
            "00000000001-0001",
            &["alice@example.org", "bob@example.net"],
        );

        harness
            .remote
            .script
            .lock()
            .unwrap()
            .push_back(Ok(DeliveryReceipt { accepted: 0 }));
        let runner = harness.runner(config(), None);

        let report = runner.run_once(1_000).await.unwrap();
        assert_eq!(report.failed, 1);

        let entries = harness.store.load_all().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].recipients,
            vec!["bob@example.net".to_string()],
            "本地已投递的收件人必须已从磁盘条目摘除"
        );
    }

    #[tokio::test]
    async fn a_remote_mismatch_error_still_flushes_pending_bounces() {
        let harness = Harness::new(ScriptedTransport::ok(), ScriptedTransport::ok());
        enqueue_outbound(
            &harness.store,
            "00000000001-0001",
            &["alice@example.org", "bob@example.net"],
        );

        harness
            .local
            .script
            .lock()
            .unwrap()
            .push_back(Err(DeliveryFailure::permanent(
                "RcptRejected",
                "550 no such user",
            )));

        harness
            .remote
            .script
            .lock()
            .unwrap()
            .push_back(Ok(DeliveryReceipt { accepted: 0 }));
        let runner = harness.runner(config(), None);

        let report = runner.run_once(1_000).await.unwrap();
        assert_eq!(report.failed, 1);

        let entries = harness.store.load_all().unwrap();

        let original = entries
            .iter()
            .find(|e| e.id == "00000000001-0001")
            .expect("原条目必须保留（远端收件人待重试）");
        assert_eq!(original.recipients, vec!["bob@example.net".to_string()]);

        let dsn = entries
            .iter()
            .find(|e| e.kind == EntryKind::Bounce)
            .expect("本地阶段判定的退信必须已入队");
        assert_eq!(dsn.recipients, vec!["sender@example.org".to_string()]);
        assert!(dsn.data.contains("550 no such user"));
    }

    #[tokio::test]
    async fn a_signing_failure_defers_without_tripping_the_outbound_verdict() {
        let harness = Harness::new(ScriptedTransport::ok(), ScriptedTransport::ok());
        enqueue_outbound(&harness.store, "00000000001-0001", &["bob@example.net"]);
        let runner = harness.runner_with_signer(config(), None, Arc::new(FailingSigner));

        let report = runner.run_once(1_000).await.unwrap();

        assert!(
            harness.remote.calls().is_empty(),
            "签名失败时绝不能把未签名邮件投出去"
        );
        assert_eq!(report.deferred, 1, "应退回队列重试");
        assert_eq!(report.bounced, 0, "第一次失败不该立即退信");

        let health = runner.outbound_health();
        assert_eq!(
            health.consecutive_failures, 0,
            "DKIM 签名失败不得计入出站健康"
        );
        assert!(!health.blocked, "不得因此判定出站不可用");

        let entries = harness.store.load_all().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].attempts, 1, "应已进入退避重试");
        assert!(
            entries[0]
                .last_error
                .as_deref()
                .unwrap_or_default()
                .contains("key is unreadable"),
            "失败原因必须留在条目上，否则运维无从定位：{:?}",
            entries[0].last_error
        );
    }

    #[tokio::test]
    async fn a_failed_claim_does_not_abort_the_entries_already_in_flight() {
        let harness = Harness::new(ScriptedTransport::ok(), ScriptedTransport::ok());

        enqueue_outbound(&harness.store, "00000000001-0001", &["alice@example.net"]);
        enqueue_outbound(&harness.store, "00000000002-0002", &["bob@example.net"]);

        harness.store.fail_next_claim("00000000002-0002");
        let runner = harness.runner(config(), None);

        let report = runner
            .run_once(1_000)
            .await
            .expect("逐条目认领失败不是整轮失败");

        assert_eq!(report.delivered, 1, "第 1 条必须照常投递完成");
        assert_eq!(report.failed, 1, "认领失败必须计入 failed（可观测）");
        let calls = harness.remote.calls();
        assert_eq!(calls.len(), 1, "在途投递不得因为后续认领失败被取消");
        assert_eq!(calls[0].0, "00000000001-0001");

        let entries = harness.store.load_all().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, "00000000002-0002");
        assert_eq!(entries[0].recipients, vec!["bob@example.net".to_string()]);
    }

    #[tokio::test]
    async fn run_once_does_not_load_entries_that_are_not_due() {
        let harness = Harness::new(ScriptedTransport::ok(), ScriptedTransport::ok());
        enqueue_outbound(&harness.store, "00000000001-0001", &["bob@example.net"]);

        fs_write_future_entry(&harness.store, "00000000002-0002", 9_999_999_999);

        enqueue_outbound(&harness.store, "00000000003-0003", &["carol@example.net"]);

        let runner = harness.runner(config(), None);
        let report = runner.run_once(1_000).await.unwrap();

        assert_eq!(report.delivered, 2, "两条到期条目都应投递");
        assert_eq!(report.backlog, 1, "未到期条目仍留在队列里");
        assert!(
            harness
                .store
                .entries_dir()
                .join("00000000002-0002.json")
                .exists(),
            "未到期条目不得被调度路径完整解析（否则空正文会被 validate 判非法并隔离）"
        );
        let corrupt = match std::fs::read_dir(harness.store.corrupt_dir()) {
            Ok(read) => read.count(),
            Err(_) => 0,
        };
        assert_eq!(corrupt, 0, "调度不得把未到期条目当损坏隔离");
    }

    fn fs_write_future_entry(store: &QueueStore, id: &str, next_attempt_unix: i64) {
        let entries = store.entries_dir();
        std::fs::create_dir_all(&entries).unwrap();
        let payload = serde_json::json!({
            "id": id,
            "kind": "outbound",
            "mailFrom": "sender@example.org",
            "recipients": ["dave@example.net"],
            "data": "",
            "createdAt": "2026-01-01T00:00:00+00:00",
            "attempts": 0,
            "nextAttemptUnix": next_attempt_unix,
        });
        std::fs::write(
            entries.join(format!("{id}.json")),
            serde_json::to_vec_pretty(&payload).unwrap(),
        )
        .unwrap();
    }
}
