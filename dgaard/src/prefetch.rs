//! Background prefetch worker — Phase 5 of the recursive-DNS roadmap.
//!
//! When a cache hit's remaining TTL falls below a configured threshold,
//! [`handle_query`](crate::dns::handle_query) enqueues a `(domain, qtype)`
//! refresh request onto a bounded MPSC channel. A single worker task
//! drains the channel, throttles itself to at most one resolution per
//! `interval_ms`, runs the request through the global
//! [`UpstreamResolver`](crate::dns::resolver::UpstreamResolver), and
//! inserts the new bytes back into the response cache before the client
//! comes back for them.
//!
//! ## Correctness notes
//!
//! * **A refresh is judged like a client query**: the name goes through
//!   the filter pipeline again (blocklist, pre-upstream score gate) and the
//!   fresh answer through the same post-processing as `handle_query`
//!   ([`forward_and_inspect`](crate::dns::forward_and_inspect): DNSSEC,
//!   rebinding shield, CNAME cloaking, ASN, low TTL, score threshold). An
//!   allowed *name* says nothing about its next *answer*: a domain that
//!   first answered with a public IP may refresh to `192.168.1.1`. A
//!   rejected refresh evicts the cached entry instead of replacing it.
//! * **Single in-flight per (domain, qtype) is not enforced** here. Two
//!   triggers within a tight window can both land in the queue; the
//!   second one will simply overwrite the cache entry with the same
//!   fresh bytes. Cheap enough to ignore — adding a dedupe set would
//!   cost a `DashSet<(String, u16)>` on the hot path.
//! * **Popularity**: an accepted refresh `record_hit`s the tracker (a
//!   prefetch is, by definition, evidence that the domain matters).
//!
//! ## Counters
//!
//! * `prefetch_dropped_total` — `try_send` rejected because the channel
//!   was full. Increment lives in `handle_query`, near the trigger.
//! * `prefetch_completed_total` — the fresh answer was accepted (and
//!   cached when it carries a TTL).
//! * `prefetch_failed_total` — the resolver returned an error, or the name
//!   or the fresh answer was rejected (its cached entry is then evicted).
//!   Failures are silent for the client; the next miss re-resolves.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use tokio::sync::{mpsc, watch};
use tokio::time::Instant;

use crate::debug::debug_print;
use crate::dns::packet::DnsPacket;
use crate::dns::resolver::UpstreamResolver;
use crate::dns::{ForwardOutcome, block_before_upstream, evict_cached, forward_and_inspect};
use crate::model::{Action, StatAction};

/// Public alias — what the channel carries. Plain `(String, u16)` keeps
/// the surface unsurprising and avoids leaking module-private types
/// across the `handle_query`/worker boundary.
pub type PrefetchRequest = (String, u16);

/// Process-wide sender slot. Set exactly once during runtime startup
/// (see [`init_global_sender`]); `handle_query` reads through this to
/// fire-and-forget on a hot cache hit.
pub static PREFETCH_SENDER: OnceLock<mpsc::Sender<PrefetchRequest>> = OnceLock::new();

/// Install the global prefetch sender. Idempotent — re-calls are a
/// no-op rather than an error so the multi-worker startup paths can
/// initialise without coordinating. Tests that build their own runtime
/// can swap in a sender by setting [`PREFETCH_SENDER`] directly via
/// [`OnceLock::set`].
pub fn init_global_sender(tx: mpsc::Sender<PrefetchRequest>) {
    let _ = PREFETCH_SENDER.set(tx);
}

/// Non-blocking enqueue. Returns `false` when:
///
/// * the worker isn't running (sender not installed — prefetch disabled
///   at startup);
/// * the channel is full — counts toward `prefetch_dropped_total`.
///
/// The caller should not retry: the cache hit it just served still
/// covers the client, and a future client query within the TTL window
/// will trigger again.
pub fn try_enqueue(domain: &str, qtype: u16) -> bool {
    let Some(tx) = PREFETCH_SENDER.get() else {
        return false;
    };
    match tx.try_send((domain.to_owned(), qtype)) {
        Ok(()) => true,
        Err(mpsc::error::TrySendError::Full(_)) => {
            crate::STATS_COUNTERS.increment_prefetch_dropped();
            false
        }
        // Closed means the worker exited (shutdown). Don't count as a
        // user-visible drop — it's expected during teardown.
        Err(mpsc::error::TrySendError::Closed(_)) => false,
    }
}

/// Runtime parameters for the worker task. Plain `Copy` struct so tests
/// can construct one literally without weaving `Config` through. Cache
/// TTL policy is read from the live `CONFIG`, like `handle_query` does.
#[derive(Clone, Copy, Debug)]
pub struct PrefetchWorkerCfg {
    pub interval_ms: u64,
}

/// Drain `rx` and refresh the cache via `resolver`.
///
/// Exits cleanly when `shutdown_rx` flips to `true` *or* when every
/// sender has been dropped (`rx.recv()` returns `None`). The latter
/// matters for tests that never plumb a shutdown channel.
pub async fn run_prefetch_worker(
    mut rx: mpsc::Receiver<PrefetchRequest>,
    resolver: Arc<dyn UpstreamResolver>,
    cfg: PrefetchWorkerCfg,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    // `next_allowed` enforces the rate limit. Using `Instant` directly
    // (vs. `tokio::time::Interval`) sidesteps the "first tick fires
    // immediately" quirk and lets us debit the budget per-request even
    // when several arrive bunched up.
    let interval = Duration::from_millis(cfg.interval_ms);
    let mut next_allowed = Instant::now();

    loop {
        let req = tokio::select! {
            biased;
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    return;
                }
                continue;
            }
            req = rx.recv() => match req {
                Some(r) => r,
                None => return,
            }
        };

        // Throttle. Sleep with cancellation on shutdown so teardown
        // isn't held up by a long interval_ms.
        let now = Instant::now();
        if now < next_allowed {
            let delay = next_allowed - now;
            tokio::select! {
                biased;
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        return;
                    }
                }
                _ = tokio::time::sleep(delay) => {}
            }
        }
        next_allowed = Instant::now() + interval;

        process_one(&req.0, req.1, &resolver).await;
    }
}

/// Refresh one cache entry. The name is re-judged by the filter pipeline
/// and the fresh answer post-processed exactly like a client query's; a
/// rejection evicts the entry. Pulled out of the loop so tests can drive it
/// directly.
pub async fn process_one(domain: &str, qtype: u16, resolver: &Arc<dyn UpstreamResolver>) {
    let Some(query) = DnsPacket::new_query(domain, qtype) else {
        // Unreachable in practice — cache keys come from validated
        // queries. Count it as a failure instead of panicking so a
        // malformed key from a future code path doesn't tear the worker
        // down.
        crate::STATS_COUNTERS.increment_prefetch_failed();
        return;
    };

    let resolved = crate::resolve::resolve_with_score(&query.domain);
    let pass_action = match resolved.action {
        Action::Allow => StatAction::Allowed,
        Action::ProxyToUpstream => StatAction::Proxied,
        // No longer forwarded (newly blocked, overridden…): stop serving
        // the cached answer.
        _ => {
            reject(&query);
            return;
        }
    };
    let cfg = crate::CONFIG.load();
    if block_before_upstream(&resolved.action, &resolved.score, &cfg.security.scoring).is_some() {
        reject(&query);
        return;
    }

    let upstream = resolver.resolve(&query);
    match forward_and_inspect(&query, upstream, resolved.score, pass_action, &cfg).await {
        ForwardOutcome::Serve { .. } => {
            crate::POPULARITY_TRACKER.record_hit(&query.domain);
            crate::STATS_COUNTERS.increment_prefetch_completed();
        }
        // forward_and_inspect already evicted the entry.
        ForwardOutcome::Blocked(_) | ForwardOutcome::Bogus => {
            debug_print!("Prefetch rejected refreshed answer: {}", query.domain);
            crate::STATS_COUNTERS.increment_prefetch_failed();
        }
        // The cached answer stays valid until its own TTL.
        ForwardOutcome::UpstreamError => {
            crate::STATS_COUNTERS.increment_prefetch_failed();
        }
    }
}

/// Refuse a refresh before any upstream traffic: evict the entry.
fn reject(query: &DnsPacket) {
    debug_print!("Prefetch rejected name: {}", query.domain);
    evict_cached(&query.domain, query.qtype);
    crate::STATS_COUNTERS.increment_prefetch_failed();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::sync::Mutex;

    use async_trait::async_trait;
    use hickory_resolver::proto::op::{Message, MessageType};
    use hickory_resolver::proto::rr::rdata::A;
    use hickory_resolver::proto::rr::{Name, RData, Record};

    use crate::cache::ResponseCache;
    use crate::config::Config;
    use crate::dns::resolver::UpstreamResolver;
    use crate::resolve::tests::{create_test_engine, run_with_globals};
    use crate::{CONFIG, CURRENT_ENGINE, RESPONSE_CACHE};

    const QTYPE_A: u16 = 1;

    /// Test double: records every domain it's asked to resolve and answers
    /// with a single A record (`ip`, `ttl`), or fails.
    struct FakeResolver {
        ttl: u32,
        ip: Ipv4Addr,
        calls: Mutex<Vec<String>>,
        fail: bool,
    }

    impl FakeResolver {
        fn answering(ip: Ipv4Addr) -> Self {
            Self {
                ttl: 60,
                ip,
                calls: Mutex::new(Vec::new()),
                fail: false,
            }
        }

        fn failing() -> Self {
            Self {
                fail: true,
                ..Self::answering(Ipv4Addr::new(93, 184, 216, 34))
            }
        }
    }

    #[async_trait]
    impl UpstreamResolver for FakeResolver {
        async fn resolve(&self, query: &DnsPacket) -> std::io::Result<Vec<u8>> {
            self.calls.lock().unwrap().push(query.domain.clone());
            if self.fail {
                return Err(std::io::Error::other("upstream down"));
            }
            Ok(canned_a_response(&query.domain, self.ttl, self.ip))
        }
    }

    fn canned_a_response(domain: &str, ttl: u32, ip: Ipv4Addr) -> Vec<u8> {
        let name = Name::parse(domain, Some(&Name::root())).unwrap();
        let mut msg = Message::query();
        msg.metadata.message_type = MessageType::Response;
        msg.add_answer(Record::from_rdata(name, ttl, RData::A(A(ip))));
        msg.to_vec().unwrap()
    }

    fn fake_cfg() -> PrefetchWorkerCfg {
        PrefetchWorkerCfg { interval_ms: 0 }
    }

    /// Blocklist `blocked`, DGA heuristics off (not what these tests are
    /// about), and make sure a response cache exists.
    fn install_policy(blocked: &[&str]) {
        CURRENT_ENGINE.store(Arc::new(create_test_engine(blocked, &[], &[])));
        let mut config = Config::default();
        config.security.intelligence.enabled = false;
        CONFIG.store(Arc::new(config));
    }

    fn cache() -> &'static ResponseCache {
        RESPONSE_CACHE.get_or_init(|| ResponseCache::new(1024))
    }

    /// Seed the cache with a previously accepted (public) answer.
    fn seed_cache(domain: &str) {
        let bytes = canned_a_response(domain, 300, Ipv4Addr::new(1, 1, 1, 1));
        cache().insert(domain, QTYPE_A, &bytes, 300, 0);
    }

    fn cached_ip(domain: &str) -> Option<Ipv4Addr> {
        let bytes = cache().get(domain, QTYPE_A, [0, 0])?;
        Message::from_vec(&bytes)
            .unwrap()
            .answers
            .iter()
            .find_map(|r| match &r.data {
                RData::A(a) => Some(a.0),
                _ => None,
            })
    }

    fn resolver_of(fake: FakeResolver) -> (Arc<FakeResolver>, Arc<dyn UpstreamResolver>) {
        let fake = Arc::new(fake);
        let dynamic: Arc<dyn UpstreamResolver> = fake.clone();
        (fake, dynamic)
    }

    #[test]
    fn accepted_refresh_replaces_the_cached_answer() {
        run_with_globals(async {
            install_policy(&[]);
            let domain = "refreshed-site.com";
            seed_cache(domain);
            let baseline = crate::STATS_COUNTERS.get_prefetch_completed();
            let (_, resolver) =
                resolver_of(FakeResolver::answering(Ipv4Addr::new(93, 184, 216, 34)));

            process_one(domain, QTYPE_A, &resolver).await;

            assert_eq!(cached_ip(domain), Some(Ipv4Addr::new(93, 184, 216, 34)));
            assert!(crate::STATS_COUNTERS.get_prefetch_completed() > baseline);
            assert_eq!(crate::POPULARITY_TRACKER.score(domain, 86_400), 1);
        });
    }

    #[test]
    fn refresh_to_a_private_address_evicts_the_cached_answer() {
        // Review E4: the name was allowed, its first answer was public, the
        // refresh rebinds to the LAN. The shield must catch it here too.
        run_with_globals(async {
            install_policy(&[]);
            let domain = "rebinding-site.com";
            seed_cache(domain);
            let baseline = crate::STATS_COUNTERS.get_prefetch_failed();
            let (_, resolver) = resolver_of(FakeResolver::answering(Ipv4Addr::new(192, 168, 1, 1)));

            process_one(domain, QTYPE_A, &resolver).await;

            assert_eq!(
                cached_ip(domain),
                None,
                "neither the old nor the rebound answer"
            );
            assert!(crate::STATS_COUNTERS.get_prefetch_failed() > baseline);
            assert_eq!(crate::POPULARITY_TRACKER.score(domain, 86_400), 0);
        });
    }

    #[test]
    fn newly_blocked_name_is_evicted_without_resolving() {
        run_with_globals(async {
            let domain = "now-blocked-site.com";
            install_policy(&[domain]);
            seed_cache(domain);
            let (fake, resolver) =
                resolver_of(FakeResolver::answering(Ipv4Addr::new(93, 184, 216, 34)));

            process_one(domain, QTYPE_A, &resolver).await;

            assert_eq!(cached_ip(domain), None);
            assert!(fake.calls.lock().unwrap().is_empty());
        });
    }

    #[test]
    fn over_threshold_name_is_evicted_without_resolving() {
        // Pre-upstream score gate (review E2) applies to refreshes too.
        run_with_globals(async {
            install_policy(&[]);
            let domain = format!("{}.tunnel.com", "a".repeat(50));
            let mut config = (*CONFIG.load_full()).clone();
            config.security.scoring.blocking_threshold = u8::MAX;
            CONFIG.store(Arc::new(config.clone()));
            let score = crate::resolve::resolve_with_score(&domain).score.total;
            assert!(score > 0);
            config.security.scoring.blocking_threshold = score;
            CONFIG.store(Arc::new(config));
            seed_cache(&domain);
            let (fake, resolver) =
                resolver_of(FakeResolver::answering(Ipv4Addr::new(93, 184, 216, 34)));

            process_one(&domain, QTYPE_A, &resolver).await;

            assert_eq!(cached_ip(&domain), None);
            assert!(fake.calls.lock().unwrap().is_empty());
        });
    }

    #[test]
    fn upstream_failure_keeps_the_cached_answer() {
        run_with_globals(async {
            install_policy(&[]);
            let domain = "flaky-upstream-site.com";
            seed_cache(domain);
            let baseline = crate::STATS_COUNTERS.get_prefetch_failed();
            let (_, resolver) = resolver_of(FakeResolver::failing());

            process_one(domain, QTYPE_A, &resolver).await;

            // Still valid until its own TTL.
            assert_eq!(cached_ip(domain), Some(Ipv4Addr::new(1, 1, 1, 1)));
            assert!(crate::STATS_COUNTERS.get_prefetch_failed() > baseline);
        });
    }

    #[tokio::test]
    async fn process_one_malformed_domain_counts_as_failure() {
        let baseline = crate::STATS_COUNTERS.get_prefetch_failed();
        let (_, resolver) = resolver_of(FakeResolver::answering(Ipv4Addr::new(93, 184, 216, 34)));
        // A leading dot fails `Name::parse`; the worker must not panic.
        process_one("..bad..", QTYPE_A, &resolver).await;
        assert!(
            crate::STATS_COUNTERS.get_prefetch_failed() > baseline,
            "malformed-domain branch must bump the failed counter"
        );
    }

    #[tokio::test]
    async fn try_enqueue_drops_when_channel_full() {
        // Build a 1-slot channel, fill it, then verify the next send
        // bumps `prefetch_dropped_total`. OnceLock can't be reset, so the
        // global path is exercised through the same local sender logic.
        let (tx, _rx) = mpsc::channel::<PrefetchRequest>(1);
        tx.try_send(("first.example".into(), 1)).unwrap();

        let baseline_dropped = crate::STATS_COUNTERS.get_prefetch_dropped();
        let attempt = tx.try_send(("second.example".into(), 1));
        assert!(matches!(attempt, Err(mpsc::error::TrySendError::Full(_))));
        // Simulate the increment that try_enqueue performs.
        crate::STATS_COUNTERS.increment_prefetch_dropped();
        assert!(crate::STATS_COUNTERS.get_prefetch_dropped() > baseline_dropped);
    }

    #[tokio::test]
    async fn worker_exits_when_senders_drop() {
        // Drop the sender → worker should observe channel closed and
        // return without us flipping the shutdown bit.
        let (tx, rx) = mpsc::channel::<PrefetchRequest>(4);
        let (_, resolver) = resolver_of(FakeResolver::answering(Ipv4Addr::new(93, 184, 216, 34)));
        let (_sd_tx, sd_rx) = watch::channel(false);

        let handle = tokio::spawn(run_prefetch_worker(rx, resolver, fake_cfg(), sd_rx));
        drop(tx);

        let res = tokio::time::timeout(Duration::from_secs(1), handle).await;
        assert!(res.is_ok(), "worker did not exit after senders dropped");
    }

    #[test]
    fn worker_refreshes_a_queued_domain() {
        // End to end through the channel: the worker drains the request,
        // resolves it and the fresh answer lands in the cache.
        run_with_globals(async {
            install_policy(&[]);
            let domain = "expiring-site.com";
            let (tx, rx) = mpsc::channel::<PrefetchRequest>(4);
            let (fake, resolver) =
                resolver_of(FakeResolver::answering(Ipv4Addr::new(93, 184, 216, 34)));
            let (_sd_tx, sd_rx) = watch::channel(false);
            tokio::spawn(run_prefetch_worker(rx, resolver, fake_cfg(), sd_rx));

            tx.send((domain.into(), QTYPE_A)).await.unwrap();
            for _ in 0..50 {
                if cached_ip(domain).is_some() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }

            assert_eq!(*fake.calls.lock().unwrap(), [domain]);
            assert_eq!(cached_ip(domain), Some(Ipv4Addr::new(93, 184, 216, 34)));
        });
    }
}
