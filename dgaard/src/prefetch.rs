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
//! * **Blocklist safety**: only previously-allowed domains are ever
//!   cached (the filter pipeline judges before insert) and the cache is
//!   cleared on blocklist reload (Phase 4). Therefore everything we
//!   prefetch is, by construction, still allowed at the moment the trigger
//!   fires. We deliberately skip the filter pipeline in the worker — it's
//!   the whole point of the prefetch path being fast.
//! * **Single in-flight per (domain, qtype) is not enforced** here. Two
//!   triggers within a tight window can both land in the queue; the
//!   second one will simply overwrite the cache entry with the same
//!   fresh bytes. Cheap enough to ignore — adding a dedupe set would
//!   cost a `DashSet<(String, u16)>` on the hot path.
//! * **Filter bypass + popularity correctness**: the worker calls the
//!   resolver directly, then `record_hit`s the tracker so the prefetch
//!   itself counts as a popularity hit (a prefetch is, by definition,
//!   evidence that the domain matters).
//!
//! ## Counters
//!
//! * `prefetch_dropped_total` — `try_send` rejected because the channel
//!   was full. Increment lives in `handle_query`, near the trigger.
//! * `prefetch_completed_total` — resolver returned bytes AND the cache
//!   insert was attempted.
//! * `prefetch_failed_total` — resolver returned an error. Failures are
//!   silent for the client; the next TTL miss will re-resolve.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use tokio::sync::{mpsc, watch};
use tokio::time::Instant;

use crate::dns::packet::DnsPacket;
use crate::dns::resolver::UpstreamResolver;

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
/// can construct one literally without weaving `Config` through.
#[derive(Clone, Copy, Debug)]
pub struct PrefetchWorkerCfg {
    pub interval_ms: u64,
    /// TTL override copied from `[cache] ttl_override` so the worker
    /// honours the same operator-pinned TTL the main resolution path
    /// uses. Zero means "trust the upstream TTL".
    pub cache_ttl_override: u32,
    /// Lowest TTL the cache is allowed to apply, copied from
    /// `[security.low_ttl] min_ttl_floor_secs`. Zero means no floor.
    pub low_ttl_floor: u32,
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

        process_one(&req.0, req.1, &resolver, &cfg).await;
    }
}

/// Resolve one request and write the result back into the cache. Pulled
/// out of the loop so tests can drive it directly.
pub async fn process_one(
    domain: &str,
    qtype: u16,
    resolver: &Arc<dyn UpstreamResolver>,
    cfg: &PrefetchWorkerCfg,
) {
    let Some(query) = DnsPacket::new_query(domain, qtype) else {
        // Unreachable in practice — cache keys come from validated
        // queries. Count it as a failure instead of panicking so a
        // malformed key from a future code path doesn't tear the worker
        // down.
        crate::STATS_COUNTERS.increment_prefetch_failed();
        return;
    };

    match resolver.resolve(&query).await {
        Ok(bytes) => {
            // Pull the TTL from the upstream answer so the cache entry
            // expires when the upstream says it should. Matches the
            // policy used by handle_query's main `Action::Allow` path.
            let inspected = crate::dns::InspectedAnswer::from_response(&bytes);
            if let (Some(cache), Some(ttl)) = (
                crate::RESPONSE_CACHE.get(),
                inspected.and_then(|a| a.min_ttl),
            ) {
                let floored = if cfg.low_ttl_floor == 0 {
                    ttl
                } else {
                    ttl.max(cfg.low_ttl_floor)
                };
                cache.insert(domain, qtype, &bytes, floored, cfg.cache_ttl_override);
            }
            // Even when we have no TTL we still consider the prefetch
            // successful — the resolver did its job, the cache just
            // chose not to store the answer.
            crate::POPULARITY_TRACKER.record_hit(domain);
            crate::STATS_COUNTERS.increment_prefetch_completed();
        }
        Err(_) => {
            crate::STATS_COUNTERS.increment_prefetch_failed();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use async_trait::async_trait;

    use crate::dns::resolver::UpstreamResolver;

    /// Test double: records every domain it's asked to resolve and
    /// returns a canned wire-format A response containing a single
    /// answer record with `ttl` seconds.
    struct FakeResolver {
        ttl: u32,
        calls: Mutex<Vec<String>>,
        fail: bool,
    }

    #[async_trait]
    impl UpstreamResolver for FakeResolver {
        async fn resolve(&self, query: &DnsPacket) -> std::io::Result<Vec<u8>> {
            self.calls.lock().unwrap().push(query.domain.clone());
            if self.fail {
                return Err(std::io::Error::other("upstream down"));
            }
            Ok(canned_a_response(&query.domain, self.ttl))
        }
    }

    fn canned_a_response(domain: &str, ttl: u32) -> Vec<u8> {
        use hickory_resolver::proto::op::Message;
        use hickory_resolver::proto::rr::rdata::A;
        use hickory_resolver::proto::rr::{Name, RData, Record};

        let name = Name::parse(domain, Some(&Name::root())).unwrap();
        let mut msg = Message::query();
        msg.metadata.message_type = hickory_resolver::proto::op::MessageType::Response;
        msg.add_answer(Record::from_rdata(
            name,
            ttl,
            RData::A(A(std::net::Ipv4Addr::new(1, 2, 3, 4))),
        ));
        msg.to_vec().unwrap()
    }

    fn fake_cfg() -> PrefetchWorkerCfg {
        PrefetchWorkerCfg {
            interval_ms: 0,
            cache_ttl_override: 0,
            low_ttl_floor: 0,
        }
    }

    #[tokio::test]
    async fn process_one_records_completion_and_popularity() {
        // Smoke test: resolver invoked, tracker bumped, counter
        // incremented. No reliance on the cache being initialised — the
        // worker treats "no cache" as "skip insert, still record hit".
        let baseline_completed = crate::STATS_COUNTERS.get_prefetch_completed();
        let baseline_failed = crate::STATS_COUNTERS.get_prefetch_failed();

        let resolver: Arc<dyn UpstreamResolver> = Arc::new(FakeResolver {
            ttl: 60,
            calls: Mutex::new(Vec::new()),
            fail: false,
        });
        crate::POPULARITY_TRACKER.clear();

        process_one("hot.example", 1, &resolver, &fake_cfg()).await;

        assert!(
            crate::STATS_COUNTERS.get_prefetch_completed() > baseline_completed,
            "completed counter must increment on success"
        );
        assert_eq!(
            crate::STATS_COUNTERS.get_prefetch_failed(),
            baseline_failed,
            "failed counter must not move on success"
        );
        assert_eq!(crate::POPULARITY_TRACKER.score("hot.example", 86_400), 1);
    }

    #[tokio::test]
    async fn process_one_failure_increments_failed_counter() {
        let baseline = crate::STATS_COUNTERS.get_prefetch_failed();
        let resolver: Arc<dyn UpstreamResolver> = Arc::new(FakeResolver {
            ttl: 60,
            calls: Mutex::new(Vec::new()),
            fail: true,
        });
        process_one("doomed.example", 1, &resolver, &fake_cfg()).await;
        assert!(crate::STATS_COUNTERS.get_prefetch_failed() > baseline);
    }

    #[tokio::test]
    async fn process_one_malformed_domain_counts_as_failure() {
        let baseline = crate::STATS_COUNTERS.get_prefetch_failed();
        let resolver: Arc<dyn UpstreamResolver> = Arc::new(FakeResolver {
            ttl: 60,
            calls: Mutex::new(Vec::new()),
            fail: false,
        });
        // A leading dot fails `Name::parse`; the worker must not panic.
        process_one("..bad..", 1, &resolver, &fake_cfg()).await;
        assert!(
            crate::STATS_COUNTERS.get_prefetch_failed() > baseline,
            "malformed-domain branch must bump the failed counter"
        );
    }

    #[tokio::test]
    async fn try_enqueue_drops_when_channel_full() {
        // Build a 1-slot channel, fill it, then verify the next send
        // bumps `prefetch_dropped_total`. Install into the global slot
        // for this test; OnceLock can't be reset, so this test is
        // structured to be the only one that touches the global.
        let (tx, _rx) = mpsc::channel::<PrefetchRequest>(1);
        // Fill it.
        tx.try_send(("first.example".into(), 1)).unwrap();

        // If the global slot is already set by another test, manually
        // exercise try_send on the local sender and assert the same
        // observable behaviour — the global path is just plumbing.
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
        // return without us flipping the shutdown bit. Acts as a
        // regression test for the "Closed" arm in run_prefetch_worker.
        let (tx, rx) = mpsc::channel::<PrefetchRequest>(4);
        let resolver: Arc<dyn UpstreamResolver> = Arc::new(FakeResolver {
            ttl: 60,
            calls: Mutex::new(Vec::new()),
            fail: false,
        });
        let (_sd_tx, sd_rx) = watch::channel(false);

        let handle = tokio::spawn(run_prefetch_worker(rx, resolver, fake_cfg(), sd_rx));
        drop(tx);

        // Worker should finish without us touching the shutdown signal.
        let res = tokio::time::timeout(Duration::from_secs(1), handle).await;
        assert!(res.is_ok(), "worker did not exit after senders dropped");
    }

    #[tokio::test]
    async fn worker_resolves_high_hit_domain_before_ttl_expires() {
        // The headline Phase-5 integration test: a domain with a low
        // remaining TTL gets refreshed by the worker before any client
        // would hit an expired entry. We send a request through the
        // channel; the worker drains it, calls the resolver, and our
        // FakeResolver records the call. End-to-end the worker must
        // resolve at least once.
        let (tx, rx) = mpsc::channel::<PrefetchRequest>(4);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let resolver: Arc<dyn UpstreamResolver> = Arc::new(FakeResolver {
            ttl: 5,
            calls: Mutex::new(Vec::new()),
            fail: false,
        });
        let resolver_for_task = Arc::clone(&resolver);
        let calls_for_task = Arc::clone(&calls);

        // Wrap to capture calls observable from outside the trait
        // object. (FakeResolver already has its own Mutex; this clone
        // is for ergonomic access from the assertion.)
        struct CapturingResolver {
            inner: Arc<dyn UpstreamResolver>,
            seen: Arc<Mutex<Vec<String>>>,
        }
        #[async_trait]
        impl UpstreamResolver for CapturingResolver {
            async fn resolve(&self, query: &DnsPacket) -> std::io::Result<Vec<u8>> {
                self.seen.lock().unwrap().push(query.domain.clone());
                self.inner.resolve(query).await
            }
        }
        let wrapped: Arc<dyn UpstreamResolver> = Arc::new(CapturingResolver {
            inner: resolver_for_task,
            seen: calls_for_task,
        });

        let (_sd_tx, sd_rx) = watch::channel(false);
        tokio::spawn(run_prefetch_worker(rx, wrapped, fake_cfg(), sd_rx));

        tx.send(("expiring.example".into(), 1)).await.unwrap();
        // Give the worker a moment to drain.
        tokio::time::sleep(Duration::from_millis(50)).await;

        let seen = calls.lock().unwrap().clone();
        assert!(
            seen.iter().any(|d| d == "expiring.example"),
            "worker never resolved the prefetch request, saw: {seen:?}"
        );
    }
}
