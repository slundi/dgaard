//! Statistics collection and telemetry streaming.
//!
//! This module provides an MPSC channel-based system for collecting DNS query
//! events from worker tasks and streaming them to external consumers via Unix socket.

use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::mpsc;

use crate::GLOBAL_SEED;
use crate::debug::debug_print;
use crate::model::{StatAction, StatBlockReason, StatEvent, StatMessage};

/// Channel capacity for the stats queue.
/// Bounded to provide backpressure when the collector is slow.
const CHANNEL_CAPACITY: usize = 4096;

/// Sender handle for emitting stat events from DNS handlers.
///
/// Clone this to distribute across worker tasks. Sending is non-blocking
/// and will drop events if the channel is full (to avoid slowing DNS resolution).
#[derive(Clone)]
pub struct StatsSender {
    tx: mpsc::Sender<StatMessage>,
    /// Tracks which domain hashes have already been announced.
    /// Uses a thread-safe set to avoid duplicate DomainMapping messages.
    announced: std::sync::Arc<dashmap::DashSet<u64>>,
}

impl StatsSender {
    /// Send a DNS query event to the stats collector.
    ///
    /// This method:
    /// 1. Sends a DomainMapping message if this domain hasn't been seen before
    /// 2. Sends the StatEvent with query details
    ///
    /// Events are dropped silently if the channel is full (non-blocking).
    pub fn send_event(&self, domain: &str, client_addr: std::net::SocketAddr, action: StatAction) {
        debug_print!(
            "Send DNS query for {} from {}: {:?}",
            domain,
            client_addr,
            action
        );
        let hash =
            twox_hash::XxHash64::oneshot(GLOBAL_SEED.load(Ordering::Relaxed), domain.as_bytes());

        // Send domain mapping if not already announced
        if !self.announced.contains(&hash) {
            let mapping = StatMessage::DomainMapping {
                hash,
                domain: domain.to_string(),
            };
            // Only mark as announced if the message was actually queued.
            // If the channel is full, skip the insert so we retry next time.
            if self.tx.try_send(mapping).is_ok() {
                self.announced.insert(hash);
            } else {
                crate::STATS_COUNTERS.increment_stats_dropped();
            }
        }

        // Send the event
        let event = StatEvent::new(hash, client_addr, action);
        if self.tx.try_send(StatMessage::Event(event)).is_err() {
            crate::STATS_COUNTERS.increment_stats_dropped();
        }
    }

    /// Send a block event with a specific reason.
    pub fn send_block(
        &self,
        domain: &str,
        client_addr: std::net::SocketAddr,
        reason: StatBlockReason,
    ) {
        debug_print!(
            "Event blocked for {} from {}: {:?}",
            domain,
            client_addr,
            reason
        );
        self.send_event(domain, client_addr, StatAction::Blocked(reason));
    }

    /// Send an allowed event (whitelist hit or passed filters).
    pub fn send_allowed(&self, domain: &str, client_addr: std::net::SocketAddr) {
        debug_print!("Event allowed for {} from {}", domain, client_addr);
        self.send_event(domain, client_addr, StatAction::Allowed);
    }

    /// Send a proxied event (forwarded to upstream).
    pub fn send_proxied(&self, domain: &str, client_addr: std::net::SocketAddr) {
        debug_print!("Event proxied for {} from {}", domain, client_addr);
        self.send_event(domain, client_addr, StatAction::Proxied);
    }
}

/// Receiver handle for the stats collector task.
pub struct StatsReceiver {
    rx: mpsc::Receiver<StatMessage>,
}

impl StatsReceiver {
    /// Receive the next stat message.
    ///
    /// Returns `None` when all senders have been dropped.
    pub async fn recv(&mut self) -> Option<StatMessage> {
        self.rx.recv().await
    }

    /// Try to receive a message without blocking.
    pub fn try_recv(&mut self) -> Result<StatMessage, mpsc::error::TryRecvError> {
        self.rx.try_recv()
    }
}

/// Create a new stats channel pair.
///
/// Returns a sender (cloneable for distribution to workers) and a receiver
/// for the collector task.
pub fn channel() -> (StatsSender, StatsReceiver) {
    let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
    let sender = StatsSender {
        tx,
        announced: std::sync::Arc::new(dashmap::DashSet::new()),
    };
    let receiver = StatsReceiver { rx };
    (sender, receiver)
}

/// Global statistics counters for quick access without channel overhead.
pub struct StatsCounters {
    pub queries_total: AtomicU64,
    pub queries_blocked: AtomicU64,
    pub queries_allowed: AtomicU64,
    pub queries_proxied: AtomicU64,
    pub queries_cached: AtomicU64,
    pub queries_upstream_errors: AtomicU64,
    pub stats_events_dropped: AtomicU64,

    // Phase 2 — iterative recursive resolver visibility.
    // Each one increments at most a handful of times per top-level
    // client query, so plain Relaxed atomics are cheap enough that the
    // hot path doesn't notice them.
    pub recursive_queries: AtomicU64,
    pub recursive_referrals: AtomicU64,
    pub recursive_glue_hit: AtomicU64,
    pub recursive_glue_miss: AtomicU64,
    pub recursive_tcp_fallback: AtomicU64,
    pub recursive_cycle_detected: AtomicU64,
    pub recursive_depth_cap_hit: AtomicU64,
    pub recursive_query_cap_hit: AtomicU64,
    pub recursive_bailiwick_reject: AtomicU64,

    // Phase 6 session 2 — chain-of-trust construction outcomes from the
    // iterative resolver. `chain_built` is the success path (DNSKEY +
    // DS verified all the way to root); `chain_broken` is any Bogus
    // verdict from the validator. Both are intended as health
    // indicators on dashboards, not per-query stats.
    pub recursive_dnssec_chain_built: AtomicU64,
    pub recursive_dnssec_chain_broken: AtomicU64,

    // Phase 5 — prefetch worker observability.
    pub prefetch_dropped: AtomicU64,
    pub prefetch_completed: AtomicU64,
    pub prefetch_failed: AtomicU64,
}

impl StatsCounters {
    pub const fn new() -> Self {
        Self {
            queries_total: AtomicU64::new(0),
            queries_blocked: AtomicU64::new(0),
            queries_allowed: AtomicU64::new(0),
            queries_proxied: AtomicU64::new(0),
            queries_cached: AtomicU64::new(0),
            queries_upstream_errors: AtomicU64::new(0),
            stats_events_dropped: AtomicU64::new(0),

            recursive_queries: AtomicU64::new(0),
            recursive_referrals: AtomicU64::new(0),
            recursive_glue_hit: AtomicU64::new(0),
            recursive_glue_miss: AtomicU64::new(0),
            recursive_tcp_fallback: AtomicU64::new(0),
            recursive_cycle_detected: AtomicU64::new(0),
            recursive_depth_cap_hit: AtomicU64::new(0),
            recursive_query_cap_hit: AtomicU64::new(0),
            recursive_bailiwick_reject: AtomicU64::new(0),

            recursive_dnssec_chain_built: AtomicU64::new(0),
            recursive_dnssec_chain_broken: AtomicU64::new(0),

            prefetch_dropped: AtomicU64::new(0),
            prefetch_completed: AtomicU64::new(0),
            prefetch_failed: AtomicU64::new(0),
        }
    }

    pub fn increment_prefetch_dropped(&self) {
        self.prefetch_dropped.fetch_add(1, Ordering::Relaxed);
    }
    pub fn increment_prefetch_completed(&self) {
        self.prefetch_completed.fetch_add(1, Ordering::Relaxed);
    }
    pub fn increment_prefetch_failed(&self) {
        self.prefetch_failed.fetch_add(1, Ordering::Relaxed);
    }
    pub fn get_prefetch_dropped(&self) -> u64 {
        self.prefetch_dropped.load(Ordering::Relaxed)
    }
    pub fn get_prefetch_completed(&self) -> u64 {
        self.prefetch_completed.load(Ordering::Relaxed)
    }
    pub fn get_prefetch_failed(&self) -> u64 {
        self.prefetch_failed.load(Ordering::Relaxed)
    }

    pub fn increment_recursive_queries(&self) {
        self.recursive_queries.fetch_add(1, Ordering::Relaxed);
    }
    pub fn increment_recursive_referrals(&self) {
        self.recursive_referrals.fetch_add(1, Ordering::Relaxed);
    }
    pub fn increment_recursive_glue_hit(&self) {
        self.recursive_glue_hit.fetch_add(1, Ordering::Relaxed);
    }
    pub fn increment_recursive_glue_miss(&self) {
        self.recursive_glue_miss.fetch_add(1, Ordering::Relaxed);
    }
    pub fn increment_recursive_tcp_fallback(&self) {
        self.recursive_tcp_fallback.fetch_add(1, Ordering::Relaxed);
    }
    pub fn increment_recursive_cycle_detected(&self) {
        self.recursive_cycle_detected
            .fetch_add(1, Ordering::Relaxed);
    }
    pub fn increment_recursive_depth_cap_hit(&self) {
        self.recursive_depth_cap_hit.fetch_add(1, Ordering::Relaxed);
    }
    pub fn increment_recursive_query_cap_hit(&self) {
        self.recursive_query_cap_hit.fetch_add(1, Ordering::Relaxed);
    }
    pub fn increment_recursive_bailiwick_reject(&self) {
        self.recursive_bailiwick_reject
            .fetch_add(1, Ordering::Relaxed);
    }
    pub fn increment_recursive_dnssec_chain_built(&self) {
        self.recursive_dnssec_chain_built
            .fetch_add(1, Ordering::Relaxed);
    }
    pub fn increment_recursive_dnssec_chain_broken(&self) {
        self.recursive_dnssec_chain_broken
            .fetch_add(1, Ordering::Relaxed);
    }
    pub fn get_recursive_dnssec_chain_built(&self) -> u64 {
        self.recursive_dnssec_chain_built.load(Ordering::Relaxed)
    }
    pub fn get_recursive_dnssec_chain_broken(&self) -> u64 {
        self.recursive_dnssec_chain_broken.load(Ordering::Relaxed)
    }

    pub fn get_recursive_queries(&self) -> u64 {
        self.recursive_queries.load(Ordering::Relaxed)
    }
    pub fn get_recursive_referrals(&self) -> u64 {
        self.recursive_referrals.load(Ordering::Relaxed)
    }
    pub fn get_recursive_glue_hit(&self) -> u64 {
        self.recursive_glue_hit.load(Ordering::Relaxed)
    }
    pub fn get_recursive_glue_miss(&self) -> u64 {
        self.recursive_glue_miss.load(Ordering::Relaxed)
    }
    pub fn get_recursive_tcp_fallback(&self) -> u64 {
        self.recursive_tcp_fallback.load(Ordering::Relaxed)
    }
    pub fn get_recursive_cycle_detected(&self) -> u64 {
        self.recursive_cycle_detected.load(Ordering::Relaxed)
    }
    pub fn get_recursive_depth_cap_hit(&self) -> u64 {
        self.recursive_depth_cap_hit.load(Ordering::Relaxed)
    }
    pub fn get_recursive_query_cap_hit(&self) -> u64 {
        self.recursive_query_cap_hit.load(Ordering::Relaxed)
    }
    pub fn get_recursive_bailiwick_reject(&self) -> u64 {
        self.recursive_bailiwick_reject.load(Ordering::Relaxed)
    }

    pub fn increment_total(&self) {
        self.queries_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_blocked(&self) {
        self.queries_blocked.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_allowed(&self) {
        self.queries_allowed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_proxied(&self) {
        self.queries_proxied.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_cached(&self) {
        self.queries_cached.fetch_add(1, Ordering::Relaxed);
    }

    /// Incremented when forwarding a query upstream fails (all upstreams
    /// timed out or refused). The client receives a SERVFAIL.
    pub fn increment_upstream_errors(&self) {
        self.queries_upstream_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_stats_dropped(&self) {
        self.stats_events_dropped.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get_total(&self) -> u64 {
        self.queries_total.load(Ordering::Relaxed)
    }

    pub fn get_blocked(&self) -> u64 {
        self.queries_blocked.load(Ordering::Relaxed)
    }

    pub fn get_allowed(&self) -> u64 {
        self.queries_allowed.load(Ordering::Relaxed)
    }

    pub fn get_proxied(&self) -> u64 {
        self.queries_proxied.load(Ordering::Relaxed)
    }

    pub fn get_cached(&self) -> u64 {
        self.queries_cached.load(Ordering::Relaxed)
    }

    pub fn get_upstream_errors(&self) -> u64 {
        self.queries_upstream_errors.load(Ordering::Relaxed)
    }

    pub fn get_stats_dropped(&self) -> u64 {
        self.stats_events_dropped.load(Ordering::Relaxed)
    }
}

impl Default for StatsCounters {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn init_test_seed() {
        GLOBAL_SEED.store(42, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn test_channel_send_receive() {
        init_test_seed();
        let (sender, mut receiver) = channel();

        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        sender.send_proxied("example.com", addr);

        // Should receive DomainMapping first
        let msg1 = receiver.recv().await.unwrap();
        assert!(matches!(msg1, StatMessage::DomainMapping { .. }));

        // Then the Event
        let msg2 = receiver.recv().await.unwrap();
        assert!(matches!(msg2, StatMessage::Event(_)));
    }

    #[tokio::test]
    async fn test_domain_mapping_sent_once() {
        init_test_seed();
        let (sender, mut receiver) = channel();

        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        // Send two events for the same domain
        sender.send_proxied("example.com", addr);
        sender.send_block("example.com", addr, StatBlockReason::STATIC_BLACKLIST);

        // First domain: mapping + event
        let msg1 = receiver.recv().await.unwrap();
        assert!(matches!(msg1, StatMessage::DomainMapping { .. }));
        let msg2 = receiver.recv().await.unwrap();
        assert!(matches!(msg2, StatMessage::Event(_)));

        // Second event: no mapping (already announced), just event
        let msg3 = receiver.recv().await.unwrap();
        assert!(matches!(msg3, StatMessage::Event(_)));

        // No more messages
        assert!(receiver.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_different_domains_get_mappings() {
        init_test_seed();
        let (sender, mut receiver) = channel();

        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        sender.send_proxied("example.com", addr);
        sender.send_proxied("other.com", addr);

        // First domain
        let msg1 = receiver.recv().await.unwrap();
        assert!(
            matches!(msg1, StatMessage::DomainMapping { domain, .. } if domain == "example.com")
        );
        let _event1 = receiver.recv().await.unwrap();

        // Second domain gets its own mapping
        let msg3 = receiver.recv().await.unwrap();
        assert!(matches!(msg3, StatMessage::DomainMapping { domain, .. } if domain == "other.com"));
        let _event2 = receiver.recv().await.unwrap();
    }

    #[tokio::test]
    async fn test_sender_clone_shares_announced_set() {
        init_test_seed();
        let (sender1, mut receiver) = channel();
        let sender2 = sender1.clone();

        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        // Send from first sender
        sender1.send_proxied("example.com", addr);

        // Drain messages
        let _ = receiver.recv().await; // mapping
        let _ = receiver.recv().await; // event

        // Send from cloned sender - should NOT send mapping again
        sender2.send_proxied("example.com", addr);

        let msg = receiver.recv().await.unwrap();
        // Should be Event, not DomainMapping
        assert!(matches!(msg, StatMessage::Event(_)));
    }

    #[test]
    fn test_stats_counters() {
        let counters = StatsCounters::new();

        assert_eq!(counters.get_total(), 0);
        assert_eq!(counters.get_blocked(), 0);

        counters.increment_total();
        counters.increment_total();
        counters.increment_blocked();

        assert_eq!(counters.get_total(), 2);
        assert_eq!(counters.get_blocked(), 1);
        assert_eq!(counters.get_allowed(), 0);
        assert_eq!(counters.get_proxied(), 0);
    }

    #[test]
    fn test_try_recv_empty() {
        let (_sender, mut receiver) = channel();
        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn test_stats_counters_dropped() {
        let counters = StatsCounters::new();
        assert_eq!(counters.get_stats_dropped(), 0);
        counters.increment_stats_dropped();
        counters.increment_stats_dropped();
        assert_eq!(counters.get_stats_dropped(), 2);
    }

    #[test]
    fn test_stats_counters_upstream_errors() {
        let counters = StatsCounters::new();
        assert_eq!(counters.get_upstream_errors(), 0);
        counters.increment_upstream_errors();
        counters.increment_upstream_errors();
        counters.increment_upstream_errors();
        assert_eq!(counters.get_upstream_errors(), 3);
        // Other counters must remain unaffected.
        assert_eq!(counters.get_allowed(), 0);
        assert_eq!(counters.get_proxied(), 0);
    }

    #[tokio::test]
    async fn send_event_increments_drop_counter_when_channel_full() {
        init_test_seed();

        // Use a capacity-1 channel so it fills after the first domain mapping.
        let (tx, _rx) = mpsc::channel::<StatMessage>(1);
        let sender = StatsSender {
            tx,
            announced: std::sync::Arc::new(dashmap::DashSet::new()),
        };

        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        // First call: mapping fills the single slot → event is dropped.
        let before = crate::STATS_COUNTERS.get_stats_dropped();
        sender.send_event("overflow.test", addr, StatAction::Allowed);
        let after = crate::STATS_COUNTERS.get_stats_dropped();
        // The event try_send must have been dropped (channel already full).
        assert!(after > before, "expected at least one drop");
    }
}
