//! Statistics collection and telemetry streaming.
//!
//! This module provides an MPSC channel-based system for collecting DNS query
//! events from worker tasks and streaming them to external consumers via Unix socket.

use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::mpsc;

use crate::GLOBAL_SEED;
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
        let hash =
            twox_hash::XxHash64::oneshot(GLOBAL_SEED.load(Ordering::Relaxed), domain.as_bytes());

        // Send domain mapping if not already announced
        if !self.announced.contains(&hash) {
            let mapping = StatMessage::DomainMapping {
                hash,
                domain: domain.to_string(),
            };
            // Use try_send to avoid blocking - drop if full
            let _ = self.tx.try_send(mapping);
            self.announced.insert(hash);
        }

        // Send the event
        let event = StatEvent::new(hash, client_addr, action);
        let _ = self.tx.try_send(StatMessage::Event(event));
    }

    /// Send a block event with a specific reason.
    pub fn send_block(
        &self,
        domain: &str,
        client_addr: std::net::SocketAddr,
        reason: StatBlockReason,
    ) {
        self.send_event(domain, client_addr, StatAction::Blocked(reason));
    }

    /// Send an allowed event (whitelist hit or passed filters).
    pub fn send_allowed(&self, domain: &str, client_addr: std::net::SocketAddr) {
        self.send_event(domain, client_addr, StatAction::Allowed);
    }

    /// Send a proxied event (forwarded to upstream).
    pub fn send_proxied(&self, domain: &str, client_addr: std::net::SocketAddr) {
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
/// Returns a sender (clonable for distribution to workers) and a receiver
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
}

impl StatsCounters {
    pub const fn new() -> Self {
        Self {
            queries_total: AtomicU64::new(0),
            queries_blocked: AtomicU64::new(0),
            queries_allowed: AtomicU64::new(0),
            queries_proxied: AtomicU64::new(0),
        }
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
        sender.send_block("example.com", addr, StatBlockReason::StaticBlacklist);

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
}
