use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, broadcast};

use crate::protocol::{StatAction, StatError, StatEvent};

#[allow(dead_code)]
pub const DEFAULT_WINDOW: Duration = Duration::from_secs(3600); // 1 hour

pub struct RollingStats {
    pub total: u64,
    pub blocked: u64,
    pub allowed: u64,
    pub proxied: u64,
    /// (time_received, event) — sliding window
    events: VecDeque<(Instant, StatEvent)>,
    window: Duration,
    /// All-time domain hit counts by hash
    pub domain_hits: HashMap<u64, u64>,
    /// All-time client hit counts by IP bytes
    pub client_hits: HashMap<[u8; 16], u64>,
}

impl RollingStats {
    pub fn new(window: Duration) -> Self {
        Self {
            total: 0,
            blocked: 0,
            allowed: 0,
            proxied: 0,
            events: VecDeque::new(),
            window,
            domain_hits: HashMap::new(),
            client_hits: HashMap::new(),
        }
    }

    pub fn record(&mut self, event: StatEvent) {
        self.total += 1;

        match &event.action {
            // A cache hit is an allowed answer that skipped the upstream.
            StatAction::Allowed | StatAction::AllowedWithOverride | StatAction::Cached => {
                self.allowed += 1
            }
            StatAction::Proxied => self.proxied += 1,
            StatAction::Blocked(_)
            | StatAction::Suspicious(_)
            | StatAction::HighlySuspicious(_)
            | StatAction::Error(StatError::DnssecBogus) => self.blocked += 1,
            // Counted in `total` only: neither an answer nor a block.
            StatAction::Error(StatError::Upstream) => {}
        }

        *self.domain_hits.entry(event.domain_hash).or_insert(0) += 1;
        *self.client_hits.entry(event.client_ip).or_insert(0) += 1;

        let now = Instant::now();
        self.events.push_back((now, event));
        self.evict_old();
    }

    pub fn evict_old(&mut self) {
        let now = Instant::now();
        while let Some((ts, _)) = self.events.front() {
            if now.duration_since(*ts) > self.window {
                self.events.pop_front();
            } else {
                break;
            }
        }
    }

    #[allow(dead_code)]
    pub fn window_events(&self) -> &VecDeque<(Instant, StatEvent)> {
        &self.events
    }

    #[allow(dead_code)]
    pub fn top_domains(&self, n: usize) -> Vec<(u64, u64)> {
        let mut pairs: Vec<(u64, u64)> = self.domain_hits.iter().map(|(&k, &v)| (k, v)).collect();
        pairs.sort_unstable_by_key(|b| std::cmp::Reverse(b.1));
        pairs.truncate(n);
        pairs
    }

    #[allow(dead_code)]
    pub fn top_clients(&self, n: usize) -> Vec<([u8; 16], u64)> {
        let mut pairs: Vec<([u8; 16], u64)> =
            self.client_hits.iter().map(|(&k, &v)| (k, v)).collect();
        pairs.sort_unstable_by_key(|b| std::cmp::Reverse(b.1));
        pairs.truncate(n);
        pairs
    }
}

pub struct AppState {
    /// Host-index entries merged with `live_domains`. Readers use this one.
    pub domain_map: Arc<RwLock<HashMap<u64, String>>>,
    /// Mappings learned at runtime (socket `DomainMapping`, NATS). Kept apart
    /// so an index reload can replace `domain_map` without dropping them.
    live_domains: RwLock<HashMap<u64, String>>,
    pub stats: Arc<RwLock<RollingStats>>,
    /// Every event, whatever its origin (Unix socket or federation).
    events_tx: broadcast::Sender<StatEvent>,
    /// Only events produced by the local dgaard daemon. Federation
    /// publishers read this one so remote events are never re-emitted.
    local_tx: broadcast::Sender<StatEvent>,
}

impl AppState {
    pub fn new(window: Duration) -> Self {
        let (events_tx, _) = broadcast::channel(256);
        let (local_tx, _) = broadcast::channel(256);
        Self {
            domain_map: Arc::new(RwLock::new(HashMap::new())),
            live_domains: RwLock::new(HashMap::new()),
            stats: Arc::new(RwLock::new(RollingStats::new(window))),
            events_tx,
            local_tx,
        }
    }

    /// Record an event produced by the local dgaard daemon.
    pub async fn record_event(&self, event: StatEvent) {
        self.record(event.clone()).await;
        let _ = self.local_tx.send(event);
    }

    /// Record an event received from a federated peer (e.g. NATS). It feeds
    /// stats and `subscribe()` but not `subscribe_local()`.
    pub async fn record_remote_event(&self, event: StatEvent) {
        self.record(event).await;
    }

    async fn record(&self, event: StatEvent) {
        // Update the rolling stats first so a subscriber that reads `stats`
        // immediately after receiving the broadcast sees a counter that
        // already includes this event. The previous order opened a brief
        // TOCTOU window where the counter trailed the broadcast.
        self.stats.write().await.record(event.clone());
        let _ = self.events_tx.send(event);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<StatEvent> {
        self.events_tx.subscribe()
    }

    /// Subscribe to events from the local daemon only.
    pub fn subscribe_local(&self) -> broadcast::Receiver<StatEvent> {
        self.local_tx.subscribe()
    }

    /// Record a mapping learned at runtime. It survives index reloads.
    pub async fn insert_domain(&self, hash: u64, domain: String) {
        // Lock order: live_domains, then domain_map (same as replace_index).
        let mut live = self.live_domains.write().await;
        live.insert(hash, domain.clone());
        self.domain_map.write().await.insert(hash, domain);
    }

    /// Replace the host-index part of `domain_map` under a single write lock.
    /// Entries missing from `index` disappear; runtime mappings are kept.
    pub async fn replace_index(&self, mut index: HashMap<u64, String>) {
        // Hold the read lock across the swap so a concurrent `insert_domain`
        // cannot land in the old map and be lost.
        let live = self.live_domains.read().await;
        index.extend(live.iter().map(|(hash, domain)| (*hash, domain.clone())));
        let old = std::mem::replace(&mut *self.domain_map.write().await, index);
        drop(live);
        // Free a potentially multi-million-entry map outside the locks.
        drop(old);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{StatAction, StatBlockReason, StatEvent};

    fn make_event(hash: u64, ip: [u8; 16], action: StatAction) -> StatEvent {
        StatEvent {
            timestamp: 0,
            domain_hash: hash,
            client_ip: ip,
            action,
        }
    }

    fn ip(a: u8) -> [u8; 16] {
        [a, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    }

    #[test]
    fn test_record_counters() {
        let mut stats = RollingStats::new(DEFAULT_WINDOW);

        stats.record(make_event(1, ip(1), StatAction::Allowed));
        stats.record(make_event(2, ip(2), StatAction::Proxied));
        stats.record(make_event(
            3,
            ip(3),
            StatAction::Blocked(StatBlockReason::STATIC_BLACKLIST),
        ));
        stats.record(make_event(
            4,
            ip(4),
            StatAction::Suspicious(StatBlockReason::HIGH_ENTROPY),
        ));
        stats.record(make_event(
            5,
            ip(5),
            StatAction::HighlySuspicious(StatBlockReason::NRD_LIST),
        ));

        assert_eq!(stats.total, 5);
        assert_eq!(stats.allowed, 1);
        assert_eq!(stats.proxied, 1);
        assert_eq!(stats.blocked, 3); // Blocked + Suspicious + HighlySuspicious
    }

    #[test]
    fn test_sliding_window_eviction() {
        let window = Duration::from_millis(50);
        let mut stats = RollingStats::new(window);

        stats.record(make_event(1, ip(1), StatAction::Allowed));
        stats.record(make_event(2, ip(2), StatAction::Allowed));
        assert_eq!(stats.window_events().len(), 2);

        // Manually push old events
        let old_instant = Instant::now() - Duration::from_millis(200);
        // Replace events with artificially old timestamps
        stats.events.clear();
        stats
            .events
            .push_back((old_instant, make_event(1, ip(1), StatAction::Allowed)));
        stats
            .events
            .push_back((old_instant, make_event(2, ip(2), StatAction::Allowed)));

        stats.evict_old();
        assert_eq!(stats.window_events().len(), 0);
    }

    #[test]
    fn test_top_domains_sorted_descending() {
        let mut stats = RollingStats::new(DEFAULT_WINDOW);

        // hash 1 hit 3 times, hash 2 hit 1 time, hash 3 hit 5 times
        for _ in 0..3 {
            stats.record(make_event(1, ip(1), StatAction::Allowed));
        }
        stats.record(make_event(2, ip(2), StatAction::Allowed));
        for _ in 0..5 {
            stats.record(make_event(3, ip(3), StatAction::Allowed));
        }

        let top = stats.top_domains(3);
        assert_eq!(top[0], (3, 5));
        assert_eq!(top[1], (1, 3));
        assert_eq!(top[2], (2, 1));
    }

    #[test]
    fn test_top_domains_truncates_to_n() {
        let mut stats = RollingStats::new(DEFAULT_WINDOW);
        for i in 0..10u64 {
            stats.record(make_event(i, ip(1), StatAction::Allowed));
        }
        let top = stats.top_domains(5);
        assert_eq!(top.len(), 5);
    }

    #[test]
    fn test_top_clients_sorted_descending() {
        let mut stats = RollingStats::new(DEFAULT_WINDOW);

        for _ in 0..4 {
            stats.record(make_event(1, ip(10), StatAction::Allowed));
        }
        for _ in 0..2 {
            stats.record(make_event(1, ip(20), StatAction::Allowed));
        }
        stats.record(make_event(1, ip(30), StatAction::Allowed));

        let top = stats.top_clients(3);
        assert_eq!(top[0].1, 4);
        assert_eq!(top[1].1, 2);
        assert_eq!(top[2].1, 1);
    }

    #[tokio::test]
    async fn test_domain_map_insertion_and_lookup() {
        let state = AppState::new(DEFAULT_WINDOW);

        state
            .insert_domain(0xdeadbeef, "example.com".to_string())
            .await;
        state
            .insert_domain(0xcafebabe, "test.org".to_string())
            .await;

        let map = state.domain_map.read().await;
        assert_eq!(map.get(&0xdeadbeef), Some(&"example.com".to_string()));
        assert_eq!(map.get(&0xcafebabe), Some(&"test.org".to_string()));
        assert!(map.get(&0x00000000).is_none());
    }

    #[tokio::test]
    async fn test_record_event_async() {
        let state = AppState::new(DEFAULT_WINDOW);

        state
            .record_event(make_event(1, ip(1), StatAction::Allowed))
            .await;
        state
            .record_event(make_event(
                2,
                ip(2),
                StatAction::Blocked(StatBlockReason::ABP_RULE),
            ))
            .await;

        let stats = state.stats.read().await;
        assert_eq!(stats.total, 2);
        assert_eq!(stats.allowed, 1);
        assert_eq!(stats.blocked, 1);
    }

    #[tokio::test]
    async fn test_replace_index_drops_stale_entries_and_keeps_live_ones() {
        let state = AppState::new(DEFAULT_WINDOW);
        state
            .replace_index(HashMap::from([
                (1, "old.test".to_string()),
                (2, "kept.test".to_string()),
            ]))
            .await;
        state.insert_domain(9, "live.test".to_string()).await;

        state
            .replace_index(HashMap::from([
                (2, "kept.test".to_string()),
                (3, "new.test".to_string()),
            ]))
            .await;

        let map = state.domain_map.read().await;
        assert_eq!(map.len(), 3);
        assert!(map.get(&1).is_none(), "entry removed from the index");
        assert_eq!(map.get(&2).map(String::as_str), Some("kept.test"));
        assert_eq!(map.get(&3).map(String::as_str), Some("new.test"));
        assert_eq!(map.get(&9).map(String::as_str), Some("live.test"));
    }

    #[tokio::test]
    async fn test_live_mapping_wins_over_index_entry() {
        let state = AppState::new(DEFAULT_WINDOW);
        state.insert_domain(1, "from-socket.test".to_string()).await;
        state
            .replace_index(HashMap::from([(1, "from-index.test".to_string())]))
            .await;
        assert_eq!(
            state.domain_map.read().await.get(&1).map(String::as_str),
            Some("from-socket.test")
        );
    }

    #[tokio::test]
    async fn test_local_event_reaches_both_broadcasts() {
        let state = AppState::new(DEFAULT_WINDOW);
        let mut all_rx = state.subscribe();
        let mut local_rx = state.subscribe_local();

        let event = make_event(1, ip(1), StatAction::Allowed);
        state.record_event(event.clone()).await;

        assert_eq!(all_rx.try_recv().unwrap(), event);
        assert_eq!(local_rx.try_recv().unwrap(), event);
    }

    #[tokio::test]
    async fn test_remote_event_skips_local_broadcast() {
        let state = AppState::new(DEFAULT_WINDOW);
        let mut all_rx = state.subscribe();
        let mut local_rx = state.subscribe_local();

        let event = make_event(1, ip(1), StatAction::Allowed);
        state.record_remote_event(event.clone()).await;

        assert_eq!(all_rx.try_recv().unwrap(), event);
        assert!(matches!(
            local_rx.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));
        assert_eq!(state.stats.read().await.total, 1);
    }
}
