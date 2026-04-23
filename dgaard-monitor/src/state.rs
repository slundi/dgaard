use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, broadcast};

use crate::protocol::{StatAction, StatEvent};

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
            StatAction::Allowed => self.allowed += 1,
            StatAction::Proxied => self.proxied += 1,
            StatAction::Blocked(_)
            | StatAction::Suspicious(_)
            | StatAction::HighlySuspicious(_) => self.blocked += 1,
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
        pairs.sort_unstable_by(|a, b| b.1.cmp(&a.1));
        pairs.truncate(n);
        pairs
    }

    #[allow(dead_code)]
    pub fn top_clients(&self, n: usize) -> Vec<([u8; 16], u64)> {
        let mut pairs: Vec<([u8; 16], u64)> =
            self.client_hits.iter().map(|(&k, &v)| (k, v)).collect();
        pairs.sort_unstable_by(|a, b| b.1.cmp(&a.1));
        pairs.truncate(n);
        pairs
    }
}

pub struct AppState {
    pub domain_map: Arc<RwLock<HashMap<u64, String>>>,
    pub stats: Arc<RwLock<RollingStats>>,
    events_tx: broadcast::Sender<StatEvent>,
}

impl AppState {
    pub fn new(window: Duration) -> Self {
        let (events_tx, _) = broadcast::channel(256);
        Self {
            domain_map: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(RollingStats::new(window))),
            events_tx,
        }
    }

    pub async fn record_event(&self, event: StatEvent) {
        let _ = self.events_tx.send(event.clone());
        self.stats.write().await.record(event);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<StatEvent> {
        self.events_tx.subscribe()
    }

    pub async fn insert_domain(&self, hash: u64, domain: String) {
        self.domain_map.write().await.insert(hash, domain);
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
}
