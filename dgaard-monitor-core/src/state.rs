use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, broadcast};

use crate::protocol::{StatAction, StatError, StatEvent};

pub const DEFAULT_WINDOW: Duration = Duration::from_secs(3600); // 1 hour

/// Default cap on events kept in the sliding window (56 bytes each, ~11 MB).
/// Without it the window grows with the query rate: 1.8 M events per hour
/// at 500 q/s.
pub const DEFAULT_MAX_WINDOW_EVENTS: usize = 200_000;

/// Distinct domains tracked by `RollingStats::domain_hits`.
pub const DOMAIN_HITS_CAPACITY: usize = 50_000;

/// Cap on mappings accepted from federation peers. Past it, new remote
/// mappings are refused so an untrusted publisher cannot exhaust memory.
pub const MAX_REMOTE_DOMAINS: usize = 100_000;

/// Default capacity of the event bus: enough to absorb a DNS burst while a
/// slow sink (SQLite flush, HTTP POST) catches up.
pub const DEFAULT_EVENT_BUFFER: usize = 8192;

/// Event consumers whose losses are counted (`dropped_total{sink}`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sink {
    Persistence,
    Forwarding,
    /// The HTTP queue of the forwarding sink overflowed.
    ForwardingHttp,
    Headless,
    NatsPublisher,
    Web,
}

impl Sink {
    pub const ALL: [Sink; 6] = [
        Sink::Persistence,
        Sink::Forwarding,
        Sink::ForwardingHttp,
        Sink::Headless,
        Sink::NatsPublisher,
        Sink::Web,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Sink::Persistence => "persistence",
            Sink::Forwarding => "forwarding",
            Sink::ForwardingHttp => "forwarding_http",
            Sink::Headless => "headless",
            Sink::NatsPublisher => "nats_publisher",
            Sink::Web => "web",
        }
    }
}

/// Hit counts per key, bounded to `capacity` keys.
///
/// When a new key arrives at capacity, the less frequent half of the keys is
/// forgotten (amortized O(1) per hit). Frequent keys keep exact counts; a
/// forgotten key that comes back restarts from zero, so counts of the long
/// tail are lower bounds.
#[derive(Debug)]
pub struct HitCounter {
    counts: HashMap<u64, u64>,
    capacity: usize,
}

impl HitCounter {
    pub fn new(capacity: usize) -> Self {
        Self {
            counts: HashMap::new(),
            capacity: capacity.max(2),
        }
    }

    pub fn increment(&mut self, key: u64) {
        if let Some(count) = self.counts.get_mut(&key) {
            *count += 1;
            return;
        }
        if self.counts.len() >= self.capacity {
            self.forget_least_frequent_half();
        }
        self.counts.insert(key, 1);
    }

    fn forget_least_frequent_half(&mut self) {
        let mut counts: Vec<u64> = self.counts.values().copied().collect();
        let middle = counts.len() / 2;
        let (_, median, _) = counts.select_nth_unstable(middle);
        let threshold = *median;
        self.counts.retain(|_, count| *count > threshold);
        // Many keys sharing the median count: drop down to half regardless.
        if self.counts.len() > middle {
            let mut kept: Vec<(u64, u64)> = self.counts.drain().collect();
            kept.sort_unstable_by_key(|&(_, count)| std::cmp::Reverse(count));
            kept.truncate(middle);
            self.counts.extend(kept);
        }
    }

    pub fn get(&self, key: u64) -> Option<u64> {
        self.counts.get(&key).copied()
    }

    pub fn len(&self) -> usize {
        self.counts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.counts.is_empty()
    }

    /// The `n` most frequent keys, most frequent first.
    pub fn top(&self, n: usize) -> Vec<(u64, u64)> {
        let mut pairs: Vec<(u64, u64)> = self.counts.iter().map(|(&k, &v)| (k, v)).collect();
        pairs.sort_unstable_by_key(|&(_, count)| std::cmp::Reverse(count));
        pairs.truncate(n);
        pairs
    }
}

pub struct RollingStats {
    pub total: u64,
    pub blocked: u64,
    pub allowed: u64,
    pub proxied: u64,
    /// (time_received, event) — sliding window, read by the REST services.
    events: VecDeque<(Instant, StatEvent)>,
    window: Duration,
    /// Most events kept in `events`; 0 keeps none (no reader configured).
    max_events: usize,
    /// Per-domain hit counts since startup, bounded (see `HitCounter`).
    pub domain_hits: HitCounter,
}

impl RollingStats {
    pub fn new(window: Duration) -> Self {
        Self::with_limit(window, DEFAULT_MAX_WINDOW_EVENTS)
    }

    /// Keep at most `max_events` events of the last `window`; 0 disables the
    /// window (counters still work).
    pub fn with_limit(window: Duration, max_events: usize) -> Self {
        Self {
            total: 0,
            blocked: 0,
            allowed: 0,
            proxied: 0,
            events: VecDeque::new(),
            window,
            max_events,
            domain_hits: HitCounter::new(DOMAIN_HITS_CAPACITY),
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

        self.domain_hits.increment(event.domain_hash);

        if self.max_events == 0 {
            return;
        }
        self.events.push_back((Instant::now(), event));
        self.evict_old();
        while self.events.len() > self.max_events {
            self.events.pop_front();
        }
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

    pub fn window_events(&self) -> &VecDeque<(Instant, StatEvent)> {
        &self.events
    }

    pub fn top_domains(&self, n: usize) -> Vec<(u64, u64)> {
        self.domain_hits.top(n)
    }
}

/// How `AppState` sizes its buffers.
#[derive(Debug, Clone)]
pub struct StateOptions {
    /// Length of the sliding window of recent events.
    pub window: Duration,
    /// Most events kept in the window; 0 keeps none.
    pub max_window_events: usize,
    /// How many events a sink may fall behind before it loses them.
    pub event_buffer: usize,
}

impl Default for StateOptions {
    fn default() -> Self {
        Self {
            window: DEFAULT_WINDOW,
            max_window_events: DEFAULT_MAX_WINDOW_EVENTS,
            event_buffer: DEFAULT_EVENT_BUFFER,
        }
    }
}

/// Poll `condition` until it holds or `timeout` elapses (broadcast channels
/// do not notify new subscriptions).
async fn wait_until(condition: impl Fn() -> bool, timeout: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if condition() {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

pub struct AppState {
    /// Host-index entries merged with `live_domains` and `remote_domains`.
    /// Readers use this one.
    pub domain_map: Arc<RwLock<HashMap<u64, String>>>,
    /// Mappings from the local dgaard socket (`DomainMapping`). Kept apart so
    /// an index reload can replace `domain_map` without dropping them.
    live_domains: RwLock<HashMap<u64, String>>,
    /// Mappings from federation peers (NATS). Untrusted: they never replace
    /// an index or live entry, and the table is capped at `MAX_REMOTE_DOMAINS`.
    remote_domains: RwLock<HashMap<u64, String>>,
    pub stats: Arc<RwLock<RollingStats>>,
    /// Every event, whatever its origin (Unix socket or federation).
    events_tx: broadcast::Sender<StatEvent>,
    /// Only events produced by the local dgaard daemon. Federation
    /// publishers read this one so remote events are never re-emitted.
    local_tx: broadcast::Sender<StatEvent>,
    /// Events lost per sink, indexed like `Sink::ALL`.
    dropped: [AtomicU64; Sink::ALL.len()],
}

impl AppState {
    pub fn new(window: Duration) -> Self {
        Self::with_options(StateOptions {
            window,
            ..StateOptions::default()
        })
    }

    /// `event_buffer` is how many events a sink may fall behind before it
    /// starts losing them.
    pub fn with_event_buffer(window: Duration, event_buffer: usize) -> Self {
        Self::with_options(StateOptions {
            window,
            event_buffer,
            ..StateOptions::default()
        })
    }

    pub fn with_options(options: StateOptions) -> Self {
        let (events_tx, _) = broadcast::channel(options.event_buffer);
        let (local_tx, _) = broadcast::channel(options.event_buffer);
        Self {
            domain_map: Arc::new(RwLock::new(HashMap::new())),
            live_domains: RwLock::new(HashMap::new()),
            remote_domains: RwLock::new(HashMap::new()),
            stats: Arc::new(RwLock::new(RollingStats::with_limit(
                options.window,
                options.max_window_events,
            ))),
            events_tx,
            local_tx,
            dropped: Default::default(),
        }
    }

    /// Count `count` events lost by `sink`.
    pub fn record_drop(&self, sink: Sink, count: u64) {
        self.dropped[sink as usize].fetch_add(count, Ordering::Relaxed);
    }

    pub fn dropped(&self, sink: Sink) -> u64 {
        self.dropped[sink as usize].load(Ordering::Relaxed)
    }

    /// `(sink name, events lost)` for every sink.
    pub fn dropped_counts(&self) -> Vec<(&'static str, u64)> {
        Sink::ALL
            .iter()
            .map(|sink| (sink.name(), self.dropped(*sink)))
            .collect()
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

    /// Sinks currently subscribed to every event (`subscribe`).
    pub fn subscriber_count(&self) -> usize {
        self.events_tx.receiver_count()
    }

    /// Publishers currently subscribed to local events (`subscribe_local`).
    pub fn local_subscriber_count(&self) -> usize {
        self.local_tx.receiver_count()
    }

    /// Wait until at least `count` sinks subscribed to every event, or until
    /// `timeout`. An event recorded before a sink subscribed never reaches it,
    /// so this tells when emitting is safe. Returns whether they did.
    pub async fn wait_for_subscribers(&self, count: usize, timeout: Duration) -> bool {
        wait_until(|| self.subscriber_count() >= count, timeout).await
    }

    /// Same as [`Self::wait_for_subscribers`], for local-event publishers.
    pub async fn wait_for_local_subscribers(&self, count: usize, timeout: Duration) -> bool {
        wait_until(|| self.local_subscriber_count() >= count, timeout).await
    }

    /// Record a mapping from the local daemon. It survives index reloads.
    pub async fn insert_domain(&self, hash: u64, domain: String) {
        // Lock order everywhere: live_domains, remote_domains, domain_map.
        let mut live = self.live_domains.write().await;
        live.insert(hash, domain.clone());
        self.domain_map.write().await.insert(hash, domain);
    }

    /// Record a mapping received from a federation peer. It is ignored when
    /// the hash is already mapped (a peer must not rename a known domain) or
    /// when the remote table is full. Returns whether it was stored.
    pub async fn insert_remote_domain(&self, hash: u64, domain: String) -> bool {
        let mut remote = self.remote_domains.write().await;
        let mut map = self.domain_map.write().await;
        if map.contains_key(&hash) || remote.len() >= MAX_REMOTE_DOMAINS {
            return false;
        }
        remote.insert(hash, domain.clone());
        map.insert(hash, domain);
        true
    }

    /// Replace the host-index part of `domain_map` under a single write lock.
    /// Entries missing from `index` disappear; runtime mappings are kept,
    /// with local ones taking precedence over remote ones.
    pub async fn replace_index(&self, mut index: HashMap<u64, String>) {
        // Hold the read locks across the swap so a concurrent insert cannot
        // land in the old map and be lost.
        let live = self.live_domains.read().await;
        let remote = self.remote_domains.read().await;
        for (hash, domain) in remote.iter() {
            index.entry(*hash).or_insert_with(|| domain.clone());
        }
        index.extend(live.iter().map(|(hash, domain)| (*hash, domain.clone())));
        let old = std::mem::replace(&mut *self.domain_map.write().await, index);
        drop(remote);
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
            country: None,
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

    /// Regression: the window kept every event of the last hour, so memory
    /// grew with the query rate (1.8 M events per hour at 500 q/s).
    #[test]
    fn test_window_is_capped() {
        let mut stats = RollingStats::with_limit(DEFAULT_WINDOW, 3);
        for hash in 0..10 {
            stats.record(make_event(hash, ip(1), StatAction::Allowed));
        }
        let kept: Vec<u64> = stats
            .window_events()
            .iter()
            .map(|(_, ev)| ev.domain_hash)
            .collect();
        assert_eq!(kept, [7, 8, 9], "the most recent events are kept");
        assert_eq!(stats.total, 10);
    }

    #[test]
    fn test_window_can_be_disabled() {
        let mut stats = RollingStats::with_limit(DEFAULT_WINDOW, 0);
        for hash in 0..10 {
            stats.record(make_event(hash, ip(1), StatAction::Allowed));
        }
        assert!(stats.window_events().is_empty());
        assert_eq!(stats.total, 10);
        assert_eq!(stats.allowed, 10);
        assert_eq!(stats.domain_hits.len(), 10);
    }

    #[test]
    fn test_state_options_size_the_window() {
        let state = AppState::with_options(StateOptions {
            max_window_events: 0,
            ..StateOptions::default()
        });
        assert!(state.stats.try_read().unwrap().window_events().is_empty());
    }

    #[test]
    fn test_hit_counter_is_exact_below_capacity() {
        let mut hits = HitCounter::new(10);
        for key in [1, 2, 1, 3, 1, 2] {
            hits.increment(key);
        }
        assert_eq!(hits.get(1), Some(3));
        assert_eq!(hits.get(2), Some(2));
        assert_eq!(hits.get(3), Some(1));
        assert_eq!(hits.get(4), None);
        assert_eq!(hits.top(2), [(1, 3), (2, 2)]);
    }

    /// Regression: `domain_hits` (and `client_hits`) grew with every distinct
    /// domain ever seen. A heavy hitter must survive with its exact count.
    #[test]
    fn test_hit_counter_stays_bounded_and_keeps_heavy_hitters() {
        let capacity = 1_000;
        let mut hits = HitCounter::new(capacity);
        for round in 0..100_000u64 {
            hits.increment(u64::MAX); // the heavy hitter
            hits.increment(round); // a long tail of one-off domains
            assert!(hits.len() <= capacity);
        }
        assert_eq!(hits.get(u64::MAX), Some(100_000));
        assert_eq!(hits.top(1), [(u64::MAX, 100_000)]);
    }

    #[test]
    fn test_hit_counter_handles_ties_at_capacity() {
        let mut hits = HitCounter::new(4);
        for key in 0..100 {
            hits.increment(key);
            assert!(hits.len() <= 4);
        }
        assert!(!hits.is_empty());
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
    async fn test_remote_domain_never_renames_a_known_hash() {
        let state = AppState::new(DEFAULT_WINDOW);
        state
            .replace_index(HashMap::from([(1, "evil.test".to_string())]))
            .await;
        state.insert_domain(2, "live.test".to_string()).await;

        assert!(
            !state
                .insert_remote_domain(1, "google.com".to_string())
                .await
        );
        assert!(
            !state
                .insert_remote_domain(2, "google.com".to_string())
                .await
        );
        assert!(state.insert_remote_domain(3, "peer.test".to_string()).await);
        // First remote mapping wins over later ones too.
        assert!(
            !state
                .insert_remote_domain(3, "other.test".to_string())
                .await
        );

        let map = state.domain_map.read().await;
        assert_eq!(map.get(&1).map(String::as_str), Some("evil.test"));
        assert_eq!(map.get(&2).map(String::as_str), Some("live.test"));
        assert_eq!(map.get(&3).map(String::as_str), Some("peer.test"));
    }

    #[tokio::test]
    async fn test_local_mapping_overrides_remote_one() {
        let state = AppState::new(DEFAULT_WINDOW);
        assert!(state.insert_remote_domain(1, "peer.test".to_string()).await);
        state.insert_domain(1, "local.test".to_string()).await;
        assert_eq!(
            state.domain_map.read().await.get(&1).map(String::as_str),
            Some("local.test")
        );

        // An index entry also wins over a remote one across reloads, and
        // remote-only entries survive the reload.
        assert!(
            state
                .insert_remote_domain(2, "peer2.test".to_string())
                .await
        );
        state
            .replace_index(HashMap::from([(1, "index.test".to_string())]))
            .await;
        let map = state.domain_map.read().await;
        assert_eq!(map.get(&1).map(String::as_str), Some("local.test"));
        assert_eq!(map.get(&2).map(String::as_str), Some("peer2.test"));
    }

    #[tokio::test]
    async fn test_remote_domains_are_capped() {
        let state = AppState::new(DEFAULT_WINDOW);
        for hash in 0..MAX_REMOTE_DOMAINS as u64 {
            assert!(
                state
                    .insert_remote_domain(hash, "peer.test".to_string())
                    .await
            );
        }
        let extra = MAX_REMOTE_DOMAINS as u64;
        assert!(
            !state
                .insert_remote_domain(extra, "more.test".to_string())
                .await
        );
        assert!(state.domain_map.read().await.get(&extra).is_none());
        // Local mappings are not subject to the cap.
        state.insert_domain(extra, "local.test".to_string()).await;
        assert!(state.domain_map.read().await.contains_key(&extra));
    }

    #[test]
    fn test_sink_indices_match_all() {
        for (index, sink) in Sink::ALL.iter().enumerate() {
            assert_eq!(*sink as usize, index, "{sink:?}");
        }
    }

    #[test]
    fn test_drop_counters_are_per_sink() {
        let state = AppState::new(DEFAULT_WINDOW);
        state.record_drop(Sink::Persistence, 3);
        state.record_drop(Sink::Persistence, 2);
        state.record_drop(Sink::ForwardingHttp, 1);
        assert_eq!(state.dropped(Sink::Persistence), 5);
        assert_eq!(state.dropped(Sink::ForwardingHttp), 1);
        assert_eq!(state.dropped(Sink::Headless), 0);
        let counts = state.dropped_counts();
        assert_eq!(counts.len(), Sink::ALL.len());
        assert!(counts.contains(&("persistence", 5)));
    }

    /// Regression: the bus held 256 events, so a short stall of one sink
    /// lost events for good.
    #[tokio::test]
    async fn test_event_buffer_absorbs_a_burst() {
        let state = AppState::new(DEFAULT_WINDOW);
        let mut slow = state.subscribe();
        for hash in 0..DEFAULT_EVENT_BUFFER as u64 {
            state
                .record_event(make_event(hash, ip(1), StatAction::Allowed))
                .await;
        }
        for hash in 0..DEFAULT_EVENT_BUFFER as u64 {
            assert_eq!(slow.try_recv().unwrap().domain_hash, hash);
        }

        let small = AppState::with_event_buffer(DEFAULT_WINDOW, 4);
        let mut slow = small.subscribe();
        for hash in 0..5 {
            small
                .record_event(make_event(hash, ip(1), StatAction::Allowed))
                .await;
        }
        assert!(matches!(
            slow.try_recv(),
            Err(broadcast::error::TryRecvError::Lagged(1))
        ));
    }

    #[tokio::test]
    async fn test_wait_for_subscribers() {
        let state = Arc::new(AppState::new(DEFAULT_WINDOW));
        assert_eq!(state.subscriber_count(), 0);
        assert!(
            !state
                .wait_for_subscribers(1, Duration::from_millis(30))
                .await
        );

        // A sink that subscribes a little later, like a spawned task.
        let late = Arc::clone(&state);
        let sink = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            let rx = late.subscribe();
            tokio::time::sleep(Duration::from_secs(1)).await;
            drop(rx);
        });
        assert!(state.wait_for_subscribers(1, Duration::from_secs(2)).await);
        assert_eq!(state.subscriber_count(), 1);
        // Local publishers are counted apart.
        assert_eq!(state.local_subscriber_count(), 0);
        let _local = state.subscribe_local();
        assert!(
            state
                .wait_for_local_subscribers(1, Duration::from_millis(30))
                .await
        );
        sink.abort();
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
