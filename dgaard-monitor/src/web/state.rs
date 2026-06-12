use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Arc;

use dashmap::DashMap;
use tokio::sync::{Mutex, broadcast};

use crate::db::Database;
use crate::state::AppState;
use crate::util::EventRecord;

const BROADCAST_CAPACITY: usize = 1024;

/// Number of 5-minute timeline buckets kept in the ring buffer (24 h × 12).
pub const BUCKET_COUNT: usize = 288;
/// Duration of one timeline bucket in seconds.
pub const BUCKET_SECS: u64 = 300;

pub struct ClientStats {
    pub count: u64,
    pub blocked: u64,
    pub first_seen: u64,
    pub last_seen: u64,
}

/// One 5-minute aggregation bucket.
#[derive(Clone, Default)]
pub struct TimelineBucket {
    /// Bucket start timestamp (aligned to `BUCKET_SECS`). Zero means unused.
    pub ts: u64,
    pub total: u64,
    pub blocked: u64,
    pub suspicious: u64,
}

pub struct WebState {
    pub app: Arc<AppState>,
    pub query_log: Mutex<VecDeque<EventRecord>>,
    pub client_stats: DashMap<IpAddr, ClientStats>,
    /// Reverse-DNS cache: IP → resolved PTR hostname.
    /// Populated lazily by background tasks spawned from the ingestor.
    pub hostname_cache: DashMap<IpAddr, String>,
    /// Circular ring of 288 five-minute aggregation buckets covering 24 h.
    pub timeline: Mutex<Vec<TimelineBucket>>,
    /// SQLite database for persistent query history. `None` when persistence
    /// is not configured or the DB failed to open.
    pub db: Option<Arc<Database>>,
    pub(crate) broadcast_tx: broadcast::Sender<EventRecord>,
    pub history_size: usize,
    /// Minimum number of observations before a (client, domain) pair is
    /// considered for beaconing analysis.
    pub beaconing_min_observations: usize,
    /// Coefficient of Variation threshold below which a pair is flagged.
    pub beaconing_cov_threshold: f64,
}

impl WebState {
    pub fn new(app: Arc<AppState>, history_size: usize) -> Self {
        let (broadcast_tx, _) = broadcast::channel(BROADCAST_CAPACITY);
        Self {
            app,
            query_log: Mutex::new(VecDeque::with_capacity(history_size.min(4096))),
            client_stats: DashMap::new(),
            hostname_cache: DashMap::new(),
            timeline: Mutex::new(vec![TimelineBucket::default(); BUCKET_COUNT]),
            db: None,
            broadcast_tx,
            history_size,
            beaconing_min_observations: 5,
            beaconing_cov_threshold: 0.15,
        }
    }

    /// Attach a database connection for persistent query history.
    pub fn with_db(self, db: Arc<Database>) -> Self {
        Self {
            db: Some(db),
            ..self
        }
    }

    /// Override beaconing detection thresholds from config.
    pub fn with_beaconing(self, min_observations: usize, cov_threshold: f64) -> Self {
        Self {
            beaconing_min_observations: min_observations,
            beaconing_cov_threshold: cov_threshold,
            ..self
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<EventRecord> {
        self.broadcast_tx.subscribe()
    }

    pub async fn push_event(&self, record: EventRecord) {
        let _ = self.broadcast_tx.send(record.clone());

        // Update the 5-minute ring-buffer bucket for this event's timestamp.
        {
            let bucket_ts = (record.timestamp / BUCKET_SECS) * BUCKET_SECS;
            let idx = (record.timestamp / BUCKET_SECS) as usize % BUCKET_COUNT;
            let is_blocked = record.action == "Blocked";
            let is_suspicious = matches!(record.action.as_str(), "Suspicious" | "HighlySuspicious");
            let mut tl = self.timeline.lock().await;
            if tl[idx].ts != bucket_ts {
                tl[idx] = TimelineBucket {
                    ts: bucket_ts,
                    total: 0,
                    blocked: 0,
                    suspicious: 0,
                };
            }
            tl[idx].total += 1;
            if is_blocked {
                tl[idx].blocked += 1;
            }
            if is_suspicious {
                tl[idx].suspicious += 1;
            }
        }

        let mut log = self.query_log.lock().await;
        if log.len() >= self.history_size {
            log.pop_front();
        }
        log.push_back(record);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn make_app() -> Arc<AppState> {
        Arc::new(AppState::new(Duration::from_secs(3600)))
    }

    fn make_record(ts: u64) -> EventRecord {
        make_record_action(ts, "Allowed")
    }

    fn make_record_action(ts: u64, action: &str) -> EventRecord {
        EventRecord {
            timestamp: ts,
            domain: None,
            domain_hash: format!("{:016x}", ts),
            client_ip: "192.168.1.1".to_string(),
            action: action.to_string(),
            flags: None,
            flags_labels: vec![],
        }
    }

    #[tokio::test]
    async fn new_state_has_empty_log() {
        let state = WebState::new(make_app(), 100);
        let log = state.query_log.lock().await;
        assert!(log.is_empty());
    }

    #[tokio::test]
    async fn push_event_appends_to_log() {
        let state = WebState::new(make_app(), 100);
        state.push_event(make_record(1000)).await;
        state.push_event(make_record(2000)).await;
        let log = state.query_log.lock().await;
        assert_eq!(log.len(), 2);
    }

    #[tokio::test]
    async fn push_event_caps_at_history_size() {
        let state = WebState::new(make_app(), 3);
        for i in 0..5u64 {
            state.push_event(make_record(i)).await;
        }
        let log = state.query_log.lock().await;
        assert_eq!(log.len(), 3);
        assert_eq!(log.front().unwrap().timestamp, 2);
        assert_eq!(log.back().unwrap().timestamp, 4);
    }

    #[tokio::test]
    async fn push_event_broadcasts_to_subscriber() {
        let state = WebState::new(make_app(), 100);
        let mut rx = state.subscribe();
        state.push_event(make_record(9999)).await;
        let received = rx.try_recv().unwrap();
        assert_eq!(received.timestamp, 9999);
    }

    #[tokio::test]
    async fn multiple_subscribers_each_receive_event() {
        let state = WebState::new(make_app(), 100);
        let mut rx1 = state.subscribe();
        let mut rx2 = state.subscribe();
        state.push_event(make_record(42)).await;
        assert_eq!(rx1.try_recv().unwrap().timestamp, 42);
        assert_eq!(rx2.try_recv().unwrap().timestamp, 42);
    }

    #[test]
    fn history_size_zero_is_accepted() {
        let state = WebState::new(make_app(), 0);
        assert_eq!(state.history_size, 0);
    }

    // ── timeline bucket aggregation ───────────────────────────────────────────

    #[tokio::test]
    async fn push_event_increments_total_in_bucket() {
        let state = WebState::new(make_app(), 100);
        // ts=300 → bucket_ts=300, idx=1
        state.push_event(make_record(300)).await;
        let tl = state.timeline.lock().await;
        let idx = (300u64 / BUCKET_SECS) as usize % BUCKET_COUNT;
        assert_eq!(tl[idx].ts, 300);
        assert_eq!(tl[idx].total, 1);
        assert_eq!(tl[idx].blocked, 0);
        assert_eq!(tl[idx].suspicious, 0);
    }

    #[tokio::test]
    async fn push_event_counts_blocked_action() {
        let state = WebState::new(make_app(), 100);
        state.push_event(make_record_action(300, "Blocked")).await;
        let tl = state.timeline.lock().await;
        let idx = (300u64 / BUCKET_SECS) as usize % BUCKET_COUNT;
        assert_eq!(tl[idx].total, 1);
        assert_eq!(tl[idx].blocked, 1);
        assert_eq!(tl[idx].suspicious, 0);
    }

    #[tokio::test]
    async fn push_event_counts_suspicious_actions() {
        let state = WebState::new(make_app(), 100);
        state
            .push_event(make_record_action(300, "Suspicious"))
            .await;
        state
            .push_event(make_record_action(300, "HighlySuspicious"))
            .await;
        let tl = state.timeline.lock().await;
        let idx = (300u64 / BUCKET_SECS) as usize % BUCKET_COUNT;
        assert_eq!(tl[idx].total, 2);
        assert_eq!(tl[idx].suspicious, 2);
        assert_eq!(tl[idx].blocked, 0);
    }

    #[tokio::test]
    async fn push_event_resets_bucket_on_rollover() {
        let state = WebState::new(make_app(), 100);
        // Fill slot idx=1 at ts=300
        state.push_event(make_record(300)).await;
        // 288 buckets later lands on the same slot but different ts
        let new_ts = 300 + (BUCKET_COUNT as u64 * BUCKET_SECS);
        state
            .push_event(make_record_action(new_ts, "Blocked"))
            .await;
        let tl = state.timeline.lock().await;
        let new_bucket_ts = (new_ts / BUCKET_SECS) * BUCKET_SECS;
        let idx = (new_ts / BUCKET_SECS) as usize % BUCKET_COUNT;
        // Slot was reset: only the new event is counted
        assert_eq!(tl[idx].ts, new_bucket_ts);
        assert_eq!(tl[idx].total, 1);
        assert_eq!(tl[idx].blocked, 1);
    }

    #[tokio::test]
    async fn push_event_accumulates_within_same_bucket() {
        let state = WebState::new(make_app(), 100);
        // All three timestamps fall in the same 5-min bucket (0–299)
        state.push_event(make_record(0)).await;
        state.push_event(make_record_action(1, "Blocked")).await;
        state
            .push_event(make_record_action(299, "Suspicious"))
            .await;
        let tl = state.timeline.lock().await;
        let idx = 0; // ts=0 → bucket_ts=0, idx=0
        assert_eq!(tl[idx].ts, 0);
        assert_eq!(tl[idx].total, 3);
        assert_eq!(tl[idx].blocked, 1);
        assert_eq!(tl[idx].suspicious, 1);
    }
}
