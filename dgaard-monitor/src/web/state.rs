use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Arc;

use dashmap::DashMap;
use tokio::sync::{Mutex, broadcast};

use crate::state::AppState;
use crate::util::EventRecord;

const BROADCAST_CAPACITY: usize = 1024;

pub struct ClientStats {
    pub count: u64,
    pub blocked: u64,
    #[allow(dead_code)]
    pub first_seen: u64,
    pub last_seen: u64,
}

pub struct WebState {
    #[allow(dead_code)]
    pub app: Arc<AppState>,
    pub query_log: Mutex<VecDeque<EventRecord>>,
    pub client_stats: DashMap<IpAddr, ClientStats>,
    pub(crate) broadcast_tx: broadcast::Sender<EventRecord>,
    pub history_size: usize,
}

impl WebState {
    pub fn new(app: Arc<AppState>, history_size: usize) -> Self {
        let (broadcast_tx, _) = broadcast::channel(BROADCAST_CAPACITY);
        Self {
            app,
            query_log: Mutex::new(VecDeque::with_capacity(history_size.min(4096))),
            client_stats: DashMap::new(),
            broadcast_tx,
            history_size,
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<EventRecord> {
        self.broadcast_tx.subscribe()
    }

    pub async fn push_event(&self, record: EventRecord) {
        let _ = self.broadcast_tx.send(record.clone());
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
        EventRecord {
            timestamp: ts,
            domain: None,
            domain_hash: format!("{:016x}", ts),
            client_ip: "192.168.1.1".to_string(),
            action: "Allowed".to_string(),
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
}
