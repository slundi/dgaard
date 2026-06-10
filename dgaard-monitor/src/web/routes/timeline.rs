use std::sync::Arc;

use axum::Json;
use axum::extract::{Query, State};
use serde::{Deserialize, Serialize};

use crate::web::state::WebState;

#[derive(Deserialize)]
pub struct TimelineParams {
    /// Return only the last N buckets (most recent). Omit to return all.
    pub limit: Option<usize>,
}

#[derive(Serialize)]
pub struct BucketJson {
    pub ts: u64,
    pub total: u64,
    pub blocked: u64,
    pub suspicious: u64,
}

pub async fn timelines_handler(
    State(web): State<Arc<WebState>>,
    Query(params): Query<TimelineParams>,
) -> Json<Vec<BucketJson>> {
    let tl = web.timeline.lock().await;
    let mut buckets: Vec<BucketJson> = tl
        .iter()
        .filter(|b| b.ts > 0)
        .map(|b| BucketJson {
            ts: b.ts,
            total: b.total,
            blocked: b.blocked,
            suspicious: b.suspicious,
        })
        .collect();
    drop(tl);

    buckets.sort_unstable_by_key(|b| b.ts);
    if let Some(n) = params.limit {
        let skip = buckets.len().saturating_sub(n);
        buckets.drain(..skip);
    }
    Json(buckets)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::AppState;
    use crate::util::EventRecord;
    use crate::web::state::WebState;
    use axum::extract::State;
    use std::time::Duration;

    fn make_web_state() -> Arc<WebState> {
        let app = Arc::new(AppState::new(Duration::from_secs(3600)));
        Arc::new(WebState::new(app, 100))
    }

    fn record(ts: u64, action: &str) -> EventRecord {
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
    async fn empty_state_returns_empty_array() {
        let web = make_web_state();
        let Json(buckets) =
            timelines_handler(State(web), Query(TimelineParams { limit: None })).await;
        assert!(buckets.is_empty());
    }

    #[tokio::test]
    async fn returns_buckets_sorted_ascending() {
        let web = make_web_state();
        web.push_event(record(600, "Allowed")).await;
        web.push_event(record(300, "Allowed")).await;
        let Json(buckets) =
            timelines_handler(State(web), Query(TimelineParams { limit: None })).await;
        assert_eq!(buckets.len(), 2);
        assert!(buckets[0].ts < buckets[1].ts);
    }

    #[tokio::test]
    async fn blocked_events_reflected_in_bucket() {
        let web = make_web_state();
        web.push_event(record(300, "Blocked")).await;
        web.push_event(record(300, "Allowed")).await;
        let Json(buckets) =
            timelines_handler(State(web), Query(TimelineParams { limit: None })).await;
        assert_eq!(buckets.len(), 1);
        assert_eq!(buckets[0].total, 2);
        assert_eq!(buckets[0].blocked, 1);
    }

    #[tokio::test]
    async fn limit_returns_most_recent_buckets() {
        let web = make_web_state();
        // ts=300,600,900,1200 → 4 distinct buckets; limit=2 keeps the newest two
        for i in 1u64..=4 {
            web.push_event(record(i * 300, "Allowed")).await;
        }
        let Json(buckets) =
            timelines_handler(State(web), Query(TimelineParams { limit: Some(2) })).await;
        assert_eq!(buckets.len(), 2);
        assert_eq!(buckets[0].ts, 900);
        assert_eq!(buckets[1].ts, 1200);
    }

    #[tokio::test]
    async fn limit_larger_than_data_returns_all() {
        let web = make_web_state();
        web.push_event(record(300, "Allowed")).await;
        let Json(buckets) =
            timelines_handler(State(web), Query(TimelineParams { limit: Some(100) })).await;
        assert_eq!(buckets.len(), 1);
    }
}
