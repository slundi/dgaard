use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use serde::Serialize;

use crate::web::state::WebState;

#[derive(Serialize)]
pub struct TalkerRecord {
    pub client: String,
    pub hostname: Option<String>,
    pub count: u64,
    pub blocked: u64,
    pub first_seen: u64,
    pub last_seen: u64,
}

pub async fn talkers_handler(State(web): State<Arc<WebState>>) -> Json<Vec<TalkerRecord>> {
    let mut records: Vec<TalkerRecord> = web
        .client_stats
        .iter()
        .map(|entry| {
            let ip = entry.key();
            let stats = entry.value();
            TalkerRecord {
                hostname: web.hostname_cache.get(ip).map(|h| h.clone()),
                client: ip.to_string(),
                count: stats.count,
                blocked: stats.blocked,
                first_seen: stats.first_seen,
                last_seen: stats.last_seen,
            }
        })
        .collect();

    records.sort_unstable_by_key(|r| std::cmp::Reverse(r.count));

    Json(records)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::AppState;
    use crate::web::state::{ClientStats, WebState};
    use std::net::IpAddr;
    use std::time::Duration;

    fn make_web_state() -> Arc<WebState> {
        let app = Arc::new(AppState::new(Duration::from_secs(3600)));
        Arc::new(WebState::new(app, 100))
    }

    fn insert_client(web: &WebState, ip: &str, count: u64, blocked: u64) {
        let addr: IpAddr = ip.parse().unwrap();
        web.client_stats.insert(
            addr,
            ClientStats {
                count,
                blocked,
                first_seen: 1000,
                last_seen: 2000,
            },
        );
    }

    #[tokio::test]
    async fn empty_state_returns_empty_list() {
        let web = make_web_state();
        let Json(records) = talkers_handler(State(web)).await;
        assert!(records.is_empty());
    }

    #[tokio::test]
    async fn entries_sorted_by_count_descending() {
        let web = make_web_state();
        insert_client(&web, "10.0.0.1", 5, 0);
        insert_client(&web, "10.0.0.2", 50, 2);
        insert_client(&web, "10.0.0.3", 1, 0);

        let Json(records) = talkers_handler(State(web)).await;
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].count, 50);
        assert_eq!(records[1].count, 5);
        assert_eq!(records[2].count, 1);
    }
}
