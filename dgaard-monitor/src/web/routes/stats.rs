use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Json;
use axum::extract::State;
use serde::Serialize;

use crate::protocol::StatAction;
use crate::web::state::WebState;

#[derive(Serialize)]
pub struct DomainCount {
    pub domain: String,
    pub count: u64,
}

#[derive(Serialize)]
pub struct ReasonCount {
    pub reason: String,
    pub count: u64,
}

#[derive(Serialize)]
pub struct StatsResponse {
    pub total: u64,
    pub blocked: u64,
    pub suspicious: u64,
    pub allowed: u64,
    pub proxied: u64,
    pub qps: f64,
    pub active_clients: usize,
    pub blocked_pct: String,
    pub top_domains: Vec<DomainCount>,
    pub top_reasons: Vec<ReasonCount>,
}

pub async fn stats_handler(State(web): State<Arc<WebState>>) -> Json<StatsResponse> {
    let stats = web.app.stats.read().await;
    let domain_map = web.app.domain_map.read().await;

    let now = Instant::now();
    let sixty_secs = Duration::from_secs(60);

    let recent_count = stats
        .window_events()
        .iter()
        .rev()
        .take_while(|(ts, _)| now.duration_since(*ts) <= sixty_secs)
        .count();
    let qps = (recent_count as f64 / 60.0 * 100.0).round() / 100.0;

    let suspicious: u64 = stats
        .window_events()
        .iter()
        .filter(|(_, ev)| {
            matches!(
                ev.action,
                StatAction::Suspicious(_) | StatAction::HighlySuspicious(_)
            )
        })
        .count() as u64;

    let mut reason_tally: HashMap<String, u64> = HashMap::new();
    for (_, ev) in stats.window_events() {
        let reason = match &ev.action {
            StatAction::Blocked(r)
            | StatAction::Suspicious(r)
            | StatAction::HighlySuspicious(r) => Some(*r),
            _ => None,
        };
        if let Some(r) = reason {
            for label in crate::util::reason_labels(r) {
                *reason_tally.entry(label).or_insert(0) += 1;
            }
        }
    }

    let mut top_reasons: Vec<ReasonCount> = reason_tally
        .into_iter()
        .map(|(reason, count)| ReasonCount {
            reason: reason.to_string(),
            count,
        })
        .collect();
    top_reasons.sort_unstable_by_key(|r| std::cmp::Reverse(r.count));
    top_reasons.truncate(10);

    let mut domain_pairs: Vec<(u64, u64)> = stats
        .domain_hits
        .iter()
        .map(|(&hash, &count)| (hash, count))
        .collect();
    domain_pairs.sort_unstable_by_key(|&(_, c)| std::cmp::Reverse(c));
    domain_pairs.truncate(10);

    let top_domains: Vec<DomainCount> = domain_pairs
        .into_iter()
        .map(|(hash, count)| {
            let domain = domain_map
                .get(&hash)
                .cloned()
                .unwrap_or_else(|| format!("#{:016x}", hash));
            DomainCount { domain, count }
        })
        .collect();

    let total = stats.total;
    let blocked = stats.blocked;
    let allowed = stats.allowed;
    let proxied = stats.proxied;

    drop(domain_map);
    drop(stats);

    let active_clients = web.client_stats.len();

    let blocked_pct = if total == 0 {
        "0.0%".to_string()
    } else {
        format!("{:.1}%", blocked as f64 / total as f64 * 100.0)
    };

    Json(StatsResponse {
        total,
        blocked,
        suspicious,
        allowed,
        proxied,
        qps,
        active_clients,
        blocked_pct,
        top_domains,
        top_reasons,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::AppState;
    use crate::web::state::WebState;
    use std::time::Duration;

    fn make_web_state() -> Arc<WebState> {
        let app = Arc::new(AppState::new(Duration::from_secs(3600)));
        Arc::new(WebState::new(app, 100))
    }

    #[tokio::test]
    async fn empty_state_returns_zeros() {
        let web = make_web_state();
        let Json(resp) = stats_handler(State(web)).await;
        assert_eq!(resp.total, 0);
        assert_eq!(resp.allowed, 0);
        assert_eq!(resp.blocked, 0);
        assert_eq!(resp.proxied, 0);
        assert_eq!(resp.suspicious, 0);
    }

    #[tokio::test]
    async fn blocked_pct_is_zero_when_no_queries() {
        let web = make_web_state();
        let Json(resp) = stats_handler(State(web)).await;
        assert_eq!(resp.blocked_pct, "0.0%");
    }
}
