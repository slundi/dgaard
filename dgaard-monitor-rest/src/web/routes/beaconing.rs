use std::sync::Arc;

use axum::Json;
use axum::extract::{Query, State};
use serde::Deserialize;

use crate::web::state::WebState;
use dgaard_monitor_core::service::beaconing::{BeaconEntry, find_beacons};

#[derive(Deserialize)]
pub struct BeaconingParams {
    /// Override the configured minimum observation count for this request.
    pub min_obs: Option<usize>,
    /// Override the configured CoV threshold for this request.
    pub cov: Option<f64>,
}

pub async fn beaconing_handler(
    State(web): State<Arc<WebState>>,
    Query(params): Query<BeaconingParams>,
) -> Json<Vec<BeaconEntry>> {
    let min_obs = params.min_obs.unwrap_or(web.beaconing_min_observations);
    let cov_threshold = params.cov.unwrap_or(web.beaconing_cov_threshold);
    Json(find_beacons(web.db.as_ref(), &web.query_log, min_obs, cov_threshold).await)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::state::WebState;
    use axum::extract::State;
    use dgaard_monitor_core::state::AppState;
    use dgaard_monitor_core::util::EventRecord;
    use std::time::Duration;

    fn make_web_state() -> Arc<WebState> {
        let app = Arc::new(AppState::new(Duration::from_secs(3600)));
        Arc::new(WebState::new(app, 1000))
    }

    fn event(ts: u64, client: &str, domain: &str, hash: &str) -> EventRecord {
        EventRecord {
            timestamp: ts,
            domain: Some(domain.to_string()),
            domain_hash: hash.to_string(),
            client_ip: client.to_string(),
            action: "Allowed".to_string(),
            flags: None,
            flags_labels: vec![],
        }
    }

    // Push a regular beacon: N events spaced exactly `interval` seconds apart.
    async fn push_beacon(web: &WebState, n: usize, interval: u64, client: &str, domain: &str) {
        for i in 0..n {
            web.push_event(event(
                1_700_000_000 + i as u64 * interval,
                client,
                domain,
                "0000000000000001",
            ))
            .await;
        }
    }

    // Push N events with random-ish jitter (high CoV).
    async fn push_noisy(web: &WebState, client: &str, domain: &str) {
        let gaps = [10u64, 500, 3, 900, 2, 1000, 5, 800, 1, 600];
        let mut ts = 1_700_000_000u64;
        for g in &gaps {
            web.push_event(event(ts, client, domain, "0000000000000002"))
                .await;
            ts += g;
        }
    }

    // ── Integration: handler uses query_log ──────────────────────────────────

    #[tokio::test]
    async fn handler_detects_beacon_from_log() {
        let web = make_web_state();
        push_beacon(&web, 10, 300, "192.168.1.1", "c2.evil.com").await;

        let Json(beacons) = beaconing_handler(
            State(Arc::clone(&web)),
            Query(BeaconingParams {
                min_obs: None,
                cov: None,
            }),
        )
        .await;

        assert_eq!(beacons.len(), 1);
        assert_eq!(beacons[0].client, "192.168.1.1");
        assert_eq!(beacons[0].mean_interval_secs, 300.0);
        assert_eq!(beacons[0].cov, 0.0);
    }

    #[tokio::test]
    async fn handler_ignores_noisy_pair() {
        let web = make_web_state();
        push_noisy(&web, "192.168.1.2", "noise.example.com").await;

        let Json(beacons) = beaconing_handler(
            State(web),
            Query(BeaconingParams {
                min_obs: None,
                cov: None,
            }),
        )
        .await;
        assert!(beacons.is_empty());
    }

    #[tokio::test]
    async fn handler_respects_query_param_overrides() {
        let web = make_web_state();
        // Push only 3 events (below default min_obs=5).
        push_beacon(&web, 3, 300, "10.0.0.1", "low.example.com").await;

        // With default min_obs=5: not detected.
        let Json(default_result) = beaconing_handler(
            State(Arc::clone(&web)),
            Query(BeaconingParams {
                min_obs: None,
                cov: None,
            }),
        )
        .await;
        assert!(default_result.is_empty());

        // With min_obs=2 override: detected (3 >= 2).
        let Json(override_result) = beaconing_handler(
            State(web),
            Query(BeaconingParams {
                min_obs: Some(2),
                cov: None,
            }),
        )
        .await;
        assert_eq!(override_result.len(), 1);
    }

    #[tokio::test]
    async fn handler_returns_empty_for_empty_log() {
        let web = make_web_state();
        let Json(beacons) = beaconing_handler(
            State(web),
            Query(BeaconingParams {
                min_obs: None,
                cov: None,
            }),
        )
        .await;
        assert!(beacons.is_empty());
    }
}
