use std::collections::HashMap;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Query, State};
use serde::{Deserialize, Serialize};

use crate::web::state::WebState;

// Pairs whose mean inter-arrival time is below this are skipped — they are
// bursts rather than periodic beacons and would produce meaningless CoV values.
const MIN_MEAN_INTERVAL_SECS: f64 = 1.0;

// ── Public types ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct BeaconingParams {
    /// Override the configured minimum observation count for this request.
    pub min_obs: Option<usize>,
    /// Override the configured CoV threshold for this request.
    pub cov: Option<f64>,
}

#[derive(Serialize)]
pub struct BeaconEntry {
    pub client: String,
    /// Resolved domain name, or `"#<hash>"` when the hash is unmapped.
    pub domain: String,
    pub domain_hash: String,
    pub count: usize,
    pub mean_interval_secs: f64,
    pub cov: f64,
    pub first_seen: u64,
    pub last_seen: u64,
}

// ── Handler ───────────────────────────────────────────────────────────────────

pub async fn beaconing_handler(
    State(web): State<Arc<WebState>>,
    Query(params): Query<BeaconingParams>,
) -> Json<Vec<BeaconEntry>> {
    let min_obs = params.min_obs.unwrap_or(web.beaconing_min_observations);
    let cov_threshold = params.cov.unwrap_or(web.beaconing_cov_threshold);

    let groups = if let Some(db) = web.db.as_ref() {
        let db2 = std::sync::Arc::clone(db);
        let rows_result = tokio::task::spawn_blocking(move || {
            db2.query_beaconing_timestamps(min_obs as i64)
        })
        .await;

        match rows_result {
            Ok(Ok(rows)) => groups_from_db_rows(rows),
            _ => groups_from_log(&web).await,
        }
    } else {
        groups_from_log(&web).await
    };

    Json(detect(groups, min_obs, cov_threshold))
}

// ── Data collection ───────────────────────────────────────────────────────────

struct PairData {
    timestamps: Vec<u64>,
    domain: Option<String>,
}

async fn groups_from_log(web: &WebState) -> HashMap<(String, String), PairData> {
    let log = web.query_log.lock().await;
    let mut groups: HashMap<(String, String), PairData> = HashMap::new();
    for record in log.iter() {
        let key = (record.client_ip.clone(), record.domain_hash.clone());
        let entry = groups.entry(key).or_insert_with(|| PairData {
            timestamps: Vec::new(),
            domain: None,
        });
        entry.timestamps.push(record.timestamp);
        if entry.domain.is_none() {
            entry.domain = record.domain.clone();
        }
    }
    groups
}

fn groups_from_db_rows(
    rows: Vec<(String, String, Option<String>, u64)>,
) -> HashMap<(String, String), PairData> {
    let mut groups: HashMap<(String, String), PairData> = HashMap::new();
    // Rows arrive pre-sorted by (client_ip, domain_hash, timestamp) from SQL.
    for (client_ip, domain_hash, domain, timestamp) in rows {
        let key = (client_ip, domain_hash);
        let entry = groups.entry(key).or_insert_with(|| PairData {
            timestamps: Vec::new(),
            domain: None,
        });
        entry.timestamps.push(timestamp);
        if entry.domain.is_none() && domain.is_some() {
            entry.domain = domain;
        }
    }
    groups
}

// ── Detection algorithm ───────────────────────────────────────────────────────

fn detect(
    groups: HashMap<(String, String), PairData>,
    min_obs: usize,
    cov_threshold: f64,
) -> Vec<BeaconEntry> {
    let mut results = Vec::new();

    for ((client_ip, domain_hash), mut data) in groups {
        if data.timestamps.len() < min_obs {
            continue;
        }

        data.timestamps.sort_unstable();
        let count = data.timestamps.len();
        let first_seen = data.timestamps[0];
        let last_seen = data.timestamps[count - 1];

        let intervals: Vec<f64> = data
            .timestamps
            .windows(2)
            .map(|w| (w[1] - w[0]) as f64)
            .collect();

        if intervals.is_empty() {
            continue;
        }

        let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
        if mean < MIN_MEAN_INTERVAL_SECS {
            continue;
        }

        let variance = intervals.iter().map(|x| (x - mean).powi(2)).sum::<f64>()
            / intervals.len() as f64;
        let cov = variance.sqrt() / mean;

        if cov < cov_threshold {
            let domain = data
                .domain
                .unwrap_or_else(|| format!("#{}", domain_hash));

            results.push(BeaconEntry {
                client: client_ip,
                domain,
                domain_hash,
                count,
                mean_interval_secs: (mean * 10.0).round() / 10.0,
                cov: (cov * 1000.0).round() / 1000.0,
                first_seen,
                last_seen,
            });
        }
    }

    // Most regular (lowest CoV) first.
    results.sort_unstable_by(|a, b| {
        a.cov
            .partial_cmp(&b.cov)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    results
}

// ── Tests ─────────────────────────────────────────────────────────────────────

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

    // ── detect() unit tests ──────────────────────────────────────────────────

    #[test]
    fn perfect_beacon_is_detected() {
        let mut groups = HashMap::new();
        // 10 events at exactly 300-second intervals.
        let ts: Vec<u64> = (0..10).map(|i| 1_700_000_000 + i * 300).collect();
        groups.insert(("10.0.0.1".to_string(), "aabbccdd".to_string()), PairData {
            timestamps: ts,
            domain: Some("evil.com".to_string()),
        });
        let results = detect(groups, 5, 0.15);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].client, "10.0.0.1");
        assert_eq!(results[0].domain, "evil.com");
        assert_eq!(results[0].cov, 0.0);
    }

    #[test]
    fn noisy_pair_is_not_detected() {
        let mut groups = HashMap::new();
        let ts: Vec<u64> = vec![100, 600, 602, 1500, 1501, 3000, 3001, 8000, 8001, 9000];
        groups.insert(("10.0.0.2".to_string(), "deadbeef".to_string()), PairData {
            timestamps: ts,
            domain: Some("noisy.com".to_string()),
        });
        let results = detect(groups, 5, 0.15);
        assert!(results.is_empty());
    }

    #[test]
    fn below_min_obs_is_skipped() {
        let mut groups = HashMap::new();
        let ts: Vec<u64> = (0..4).map(|i| 1_000 + i * 300).collect(); // 4 < min_obs=5
        groups.insert(("10.0.0.3".to_string(), "12345678".to_string()), PairData {
            timestamps: ts,
            domain: None,
        });
        let results = detect(groups, 5, 0.15);
        assert!(results.is_empty());
    }

    #[test]
    fn zero_interval_burst_is_skipped() {
        let mut groups = HashMap::new();
        // All events at the same timestamp → mean interval = 0 < MIN_MEAN_INTERVAL_SECS.
        let ts: Vec<u64> = vec![1_000_000u64; 10];
        groups.insert(("10.0.0.4".to_string(), "00000000".to_string()), PairData {
            timestamps: ts,
            domain: None,
        });
        let results = detect(groups, 5, 0.30);
        assert!(results.is_empty());
    }

    #[test]
    fn results_sorted_by_cov_ascending() {
        let mut groups = HashMap::new();
        // Pair A: CoV = 0.0 (perfect)
        let ts_a: Vec<u64> = (0..10).map(|i| 1_000_000 + i * 60).collect();
        groups.insert(("a".to_string(), "aaaa".to_string()), PairData {
            timestamps: ts_a,
            domain: Some("a.com".to_string()),
        });
        // Pair B: slight jitter CoV ~0.05
        let ts_b = vec![
            0u64, 59, 121, 180, 239, 301, 360, 420, 479, 541,
        ];
        groups.insert(("b".to_string(), "bbbb".to_string()), PairData {
            timestamps: ts_b,
            domain: Some("b.com".to_string()),
        });
        let results = detect(groups, 5, 0.15);
        assert_eq!(results.len(), 2);
        assert!(results[0].cov <= results[1].cov);
    }

    #[test]
    fn unknown_domain_falls_back_to_hash() {
        let mut groups = HashMap::new();
        let ts: Vec<u64> = (0..10).map(|i| i * 300).collect();
        groups.insert(("10.0.0.5".to_string(), "deadbeef12345678".to_string()), PairData {
            timestamps: ts,
            domain: None,
        });
        let results = detect(groups, 5, 0.15);
        assert_eq!(results.len(), 1);
        assert!(results[0].domain.starts_with('#'));
    }

    // ── Integration: handler uses query_log ──────────────────────────────────

    #[tokio::test]
    async fn handler_detects_beacon_from_log() {
        let web = make_web_state();
        push_beacon(&web, 10, 300, "192.168.1.1", "c2.evil.com").await;

        let Json(beacons) = beaconing_handler(
            State(Arc::clone(&web)),
            Query(BeaconingParams { min_obs: None, cov: None }),
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
            Query(BeaconingParams { min_obs: None, cov: None }),
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
            Query(BeaconingParams { min_obs: None, cov: None }),
        )
        .await;
        assert!(default_result.is_empty());

        // With min_obs=2 override: detected (3 >= 2).
        let Json(override_result) = beaconing_handler(
            State(web),
            Query(BeaconingParams { min_obs: Some(2), cov: None }),
        )
        .await;
        assert_eq!(override_result.len(), 1);
    }

    #[tokio::test]
    async fn handler_returns_empty_for_empty_log() {
        let web = make_web_state();
        let Json(beacons) = beaconing_handler(
            State(web),
            Query(BeaconingParams { min_obs: None, cov: None }),
        )
        .await;
        assert!(beacons.is_empty());
    }
}
