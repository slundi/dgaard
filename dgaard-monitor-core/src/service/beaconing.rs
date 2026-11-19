//! Beaconing detection: flags (client, domain) pairs whose query
//! inter-arrival times are suspiciously regular (low coefficient of
//! variation), a typical signature of C2 implants polling home.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use serde::Serialize;
use tokio::sync::Mutex;

use crate::db::Database;
use crate::util::EventRecord;

// Pairs whose mean inter-arrival time is below this are skipped — they are
// bursts rather than periodic beacons and would produce meaningless CoV values.
const MIN_MEAN_INTERVAL_SECS: f64 = 1.0;

#[derive(Debug, Serialize)]
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

/// Detect beacons, most regular (lowest CoV) first.
///
/// Reads from SQLite when persistence is configured, falling back to the
/// in-memory query log when there is no database or the query fails.
pub async fn find_beacons(
    db: Option<&Arc<Database>>,
    log: &Mutex<VecDeque<EventRecord>>,
    min_obs: usize,
    cov_threshold: f64,
) -> Vec<BeaconEntry> {
    let from_db = match db {
        Some(db) => {
            let db = Arc::clone(db);
            tokio::task::spawn_blocking(move || db.query_beaconing_timestamps(min_obs as i64))
                .await
                .ok()
                .and_then(Result::ok)
        }
        None => None,
    };

    let groups = match from_db {
        Some(rows) => groups_from_db_rows(rows),
        None => groups_from_records(log.lock().await.iter()),
    };
    detect(groups, min_obs, cov_threshold)
}

// ── Data collection ───────────────────────────────────────────────────────────

struct PairData {
    timestamps: Vec<u64>,
    domain: Option<String>,
}

type PairGroups = HashMap<(String, String), PairData>;

fn groups_from_records<'a>(records: impl Iterator<Item = &'a EventRecord>) -> PairGroups {
    let mut groups = PairGroups::new();
    for record in records {
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

fn groups_from_db_rows(rows: Vec<(String, String, Option<String>, u64)>) -> PairGroups {
    let mut groups = PairGroups::new();
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

fn detect(groups: PairGroups, min_obs: usize, cov_threshold: f64) -> Vec<BeaconEntry> {
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
            .map(|pair| (pair[1] - pair[0]) as f64)
            .collect();

        if intervals.is_empty() {
            continue;
        }

        let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
        if mean < MIN_MEAN_INTERVAL_SECS {
            continue;
        }

        let variance = intervals
            .iter()
            .map(|interval| (interval - mean).powi(2))
            .sum::<f64>()
            / intervals.len() as f64;
        let cov = variance.sqrt() / mean;

        if cov < cov_threshold {
            let domain = data.domain.unwrap_or_else(|| format!("#{}", domain_hash));

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
    results.sort_unstable_by(|left, right| {
        left.cov
            .partial_cmp(&right.cov)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    results
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(timestamps: Vec<u64>, domain: Option<&str>) -> PairData {
        PairData {
            timestamps,
            domain: domain.map(str::to_string),
        }
    }

    fn single_group(client: &str, hash: &str, data: PairData) -> PairGroups {
        let mut groups = PairGroups::new();
        groups.insert((client.to_string(), hash.to_string()), data);
        groups
    }

    fn event(ts: u64, client: &str, domain: &str, hash: &str) -> EventRecord {
        EventRecord {
            country: None,
            timestamp: ts,
            domain: Some(domain.to_string()),
            domain_hash: hash.to_string(),
            client_ip: client.to_string(),
            action: "Allowed".to_string(),
            flags: None,
            flags_labels: vec![],
        }
    }

    fn beacon(count: u64, interval: u64, client: &str, domain: &str) -> Vec<EventRecord> {
        (0..count)
            .map(|index| {
                event(
                    1_700_000_000 + index * interval,
                    client,
                    domain,
                    "0000000000000001",
                )
            })
            .collect()
    }

    // ── detect() ─────────────────────────────────────────────────────────────

    #[test]
    fn perfect_beacon_is_detected() {
        let timestamps: Vec<u64> = (0..10).map(|index| 1_700_000_000 + index * 300).collect();
        let groups = single_group("10.0.0.1", "aabbccdd", pair(timestamps, Some("evil.com")));
        let results = detect(groups, 5, 0.15);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].client, "10.0.0.1");
        assert_eq!(results[0].domain, "evil.com");
        assert_eq!(results[0].cov, 0.0);
        assert_eq!(results[0].mean_interval_secs, 300.0);
        assert_eq!(results[0].first_seen, 1_700_000_000);
        assert_eq!(results[0].last_seen, 1_700_000_000 + 9 * 300);
    }

    #[test]
    fn noisy_pair_is_not_detected() {
        let timestamps = vec![100, 600, 602, 1500, 1501, 3000, 3001, 8000, 8001, 9000];
        let groups = single_group("10.0.0.2", "deadbeef", pair(timestamps, Some("noisy.com")));
        assert!(detect(groups, 5, 0.15).is_empty());
    }

    #[test]
    fn below_min_obs_is_skipped() {
        let timestamps: Vec<u64> = (0..4).map(|index| 1_000 + index * 300).collect();
        let groups = single_group("10.0.0.3", "12345678", pair(timestamps, None));
        assert!(detect(groups, 5, 0.15).is_empty());
    }

    #[test]
    fn single_observation_has_no_interval() {
        let groups = single_group("10.0.0.3", "12345678", pair(vec![1_000], None));
        assert!(detect(groups, 1, 0.15).is_empty());
    }

    #[test]
    fn zero_interval_burst_is_skipped() {
        // All events at the same timestamp → mean interval = 0 < MIN_MEAN_INTERVAL_SECS.
        let groups = single_group("10.0.0.4", "00000000", pair(vec![1_000_000u64; 10], None));
        assert!(detect(groups, 5, 0.30).is_empty());
    }

    #[test]
    fn results_sorted_by_cov_ascending() {
        let mut groups = PairGroups::new();
        // Pair A: CoV = 0.0 (perfect)
        let ts_a: Vec<u64> = (0..10).map(|index| 1_000_000 + index * 60).collect();
        groups.insert(("a".into(), "aaaa".into()), pair(ts_a, Some("a.com")));
        // Pair B: slight jitter CoV ~0.05
        let ts_b = vec![0u64, 59, 121, 180, 239, 301, 360, 420, 479, 541];
        groups.insert(("b".into(), "bbbb".into()), pair(ts_b, Some("b.com")));

        let results = detect(groups, 5, 0.15);
        assert_eq!(results.len(), 2);
        assert!(results[0].cov <= results[1].cov);
    }

    #[test]
    fn unknown_domain_falls_back_to_hash() {
        let timestamps: Vec<u64> = (0..10).map(|index| index * 300).collect();
        let groups = single_group("10.0.0.5", "deadbeef12345678", pair(timestamps, None));
        let results = detect(groups, 5, 0.15);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].domain, "#deadbeef12345678");
    }

    // ── grouping ─────────────────────────────────────────────────────────────

    #[test]
    fn records_group_by_client_and_hash_keeping_first_domain() {
        let mut records = beacon(3, 60, "10.0.0.1", "first.com");
        records.push(event(5, "10.0.0.2", "other.com", "0000000000000001"));
        records[1].domain = Some("second.com".into());

        let groups = groups_from_records(records.iter());
        assert_eq!(groups.len(), 2);
        let data = &groups[&("10.0.0.1".to_string(), "0000000000000001".to_string())];
        assert_eq!(data.timestamps.len(), 3);
        assert_eq!(data.domain.as_deref(), Some("first.com"));
    }

    #[test]
    fn db_rows_keep_first_known_domain() {
        let rows = vec![
            ("10.0.0.1".into(), "aa".into(), None, 10),
            ("10.0.0.1".into(), "aa".into(), Some("late.com".into()), 20),
            ("10.0.0.1".into(), "aa".into(), Some("later.com".into()), 30),
        ];
        let groups = groups_from_db_rows(rows);
        let data = &groups[&("10.0.0.1".to_string(), "aa".to_string())];
        assert_eq!(data.timestamps, vec![10, 20, 30]);
        assert_eq!(data.domain.as_deref(), Some("late.com"));
    }

    // ── find_beacons ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn find_beacons_uses_log_without_db() {
        let log = Mutex::new(beacon(10, 300, "192.168.1.1", "c2.evil.com").into());
        let beacons = find_beacons(None, &log, 5, 0.15).await;
        assert_eq!(beacons.len(), 1);
        assert_eq!(beacons[0].client, "192.168.1.1");
        assert_eq!(beacons[0].domain, "c2.evil.com");
    }

    #[tokio::test]
    async fn find_beacons_prefers_db_when_configured() {
        let db = Arc::new(Database::open_in_memory().unwrap());
        db.insert_events(&beacon(8, 120, "10.0.0.7", "db.evil.com"))
            .unwrap();
        // A beacon that only lives in memory must not be reported.
        let log = Mutex::new(beacon(10, 300, "192.168.1.1", "mem.evil.com").into());

        let beacons = find_beacons(Some(&db), &log, 5, 0.15).await;
        assert_eq!(beacons.len(), 1);
        assert_eq!(beacons[0].client, "10.0.0.7");
        assert_eq!(beacons[0].count, 8);
        assert_eq!(beacons[0].mean_interval_secs, 120.0);
    }
}
