use std::collections::VecDeque;
use std::sync::Arc;

use serde::Deserialize;
use tokio::sync::Mutex;

use super::ServiceError;
use crate::db::Database;
use crate::protocol::StatBlockReason;
use crate::state::AppState;
use crate::util::{EventRecord, action_name, event_to_record, flags_of, parse_client_ip};

const DEFAULT_WINDOW_LIMIT: u64 = 200;
const DEFAULT_HISTORY_LIMIT: usize = 100;
const MAX_LIMIT: usize = 1_000;

/// Actions accepted by [`query_history`]; compared case-insensitively.
const HISTORY_ACTIONS: [&str; 5] = [
    "allowed",
    "blocked",
    "suspicious",
    "highlysuspicious",
    "proxied",
];

/// Action filters are case-insensitive on every surface.
pub fn action_matches(actual: &str, wanted: &str) -> bool {
    actual.eq_ignore_ascii_case(wanted)
}

// ── Rolling-window query ───────────────────────────────────────────────────────

/// Filter over the in-memory rolling event window. Every field is optional;
/// an omitted field applies no restriction for that dimension.
#[derive(Debug, Default, Clone, Deserialize)]
pub struct EventFilter {
    /// Start of time range, inclusive (UTC unix timestamp in seconds).
    pub from_ts: Option<u64>,
    /// End of time range, inclusive (UTC unix timestamp in seconds).
    pub to_ts: Option<u64>,
    /// Client IP address (IPv4 or IPv6 string, exact match).
    pub client_ip: Option<String>,
    /// Domain name substring (case-insensitive). Falls back to matching the
    /// hex-encoded hash when the domain is unknown.
    pub domain: Option<String>,
    /// Action variant name (case-insensitive).
    pub action: Option<String>,
    /// Block-reason bitmask; events must contain ALL supplied bits.
    pub flags: Option<u32>,
    /// Maximum number of results. Defaults to 200; capped at 1 000.
    pub limit: Option<u64>,
}

/// Query the rolling window, newest first.
pub async fn query_window(
    state: &AppState,
    filter: &EventFilter,
) -> Result<Vec<EventRecord>, ServiceError> {
    let limit = filter
        .limit
        .unwrap_or(DEFAULT_WINDOW_LIMIT)
        .min(MAX_LIMIT as u64) as usize;

    let ip_filter: Option<[u8; 16]> = filter
        .client_ip
        .as_deref()
        .map(|s| parse_client_ip(s).ok_or_else(|| ServiceError::InvalidIp(s.to_string())))
        .transpose()?;

    // from_bits_retain (not _truncate) so user-defined bits 16–31 are
    // preserved for the filter check.
    let required_flags: Option<StatBlockReason> =
        filter.flags.map(StatBlockReason::from_bits_retain);
    let needle = filter.domain.as_deref().map(str::to_ascii_lowercase);

    // Snapshot events while holding the lock as briefly as possible.
    let events_snapshot: Vec<_> = {
        let stats = state.stats.read().await;
        stats
            .window_events()
            .iter()
            .map(|(_, ev)| ev.clone())
            .collect()
    };
    let domain_map = state.domain_map.read().await;

    let mut records: Vec<EventRecord> = events_snapshot
        .into_iter()
        .filter(|ev| {
            if let Some(from) = filter.from_ts
                && ev.timestamp < from
            {
                return false;
            }
            if let Some(to) = filter.to_ts
                && ev.timestamp > to
            {
                return false;
            }
            if let Some(ip) = ip_filter
                && ev.client_ip != ip
            {
                return false;
            }
            if let Some(ref wanted) = filter.action
                && !action_matches(action_name(&ev.action), wanted)
            {
                return false;
            }
            if let Some(required) = required_flags {
                return flags_of(&ev.action).is_some_and(|reason| reason.contains(required));
            }
            true
        })
        .filter(|ev| {
            let Some(ref needle) = needle else {
                return true;
            };
            let name_match = domain_map
                .get(&ev.domain_hash)
                .is_some_and(|name| name.to_ascii_lowercase().contains(needle));
            name_match || format!("{:016x}", ev.domain_hash).contains(needle)
        })
        .map(|ev| event_to_record(&ev, &domain_map))
        .collect();

    records.sort_unstable_by_key(|record| std::cmp::Reverse(record.timestamp));
    records.truncate(limit);
    Ok(records)
}

// ── History query ──────────────────────────────────────────────────────────────

/// Paginated query over the web history. A time range (`from` and/or `to`)
/// is served from SQLite; otherwise the in-memory query log is used.
#[derive(Debug, Default, Clone, Deserialize)]
pub struct HistoryQuery {
    /// Maximum number of results. Defaults to 100; capped at 1 000.
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    /// Client IP address (exact string match).
    pub client: Option<String>,
    /// Action variant name (case-insensitive).
    pub action: Option<String>,
    /// Start of time range (Unix timestamp, inclusive). Enables DB query.
    pub from: Option<u64>,
    /// End of time range (Unix timestamp, inclusive). Enables DB query.
    pub to: Option<u64>,
}

/// Query the history, newest first.
pub async fn query_history(
    db: Option<&Arc<Database>>,
    log: &Mutex<VecDeque<EventRecord>>,
    query: &HistoryQuery,
) -> Result<Vec<EventRecord>, ServiceError> {
    if let Some(action) = query.action.as_deref()
        && !HISTORY_ACTIONS
            .iter()
            .any(|known| action_matches(known, action))
    {
        return Err(ServiceError::InvalidAction(action.to_string()));
    }

    let limit = query.limit.unwrap_or(DEFAULT_HISTORY_LIMIT).min(MAX_LIMIT);
    let offset = query.offset.unwrap_or(0);

    if query.from.is_some() || query.to.is_some() {
        let db = Arc::clone(db.ok_or(ServiceError::PersistenceUnavailable)?);
        let from = query.from.unwrap_or(0);
        let to = query.to.unwrap_or(u64::MAX);
        let client = query.client.clone();
        let action = query.action.clone();
        let records = tokio::task::spawn_blocking(move || {
            db.query_range(from, to, client, action, limit, offset)
        })
        .await??;
        return Ok(records);
    }

    let log = log.lock().await;
    Ok(log
        .iter()
        .rev()
        .filter(|record| {
            query
                .client
                .as_ref()
                .is_none_or(|client| &record.client_ip == client)
                && query
                    .action
                    .as_deref()
                    .is_none_or(|wanted| action_matches(&record.action, wanted))
        })
        .skip(offset)
        .take(limit)
        .cloned()
        .collect())
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{StatAction, StatEvent};
    use std::time::Duration;

    fn make_state() -> AppState {
        AppState::new(Duration::from_secs(3600))
    }

    /// IPv4 client as dgaard sends it: IPv4-mapped IPv6.
    fn ipv4(a: u8, b: u8, c: u8, d: u8) -> [u8; 16] {
        std::net::Ipv4Addr::new(a, b, c, d)
            .to_ipv6_mapped()
            .octets()
    }

    fn allowed_event(ts: u64, hash: u64, ip: [u8; 16]) -> StatEvent {
        StatEvent {
            timestamp: ts,
            domain_hash: hash,
            client_ip: ip,
            action: StatAction::Allowed,
        }
    }

    fn blocked_event(ts: u64, hash: u64, ip: [u8; 16], reason: StatBlockReason) -> StatEvent {
        StatEvent {
            timestamp: ts,
            domain_hash: hash,
            client_ip: ip,
            action: StatAction::Blocked(reason),
        }
    }

    async fn window(state: &AppState, filter: EventFilter) -> Vec<EventRecord> {
        query_window(state, &filter).await.unwrap()
    }

    // ── action_matches ────────────────────────────────────────────────────────

    #[test]
    fn action_matches_ignores_case() {
        assert!(action_matches("Blocked", "blocked"));
        assert!(action_matches("HighlySuspicious", "HIGHLYSUSPICIOUS"));
        assert!(!action_matches("Blocked", "allowed"));
    }

    // ── query_window ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn window_returns_all_events_with_no_filters() {
        let state = make_state();
        state
            .record_event(allowed_event(1000, 1, ipv4(1, 0, 0, 0)))
            .await;
        state
            .record_event(blocked_event(
                2000,
                2,
                ipv4(2, 0, 0, 0),
                StatBlockReason::STATIC_BLACKLIST,
            ))
            .await;

        let records = window(&state, EventFilter::default()).await;
        assert_eq!(records.len(), 2);
    }

    #[tokio::test]
    async fn window_filters_by_time_range() {
        let state = make_state();
        for (ts, hash) in [(500, 1), (1500, 2), (2500, 3)] {
            state
                .record_event(allowed_event(ts, hash, ipv4(1, 0, 0, 0)))
                .await;
        }

        let records = window(
            &state,
            EventFilter {
                from_ts: Some(1000),
                to_ts: Some(2000),
                ..Default::default()
            },
        )
        .await;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].timestamp, 1500);
    }

    #[tokio::test]
    async fn window_filters_by_client_ip() {
        let state = make_state();
        state
            .record_event(allowed_event(1000, 1, ipv4(10, 0, 0, 1)))
            .await;
        state
            .record_event(allowed_event(1001, 2, ipv4(10, 0, 0, 2)))
            .await;

        let records = window(
            &state,
            EventFilter {
                client_ip: Some("10.0.0.1".into()),
                ..Default::default()
            },
        )
        .await;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].client_ip, "10.0.0.1");
    }

    #[tokio::test]
    async fn window_filters_by_action_case_insensitively() {
        let state = make_state();
        state
            .record_event(allowed_event(1000, 1, ipv4(1, 0, 0, 0)))
            .await;
        state
            .record_event(blocked_event(
                1001,
                2,
                ipv4(2, 0, 0, 0),
                StatBlockReason::ABP_RULE,
            ))
            .await;

        for wanted in ["Blocked", "blocked", "BLOCKED"] {
            let records = window(
                &state,
                EventFilter {
                    action: Some(wanted.into()),
                    ..Default::default()
                },
            )
            .await;
            assert_eq!(records.len(), 1, "action filter {wanted:?}");
            assert_eq!(records[0].action, "Blocked");
        }
    }

    #[tokio::test]
    async fn window_filters_by_flags_bitmask() {
        let state = make_state();
        state
            .record_event(blocked_event(
                1000,
                1,
                ipv4(1, 0, 0, 0),
                StatBlockReason::STATIC_BLACKLIST,
            ))
            .await;
        state
            .record_event(blocked_event(
                1001,
                2,
                ipv4(2, 0, 0, 0),
                StatBlockReason::STATIC_BLACKLIST | StatBlockReason::HIGH_ENTROPY,
            ))
            .await;
        state
            .record_event(allowed_event(1002, 3, ipv4(3, 0, 0, 0)))
            .await;

        let required = (StatBlockReason::STATIC_BLACKLIST | StatBlockReason::HIGH_ENTROPY).bits();
        let records = window(
            &state,
            EventFilter {
                flags: Some(required),
                ..Default::default()
            },
        )
        .await;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].timestamp, 1001);
    }

    #[tokio::test]
    async fn window_filters_by_domain_name() {
        let state = make_state();
        state
            .insert_domain(0xaabbcc, "evil.example.com".into())
            .await;
        state.insert_domain(0xddeeff, "safe.net".into()).await;
        state
            .record_event(allowed_event(1000, 0xaabbcc, ipv4(1, 0, 0, 0)))
            .await;
        state
            .record_event(allowed_event(1001, 0xddeeff, ipv4(2, 0, 0, 0)))
            .await;

        let records = window(
            &state,
            EventFilter {
                domain: Some("EVIL".into()),
                ..Default::default()
            },
        )
        .await;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].domain.as_deref(), Some("evil.example.com"));
    }

    #[tokio::test]
    async fn window_domain_filter_falls_back_to_hash() {
        let state = make_state();
        state
            .record_event(allowed_event(1000, 0xc0ffee, ipv4(1, 0, 0, 0)))
            .await;
        state
            .record_event(allowed_event(1001, 0x123456, ipv4(1, 0, 0, 0)))
            .await;

        let records = window(
            &state,
            EventFilter {
                domain: Some("c0ffee".into()),
                ..Default::default()
            },
        )
        .await;
        assert_eq!(records.len(), 1);
        assert!(records[0].domain.is_none());
        assert_eq!(records[0].domain_hash, format!("{:016x}", 0xc0ffee_u64));
    }

    #[tokio::test]
    async fn window_results_are_sorted_newest_first() {
        let state = make_state();
        for (ts, hash) in [(300, 1), (100, 2), (200, 3)] {
            state
                .record_event(allowed_event(ts, hash, ipv4(1, 0, 0, 0)))
                .await;
        }

        let records = window(&state, EventFilter::default()).await;
        let timestamps: Vec<u64> = records.iter().map(|record| record.timestamp).collect();
        assert_eq!(timestamps, vec![300, 200, 100]);
    }

    #[tokio::test]
    async fn window_limit_is_respected_and_capped() {
        let state = make_state();
        for index in 0..10 {
            state
                .record_event(allowed_event(index, index, ipv4(1, 0, 0, 0)))
                .await;
        }

        let limited = window(
            &state,
            EventFilter {
                limit: Some(3),
                ..Default::default()
            },
        )
        .await;
        assert_eq!(limited.len(), 3);

        let capped = window(
            &state,
            EventFilter {
                limit: Some(99_999),
                ..Default::default()
            },
        )
        .await;
        assert_eq!(capped.len(), 10);
    }

    #[tokio::test]
    async fn window_invalid_ip_filter_returns_error() {
        let state = make_state();
        let result = query_window(
            &state,
            &EventFilter {
                client_ip: Some("not-an-ip".into()),
                ..Default::default()
            },
        )
        .await;
        assert!(matches!(result, Err(ServiceError::InvalidIp(ip)) if ip == "not-an-ip"));
    }

    #[tokio::test]
    async fn window_record_carries_flags_labels() {
        let state = make_state();
        state
            .record_event(blocked_event(
                1000,
                1,
                ipv4(1, 0, 0, 0),
                StatBlockReason::NRD_LIST | StatBlockReason::HIGH_ENTROPY,
            ))
            .await;
        state
            .record_event(allowed_event(999, 2, ipv4(1, 0, 0, 0)))
            .await;

        let records = window(&state, EventFilter::default()).await;
        assert!(
            records[0]
                .flags_labels
                .iter()
                .any(|label| label == "NRD_LIST")
        );
        assert!(
            records[0]
                .flags_labels
                .iter()
                .any(|label| label == "HIGH_ENTROPY")
        );
        assert!(records[1].flags.is_none());
        assert!(records[1].flags_labels.is_empty());
    }

    // ── query_history ─────────────────────────────────────────────────────────

    fn record(ts: u64, action: &str, client_ip: &str) -> EventRecord {
        EventRecord {
            timestamp: ts,
            domain: None,
            domain_hash: format!("{ts:016x}"),
            client_ip: client_ip.to_string(),
            action: action.to_string(),
            flags: None,
            flags_labels: vec![],
        }
    }

    fn log_of(records: Vec<EventRecord>) -> Mutex<VecDeque<EventRecord>> {
        Mutex::new(records.into_iter().collect())
    }

    #[tokio::test]
    async fn history_rejects_unknown_action() {
        let log = log_of(vec![]);
        let result = query_history(
            None,
            &log,
            &HistoryQuery {
                action: Some("invalid".into()),
                ..Default::default()
            },
        )
        .await;
        assert!(matches!(result, Err(ServiceError::InvalidAction(action)) if action == "invalid"));
    }

    #[tokio::test]
    async fn history_from_log_is_newest_first_and_filtered() {
        let log = log_of(vec![
            record(1, "Allowed", "10.0.0.1"),
            record(2, "Blocked", "10.0.0.1"),
            record(3, "Blocked", "10.0.0.2"),
            record(4, "Blocked", "10.0.0.1"),
        ]);

        let records = query_history(
            None,
            &log,
            &HistoryQuery {
                client: Some("10.0.0.1".into()),
                action: Some("blocked".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let timestamps: Vec<u64> = records.iter().map(|record| record.timestamp).collect();
        assert_eq!(timestamps, vec![4, 2]);
    }

    #[tokio::test]
    async fn history_from_log_applies_offset_and_limits() {
        let log = log_of(
            (0..1500)
                .map(|ts| record(ts, "Allowed", "10.0.0.1"))
                .collect(),
        );

        let default_page = query_history(None, &log, &HistoryQuery::default())
            .await
            .unwrap();
        assert_eq!(default_page.len(), 100);
        assert_eq!(default_page[0].timestamp, 1499);

        let capped = query_history(
            None,
            &log,
            &HistoryQuery {
                limit: Some(9999),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(capped.len(), 1000);

        let offset_page = query_history(
            None,
            &log,
            &HistoryQuery {
                limit: Some(2),
                offset: Some(10),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let timestamps: Vec<u64> = offset_page.iter().map(|record| record.timestamp).collect();
        assert_eq!(timestamps, vec![1489, 1488]);
    }

    #[tokio::test]
    async fn history_time_range_without_db_is_unavailable() {
        let log = log_of(vec![record(1, "Allowed", "10.0.0.1")]);
        let result = query_history(
            None,
            &log,
            &HistoryQuery {
                to: Some(10),
                ..Default::default()
            },
        )
        .await;
        assert!(matches!(result, Err(ServiceError::PersistenceUnavailable)));
    }

    #[tokio::test]
    async fn history_time_range_is_served_from_db() {
        let db = Arc::new(Database::open_in_memory().unwrap());
        db.insert_events(&[
            record(1000, "Blocked", "10.0.0.1"),
            record(2000, "Allowed", "10.0.0.2"),
        ])
        .unwrap();
        // The in-memory log must be ignored when a time range is given.
        let log = log_of(vec![record(1200, "Blocked", "10.0.0.9")]);

        let records = query_history(
            Some(&db),
            &log,
            &HistoryQuery {
                from: Some(500),
                to: Some(1500),
                action: Some("BLOCKED".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].timestamp, 1000);
        assert_eq!(records[0].client_ip, "10.0.0.1");
    }

    #[test]
    fn service_errors_render_user_facing_messages() {
        assert_eq!(
            ServiceError::InvalidIp("x".into()).to_string(),
            "invalid IP address: x"
        );
        assert_eq!(
            ServiceError::PersistenceUnavailable.to_string(),
            "persistence not configured"
        );
        assert!(
            ServiceError::InvalidAction("nope".into())
                .to_string()
                .starts_with("invalid action 'nope'")
        );
    }
}
