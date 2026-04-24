use std::sync::Arc;

use axum::{
    Router,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::get,
};
use serde::Deserialize;
use tokio::sync::watch;

use crate::config::ConnectivityConfig;
use crate::protocol::StatBlockReason;
use crate::state::AppState;
use crate::util::{EventRecord, action_name, event_to_record, flags_of, parse_filter_ip};

// ── Query params ───────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct EventsQuery {
    /// Start of time range, inclusive (UTC unix timestamp in seconds).
    from_ts: Option<u64>,
    /// End of time range, inclusive (UTC unix timestamp in seconds).
    to_ts: Option<u64>,
    /// Filter by client IP address (IPv4 or IPv6 string, exact match).
    client_ip: Option<String>,
    /// Filter by domain name substring (case-insensitive).
    domain: Option<String>,
    /// Filter by action variant: Allowed, Proxied, Blocked, Suspicious, HighlySuspicious.
    action: Option<String>,
    /// Filter by block-reason bitmask (u16). Events must contain ALL supplied bits.
    flags: Option<u16>,
    /// Maximum number of results. Defaults to 200; capped at 1 000.
    limit: Option<u64>,
}

// ── Axum state ─────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct ApiState {
    app: Arc<AppState>,
    token: String,
}

// ── Business logic ─────────────────────────────────────────────────────────────

async fn query_events(state: &AppState, q: &EventsQuery) -> Result<Vec<EventRecord>, String> {
    let limit = q.limit.unwrap_or(200).min(1_000) as usize;

    let ip_filter: Option<[u8; 16]> = q
        .client_ip
        .as_deref()
        .map(|s| parse_filter_ip(s).ok_or_else(|| format!("invalid IP address: {s}")))
        .transpose()?;

    let required_flags: Option<StatBlockReason> = q.flags.map(StatBlockReason::from_bits_truncate);

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
            if let Some(from) = q.from_ts
                && ev.timestamp < from
            {
                return false;
            }
            if let Some(to) = q.to_ts
                && ev.timestamp > to
            {
                return false;
            }
            if let Some(filter) = ip_filter
                && ev.client_ip != filter
            {
                return false;
            }
            if let Some(ref action_filter) = q.action
                && action_name(&ev.action) != action_filter.as_str()
            {
                return false;
            }
            if let Some(required) = required_flags {
                match flags_of(&ev.action) {
                    Some(r) => {
                        if !r.contains(required) {
                            return false;
                        }
                    }
                    None => return false,
                }
            }
            true
        })
        .filter_map(|ev| {
            if let Some(ref needle) = q.domain {
                let needle_lc = needle.to_ascii_lowercase();
                let resolved = domain_map.get(&ev.domain_hash);
                let name_match = resolved
                    .map(|n| n.to_ascii_lowercase().contains(&needle_lc))
                    .unwrap_or(false);
                let hash_match = format!("{:016x}", ev.domain_hash).contains(&needle_lc);
                if !name_match && !hash_match {
                    return None;
                }
            }
            Some(event_to_record(&ev, &*domain_map))
        })
        .collect();

    records.sort_unstable_by_key(|r| std::cmp::Reverse(r.timestamp));
    records.truncate(limit);
    Ok(records)
}

// ── Handlers ───────────────────────────────────────────────────────────────────

fn check_auth(token: &str, headers: &HeaderMap) -> bool {
    if token.is_empty() {
        return true;
    }
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(|v| v == format!("Bearer {token}"))
        .unwrap_or(false)
}

async fn health() -> StatusCode {
    StatusCode::OK
}

async fn get_events(
    State(api): State<ApiState>,
    headers: HeaderMap,
    Query(q): Query<EventsQuery>,
) -> Response {
    if !check_auth(&api.token, &headers) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "unauthorized"})),
        )
            .into_response();
    }
    match query_events(&api.app, &q).await {
        Ok(records) => Json(records).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e})),
        )
            .into_response(),
    }
}

// ── Router builder ─────────────────────────────────────────────────────────────

fn build_router(state: ApiState, root_path: &str) -> Router {
    let root = root_path.trim_end_matches('/');
    let events_path = if root.is_empty() {
        "/events".to_string()
    } else {
        format!("{root}/events")
    };
    Router::new()
        .route("/health", get(health))
        .route(&events_path, get(get_events))
        .with_state(state)
}

// ── Server entry-point ─────────────────────────────────────────────────────────

/// Serve the REST API.
///
/// Only called when `config.enabled` is true.
/// Returns when `shutdown` is signalled.
pub async fn run(
    config: ConnectivityConfig,
    state: Arc<AppState>,
    mut shutdown: watch::Receiver<bool>,
) {
    let api_state = ApiState {
        app: state,
        token: config.token.clone(),
    };
    let router = build_router(api_state, &config.root_path);
    let addr = format!("{}:{}", config.listen, config.port);

    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("API server: failed to bind {addr}: {e}");
            return;
        }
    };

    let serve = axum::serve(listener, router).with_graceful_shutdown(async move {
        let _ = shutdown.changed().await;
    });

    if let Err(e) = serve.await {
        eprintln!("API server error: {e}");
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        protocol::{StatAction, StatBlockReason, StatEvent},
        state::AppState,
    };
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use std::time::Duration;
    use tower::ServiceExt;

    fn make_state() -> Arc<AppState> {
        Arc::new(AppState::new(Duration::from_secs(3600)))
    }

    fn ipv4(a: u8, b: u8, c: u8, d: u8) -> [u8; 16] {
        [a, b, c, d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    }

    fn allowed_event(ts: u64, hash: u64, ip: [u8; 16]) -> StatEvent {
        StatEvent {
            timestamp: ts,
            domain_hash: hash,
            client_ip: ip,
            action: StatAction::Allowed,
        }
    }

    fn blocked_event(ts: u64, hash: u64, ip: [u8; 16], r: StatBlockReason) -> StatEvent {
        StatEvent {
            timestamp: ts,
            domain_hash: hash,
            client_ip: ip,
            action: StatAction::Blocked(r),
        }
    }

    fn make_app(state: Arc<AppState>, token: &str) -> Router {
        let api_state = ApiState {
            app: state,
            token: token.to_string(),
        };
        build_router(api_state, "/")
    }

    async fn collect_json<T: serde::de::DeserializeOwned>(body: Body) -> T {
        let bytes = body.collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    // ── query_events unit tests ────────────────────────────────────────────────

    async fn do_query(state: &Arc<AppState>, q: EventsQuery) -> Vec<EventRecord> {
        query_events(state, &q).await.unwrap()
    }

    #[tokio::test]
    async fn returns_all_events_with_no_filters() {
        let state = make_state();
        state
            .record_event(allowed_event(1000, 1, ipv4(1, 0, 0, 0)))
            .await;
        state
            .record_event(allowed_event(2000, 2, ipv4(2, 0, 0, 0)))
            .await;

        let records = do_query(
            &state,
            EventsQuery {
                from_ts: None,
                to_ts: None,
                client_ip: None,
                domain: None,
                action: None,
                flags: None,
                limit: None,
            },
        )
        .await;
        assert_eq!(records.len(), 2);
    }

    #[tokio::test]
    async fn filters_by_time_range() {
        let state = make_state();
        state
            .record_event(allowed_event(500, 1, ipv4(1, 0, 0, 0)))
            .await;
        state
            .record_event(allowed_event(1500, 2, ipv4(2, 0, 0, 0)))
            .await;
        state
            .record_event(allowed_event(2500, 3, ipv4(3, 0, 0, 0)))
            .await;

        let records = do_query(
            &state,
            EventsQuery {
                from_ts: Some(1000),
                to_ts: Some(2000),
                client_ip: None,
                domain: None,
                action: None,
                flags: None,
                limit: None,
            },
        )
        .await;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].timestamp, 1500);
    }

    #[tokio::test]
    async fn filters_by_client_ip() {
        let state = make_state();
        state
            .record_event(allowed_event(1000, 1, ipv4(10, 0, 0, 1)))
            .await;
        state
            .record_event(allowed_event(1001, 2, ipv4(10, 0, 0, 2)))
            .await;

        let records = do_query(
            &state,
            EventsQuery {
                from_ts: None,
                to_ts: None,
                client_ip: Some("10.0.0.1".into()),
                domain: None,
                action: None,
                flags: None,
                limit: None,
            },
        )
        .await;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].client_ip, "10.0.0.1");
    }

    #[tokio::test]
    async fn filters_by_action() {
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

        let records = do_query(
            &state,
            EventsQuery {
                from_ts: None,
                to_ts: None,
                client_ip: None,
                domain: None,
                action: Some("Blocked".into()),
                flags: None,
                limit: None,
            },
        )
        .await;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].action, "Blocked");
    }

    #[tokio::test]
    async fn filters_by_flags_bitmask() {
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

        let required = (StatBlockReason::STATIC_BLACKLIST | StatBlockReason::HIGH_ENTROPY).bits();
        let records = do_query(
            &state,
            EventsQuery {
                from_ts: None,
                to_ts: None,
                client_ip: None,
                domain: None,
                action: None,
                flags: Some(required),
                limit: None,
            },
        )
        .await;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].timestamp, 1001);
    }

    #[tokio::test]
    async fn filters_by_domain_name() {
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

        let records = do_query(
            &state,
            EventsQuery {
                from_ts: None,
                to_ts: None,
                client_ip: None,
                domain: Some("evil".into()),
                action: None,
                flags: None,
                limit: None,
            },
        )
        .await;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].domain.as_deref(), Some("evil.example.com"));
    }

    #[tokio::test]
    async fn results_are_sorted_newest_first() {
        let state = make_state();
        state
            .record_event(allowed_event(300, 1, ipv4(1, 0, 0, 0)))
            .await;
        state
            .record_event(allowed_event(100, 2, ipv4(2, 0, 0, 0)))
            .await;
        state
            .record_event(allowed_event(200, 3, ipv4(3, 0, 0, 0)))
            .await;

        let records = do_query(
            &state,
            EventsQuery {
                from_ts: None,
                to_ts: None,
                client_ip: None,
                domain: None,
                action: None,
                flags: None,
                limit: None,
            },
        )
        .await;
        assert_eq!(records[0].timestamp, 300);
        assert_eq!(records[1].timestamp, 200);
        assert_eq!(records[2].timestamp, 100);
    }

    #[tokio::test]
    async fn limit_is_respected() {
        let state = make_state();
        for i in 0..10 {
            state
                .record_event(allowed_event(i, i, ipv4(1, 0, 0, 0)))
                .await;
        }

        let records = do_query(
            &state,
            EventsQuery {
                from_ts: None,
                to_ts: None,
                client_ip: None,
                domain: None,
                action: None,
                flags: None,
                limit: Some(3),
            },
        )
        .await;
        assert_eq!(records.len(), 3);
    }

    #[tokio::test]
    async fn invalid_ip_filter_returns_error() {
        let state = make_state();
        let result = query_events(
            &state,
            &EventsQuery {
                from_ts: None,
                to_ts: None,
                client_ip: Some("not-an-ip".into()),
                domain: None,
                action: None,
                flags: None,
                limit: None,
            },
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn flags_labels_populated_for_blocked_event() {
        let state = make_state();
        state
            .record_event(blocked_event(
                1000,
                1,
                ipv4(1, 0, 0, 0),
                StatBlockReason::NRD_LIST | StatBlockReason::HIGH_ENTROPY,
            ))
            .await;

        let records = do_query(
            &state,
            EventsQuery {
                from_ts: None,
                to_ts: None,
                client_ip: None,
                domain: None,
                action: None,
                flags: None,
                limit: None,
            },
        )
        .await;
        assert!(records[0].flags_labels.contains(&"NRD_LIST".to_string()));
        assert!(
            records[0]
                .flags_labels
                .contains(&"HIGH_ENTROPY".to_string())
        );
    }

    #[tokio::test]
    async fn allowed_event_has_null_flags() {
        let state = make_state();
        state
            .record_event(allowed_event(1000, 1, ipv4(1, 0, 0, 0)))
            .await;

        let records = do_query(
            &state,
            EventsQuery {
                from_ts: None,
                to_ts: None,
                client_ip: None,
                domain: None,
                action: None,
                flags: None,
                limit: None,
            },
        )
        .await;
        assert!(records[0].flags.is_none());
        assert!(records[0].flags_labels.is_empty());
    }

    // ── HTTP integration tests ─────────────────────────────────────────────────

    #[tokio::test]
    async fn health_returns_200() {
        let app = make_app(make_state(), "");
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn events_without_token_returns_401() {
        let app = make_app(make_state(), "secret");
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/events")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn events_wrong_token_returns_401() {
        let app = make_app(make_state(), "secret");
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/events")
                    .header("authorization", "Bearer wrong")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn events_valid_token_returns_200_with_events() {
        let state = make_state();
        state
            .record_event(allowed_event(1000, 1, ipv4(1, 0, 0, 0)))
            .await;

        let app = make_app(state, "secret");
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/events")
                    .header("authorization", "Bearer secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let records: Vec<EventRecord> = collect_json(resp.into_body()).await;
        assert_eq!(records.len(), 1);
    }

    #[tokio::test]
    async fn events_no_token_configured_allows_unauthenticated() {
        let app = make_app(make_state(), "");
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/events")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn events_invalid_ip_param_returns_400() {
        let app = make_app(make_state(), "");
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/events?client_ip=not-an-ip")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn events_query_param_from_ts_filters_results() {
        let state = make_state();
        state
            .record_event(allowed_event(500, 1, ipv4(1, 0, 0, 0)))
            .await;
        state
            .record_event(allowed_event(1500, 2, ipv4(2, 0, 0, 0)))
            .await;

        let app = make_app(state, "");
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/events?from_ts=1000")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let records: Vec<EventRecord> = collect_json(resp.into_body()).await;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].timestamp, 1500);
    }

    #[tokio::test]
    async fn events_root_path_prefix_is_respected() {
        let state = make_state();
        let api_state = ApiState {
            app: state,
            token: String::new(),
        };
        let app = build_router(api_state, "/api/v1");

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/events")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
