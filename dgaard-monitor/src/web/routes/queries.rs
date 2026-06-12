use std::net::IpAddr;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::util::EventRecord;
use crate::web::state::WebState;

#[derive(Serialize)]
struct QueryResponse {
    #[serde(flatten)]
    record: EventRecord,
    hostname: Option<String>,
}

#[derive(Deserialize)]
pub struct QueriesParams {
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    pub client: Option<String>,
    pub action: Option<String>,
    /// Start of time range (Unix timestamp, inclusive). Enables DB query.
    pub from: Option<u64>,
    /// End of time range (Unix timestamp, inclusive). Enables DB query.
    pub to: Option<u64>,
}

fn is_valid_action(action: &str) -> bool {
    matches!(
        action.to_lowercase().as_str(),
        "allowed" | "blocked" | "suspicious" | "highlysuspicious" | "proxied"
    )
}

pub async fn queries_handler(
    State(web): State<Arc<WebState>>,
    Query(params): Query<QueriesParams>,
) -> Response {
    if params
        .action
        .as_deref()
        .is_some_and(|a| !is_valid_action(a))
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "action must be one of: allowed, blocked, suspicious, highlysuspicious, proxied"})),
        )
            .into_response();
    }

    let limit = params.limit.unwrap_or(100).min(1000);
    let offset = params.offset.unwrap_or(0);

    // When a time-range is requested, serve from SQLite.
    if params.from.is_some() || params.to.is_some() {
        let db = match web.db.as_ref() {
            Some(d) => std::sync::Arc::clone(d),
            None => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({"error": "persistence not configured"})),
                )
                    .into_response();
            }
        };

        let from = params.from.unwrap_or(0);
        let to = params.to.unwrap_or(u64::MAX);
        let client = params.client.clone();
        let action = params.action.clone();

        let result = tokio::task::spawn_blocking(move || {
            db.query_range(from, to, client, action, limit, offset)
        })
        .await;

        return match result {
            Ok(Ok(records)) => {
                let results: Vec<QueryResponse> = records
                    .into_iter()
                    .map(|record| {
                        let hostname = record
                            .client_ip
                            .parse::<IpAddr>()
                            .ok()
                            .and_then(|ip| web.hostname_cache.get(&ip).map(|h| h.clone()));
                        QueryResponse { record, hostname }
                    })
                    .collect();
                Json(results).into_response()
            }
            Ok(Err(e)) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("database error: {e}")})),
            )
                .into_response(),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("task error: {e}")})),
            )
                .into_response(),
        };
    }

    let log = web.query_log.lock().await;

    let results: Vec<QueryResponse> = log
        .iter()
        .rev()
        .filter(|record| {
            let client_ok = params
                .client
                .as_ref()
                .map(|c| &record.client_ip == c)
                .unwrap_or(true);
            let action_ok = params
                .action
                .as_ref()
                .map(|a| record.action.to_lowercase() == a.to_lowercase())
                .unwrap_or(true);
            client_ok && action_ok
        })
        .skip(offset)
        .take(limit)
        .map(|record| {
            let hostname = record
                .client_ip
                .parse::<IpAddr>()
                .ok()
                .and_then(|ip| web.hostname_cache.get(&ip).map(|h| h.clone()));
            QueryResponse {
                record: record.clone(),
                hostname,
            }
        })
        .collect();

    drop(log);

    Json(results).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::AppState;
    use crate::util::EventRecord;
    use crate::web::state::WebState;
    use std::time::Duration;

    fn make_web_state() -> Arc<WebState> {
        let app = Arc::new(AppState::new(Duration::from_secs(3600)));
        Arc::new(WebState::new(app, 2000))
    }

    fn make_record(action: &str, client_ip: &str) -> EventRecord {
        EventRecord {
            timestamp: 0,
            domain: None,
            domain_hash: "0000000000000000".to_string(),
            client_ip: client_ip.to_string(),
            action: action.to_string(),
            flags: None,
            flags_labels: vec![],
        }
    }

    #[tokio::test]
    async fn invalid_action_returns_400() {
        let web = make_web_state();
        let params = QueriesParams {
            limit: None,
            offset: None,
            client: None,
            action: Some("invalid".to_string()),
            from: None,
            to: None,
        };
        let resp = queries_handler(State(web), Query(params)).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn empty_log_returns_empty_array() {
        let web = make_web_state();
        let params = QueriesParams {
            limit: None,
            offset: None,
            client: None,
            action: None,
            from: None,
            to: None,
        };
        let resp = queries_handler(State(web), Query(params)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert!(parsed.is_empty());
    }

    #[tokio::test]
    async fn limit_defaults_to_100_and_caps_at_1000() {
        let web = make_web_state();
        for i in 0..150u64 {
            let mut record = make_record("Allowed", "192.168.1.1");
            record.timestamp = i;
            web.push_event(record).await;
        }

        let params = QueriesParams {
            limit: None,
            offset: None,
            client: None,
            action: None,
            from: None,
            to: None,
        };
        let resp = queries_handler(State(Arc::clone(&web)), Query(params)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed.len(), 100);

        let params_capped = QueriesParams {
            limit: Some(9999),
            offset: None,
            client: None,
            action: None,
            from: None,
            to: None,
        };
        let resp2 = queries_handler(State(web), Query(params_capped)).await;
        let body2 = axum::body::to_bytes(resp2.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed2: Vec<serde_json::Value> = serde_json::from_slice(&body2).unwrap();
        assert_eq!(parsed2.len(), 150);
    }

    // ── DB-backed (from/to) path ──────────────────────────────────────────────

    fn make_web_state_with_db() -> Arc<WebState> {
        let app = Arc::new(AppState::new(std::time::Duration::from_secs(3600)));
        let db = crate::db::Database::open_in_memory().unwrap();
        Arc::new(WebState::new(app, 100).with_db(Arc::new(db)))
    }

    #[tokio::test]
    async fn from_without_db_returns_503() {
        let web = make_web_state();
        let params = QueriesParams {
            limit: None,
            offset: None,
            client: None,
            action: None,
            from: Some(0),
            to: None,
        };
        let resp = queries_handler(State(web), Query(params)).await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn from_to_returns_db_results() {
        let web = make_web_state_with_db();
        // Seed the DB through push_event (the ingestor path populates both
        // in-memory log and persists via the writer task in production; here we
        // insert directly into the DB for the test).
        if let Some(db) = &web.db {
            db.insert_events(&[
                EventRecord {
                    timestamp: 1000,
                    domain: Some("example.com".to_string()),
                    domain_hash: "0000000000000001".to_string(),
                    client_ip: "10.0.0.1".to_string(),
                    action: "Blocked".to_string(),
                    flags: None,
                    flags_labels: vec![],
                },
                EventRecord {
                    timestamp: 2000,
                    domain: Some("test.org".to_string()),
                    domain_hash: "0000000000000002".to_string(),
                    client_ip: "10.0.0.2".to_string(),
                    action: "Allowed".to_string(),
                    flags: None,
                    flags_labels: vec![],
                },
            ])
            .unwrap();
        }

        let params = QueriesParams {
            limit: None,
            offset: None,
            client: None,
            action: None,
            from: Some(500),
            to: Some(1500),
        };
        let resp = queries_handler(State(web), Query(params)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        // Only ts=1000 is in range [500, 1500]
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0]["timestamp"], 1000);
        assert_eq!(parsed[0]["action"], "Blocked");
    }
}
