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
        };
        let resp2 = queries_handler(State(web), Query(params_capped)).await;
        let body2 = axum::body::to_bytes(resp2.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed2: Vec<serde_json::Value> = serde_json::from_slice(&body2).unwrap();
        assert_eq!(parsed2.len(), 150);
    }
}
