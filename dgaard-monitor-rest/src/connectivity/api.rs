use std::sync::Arc;

use axum::{
    Router,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::get,
};
use tokio::sync::watch;

use crate::config::{ApiConfig, ServerConfig};
use crate::error::error_response;
use dgaard_monitor_core::service::events::{EventFilter, query_window};
use dgaard_monitor_core::state::AppState;

// ── Axum state ─────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct ApiState {
    app: Arc<AppState>,
    token: String,
}

// ── Handlers ───────────────────────────────────────────────────────────────────

fn check_auth(token: &str, headers: &HeaderMap) -> bool {
    if token.is_empty() {
        return true;
    }
    let expected = format!("Bearer {token}");
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(|v| constant_time_eq::constant_time_eq(v.as_bytes(), expected.as_bytes()))
        .unwrap_or(false)
}

async fn health() -> StatusCode {
    StatusCode::OK
}

async fn get_events(
    State(api): State<ApiState>,
    headers: HeaderMap,
    Query(filter): Query<EventFilter>,
) -> Response {
    if !check_auth(&api.token, &headers) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "unauthorized"})),
        )
            .into_response();
    }
    match query_window(&api.app, &filter).await {
        Ok(records) => Json(records).into_response(),
        Err(err) => error_response(err),
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
    server: ServerConfig,
    config: ApiConfig,
    state: Arc<AppState>,
    mut shutdown: watch::Receiver<bool>,
) {
    let api_state = ApiState {
        app: state,
        token: server.token,
    };
    let router = build_router(api_state, &config.root_path);
    let addr = format!("{}:{}", server.listen, config.port);

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
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use dgaard_monitor_core::protocol::{StatAction, StatBlockReason, StatEvent};
    use dgaard_monitor_core::state::AppState;
    use dgaard_monitor_core::util::EventRecord;
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
    async fn events_equal_length_wrong_token_returns_401() {
        // Regression: bearer comparison must run in constant time, so an
        // equal-length-but-wrong token must still be rejected.
        let app = make_app(make_state(), "secret");
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/events")
                    .header("authorization", "Bearer SeCrEt")
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
    async fn events_action_filter_is_case_insensitive() {
        // Regression: the API used to match `action` exactly while the web UI
        // matched case-insensitively, so `?action=blocked` returned nothing here.
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

        let app = make_app(state, "");
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/events?action=blocked")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let records: Vec<EventRecord> = collect_json(resp.into_body()).await;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].action, "Blocked");
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
