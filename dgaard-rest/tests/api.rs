//! Integration tests for the dgaard-rest HTTP API.
//!
//! Spins up the axum router in-process with `tower::ServiceExt::oneshot` —
//! no TCP listener is required. Each test builds an isolated `AppState` so
//! tests are fully independent.

use axum::{
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode, header},
};
use dgaard_engine::{Config as EngineConfig, FilterEngine};
use dgaard_rest::{HASH_SEED, routes, state::AppState};
use tower::ServiceExt;

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Default state: no domain lists loaded, standard engine heuristics, HTTP 200 for blocked.
fn default_state() -> AppState {
    let config = EngineConfig::default();
    let engine = FilterEngine::build_from_files(&config, HASH_SEED);
    AppState::new(engine, config, String::new(), 200)
}

/// Blocking state: `max_domain_length = 1` forces `InvalidStructure` for every
/// real domain, making it trivial to test the `blocked_status_code` path.
fn all_blocking_state(blocked_status_code: u16) -> AppState {
    let mut config = EngineConfig::default();
    config.security.structure.max_domain_length = 1;
    let engine = FilterEngine::build_from_files(&config, HASH_SEED);
    AppState::new(engine, config, String::new(), blocked_status_code)
}

fn get(uri: &str) -> Request<Body> {
    Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(Body::from(""))
        .unwrap()
}

fn post_empty(uri: &str) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .body(Body::from(""))
        .unwrap()
}

fn post_json(uri: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn response_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

// ── GET /api/v1/health ────────────────────────────────────────────────────────

#[tokio::test]
async fn health_returns_204_no_content() {
    let resp = routes::router()
        .with_state(default_state())
        .oneshot(get("/api/v1/health"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn health_body_is_empty() {
    let resp = routes::router()
        .with_state(default_state())
        .oneshot(get("/api/v1/health"))
        .await
        .unwrap();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    assert!(bytes.is_empty());
}

// ── GET /api/v1/blocklists ────────────────────────────────────────────────────

#[tokio::test]
async fn get_blocklists_returns_200() {
    let resp = routes::router()
        .with_state(default_state())
        .oneshot(get("/api/v1/blocklists"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn get_blocklists_returns_json_array() {
    let resp = routes::router()
        .with_state(default_state())
        .oneshot(get("/api/v1/blocklists"))
        .await
        .unwrap();
    let json = response_json(resp).await;
    assert!(json.is_array(), "expected JSON array, got: {json}");
}

#[tokio::test]
async fn get_blocklists_each_entry_has_name_count_last_updated() {
    let resp = routes::router()
        .with_state(default_state())
        .oneshot(get("/api/v1/blocklists"))
        .await
        .unwrap();
    let json = response_json(resp).await;
    for entry in json.as_array().unwrap() {
        let obj = entry.as_object().unwrap();
        assert!(obj.contains_key("name"), "missing 'name' in {entry}");
        assert!(obj.contains_key("count"), "missing 'count' in {entry}");
        assert!(
            obj.contains_key("last_updated"),
            "missing 'last_updated' in {entry}"
        );
    }
}

// ── POST /api/v1/blocklists/update ───────────────────────────────────────────

#[tokio::test]
async fn post_blocklists_update_returns_202_accepted() {
    let resp = routes::router()
        .with_state(default_state())
        .oneshot(post_empty("/api/v1/blocklists/update"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
}

// ── POST /api/v1/check — happy paths ─────────────────────────────────────────

#[tokio::test]
async fn check_clean_domain_returns_200_and_not_blocked() {
    let resp = routes::router()
        .with_state(default_state())
        .oneshot(post_json("/api/v1/check", r#"{"domain":"example.com"}"#))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = response_json(resp).await;
    assert_eq!(json["blocked"], false);
    assert_eq!(json["domain"], "example.com");
}

#[tokio::test]
async fn check_response_contains_all_required_fields() {
    let resp = routes::router()
        .with_state(default_state())
        .oneshot(post_json("/api/v1/check", r#"{"domain":"example.com"}"#))
        .await
        .unwrap();
    let json = response_json(resp).await;
    assert!(json.get("domain").is_some(), "missing 'domain'");
    assert!(json.get("score").is_some(), "missing 'score'");
    assert!(json.get("blocked").is_some(), "missing 'blocked'");
    assert!(json.get("action").is_some(), "missing 'action'");
    assert!(json.get("reasons").is_some(), "missing 'reasons'");
    assert!(json["reasons"].is_array());
}

#[tokio::test]
async fn check_blocked_domain_returns_403_when_blocked_status_code_is_403() {
    let resp = routes::router()
        .with_state(all_blocking_state(403))
        .oneshot(post_json("/api/v1/check", r#"{"domain":"example.com"}"#))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let json = response_json(resp).await;
    assert_eq!(json["blocked"], true);
}

#[tokio::test]
async fn check_blocked_domain_returns_200_when_blocked_status_code_is_200() {
    let resp = routes::router()
        .with_state(all_blocking_state(200))
        .oneshot(post_json("/api/v1/check", r#"{"domain":"example.com"}"#))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = response_json(resp).await;
    assert_eq!(json["blocked"], true);
}

// ── POST /api/v1/check — input validation (R2.5) ─────────────────────────────

#[tokio::test]
async fn check_missing_domain_field_returns_400() {
    let resp = routes::router()
        .with_state(default_state())
        .oneshot(post_json("/api/v1/check", r#"{}"#))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = response_json(resp).await;
    assert!(json.get("error").is_some(), "expected 'error' key");
}

#[tokio::test]
async fn check_empty_domain_returns_400() {
    let resp = routes::router()
        .with_state(default_state())
        .oneshot(post_json("/api/v1/check", r#"{"domain":""}"#))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = response_json(resp).await;
    assert!(json.get("error").is_some());
}

#[tokio::test]
async fn check_whitespace_only_domain_returns_400() {
    let resp = routes::router()
        .with_state(default_state())
        .oneshot(post_json("/api/v1/check", r#"{"domain":"   "}"#))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn check_domain_exceeding_253_chars_returns_422() {
    let domain = "a".repeat(254);
    let resp = routes::router()
        .with_state(default_state())
        .oneshot(post_json(
            "/api/v1/check",
            &format!(r#"{{"domain":"{domain}"}}"#),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let json = response_json(resp).await;
    assert!(json.get("error").is_some());
}
