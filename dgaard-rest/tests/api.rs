//! Integration tests for the dgaard-rest HTTP API.
//!
//! Spins up the axum router in-process with `tower::ServiceExt::oneshot` —
//! no TCP listener is required. Each test builds an isolated `AppState` so
//! tests are fully independent.

use std::io::Write;

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

// ── GET /api/v1/blocklists — with real files ──────────────────────────────────

fn write_temp_blocklist(tag: &str, content: &str) -> String {
    let path = format!("/tmp/dgaard_rest_bl_test_{tag}_{}", std::process::id());
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(content.as_bytes()).unwrap();
    path
}

fn empty_sources_config() -> EngineConfig {
    let mut config = EngineConfig::default();
    config.sources.blacklists = vec![];
    config.sources.whitelists = vec![];
    config.sources.nrd_list_path = String::new();
    config
}

fn state_with_blacklist(path: &str) -> AppState {
    let mut config = empty_sources_config();
    config.sources.blacklists = vec![path.to_string()];
    let engine = FilterEngine::build_from_files(&config, HASH_SEED);
    AppState::new(engine, config, String::new(), 200)
}

#[tokio::test]
async fn get_blocklists_with_file_returns_correct_count() {
    let path = write_temp_blocklist("count", "example.com\n# comment\ngoogle.com\n\nbad.org\n");
    let state = state_with_blacklist(&path);

    let resp = routes::router()
        .with_state(state)
        .oneshot(get("/api/v1/blocklists"))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let json = response_json(resp).await;
    let arr = json.as_array().unwrap();
    assert_eq!(arr.len(), 1, "One configured blacklist");

    let entry = &arr[0];
    assert_eq!(entry["name"], path.as_str());
    // 3 valid lines (comment and blank are not counted)
    assert_eq!(entry["count"], 3u64);
    assert!(
        !entry["last_updated"].is_null(),
        "last_updated should be set for an existing file"
    );

    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn get_blocklists_missing_file_has_zero_count() {
    // Configure a path that does not exist
    let mut config = empty_sources_config();
    config.sources.blacklists = vec!["/nonexistent/path/list.txt".to_string()];
    let engine = FilterEngine::build_from_files(&config, HASH_SEED);
    let state = AppState::new(engine, config, String::new(), 200);

    let resp = routes::router()
        .with_state(state)
        .oneshot(get("/api/v1/blocklists"))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let json = response_json(resp).await;
    let arr = json.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["count"], 0u64);
    assert!(arr[0]["last_updated"].is_null());
}

#[tokio::test]
async fn get_blocklists_nrd_list_included() {
    let path = write_temp_blocklist("nrd", "nrd1.com\nnrd2.com\n");
    let mut config = empty_sources_config();
    config.sources.nrd_list_path = path.clone();
    let engine = FilterEngine::build_from_files(&config, HASH_SEED);
    let state = AppState::new(engine, config, String::new(), 200);

    let resp = routes::router()
        .with_state(state)
        .oneshot(get("/api/v1/blocklists"))
        .await
        .unwrap();

    let json = response_json(resp).await;
    let arr = json.as_array().unwrap();
    assert_eq!(arr.len(), 1, "NRD list should appear as one entry");
    assert_eq!(arr[0]["count"], 2u64);

    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn get_blocklists_whitelist_and_blacklist_both_appear() {
    let bl_path = write_temp_blocklist("bl", "bad.com\nevil.net\n");
    let wl_path = write_temp_blocklist("wl", "safe.com\n");

    let mut config = empty_sources_config();
    config.sources.blacklists = vec![bl_path.clone()];
    config.sources.whitelists = vec![wl_path.clone()];
    let engine = FilterEngine::build_from_files(&config, HASH_SEED);
    let state = AppState::new(engine, config, String::new(), 200);

    let resp = routes::router()
        .with_state(state)
        .oneshot(get("/api/v1/blocklists"))
        .await
        .unwrap();

    let json = response_json(resp).await;
    let arr = json.as_array().unwrap();
    assert_eq!(arr.len(), 2, "Both blacklist and whitelist should appear");

    let _ = std::fs::remove_file(&bl_path);
    let _ = std::fs::remove_file(&wl_path);
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
