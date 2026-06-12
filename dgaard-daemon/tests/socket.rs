use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use dgaard_daemon::handler::handle_connection;
use dgaard_daemon::server::{EngineState, run_accept_loop};
use dgaard_engine::{Config, FilterEngine};
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

// ---------------------------------------------------------------------------
// Engine construction helpers for D4 tests
// ---------------------------------------------------------------------------

/// `DomainEntryFlags::NONE.bits()` — present in blocklist, not whitelisted.
const FLAG_BLOCKLIST: u8 = 0b0000_0000;
/// `DomainEntryFlags::WHITELIST.bits()`.
const FLAG_WHITELIST: u8 = 0b0000_0001;

/// Build a state (seed 0) with `domain` inserted in the fast_map under the
/// given `flags`.  All other engine fields are empty.
fn state_with_domain(domain: &str, flags: u8) -> Arc<ArcSwap<EngineState>> {
    let seed = 0u64;
    let hash = twox_hash::XxHash64::oneshot(seed, domain.as_bytes());
    let mut fast_map = HashMap::new();
    fast_map.insert(hash, flags);
    Arc::new(ArcSwap::from_pointee(EngineState {
        engine: FilterEngine {
            fast_map,
            seed,
            ..FilterEngine::empty()
        },
        config: Config::default(),
    }))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_state() -> Arc<ArcSwap<EngineState>> {
    Arc::new(ArcSwap::from_pointee(EngineState {
        engine: FilterEngine::empty(),
        config: Config::default(),
    }))
}

/// Serve exactly one connection on `listener` then return.
async fn serve_one(listener: UnixListener, state: Arc<ArcSwap<EngineState>>) {
    let (stream, _) = listener.accept().await.unwrap();
    handle_connection(stream, state).await;
}

/// Connect to the socket, send `domain\n`, read and parse the JSON response.
async fn query(socket_path: &std::path::Path, domain: &str) -> serde_json::Value {
    let mut client = UnixStream::connect(socket_path).await.unwrap();
    client
        .write_all(format!("{domain}\n").as_bytes())
        .await
        .unwrap();

    let mut reader = BufReader::new(client);
    let mut response = String::new();
    reader.read_line(&mut response).await.unwrap();

    serde_json::from_str(response.trim()).expect("response is valid JSON")
}

// ---------------------------------------------------------------------------
// D2 tests (updated for ArcSwap signature)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn clean_domain_is_proxied() {
    let dir = TempDir::new().unwrap();
    let socket_path = dir.path().join("clean.sock");

    let listener = UnixListener::bind(&socket_path).unwrap();
    let server = tokio::spawn(serve_one(listener, make_state()));

    let json = query(&socket_path, "google.com").await;
    server.await.unwrap();

    assert_eq!(json["blocked"], false);
    assert_eq!(json["action"], "ProxyToUpstream");
    assert!(json["score"].is_number());
    assert!(json["reasons"].is_array());
}

#[tokio::test]
async fn structurally_invalid_domain_is_blocked() {
    let dir = TempDir::new().unwrap();
    let socket_path = dir.path().join("blocked.sock");

    let listener = UnixListener::bind(&socket_path).unwrap();
    let server = tokio::spawn(serve_one(listener, make_state()));

    // 7 dots — exceeds the default max_subdomain_depth of 5
    let json = query(&socket_path, "a.b.c.d.e.f.g.example.com").await;
    server.await.unwrap();

    assert_eq!(json["blocked"], true);
    assert!(
        json["action"]
            .as_str()
            .unwrap()
            .contains("InvalidStructure"),
        "expected InvalidStructure, got: {}",
        json["action"]
    );
}

#[tokio::test]
async fn empty_input_returns_error_json() {
    let dir = TempDir::new().unwrap();
    let socket_path = dir.path().join("empty.sock");

    let listener = UnixListener::bind(&socket_path).unwrap();
    let server = tokio::spawn(serve_one(listener, make_state()));

    let mut client = UnixStream::connect(&socket_path).await.unwrap();
    client.write_all(b"\n").await.unwrap();

    let mut reader = BufReader::new(client);
    let mut response = String::new();
    reader.read_line(&mut response).await.unwrap();
    server.await.unwrap();

    let json: serde_json::Value =
        serde_json::from_str(response.trim()).expect("response is valid JSON");
    assert!(json.get("error").is_some(), "expected error field");
    assert!(json["error"].as_str().unwrap().contains("empty"));
}

#[tokio::test]
async fn oversized_domain_returns_error_json() {
    let dir = TempDir::new().unwrap();
    let socket_path = dir.path().join("oversized.sock");

    let listener = UnixListener::bind(&socket_path).unwrap();
    let server = tokio::spawn(serve_one(listener, make_state()));

    // 254 bytes — one byte over the RFC 1035 limit of 253
    let oversized = format!("{}.com", "a".repeat(250));
    let json = query(&socket_path, &oversized).await;
    server.await.unwrap();

    assert!(json.get("error").is_some(), "expected error field");
    assert!(
        json["error"].as_str().unwrap().contains("253"),
        "error should mention the 253-byte limit"
    );
}

/// An oversized domain sent without a newline (EOF-terminated) must still be
/// rejected by the explicit `> MAX_DOMAIN_LEN` check, not by the take limit.
/// With the old take(255), a 254-byte domain + '\r' (total 255 bytes at the
/// take cap) would be trimmed to 254 bytes and correctly rejected; but the
/// take limit was doing part of the work. With take(512) the explicit check
/// is the sole gate regardless of the line terminator present.
#[tokio::test]
async fn oversized_domain_without_newline_is_rejected() {
    let dir = TempDir::new().unwrap();
    let socket_path = dir.path().join("no_newline_oversized.sock");

    let listener = UnixListener::bind(&socket_path).unwrap();
    let server = tokio::spawn(serve_one(listener, make_state()));

    // 254 bytes — one byte over the limit, no newline terminator.
    // Split the socket so we can close the write half (sending EOF) while
    // keeping the read half open to receive the server's response.
    let oversized = format!("{}.com", "a".repeat(250));
    assert_eq!(oversized.len(), 254);
    let client = UnixStream::connect(&socket_path).await.unwrap();
    let (rd, mut wr) = client.into_split();
    wr.write_all(oversized.as_bytes()).await.unwrap();
    drop(wr); // EOF signals end of input to the server's read_line

    let mut reader = BufReader::new(rd);
    let mut response = String::new();
    reader.read_line(&mut response).await.unwrap();
    server.await.unwrap();

    let json: serde_json::Value =
        serde_json::from_str(response.trim()).expect("response is valid JSON");
    assert!(json.get("error").is_some(), "expected error field");
    assert!(
        json["error"].as_str().unwrap().contains("253"),
        "error should mention the 253-byte limit"
    );
}

// ---------------------------------------------------------------------------
// D3.1 — Graceful shutdown
// ---------------------------------------------------------------------------

#[tokio::test]
async fn accept_loop_drains_in_flight_connections_on_shutdown() {
    let dir = TempDir::new().unwrap();
    let socket_path = dir.path().join("shutdown.sock");

    let state = make_state();
    let listener = UnixListener::bind(&socket_path).unwrap();

    // Use a oneshot channel as the programmatic "shutdown signal"
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let server = tokio::spawn(run_accept_loop(listener, Arc::clone(&state), async move {
        shutdown_rx.await.ok();
    }));

    // Send a query to create an in-flight connection, then signal shutdown
    let json = query(&socket_path, "example.com").await;
    shutdown_tx.send(()).unwrap();

    // The accept loop must terminate within a reasonable timeout
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .expect("accept loop did not stop within 2 s")
        .unwrap();

    assert_eq!(json["blocked"], false);
}

#[tokio::test]
async fn accept_loop_stops_immediately_when_no_connections_pending() {
    let dir = TempDir::new().unwrap();
    let socket_path = dir.path().join("idle_shutdown.sock");

    let listener = UnixListener::bind(&socket_path).unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let server = tokio::spawn(run_accept_loop(listener, make_state(), async move {
        shutdown_rx.await.ok();
    }));

    shutdown_tx.send(()).unwrap();

    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .expect("accept loop did not stop within 2 s")
        .unwrap();
}

// ---------------------------------------------------------------------------
// D3.2 — Atomic config swap (SIGHUP reload)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn handle_connection_reflects_swapped_config() {
    let dir = TempDir::new().unwrap();

    let state = make_state(); // default: max_subdomain_depth = 5

    // The deep domain (7 dots) should be blocked under default config
    let socket1 = dir.path().join("swap_before.sock");
    let listener1 = UnixListener::bind(&socket1).unwrap();
    let server1 = tokio::spawn(serve_one(listener1, Arc::clone(&state)));

    let json_before = query(&socket1, "a.b.c.d.e.f.g.example.com").await;
    server1.await.unwrap();
    assert_eq!(
        json_before["blocked"], true,
        "should be blocked with default depth limit"
    );

    // Atomically swap to a permissive config (engine stays the same)
    let mut permissive = Config::default();
    permissive.security.structure.max_subdomain_depth = 100;
    state.store(Arc::new(EngineState {
        engine: FilterEngine::empty(),
        config: permissive,
    }));

    // The same domain should now be proxied
    let socket2 = dir.path().join("swap_after.sock");
    let listener2 = UnixListener::bind(&socket2).unwrap();
    let server2 = tokio::spawn(serve_one(listener2, Arc::clone(&state)));

    let json_after = query(&socket2, "a.b.c.d.e.f.g.example.com").await;
    server2.await.unwrap();
    assert_eq!(
        json_after["blocked"], false,
        "should be allowed after config swap"
    );
}

// ---------------------------------------------------------------------------
// D4.2 — known-blocked and known-clean domain via static blocklist/whitelist
// ---------------------------------------------------------------------------

/// Build an engine that contains `ads.tracker.com` in the static blocklist,
/// send it through the socket, and assert `StaticBlacklist` is the reason.
#[tokio::test]
async fn domain_on_static_blocklist_is_blocked_with_correct_reason() {
    let dir = TempDir::new().unwrap();
    let socket_path = dir.path().join("static_block.sock");

    const BLOCKED_DOMAIN: &str = "ads.tracker.com";
    let state = state_with_domain(BLOCKED_DOMAIN, FLAG_BLOCKLIST);

    let listener = UnixListener::bind(&socket_path).unwrap();
    let server = tokio::spawn(serve_one(listener, state));

    let json = query(&socket_path, BLOCKED_DOMAIN).await;
    server.await.unwrap();

    assert_eq!(json["blocked"], true, "domain should be blocked");
    assert!(
        json["action"].as_str().unwrap().contains("StaticBlacklist"),
        "expected StaticBlacklist action, got: {}",
        json["action"]
    );
    assert_eq!(json["score"].as_u64().unwrap(), 0);
    assert!(json["reasons"].is_array());
}

/// Build an engine that contains `safe.example.com` in the whitelist, send
/// it through the socket, and assert the action is `Allow`.
#[tokio::test]
async fn domain_on_whitelist_is_allowed() {
    let dir = TempDir::new().unwrap();
    let socket_path = dir.path().join("whitelist.sock");

    const SAFE_DOMAIN: &str = "safe.example.com";
    let state = state_with_domain(SAFE_DOMAIN, FLAG_WHITELIST);

    let listener = UnixListener::bind(&socket_path).unwrap();
    let server = tokio::spawn(serve_one(listener, state));

    let json = query(&socket_path, SAFE_DOMAIN).await;
    server.await.unwrap();

    assert_eq!(
        json["blocked"], false,
        "whitelisted domain should not be blocked"
    );
    assert_eq!(json["action"], "Allow");
    assert!(json["reasons"].is_array());
}

/// Verify the response JSON always contains the four required fields
/// (`score`, `blocked`, `action`, `reasons`) for every block/allow/proxy case.
#[tokio::test]
async fn response_json_always_contains_all_required_fields() {
    let dir = TempDir::new().unwrap();

    let cases: &[(&str, &str)] = &[
        ("google.com", "proxied"),
        ("a.b.c.d.e.f.g.example.com", "structural-block"),
    ];

    for (domain, label) in cases {
        let socket_path = dir.path().join(format!("fields_{label}.sock"));
        let listener = UnixListener::bind(&socket_path).unwrap();
        let server = tokio::spawn(serve_one(listener, make_state()));

        let json = query(&socket_path, domain).await;
        server.await.unwrap();

        assert!(json.get("score").is_some(), "[{label}] missing 'score'");
        assert!(json.get("blocked").is_some(), "[{label}] missing 'blocked'");
        assert!(json.get("action").is_some(), "[{label}] missing 'action'");
        assert!(json.get("reasons").is_some(), "[{label}] missing 'reasons'");
        assert!(
            json["reasons"].is_array(),
            "[{label}] 'reasons' must be an array"
        );
    }
}
