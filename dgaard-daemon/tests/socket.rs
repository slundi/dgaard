use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use dgaard_daemon::handler::handle_connection;
use dgaard_daemon::server::run_accept_loop;
use dgaard_engine::{Config, FilterEngine};
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_engine() -> Arc<ArcSwap<FilterEngine>> {
    Arc::new(ArcSwap::from_pointee(FilterEngine::empty()))
}

fn make_config() -> Arc<ArcSwap<Config>> {
    Arc::new(ArcSwap::from_pointee(Config::default()))
}

/// Serve exactly one connection on `listener` then return.
async fn serve_one(
    listener: UnixListener,
    engine: Arc<ArcSwap<FilterEngine>>,
    config: Arc<ArcSwap<Config>>,
) {
    let (stream, _) = listener.accept().await.unwrap();
    handle_connection(stream, engine, config).await;
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
    let server = tokio::spawn(serve_one(listener, make_engine(), make_config()));

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
    let server = tokio::spawn(serve_one(listener, make_engine(), make_config()));

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
    let server = tokio::spawn(serve_one(listener, make_engine(), make_config()));

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
    let server = tokio::spawn(serve_one(listener, make_engine(), make_config()));

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

// ---------------------------------------------------------------------------
// D3.1 — Graceful shutdown
// ---------------------------------------------------------------------------

#[tokio::test]
async fn accept_loop_drains_in_flight_connections_on_shutdown() {
    let dir = TempDir::new().unwrap();
    let socket_path = dir.path().join("shutdown.sock");

    let engine = make_engine();
    let config = make_config();
    let listener = UnixListener::bind(&socket_path).unwrap();

    // Use a oneshot channel as the programmatic "shutdown signal"
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let server = tokio::spawn(run_accept_loop(
        listener,
        Arc::clone(&engine),
        Arc::clone(&config),
        async move {
            shutdown_rx.await.ok();
        },
    ));

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

    let server = tokio::spawn(run_accept_loop(
        listener,
        make_engine(),
        make_config(),
        async move {
            shutdown_rx.await.ok();
        },
    ));

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

    let engine = make_engine();
    let config = make_config(); // default: max_subdomain_depth = 5

    // The deep domain (7 dots) should be blocked under default config
    let socket1 = dir.path().join("swap_before.sock");
    let listener1 = UnixListener::bind(&socket1).unwrap();
    let server1 = tokio::spawn(serve_one(
        listener1,
        Arc::clone(&engine),
        Arc::clone(&config),
    ));

    let json_before = query(&socket1, "a.b.c.d.e.f.g.example.com").await;
    server1.await.unwrap();
    assert_eq!(
        json_before["blocked"], true,
        "should be blocked with default depth limit"
    );

    // Atomically swap to a permissive config
    let mut permissive = Config::default();
    permissive.security.structure.max_subdomain_depth = 100;
    config.store(Arc::new(permissive));

    // The same domain should now be proxied
    let socket2 = dir.path().join("swap_after.sock");
    let listener2 = UnixListener::bind(&socket2).unwrap();
    let server2 = tokio::spawn(serve_one(
        listener2,
        Arc::clone(&engine),
        Arc::clone(&config),
    ));

    let json_after = query(&socket2, "a.b.c.d.e.f.g.example.com").await;
    server2.await.unwrap();
    assert_eq!(
        json_after["blocked"], false,
        "should be allowed after config swap"
    );
}
