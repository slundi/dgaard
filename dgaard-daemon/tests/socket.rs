use std::sync::Arc;

use dgaard_daemon::handler::handle_connection;
use dgaard_engine::{Config, FilterEngine};
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

/// Serve exactly one connection on `listener` then return.
async fn serve_one(listener: UnixListener, engine: Arc<FilterEngine>, config: Arc<Config>) {
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

#[tokio::test]
async fn clean_domain_is_proxied() {
    let dir = TempDir::new().unwrap();
    let socket_path = dir.path().join("clean.sock");

    let engine = Arc::new(FilterEngine::empty());
    let config = Arc::new(Config::default());

    let listener = UnixListener::bind(&socket_path).unwrap();
    let server = tokio::spawn(serve_one(
        listener,
        Arc::clone(&engine),
        Arc::clone(&config),
    ));

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

    let engine = Arc::new(FilterEngine::empty());
    let config = Arc::new(Config::default());

    let listener = UnixListener::bind(&socket_path).unwrap();
    let server = tokio::spawn(serve_one(
        listener,
        Arc::clone(&engine),
        Arc::clone(&config),
    ));

    // 12-label depth exceeds the default max_subdomain_depth of 5
    let json = query(&socket_path, "a.b.c.d.e.f.g.h.i.j.k.example.com").await;
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

    let engine = Arc::new(FilterEngine::empty());
    let config = Arc::new(Config::default());

    let listener = UnixListener::bind(&socket_path).unwrap();
    let server = tokio::spawn(serve_one(
        listener,
        Arc::clone(&engine),
        Arc::clone(&config),
    ));

    // Send only a newline (empty domain)
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

    let engine = Arc::new(FilterEngine::empty());
    let config = Arc::new(Config::default());

    let listener = UnixListener::bind(&socket_path).unwrap();
    let server = tokio::spawn(serve_one(
        listener,
        Arc::clone(&engine),
        Arc::clone(&config),
    ));

    // 254-byte domain — one byte over the RFC 1035 limit of 253
    let oversized = format!("{}.com", "a".repeat(250));
    let json = query(&socket_path, &oversized).await;
    server.await.unwrap();

    assert!(json.get("error").is_some(), "expected error field");
    assert!(
        json["error"].as_str().unwrap().contains("253"),
        "error should mention the 253-byte limit"
    );
}
