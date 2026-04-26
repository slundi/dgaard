use std::sync::Arc;

use axum::{
    Router,
    extract::{
        State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use tokio::sync::{broadcast::error::RecvError, watch};

use crate::config::ConnectivityConfig;
use crate::state::AppState;
use crate::util::event_to_record;

// ── Axum state ─────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct WsState {
    app: Arc<AppState>,
    token: String,
}

// ── Auth ───────────────────────────────────────────────────────────────────────

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

// ── WebSocket connection handler ───────────────────────────────────────────────

async fn handle_socket(mut socket: WebSocket, state: Arc<AppState>) {
    let mut rx = state.subscribe();

    loop {
        tokio::select! {
            // Prioritise client control frames so we notice a Close promptly.
            biased;

            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Ping(data))) => {
                        if socket.send(Message::Pong(data)).await.is_err() {
                            break;
                        }
                    }
                    // Close frame or connection drop.
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Err(_)) => break,
                    // Text/binary from the client is ignored — this is a push-only stream.
                    _ => {}
                }
            }

            result = rx.recv() => {
                match result {
                    Ok(event) => {
                        let record = {
                            let domain_map = state.domain_map.read().await;
                            event_to_record(&event, &domain_map)
                        };
                        let json = match serde_json::to_string(&record) {
                            Ok(j) => j,
                            Err(_) => continue,
                        };
                        if socket.send(Message::Text(json.into())).await.is_err() {
                            break; // client disconnected
                        }
                    }
                    // Slow consumer — missed some events, keep running.
                    Err(RecvError::Lagged(_)) => {}
                    // Broadcast channel closed (app is shutting down).
                    Err(RecvError::Closed) => break,
                }
            }
        }
    }
}

// ── HTTP upgrade handler ───────────────────────────────────────────────────────

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<WsState>,
    headers: HeaderMap,
) -> Response {
    if !check_auth(&state.token, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let app = Arc::clone(&state.app);
    ws.on_upgrade(move |socket| handle_socket(socket, app))
}

// ── Router builder ─────────────────────────────────────────────────────────────

fn build_router(state: WsState, root_path: &str) -> Router {
    let root = root_path.trim_end_matches('/');
    let stream_path = if root.is_empty() {
        "/events/stream".to_string()
    } else {
        format!("{root}/events/stream")
    };
    Router::new()
        .route(&stream_path, get(ws_handler))
        .with_state(state)
}

// ── Server entry-point ─────────────────────────────────────────────────────────

/// Serve the WebSocket endpoint.
///
/// Only called when `config.enabled` is true.
/// Returns when `shutdown` is signalled.
pub async fn run(
    config: ConnectivityConfig,
    state: Arc<AppState>,
    mut shutdown: watch::Receiver<bool>,
) {
    let ws_state = WsState {
        app: state,
        token: config.token.clone(),
    };
    let router = build_router(ws_state, &config.root_path);
    let addr = format!("{}:{}", config.listen, config.port);

    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("WebSocket server: failed to bind {addr}: {e}");
            return;
        }
    };

    let serve = axum::serve(listener, router).with_graceful_shutdown(async move {
        let _ = shutdown.changed().await;
    });

    if let Err(e) = serve.await {
        eprintln!("WebSocket server error: {e}");
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        protocol::{StatAction, StatBlockReason, StatEvent},
        state::AppState,
        util::EventRecord,
    };
    use std::net::SocketAddr;
    use std::time::Duration;

    fn make_state() -> Arc<AppState> {
        Arc::new(AppState::new(Duration::from_secs(3600)))
    }

    fn ipv4(a: u8, b: u8, c: u8, d: u8) -> [u8; 16] {
        [a, b, c, d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    }

    /// Bind a real TCP listener, spawn axum serving it, return the bound address.
    ///
    /// `WebSocketUpgrade` requires a genuine hyper connection (it extracts
    /// `hyper::upgrade::OnUpgrade` from request extensions), so tests that
    /// exercise the upgrade path must go through a real socket rather than
    /// `tower::ServiceExt::oneshot`.
    async fn start_test_server(state: Arc<AppState>, token: &str, root_path: &str) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let ws_state = WsState {
            app: state,
            token: token.to_string(),
        };
        let router = build_router(ws_state, root_path);
        tokio::spawn(async move {
            axum::serve(listener, router).await.ok();
        });
        addr
    }

    /// Send a raw HTTP/1.1 WebSocket upgrade request and return the response status code.
    async fn ws_upgrade_status(addr: SocketAddr, path: &str, token: Option<&str>) -> u16 {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let auth = token
            .map(|t| format!("Authorization: Bearer {t}\r\n"))
            .unwrap_or_default();
        let req = format!(
            "GET {path} HTTP/1.1\r\n\
             Host: 127.0.0.1\r\n\
             Connection: Upgrade\r\n\
             Upgrade: websocket\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Version: 13\r\n\
             {auth}\r\n"
        );
        stream.write_all(req.as_bytes()).await.unwrap();

        let mut buf = [0u8; 2048];
        let n = stream.read(&mut buf).await.unwrap();
        let response = std::str::from_utf8(&buf[..n]).unwrap_or("");
        // First line: "HTTP/1.1 NNN Reason"
        response
            .split_whitespace()
            .nth(1)
            .unwrap_or("0")
            .parse()
            .unwrap_or(0)
    }

    // ── Auth integration tests (real TCP connection) ───────────────────────────

    #[tokio::test]
    async fn upgrade_without_token_returns_401() {
        let addr = start_test_server(make_state(), "secret", "/").await;
        assert_eq!(ws_upgrade_status(addr, "/events/stream", None).await, 401);
    }

    #[tokio::test]
    async fn upgrade_wrong_token_returns_401() {
        let addr = start_test_server(make_state(), "secret", "/").await;
        assert_eq!(
            ws_upgrade_status(addr, "/events/stream", Some("wrong")).await,
            401
        );
    }

    #[tokio::test]
    async fn upgrade_valid_token_returns_101() {
        let addr = start_test_server(make_state(), "secret", "/").await;
        assert_eq!(
            ws_upgrade_status(addr, "/events/stream", Some("secret")).await,
            101
        );
    }

    #[tokio::test]
    async fn upgrade_no_token_configured_allows_unauthenticated() {
        let addr = start_test_server(make_state(), "", "/").await;
        assert_eq!(ws_upgrade_status(addr, "/events/stream", None).await, 101);
    }

    // ── Root-path integration tests ────────────────────────────────────────────

    #[tokio::test]
    async fn stream_root_path_prefix_is_respected() {
        let addr = start_test_server(make_state(), "", "/ws/v1").await;
        assert_eq!(
            ws_upgrade_status(addr, "/ws/v1/events/stream", None).await,
            101
        );
    }

    #[tokio::test]
    async fn stream_path_without_prefix_not_found_at_prefixed_route() {
        let addr = start_test_server(make_state(), "", "/ws/v1").await;
        assert_eq!(ws_upgrade_status(addr, "/events/stream", None).await, 404);
    }

    // ── Message content unit tests ─────────────────────────────────────────────

    #[test]
    fn event_to_record_produces_expected_json_shape() {
        use std::collections::HashMap;

        let event = StatEvent {
            timestamp: 9000,
            domain_hash: 0xabcd1234,
            client_ip: ipv4(10, 20, 30, 40),
            action: StatAction::Blocked(StatBlockReason::NRD_LIST),
        };
        let mut domain_map = HashMap::new();
        domain_map.insert(0xabcd1234_u64, "malware.example".to_string());

        let record = event_to_record(&event, &domain_map);
        let json = serde_json::to_string(&record).unwrap();
        let back: EventRecord = serde_json::from_str(&json).unwrap();

        assert_eq!(back.timestamp, 9000);
        assert_eq!(back.domain.as_deref(), Some("malware.example"));
        assert_eq!(back.client_ip, "10.20.30.40");
        assert_eq!(back.action, "Blocked");
        assert!(back.flags_labels.contains(&"NRD_LIST".to_string()));
    }

    #[tokio::test]
    async fn broadcast_event_reaches_subscriber() {
        let state = make_state();
        let mut rx = state.subscribe();

        state
            .record_event(StatEvent {
                timestamp: 42,
                domain_hash: 1,
                client_ip: ipv4(1, 2, 3, 4),
                action: StatAction::Allowed,
            })
            .await;

        let received = rx.try_recv().unwrap();
        assert_eq!(received.timestamp, 42);
    }

    // ── check_auth unit tests ──────────────────────────────────────────────────

    #[test]
    fn check_auth_empty_token_always_passes() {
        use axum::http::HeaderMap;
        assert!(check_auth("", &HeaderMap::new()));
    }

    #[test]
    fn check_auth_valid_bearer_passes() {
        use axum::http::{HeaderMap, HeaderValue};
        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("Bearer mysecret"));
        assert!(check_auth("mysecret", &headers));
    }

    #[test]
    fn check_auth_wrong_token_fails() {
        use axum::http::{HeaderMap, HeaderValue};
        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("Bearer wrong"));
        assert!(!check_auth("mysecret", &headers));
    }

    #[test]
    fn check_auth_missing_header_fails() {
        use axum::http::HeaderMap;
        assert!(!check_auth("mysecret", &HeaderMap::new()));
    }
}
