use std::sync::Arc;

use axum::{
    extract::{
        State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    response::Response,
};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::broadcast;

use crate::web::state::WebState;

pub async fn ws_handler(ws: WebSocketUpgrade, State(web): State<Arc<WebState>>) -> Response {
    ws.on_upgrade(|socket| async move { handle_client(socket, web).await })
}

async fn handle_client(socket: WebSocket, web: Arc<WebState>) {
    let (mut sink, mut stream) = socket.split();
    let mut rx = web.subscribe();

    loop {
        tokio::select! {
            result = rx.recv() => {
                match result {
                    Ok(record) => {
                        let json = match serde_json::to_string(&record) {
                            Ok(j) => j,
                            Err(e) => {
                                eprintln!("ws: serialize error: {e}");
                                continue;
                            }
                        };
                        if sink.send(Message::Text(json.into())).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        // Drop lagging clients without crashing the server.
                        eprintln!("ws: client lagged by {n} events, closing");
                        break;
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
            msg = stream.next() => {
                match msg {
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Err(_)) => break,
                    _ => {}
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{state::AppState, util::EventRecord, web::state::WebState};
    use std::{sync::Arc, time::Duration};

    fn make_web() -> Arc<WebState> {
        Arc::new(WebState::new(
            Arc::new(AppState::new(Duration::from_secs(3600))),
            100,
        ))
    }

    fn make_record(ts: u64, action: &str) -> EventRecord {
        EventRecord {
            timestamp: ts,
            domain: Some("example.com".into()),
            domain_hash: format!("{ts:016x}"),
            client_ip: "10.0.0.1".into(),
            action: action.into(),
            flags: None,
            flags_labels: vec![],
        }
    }

    #[tokio::test]
    async fn broadcast_event_is_serialisable() {
        let record = make_record(1_700_000_000, "Blocked");
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("example.com"));
        assert!(json.contains("Blocked"));
    }

    #[tokio::test]
    async fn subscriber_receives_pushed_event() {
        let web = make_web();
        let mut rx = web.subscribe();
        web.push_event(make_record(42, "Allowed")).await;
        let got = rx.try_recv().unwrap();
        assert_eq!(got.timestamp, 42);
        assert_eq!(got.action, "Allowed");
    }

    #[tokio::test]
    async fn lagged_receiver_gets_error() {
        // Use capacity 1 to trigger lag quickly.
        let app = Arc::new(AppState::new(Duration::from_secs(3600)));
        let (tx, mut rx) = tokio::sync::broadcast::channel::<EventRecord>(1);
        // Fill beyond capacity without subscribing.
        let _ = tx.send(make_record(1, "Allowed"));
        let _ = tx.send(make_record(2, "Allowed"));
        let _ = tx.send(make_record(3, "Allowed"));
        // Now subscribe and receive — should get Lagged.
        drop(tx);
        let err = rx.recv().await.unwrap_err();
        assert!(matches!(err, broadcast::error::RecvError::Lagged(_)));
    }
}
