use std::sync::Arc;

use tokio::sync::{broadcast, watch};

use crate::state::AppState;
use crate::util::event_to_record;

/// Runs when `--headless` is set: emits one JSON line per event to stdout.
/// The format is identical to the REST API's `/api/v1/queries` payload so
/// log shippers (Vector, Filebeat, Fluentd…) can ingest it without a custom parser.
pub async fn run(state: Arc<AppState>, mut shutdown_rx: watch::Receiver<bool>) {
    let mut events_rx = state.subscribe();
    loop {
        tokio::select! {
            biased;
            _ = shutdown_rx.changed() => break,
            result = events_rx.recv() => match result {
                Ok(event) => {
                    let map = state.domain_map.read().await;
                    let record = event_to_record(&event, &map);
                    match serde_json::to_string(&record) {
                        Ok(line) => println!("{line}"),
                        Err(e) => eprintln!("warn: failed to serialize event: {e}"),
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    eprintln!("warn: headless logger dropped {n} events (channel lagged)");
                }
                Err(broadcast::error::RecvError::Closed) => break,
            },
        }
    }
}
