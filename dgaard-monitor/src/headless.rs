use std::sync::Arc;

use tokio::io::{AsyncWrite, AsyncWriteExt, BufWriter};
use tokio::sync::{broadcast, watch};

use dgaard_monitor_core::state::{AppState, Sink};
use dgaard_monitor_core::util::event_to_record;

/// Runs when `--headless` is set: emits one JSON line per event to stdout.
/// The format is identical to the REST API's `/api/v1/queries` payload so
/// log shippers (Vector, Filebeat, Fluentd…) can ingest it without a custom parser.
/// These lines are the only thing written to stdout; diagnostics go to stderr.
pub async fn run(state: Arc<AppState>, shutdown_rx: watch::Receiver<bool>) {
    run_to(state, shutdown_rx, tokio::io::stdout()).await;
}

/// Same as [`run`], writing to `out`.
///
/// A slow reader must not stall the pipeline: the domain map is only locked
/// while the record is built, never during the write, so a pending
/// `insert_domain` cannot block every other reader behind a full pipe. Lines
/// are buffered and flushed whenever no event is waiting, and on shutdown.
async fn run_to<W: AsyncWrite + Unpin>(
    state: Arc<AppState>,
    mut shutdown_rx: watch::Receiver<bool>,
    out: W,
) {
    let mut out = BufWriter::new(out);
    let mut events_rx = state.subscribe();
    let mut line = Vec::new();
    loop {
        tokio::select! {
            biased;
            _ = shutdown_rx.changed() => break,
            result = events_rx.recv() => match result {
                Ok(event) => {
                    let record = {
                        let map = state.domain_map.read().await;
                        event_to_record(&event, &map)
                    };
                    line.clear();
                    if let Err(e) = serde_json::to_writer(&mut line, &record) {
                        eprintln!("warn: failed to serialize event: {e}");
                        continue;
                    }
                    line.push(b'\n');
                    let written = match out.write_all(&line).await {
                        Ok(()) if events_rx.is_empty() => out.flush().await,
                        other => other,
                    };
                    if let Err(e) = written {
                        eprintln!("headless: stdout write failed ({e}), stopping JSON output");
                        return;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    state.record_drop(Sink::Headless, n);
                    eprintln!("warn: headless logger dropped {n} events (channel lagged)");
                }
                Err(broadcast::error::RecvError::Closed) => break,
            },
        }
    }
    if let Err(e) = out.flush().await {
        eprintln!("headless: final stdout flush failed: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use dgaard_monitor_core::protocol::{StatAction, StatEvent};
    use tokio::io::AsyncBufReadExt;

    fn event(domain_hash: u64) -> StatEvent {
        StatEvent {
            timestamp: 1_700_000_000,
            domain_hash,
            client_ip: std::net::Ipv4Addr::new(10, 0, 0, 1)
                .to_ipv6_mapped()
                .octets(),
            action: StatAction::Allowed,
        }
    }

    fn start<W: AsyncWrite + Unpin + Send + 'static>(
        out: W,
    ) -> (
        Arc<AppState>,
        watch::Sender<bool>,
        tokio::task::JoinHandle<()>,
    ) {
        let state = Arc::new(AppState::new(Duration::from_secs(3600)));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let task = tokio::spawn(run_to(Arc::clone(&state), shutdown_rx, out));
        (state, shutdown_tx, task)
    }

    /// Give the spawned task time to subscribe before events are recorded.
    async fn settle() {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    #[tokio::test]
    async fn emits_one_json_line_per_event() {
        let (out, reader) = tokio::io::duplex(64 * 1024);
        let (state, shutdown_tx, task) = start(out);
        state.insert_domain(1, "one.test".to_string()).await;
        settle().await;

        for hash in [1, 2, 1] {
            state.record_event(event(hash)).await;
        }

        let mut lines = tokio::io::BufReader::new(reader).lines();
        let mut records = Vec::new();
        for _ in 0..3 {
            let line = tokio::time::timeout(Duration::from_secs(2), lines.next_line())
                .await
                .expect("line not flushed")
                .unwrap()
                .unwrap();
            records.push(serde_json::from_str::<serde_json::Value>(&line).unwrap());
        }
        let _ = shutdown_tx.send(true);
        let _ = task.await;

        assert_eq!(records[0]["domain"], "one.test");
        assert_eq!(records[0]["client_ip"], "10.0.0.1");
        assert_eq!(records[1]["domain"], serde_json::Value::Null);
        assert_eq!(records[2]["domain"], "one.test");
    }

    /// Regression: the read guard on `domain_map` was held while writing to
    /// stdout. With the pipe full, a waiting `insert_domain` (write lock)
    /// then blocked every reader of the map, stalling the whole pipeline.
    #[tokio::test]
    async fn blocked_output_does_not_hold_the_domain_map() {
        // A pipe nobody reads, smaller than one line: the flush never ends.
        let (out, _reader) = tokio::io::duplex(16);
        let (state, shutdown_tx, task) = start(out);
        settle().await;

        state.record_event(event(1)).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !task.is_finished(),
            "writer should be stuck on the full pipe"
        );

        tokio::time::timeout(
            Duration::from_secs(1),
            state.insert_domain(1, "late.test".to_string()),
        )
        .await
        .expect("insert_domain blocked by the headless writer");

        let _ = shutdown_tx.send(true);
        task.abort();
    }

    #[tokio::test]
    async fn pending_lines_are_flushed_on_shutdown() {
        let (out, reader) = tokio::io::duplex(64 * 1024);
        let (state, shutdown_tx, task) = start(out);
        settle().await;

        for hash in 0..5 {
            state.record_event(event(hash)).await;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = shutdown_tx.send(true);
        task.await.unwrap();

        let mut lines = tokio::io::BufReader::new(reader).lines();
        let mut count = 0;
        while let Ok(Ok(Some(_))) =
            tokio::time::timeout(Duration::from_millis(200), lines.next_line()).await
        {
            count += 1;
        }
        assert_eq!(count, 5);
    }

    /// `println!` panics when stdout is closed; the task must just stop.
    #[tokio::test]
    async fn closed_output_stops_the_task() {
        let (out, reader) = tokio::io::duplex(64);
        drop(reader);
        let (state, _shutdown_tx, task) = start(out);
        settle().await;

        state.record_event(event(1)).await;
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("task kept running on a closed pipe")
            .expect("task panicked");
    }
}
