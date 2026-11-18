//! What ends a run, and the clean shutdown sequence that follows.
//!
//! Every way out goes through [`shutdown`] so the SQLite batch, the hourly
//! aggregates and the WAL checkpoint are always flushed: a signal, but also
//! the user quitting the TUI.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tokio::task::JoinHandle;

use dgaard_monitor_core::db;

/// How long each task gets to finish once shutdown is broadcast.
const TASK_STOP_TIMEOUT: Duration = Duration::from_secs(10);

/// Why the run is ending.
#[derive(Debug, PartialEq, Eq)]
pub enum StopTrigger {
    Signal(&'static str),
    /// The interactive UI task ended: the user quit, or the terminal failed.
    UiClosed,
}

/// Wait for a termination signal or for `ui_task` to end, whichever comes
/// first. Without a UI task, only signals end the run.
pub async fn wait_for_stop(ui_task: Option<&mut JoinHandle<()>>) -> StopTrigger {
    let ui_closed = async move {
        match ui_task {
            Some(task) => {
                let _ = task.await;
            }
            None => std::future::pending::<()>().await,
        }
    };
    tokio::select! {
        trigger = wait_for_signal() => trigger,
        () = ui_closed => StopTrigger::UiClosed,
    }
}

#[cfg(unix)]
async fn wait_for_signal() -> StopTrigger {
    use tokio::signal::unix::{SignalKind, signal};
    match signal(SignalKind::terminate()) {
        Ok(mut sigterm) => {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => StopTrigger::Signal("SIGINT"),
                _ = sigterm.recv() => StopTrigger::Signal("SIGTERM"),
            }
        }
        Err(e) => {
            eprintln!("warn: SIGTERM handler unavailable ({e}); using Ctrl-C only");
            let _ = tokio::signal::ctrl_c().await;
            StopTrigger::Signal("SIGINT")
        }
    }
}

#[cfg(not(unix))]
async fn wait_for_signal() -> StopTrigger {
    if let Err(e) = tokio::signal::ctrl_c().await {
        eprintln!("warn: Ctrl-C handler error: {e}");
    }
    StopTrigger::Signal("Ctrl-C")
}

/// Broadcast shutdown, wait for every task, then checkpoint the SQLite WAL so
/// the main DB file is up to date even if the OS does not flush before exit.
pub async fn shutdown(
    shutdown_tx: watch::Sender<bool>,
    handles: Vec<JoinHandle<()>>,
    db: Option<Arc<db::Database>>,
) {
    let _ = shutdown_tx.send(true);

    for handle in handles {
        let _ = tokio::time::timeout(TASK_STOP_TIMEOUT, handle).await;
    }

    if let Some(db) = db {
        let _ = tokio::task::spawn_blocking(move || {
            if let Err(e) = db.wal_checkpoint() {
                eprintln!("warn: WAL checkpoint on shutdown failed: {e}");
            }
        })
        .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dgaard_monitor_core::protocol::{StatAction, StatEvent};
    use dgaard_monitor_core::state::AppState;

    #[tokio::test]
    async fn ui_task_end_stops_the_run() {
        let mut ui_task = tokio::spawn(async {
            tokio::time::sleep(Duration::from_millis(20)).await;
        });
        let trigger =
            tokio::time::timeout(Duration::from_secs(2), wait_for_stop(Some(&mut ui_task)))
                .await
                .expect("a finished UI task must end the wait");
        assert_eq!(trigger, StopTrigger::UiClosed);
    }

    #[tokio::test]
    async fn without_ui_only_a_signal_stops_the_run() {
        let wait = tokio::time::timeout(Duration::from_millis(200), wait_for_stop(None)).await;
        assert!(
            wait.is_err(),
            "wait_for_stop(None) returned without a signal"
        );
    }

    /// Regression for quitting the TUI with `q`: it used to call
    /// `process::exit(0)`, dropping the pending SQLite batch. Quitting must
    /// now go through the shutdown sequence and persist every event.
    #[tokio::test]
    async fn closing_the_ui_flushes_pending_events() {
        let state = Arc::new(AppState::new(Duration::from_secs(3600)));
        let database = Arc::new(db::Database::open_in_memory().unwrap());
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let writer = tokio::spawn(db::run_writer(
            Arc::clone(&state),
            Arc::clone(&database),
            shutdown_rx,
        ));
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Fewer events than a batch, well before the 5 s flush tick: they
        // only reach SQLite through the shutdown flush.
        for timestamp in 0..3 {
            state
                .record_event(StatEvent {
                    timestamp,
                    domain_hash: 1,
                    client_ip: [0; 16],
                    action: StatAction::Allowed,
                })
                .await;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            database
                .query_range(0, u64::MAX, None, None, 10, 0)
                .unwrap()
                .is_empty(),
            "events flushed before shutdown; the test proves nothing"
        );

        // The user quits: the UI task returns.
        let mut ui_task = tokio::spawn(async {});
        assert_eq!(
            wait_for_stop(Some(&mut ui_task)).await,
            StopTrigger::UiClosed
        );
        shutdown(shutdown_tx, vec![writer], Some(Arc::clone(&database))).await;

        let rows = database
            .query_range(0, u64::MAX, None, None, 10, 0)
            .unwrap();
        assert_eq!(rows.len(), 3);
    }
}
