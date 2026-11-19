//! What ends a run, and the clean shutdown sequence that follows.
//!
//! Every way out goes through [`shutdown`] so the SQLite batch, the hourly
//! aggregates and the WAL checkpoint are always flushed: a signal, but also
//! the user quitting the TUI. The whole sequence is bounded by one deadline,
//! and a second signal exits at once.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tokio::task::JoinHandle;

use dgaard_monitor_core::db;

/// Total time the tasks get to stop once shutdown is broadcast. Below the
/// 10 s grace period of `docker stop` (then SIGKILL), leaving room for the
/// WAL checkpoint.
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(8);

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

/// Exit status for a forced exit: 128 + signal number, by convention.
fn forced_exit_code(trigger: &StopTrigger) -> i32 {
    match trigger {
        StopTrigger::Signal("SIGINT" | "Ctrl-C") => 130,
        StopTrigger::Signal("SIGTERM") => 143,
        _ => 1,
    }
}

/// Once shutdown has started, let a second SIGINT/SIGTERM exit immediately,
/// skipping whatever is left of the sequence (e.g. a hung flush).
pub fn exit_on_second_signal() {
    tokio::spawn(async {
        let trigger = wait_for_signal().await;
        let name = match &trigger {
            StopTrigger::Signal(name) => name,
            StopTrigger::UiClosed => "signal",
        };
        eprintln!("{name} received during shutdown, exiting now");
        std::process::exit(forced_exit_code(&trigger));
    });
}

/// Broadcast shutdown, wait for the tasks within [`SHUTDOWN_DEADLINE`], then
/// checkpoint the SQLite WAL so the main DB file is up to date even if the OS
/// does not flush before exit.
pub async fn shutdown(
    shutdown_tx: watch::Sender<bool>,
    writer: Option<JoinHandle<()>>,
    tasks: Vec<JoinHandle<()>>,
    db: Option<Arc<db::Database>>,
) {
    shutdown_within(shutdown_tx, writer, tasks, db, SHUTDOWN_DEADLINE).await;
}

async fn shutdown_within(
    shutdown_tx: watch::Sender<bool>,
    writer: Option<JoinHandle<()>>,
    tasks: Vec<JoinHandle<()>>,
    db: Option<Arc<db::Database>>,
    deadline: Duration,
) {
    let _ = shutdown_tx.send(true);

    // One deadline for all: the tasks stop concurrently, so waiting on them
    // in turn costs no more than the slowest one. The persistence writer
    // comes first, its final flush is what must not be lost. A finished task
    // still reports success after the deadline (it is polled first).
    let expires_at = tokio::time::Instant::now() + deadline;
    let mut aborted = 0;
    for mut task in writer.into_iter().chain(tasks) {
        if tokio::time::timeout_at(expires_at, &mut task)
            .await
            .is_err()
        {
            task.abort();
            aborted += 1;
        }
    }
    if aborted > 0 {
        eprintln!("warn: {aborted} task(s) did not stop within {deadline:?}, aborted");
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
        assert!(state.wait_for_subscribers(1, Duration::from_secs(5)).await);

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
        shutdown(
            shutdown_tx,
            Some(writer),
            Vec::new(),
            Some(Arc::clone(&database)),
        )
        .await;

        let rows = database
            .query_range(0, u64::MAX, None, None, 10, 0)
            .unwrap();
        assert_eq!(rows.len(), 3);
    }

    /// Sets its flag when dropped, i.e. when the task owning it ends or is
    /// aborted.
    struct DropFlag(Arc<std::sync::atomic::AtomicBool>);

    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// A task that ignores the shutdown broadcast forever.
    fn stuck_task() -> (JoinHandle<()>, Arc<std::sync::atomic::AtomicBool>) {
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let guard = DropFlag(Arc::clone(&dropped));
        let task = tokio::spawn(async move {
            let _guard = guard;
            std::future::pending::<()>().await;
        });
        (task, dropped)
    }

    /// Regression: tasks were awaited one by one with 10 s each, so N stuck
    /// tasks took N × 10 s and were never cancelled.
    #[tokio::test]
    async fn stuck_tasks_share_one_deadline_and_are_aborted() {
        let (shutdown_tx, _shutdown_rx) = watch::channel(false);
        let stuck: Vec<_> = (0..5).map(|_| stuck_task()).collect();
        let flags: Vec<_> = stuck.iter().map(|(_, flag)| Arc::clone(flag)).collect();
        let tasks = stuck.into_iter().map(|(task, _)| task).collect();

        let deadline = Duration::from_millis(200);
        let started = std::time::Instant::now();
        shutdown_within(shutdown_tx, None, tasks, None, deadline).await;
        let elapsed = started.elapsed();

        assert!(
            elapsed < deadline * 2,
            "5 stuck tasks took {elapsed:?}, deadline is {deadline:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
        for flag in flags {
            assert!(
                flag.load(std::sync::atomic::Ordering::SeqCst),
                "task not aborted"
            );
        }
    }

    #[tokio::test]
    async fn cooperative_tasks_stop_without_waiting_for_the_deadline() {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let tasks = (0..3)
            .map(|_| {
                let mut rx = shutdown_rx.clone();
                tokio::spawn(async move {
                    let _ = rx.changed().await;
                })
            })
            .collect();

        let started = std::time::Instant::now();
        shutdown_within(shutdown_tx, None, tasks, None, Duration::from_secs(5)).await;
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    /// A writer that finished its flush after another task got stuck is
    /// still counted as stopped, not aborted mid-flush.
    #[tokio::test]
    async fn writer_is_awaited_first() {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let flushed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let writer = {
            let flushed = Arc::clone(&flushed);
            let mut rx = shutdown_rx.clone();
            tokio::spawn(async move {
                let _ = rx.changed().await;
                tokio::time::sleep(Duration::from_millis(100)).await; // final flush
                flushed.store(true, std::sync::atomic::Ordering::SeqCst);
            })
        };
        let (stuck, _) = stuck_task();

        shutdown_within(
            shutdown_tx,
            Some(writer),
            vec![stuck],
            None,
            Duration::from_millis(300),
        )
        .await;
        assert!(flushed.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn forced_exit_codes_follow_the_signal_convention() {
        assert_eq!(forced_exit_code(&StopTrigger::Signal("SIGINT")), 130);
        assert_eq!(forced_exit_code(&StopTrigger::Signal("SIGTERM")), 143);
        assert_eq!(forced_exit_code(&StopTrigger::UiClosed), 1);
    }
}
