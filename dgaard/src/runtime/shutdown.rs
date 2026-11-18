use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{sync::watch, task::JoinHandle};

/// Tracks active query tasks for graceful shutdown
#[derive(Clone)]
pub(crate) struct ShutdownGuard {
    pub(crate) active_tasks: Arc<AtomicUsize>,
    #[allow(dead_code)] // Used in is_shutting_down(), reserved for future hot-reload support
    pub(crate) shutdown_rx: watch::Receiver<bool>,
}

impl ShutdownGuard {
    pub(crate) fn new(shutdown_rx: watch::Receiver<bool>) -> Self {
        Self {
            active_tasks: Arc::new(AtomicUsize::new(0)),
            shutdown_rx,
        }
    }

    /// Increments the active task counter
    pub fn task_started(&self) {
        self.active_tasks.fetch_add(1, Ordering::SeqCst);
    }

    /// Decrements the active task counter
    #[allow(dead_code)] // Reserved for manual task tracking if TaskGuard isn't suitable
    pub fn task_finished(&self) {
        self.active_tasks.fetch_sub(1, Ordering::SeqCst);
    }

    /// Returns the current number of active tasks
    pub fn active_count(&self) -> usize {
        self.active_tasks.load(Ordering::SeqCst)
    }

    /// Returns true if shutdown has been signaled
    #[allow(dead_code)] // Reserved for checking shutdown state in long-running tasks
    pub fn is_shutting_down(&self) -> bool {
        *self.shutdown_rx.borrow()
    }
}

/// RAII guard that automatically decrements the task counter when dropped
pub(crate) struct TaskGuard {
    pub(crate) active_tasks: Arc<AtomicUsize>,
}

impl TaskGuard {
    pub(crate) fn new(guard: &ShutdownGuard) -> Self {
        guard.task_started();
        Self {
            active_tasks: Arc::clone(&guard.active_tasks),
        }
    }
}

impl Drop for TaskGuard {
    fn drop(&mut self) {
        self.active_tasks.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Spawns `future` with a `TaskGuard` taken *before* `tokio::spawn`, so a
/// task that is scheduled but not yet polled already counts for
/// `wait_for_tasks`.
pub(crate) fn spawn_tracked<F>(guard: &ShutdownGuard, future: F) -> JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    let task_guard = TaskGuard::new(guard);
    tokio::spawn(async move {
        let _task_guard = task_guard;
        future.await
    })
}

/// Waits for all active tasks to complete with a timeout
pub(crate) async fn wait_for_tasks(guard: &ShutdownGuard) {
    const MAX_WAIT: Duration = Duration::from_secs(30);
    const POLL_INTERVAL: Duration = Duration::from_millis(100);

    let start = std::time::Instant::now();

    while guard.active_count() > 0 {
        if start.elapsed() > MAX_WAIT {
            eprintln!(
                "Warning: Shutdown timeout reached with {} tasks still active",
                guard.active_count()
            );
            break;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_guard() -> (watch::Sender<bool>, ShutdownGuard) {
        let (tx, rx) = watch::channel(false);
        (tx, ShutdownGuard::new(rx))
    }

    #[test]
    fn shutdown_guard_starts_with_zero_active_tasks() {
        let (_, guard) = create_test_guard();
        assert_eq!(guard.active_count(), 0);
    }

    #[test]
    fn shutdown_guard_increments_on_task_started() {
        let (_, guard) = create_test_guard();
        guard.task_started();
        assert_eq!(guard.active_count(), 1);
        guard.task_started();
        assert_eq!(guard.active_count(), 2);
    }

    #[test]
    fn shutdown_guard_decrements_on_task_finished() {
        let (_, guard) = create_test_guard();
        guard.task_started();
        guard.task_started();
        guard.task_finished();
        assert_eq!(guard.active_count(), 1);
    }

    #[test]
    fn task_guard_increments_on_creation() {
        let (_, guard) = create_test_guard();
        let _task = TaskGuard::new(&guard);
        assert_eq!(guard.active_count(), 1);
    }

    #[test]
    fn task_guard_decrements_on_drop() {
        let (_, guard) = create_test_guard();
        {
            let _task = TaskGuard::new(&guard);
            assert_eq!(guard.active_count(), 1);
        }
        // TaskGuard dropped here
        assert_eq!(guard.active_count(), 0);
    }

    #[test]
    fn cloned_guards_share_counter() {
        let (_, guard) = create_test_guard();
        let cloned = guard.clone();

        guard.task_started();
        assert_eq!(cloned.active_count(), 1);

        cloned.task_started();
        assert_eq!(guard.active_count(), 2);
    }

    #[test]
    fn is_shutting_down_reflects_signal() {
        let (tx, guard) = create_test_guard();

        assert!(!guard.is_shutting_down());
        tx.send(true).unwrap();
        assert!(guard.is_shutting_down());
    }

    #[test]
    fn multiple_task_guards_track_correctly() {
        let (_, guard) = create_test_guard();

        let task1 = TaskGuard::new(&guard);
        let task2 = TaskGuard::new(&guard);
        let task3 = TaskGuard::new(&guard);
        assert_eq!(guard.active_count(), 3);

        drop(task1);
        assert_eq!(guard.active_count(), 2);

        drop(task2);
        drop(task3);
        assert_eq!(guard.active_count(), 0);
    }

    #[tokio::test]
    async fn wait_for_tasks_returns_when_no_active_tasks() {
        let (_, guard) = create_test_guard();
        // Should return immediately since no tasks are active
        wait_for_tasks(&guard).await;
        assert_eq!(guard.active_count(), 0);
    }

    #[tokio::test]
    async fn wait_for_tasks_waits_for_completion() {
        let (_, guard) = create_test_guard();
        let guard_clone = guard.clone();

        // Spawn a task that holds the guard for a short time
        let handle = tokio::spawn(async move {
            let _task = TaskGuard::new(&guard_clone);
            tokio::time::sleep(Duration::from_millis(50)).await;
        });

        // Give the task time to start
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(guard.active_count(), 1);

        // Wait for tasks - should complete when the spawned task finishes
        wait_for_tasks(&guard).await;
        handle.await.unwrap();
        assert_eq!(guard.active_count(), 0);
    }

    // The current-thread runtime does not poll a spawned task until the
    // caller yields, which reproduces the "spawned but not yet running" window.
    #[tokio::test(flavor = "current_thread")]
    async fn spawn_tracked_counts_task_before_first_poll() {
        let (_, guard) = create_test_guard();
        let handle = spawn_tracked(&guard, async {});
        assert_eq!(guard.active_count(), 1);
        handle.await.unwrap();
        assert_eq!(guard.active_count(), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn wait_for_tasks_does_not_miss_unpolled_task() {
        let (_, guard) = create_test_guard();
        let finished = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let finished_in_task = Arc::clone(&finished);
        let handle = spawn_tracked(&guard, async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            finished_in_task.store(true, Ordering::SeqCst);
        });

        wait_for_tasks(&guard).await;
        assert!(finished.load(Ordering::SeqCst));
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn spawn_tracked_releases_guard_on_panic() {
        let (_, guard) = create_test_guard();
        let handle = spawn_tracked(&guard, async { panic!("boom") });
        assert!(handle.await.is_err());
        assert_eq!(guard.active_count(), 0);
    }
}
