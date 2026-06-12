use std::path::Path;
use std::sync::Arc;

use arc_swap::ArcSwap;
use dgaard_engine::{Config as EngineConfig, FilterEngine};
use tokio::net::UnixListener;
use tokio::task::JoinSet;

use crate::handler::handle_connection;

pub(crate) const HASH_SEED: u64 = 42;

/// Paired engine + config replaced atomically on SIGHUP.
pub struct EngineState {
    pub engine: FilterEngine,
    pub config: EngineConfig,
}

impl EngineState {
    /// Build an `EngineState` from a config, using the crate-internal hash seed.
    pub fn new(config: EngineConfig) -> Self {
        let engine = FilterEngine::build_from_files(&config, HASH_SEED);
        Self { engine, config }
    }
}

/// Removes the Unix socket file when dropped so the filesystem is always
/// cleaned up on both graceful shutdown and panic.
#[derive(Debug)]
pub struct SocketGuard(String);

impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Bind the Unix socket, removing any stale file first, then restrict
/// permissions to owner-only (`0o600`).
///
/// Returns the listener paired with a `SocketGuard` that removes the socket
/// file when dropped.
pub fn bind_listener(socket_path: &str) -> std::io::Result<(UnixListener, SocketGuard)> {
    if let Err(e) = std::fs::remove_file(socket_path)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        return Err(e);
    }
    let listener = UnixListener::bind(socket_path)?;
    std::fs::set_permissions(
        socket_path,
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )?;
    Ok((listener, SocketGuard(socket_path.to_owned())))
}

/// Wait for SIGTERM or SIGINT, whichever arrives first.
pub async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    let mut sigterm = signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            log::info!("Received SIGINT");
        }
        _ = sigterm.recv() => {
            log::info!("Received SIGTERM");
        }
    }
}

/// Accept loop.  Runs until `shutdown` resolves, then drains in-flight tasks.
///
/// Each accepted connection is handled in its own `tokio::spawn` task.
/// `state` is `ArcSwap`-wrapped so SIGHUP reloads are visible to connections
/// accepted after the swap, and engine + config are always loaded as a pair.
pub async fn run_accept_loop<F>(
    listener: UnixListener,
    state: Arc<ArcSwap<EngineState>>,
    shutdown: F,
) where
    F: std::future::Future<Output = ()>,
{
    tokio::pin!(shutdown);
    let mut tasks: JoinSet<()> = JoinSet::new();

    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => {
                log::info!(
                    "Shutdown signal received, draining {} in-flight connection(s)",
                    tasks.len()
                );
                break;
            }
            result = listener.accept() => {
                match result {
                    Ok((stream, _addr)) => {
                        let state = Arc::clone(&state);
                        tasks.spawn(async move {
                            handle_connection(stream, state).await;
                        });
                    }
                    Err(e) => {
                        log::error!("Accept error: {e}");
                    }
                }
            }
        }
        // Reap any tasks that finished since the last iteration
        while tasks.try_join_next().is_some() {}
    }

    // Wait for all in-flight connections to complete
    while tasks.join_next().await.is_some() {}
    log::info!("dgaard-daemon stopped");
}

/// Background task: reload engine and config on every SIGHUP.
///
/// If the config file cannot be read or parsed, the current engine is kept
/// and a warning is logged — the daemon never crashes on a bad reload.
///
/// Engine and config are replaced together in a single `ArcSwap::store` so
/// connection handlers always see a matched pair; there is no torn-read window.
pub async fn sighup_reload_task(state: Arc<ArcSwap<EngineState>>, config_file: String) {
    use tokio::signal::unix::{SignalKind, signal};

    let mut sighup = match signal(SignalKind::hangup()) {
        Ok(s) => s,
        Err(e) => {
            log::error!("Failed to install SIGHUP handler: {e}");
            return;
        }
    };

    while sighup.recv().await.is_some() {
        log::info!("SIGHUP: reloading engine config from {config_file}");
        let path = config_file.clone();
        let result = tokio::task::spawn_blocking(move || {
            let new_cfg = EngineConfig::load(Path::new(&path)).map_err(|e| e.to_string())?;
            Ok::<EngineState, String>(EngineState::new(new_cfg))
        })
        .await;

        match result {
            Ok(Ok(new_state)) => {
                state.store(Arc::new(new_state));
                log::info!("SIGHUP: engine reloaded");
            }
            Ok(Err(e)) => {
                log::warn!("SIGHUP: reload failed ({e}), keeping current config");
            }
            Err(e) => {
                log::warn!("SIGHUP: reload task panicked: {e}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Returns a `(TempDir, socket_path)` pair.  The `TempDir` must be bound
    /// for the duration of the test; dropping it removes the directory.
    fn temp_socket(tag: &str) -> (tempfile::TempDir, String) {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join(format!("{tag}.sock"));
        (dir, path.to_string_lossy().into_owned())
    }

    // ── SocketGuard ───────────────────────────────────────────────────────────

    #[test]
    fn socket_guard_removes_file_on_drop() {
        let (_dir, path) = temp_socket("guard_drop");
        std::fs::write(&path, b"").unwrap();
        assert!(Path::new(&path).exists(), "file should exist before drop");
        drop(SocketGuard(path.clone()));
        assert!(
            !Path::new(&path).exists(),
            "file should be removed after guard is dropped"
        );
    }

    #[test]
    fn socket_guard_is_silent_when_file_already_gone() {
        let (_dir, path) = temp_socket("guard_missing");
        // No file created — drop must not panic
        drop(SocketGuard(path));
    }

    // ── bind_listener ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn bind_listener_creates_socket_file() {
        let (_dir, path) = temp_socket("create");
        let result = bind_listener(&path);
        assert!(result.is_ok(), "bind_listener should succeed: {result:?}");
        assert!(Path::new(&path).exists(), "Socket file should exist");
    }

    #[tokio::test]
    async fn bind_listener_removes_stale_socket_file() {
        let (_dir, path) = temp_socket("stale");
        std::fs::write(&path, b"stale socket").unwrap();
        let result = bind_listener(&path);
        assert!(
            result.is_ok(),
            "Should succeed after removing stale file: {result:?}"
        );
    }

    #[tokio::test]
    async fn bind_listener_sets_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let (_dir, path) = temp_socket("perms");
        let result = bind_listener(&path);
        assert!(result.is_ok());

        let meta = std::fs::metadata(&path).expect("socket file should exist");
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "Expected 0o600 permissions, got {mode:o}");
    }

    #[tokio::test]
    async fn bind_listener_twice_same_path_after_cleanup() {
        let (_dir, path) = temp_socket("twice");

        let first = bind_listener(&path);
        assert!(first.is_ok());
        drop(first); // SocketGuard removes the socket file

        let second = bind_listener(&path);
        assert!(
            second.is_ok(),
            "Second bind after cleanup should succeed: {second:?}"
        );
    }
}
