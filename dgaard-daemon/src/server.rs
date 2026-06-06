use std::path::Path;
use std::sync::Arc;

use arc_swap::ArcSwap;
use dgaard_engine::{Config as EngineConfig, FilterEngine};
use tokio::net::UnixListener;
use tokio::task::JoinSet;

use crate::handler::handle_connection;

pub const HASH_SEED: u64 = 42;

/// Bind the Unix socket, removing any stale file first, then restrict
/// permissions to owner-only (`0o600`).
pub fn bind_listener(socket_path: &str) -> std::io::Result<UnixListener> {
    if Path::new(socket_path).exists() {
        std::fs::remove_file(socket_path)?;
    }
    let listener = UnixListener::bind(socket_path)?;
    std::fs::set_permissions(
        socket_path,
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )?;
    Ok(listener)
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
/// `engine` and `config` are `ArcSwap`-wrapped so SIGHUP reloads are
/// visible to connections accepted after the swap.
pub async fn run_accept_loop<F>(
    listener: UnixListener,
    engine: Arc<ArcSwap<FilterEngine>>,
    config: Arc<ArcSwap<EngineConfig>>,
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
                        let engine = Arc::clone(&engine);
                        let config = Arc::clone(&config);
                        tasks.spawn(async move {
                            handle_connection(stream, engine, config).await;
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
pub async fn sighup_reload_task(
    engine: Arc<ArcSwap<FilterEngine>>,
    config: Arc<ArcSwap<EngineConfig>>,
    config_file: String,
) {
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
        match EngineConfig::load(Path::new(&config_file)) {
            Ok(new_cfg) => {
                let new_engine = FilterEngine::build_from_files(&new_cfg, HASH_SEED);
                config.store(Arc::new(new_cfg));
                engine.store(Arc::new(new_engine));
                log::info!("SIGHUP: engine reloaded");
            }
            Err(e) => {
                log::warn!("SIGHUP: reload failed ({e}), keeping current config");
            }
        }
    }
}
