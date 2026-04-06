mod shutdown;
mod stat_collector;

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    CONFIG, CONFIG_PATH, STATS_SENDER,
    dns::handle_query,
    filter::reload_lists,
    runtime::{
        shutdown::{ShutdownGuard, TaskGuard, wait_for_tasks},
        stat_collector::stats_collector_task,
    },
    utils::get_socket,
};
use crate::{
    stats::{self, StatsReceiver},
    updater::spawn_update_task,
};
use tokio::{
    net::UdpSocket,
    runtime::Builder,
    signal::unix::{SignalKind, signal},
    sync::watch::{self, Sender},
};

use crate::GLOBAL_SEED;

/// Initialize the stats channel and store the sender globally.
/// Returns the receiver for the collector task.
fn init_stats_channel() -> StatsReceiver {
    let (sender, receiver) = stats::channel();
    // Store sender globally for DNS handlers to use
    let _ = STATS_SENDER.set(sender);
    receiver
}

pub(crate) fn start_with_single_worker() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = Builder::new_current_thread()
        .enable_all()
        .thread_stack_size(CONFIG.load().server.runtime.stack_size)
        .max_blocking_threads(CONFIG.load().server.runtime.max_blocking_threads)
        .build()?;
    runtime.block_on(async {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        tokio::spawn(watch_for_reloads());
        let guard = ShutdownGuard::new(shutdown_rx.clone());

        // Initial list load (supports both file paths and URLs)
        println!("Loading filter lists...");
        reload_lists().await;

        tokio::spawn(spawn_update_task());

        // Initialize stats channel and spawn collector
        let stats_receiver = init_stats_channel();
        tokio::spawn(stats_collector_task(stats_receiver, shutdown_rx));

        let tokio_socket = get_socket(&CONFIG.load().server.listen_addr)?;

        println!("Dgaard listening on {}", CONFIG.load().server.listen_addr);

        worker_loop(tokio_socket, &guard, &shutdown_tx).await;

        // Wait for all active tasks to complete
        wait_for_tasks(&guard).await;
        println!("Graceful shutdown complete.");
        Ok(())
    })
}

pub(crate) fn start_with_workers(cpus: usize) -> Result<(), Box<dyn std::error::Error>> {
    let runtime = Builder::new_multi_thread()
        .enable_all()
        .worker_threads(cpus)
        .thread_name_fn(|| {
            static ATOMIC_ID: AtomicUsize = AtomicUsize::new(0);
            let id = ATOMIC_ID.fetch_add(1, Ordering::SeqCst);
            format!("dgaard-{}", id)
        })
        .thread_stack_size(CONFIG.load().server.runtime.stack_size)
        .max_blocking_threads(CONFIG.load().server.runtime.max_blocking_threads)
        .build()?;

    runtime.block_on(async {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let guard = ShutdownGuard::new(shutdown_rx.clone());
        tokio::spawn(watch_for_reloads());

        // Initial list load (supports both file paths and URLs)
        println!("Loading filter lists...");
        reload_lists().await;

        tokio::spawn(spawn_update_task());

        // Initialize stats channel and spawn collector
        let stats_receiver = init_stats_channel();
        tokio::spawn(stats_collector_task(stats_receiver, shutdown_rx.clone()));

        let mut handles = Vec::new();

        for _ in 0..cpus {
            let worker_guard = guard.clone();
            let mut worker_shutdown_rx = shutdown_rx.clone();

            handles.push(tokio::spawn(async move {
                let addr = &CONFIG.load().server.listen_addr;
                let tokio_socket = get_socket(addr).expect("Failed to bind socket");
                // worker_loop(tokio_socket, &worker_guard, &worker_shutdown_tx).await;
                let mut buf = [0u8; 4096];

                loop {
                    tokio::select! {
                        biased;

                        _ = worker_shutdown_rx.changed() => {
                            if *worker_shutdown_rx.borrow() {
                                break;
                            }
                        }

                        result = tokio_socket.recv_from(&mut buf) => {
                            match result {
                                Ok((len, addr)) => {
                                    let packet = buf[..len].to_vec();
                                    let socket_inner = Arc::clone(&tokio_socket);
                                    let task_guard = worker_guard.clone();

                                    // Spawn a task for each request to keep the proxy non-blocking
                                    tokio::spawn(async move {
                                        let _guard = TaskGuard::new(&task_guard);
                                        if let Err(e) = handle_query(socket_inner, packet, addr).await {
                                            eprintln!("Error handling query from {}: {}", addr, e);
                                        }
                                    });
                                }
                                Err(e) => {
                                    eprintln!("Error receiving packet: {}", e);
                                }
                            }
                        }
                    }
                }
            }));
        }

        println!("Dgaard listening on {} with {} workers", CONFIG.load().server.listen_addr, cpus);

        // Wait for shutdown signal
        tokio::signal::ctrl_c().await.expect("Failed to listen for ctrl_c");
        println!("\nShutdown signal received, waiting for {} active tasks...", guard.active_count());
        let _ = shutdown_tx.send(true);

        // Wait for all worker tasks to exit
        for h in handles {
            let _ = h.await;
        }

        // Wait for all active query tasks to complete
        wait_for_tasks(&guard).await;
        println!("Graceful shutdown complete.");
        Ok(())
    })
}

async fn worker_loop(
    tokio_socket: Arc<UdpSocket>,
    guard: &ShutdownGuard,
    shutdown_tx: &Sender<bool>,
) {
    // Buffer for incoming DNS packets (DNS over UDP is typically 512 bytes,
    // but can be larger with EDNS0, so 4096 is a safe buffer size).
    let mut buf = [0u8; 4096];
    loop {
        tokio::select! {
            biased;

            _ = tokio::signal::ctrl_c() => {
                println!("\nShutdown signal received, waiting for {} active tasks...", guard.active_count());
                let _ = shutdown_tx.send(true);
                break;
            }

            result = tokio_socket.recv_from(&mut buf) => {
                match result {
                    Ok((len, addr)) => {
                        let packet = buf[..len].to_vec();
                        let socket_inner = Arc::clone(&tokio_socket);
                        let task_guard = guard.clone();

                        // Spawn a task for each request to keep the proxy non-blocking
                        tokio::spawn(async move {
                            let _guard = TaskGuard::new(&task_guard);
                            if let Err(e) = handle_query(socket_inner, packet, addr).await {
                                eprintln!("Error handling query from {}: {}", addr, e);
                            }
                        });
                    }
                    Err(e) => {
                        eprintln!("Error receiving packet: {}", e);
                    }
                }
            }
        }
    }
}

pub async fn watch_for_reloads() {
    // Create a SIGHUP signal stream
    let mut stream = signal(SignalKind::hangup()).expect("Failed to bind SIGHUP handler");

    println!("SIGHUP handler initialized (PID: {})", std::process::id());

    while stream.recv().await.is_some() {
        println!("SIGHUP received, reloading configuration...");
        if let Err(e) = reload_config().await {
            eprintln!("Reload failed: {}", e);
        }
    }
}

/// Reloads the configuration file and filter lists.
///
/// Called in response to a SIGHUP signal. Reads the config file from the
/// path stored at startup, updates the global CONFIG, and rebuilds the
/// filter engine with fresh lists.
///
/// Returns `Ok(())` on success, or an error message on failure.
pub async fn reload_config() -> Result<(), String> {
    let config_path = CONFIG_PATH
        .get()
        .ok_or("Config path not set. Server was likely not initialized correctly.")?;

    reload_config_from_path(config_path).await
}

/// Internal function to reload config from a specific path.
/// Separated for testability.
async fn reload_config_from_path(config_path: &std::path::Path) -> Result<(), String> {
    if config_path.as_os_str().is_empty() {
        return Err("Config path is empty".to_string());
    }

    match crate::config::Config::load(config_path) {
        Ok(new_config) => {
            CONFIG.store(Arc::new(new_config));
            reload_lists().await;
            println!(
                "Configuration reloaded successfully from {}",
                config_path.display()
            );
            Ok(())
        }
        Err(e) => Err(format!("Failed to reload config: {}", e)),
    }
}

pub(crate) fn init_global_seed() {
    match getrandom::u64() {
        Ok(seed) => GLOBAL_SEED.store(seed, Ordering::Relaxed),
        Err(e) => {
            eprintln!("Unable to have a random seed: {}", e);
            GLOBAL_SEED.store(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("time should go forward")
                    .as_secs(),
                Ordering::Relaxed,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Hot reload tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn reload_config_from_path_fails_with_empty_path() {
        use std::path::Path;

        let empty_path = Path::new("");
        let result = reload_config_from_path(empty_path).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("empty"));
    }

    #[tokio::test]
    async fn reload_config_from_path_fails_with_nonexistent_file() {
        use std::path::Path;

        let nonexistent = Path::new("/nonexistent/path/to/config.toml");
        let result = reload_config_from_path(nonexistent).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to reload config"));
    }

    #[tokio::test]
    async fn reload_config_from_path_succeeds_with_valid_config() {
        use std::env;
        use std::fs;

        let temp_dir = env::temp_dir().join(format!("dgaard_reload_valid_{}", std::process::id()));
        fs::create_dir_all(&temp_dir).expect("Failed to create temp dir");

        let config_path = temp_dir.join("valid_config.toml");
        let config_content = r#"
            [server]
            listen_addr = "127.0.0.1:5454"

            [upstream]
            servers = ["8.8.8.8:53"]
            timeout_ms = 3000
        "#;
        fs::write(&config_path, config_content).expect("Failed to write config");

        let result = reload_config_from_path(&config_path).await;
        assert!(result.is_ok(), "Reload should succeed: {:?}", result);

        // Verify config was updated
        let loaded_config = CONFIG.load();
        assert_eq!(loaded_config.server.listen_addr, "127.0.0.1:5454");
        assert_eq!(loaded_config.upstream.timeout_ms, 3000);

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn reload_config_from_path_fails_with_invalid_toml() {
        use std::env;
        use std::fs;

        let temp_dir =
            env::temp_dir().join(format!("dgaard_reload_invalid_{}", std::process::id()));
        fs::create_dir_all(&temp_dir).expect("Failed to create temp dir");

        let config_path = temp_dir.join("invalid_config.toml");
        let invalid_content = "this is not valid { toml [syntax";
        fs::write(&config_path, invalid_content).expect("Failed to write config");

        let result = reload_config_from_path(&config_path).await;
        assert!(result.is_err(), "Reload should fail with invalid TOML");
        assert!(result.unwrap_err().contains("Failed to reload config"));

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn reload_config_from_path_updates_global_config() {
        use std::env;
        use std::fs;

        let temp_dir = env::temp_dir().join(format!("dgaard_reload_update_{}", std::process::id()));
        fs::create_dir_all(&temp_dir).expect("Failed to create temp dir");

        // First config
        let config_path = temp_dir.join("config.toml");
        fs::write(
            &config_path,
            r#"
            [upstream]
            timeout_ms = 1000
        "#,
        )
        .expect("Failed to write config");

        let _ = reload_config_from_path(&config_path).await;
        assert_eq!(CONFIG.load().upstream.timeout_ms, 1000);

        // Update the config file
        fs::write(
            &config_path,
            r#"
            [upstream]
            timeout_ms = 5000
        "#,
        )
        .expect("Failed to write updated config");

        // Reload and verify update
        let result = reload_config_from_path(&config_path).await;
        assert!(result.is_ok());
        assert_eq!(CONFIG.load().upstream.timeout_ms, 5000);

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }
}
