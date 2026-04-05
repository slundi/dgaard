use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::stats::{self, StatsReceiver};
use crate::{CONFIG, CONFIG_PATH, STATS_SENDER, dns::handle_query, filter::reload_lists};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::{
    net::UdpSocket,
    runtime::Builder,
    signal::{unix::SignalKind, unix::signal},
    sync::watch,
};

use crate::GLOBAL_SEED;

/// Tracks active query tasks for graceful shutdown
#[derive(Clone)]
pub struct ShutdownGuard {
    active_tasks: Arc<AtomicUsize>,
    #[allow(dead_code)] // Used in is_shutting_down(), reserved for future hot-reload support
    shutdown_rx: watch::Receiver<bool>,
}

impl ShutdownGuard {
    fn new(shutdown_rx: watch::Receiver<bool>) -> Self {
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
pub struct TaskGuard {
    active_tasks: Arc<AtomicUsize>,
}

impl TaskGuard {
    fn new(guard: &ShutdownGuard) -> Self {
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

fn get_socket(addr: &str) -> Result<Arc<tokio::net::UdpSocket>, Box<dyn std::error::Error>> {
    // 1. Create a raw socket using socket2
    let addr: SocketAddr = addr.parse()?;
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;

    // 2. Enable SO_REUSEPORT (and SO_REUSEADDR for good measure)
    // Note: .set_reuse_port() is available on Unix systems.
    #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
    socket.set_reuse_port(true)?;
    socket.set_reuse_address(true)?;

    socket.set_nonblocking(true)?; // for tokio compatibility

    // 1. Bind the UDP socket
    socket.bind(&addr.into())?;

    // 4. Convert to Tokio's UdpSocket
    let std_socket: std::net::UdpSocket = socket.into();
    let tokio_socket = Arc::new(UdpSocket::from_std(std_socket)?);
    Ok(tokio_socket)
}

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

        // Initialize stats channel and spawn collector
        let stats_receiver = init_stats_channel();
        tokio::spawn(stats_collector_task(stats_receiver, shutdown_rx));

        let tokio_socket = get_socket(&CONFIG.load().server.listen_addr)?;
        // Buffer for incoming DNS packets (DNS over UDP is typically 512 bytes,
        // but can be larger with EDNS0, so 4096 is a safe buffer size).
        let mut buf = [0u8; 4096];

        println!("Dgaard listening on {}", CONFIG.load().server.listen_addr);

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

/// Waits for all active tasks to complete with a timeout
async fn wait_for_tasks(guard: &ShutdownGuard) {
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

/// Stats collector task that receives events and handles logging/streaming.
///
/// This task:
/// 1. Receives StatMessage events from DNS handlers via MPSC channel
/// 2. Logs block events to stdout (basic CLI logger)
/// 3. Will stream to Unix socket when connected (future: step 5.3)
async fn stats_collector_task(mut receiver: StatsReceiver, mut shutdown_rx: watch::Receiver<bool>) {
    // Track domain mappings for logging
    let mut domain_map: std::collections::HashMap<u64, String> = std::collections::HashMap::new();

    loop {
        tokio::select! {
            biased;

            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    // Drain remaining messages before exit
                    while let Ok(msg) = receiver.try_recv() {
                        process_stat_message(&msg, &mut domain_map);
                    }
                    break;
                }
            }

            msg = receiver.recv() => {
                match msg {
                    Some(msg) => process_stat_message(&msg, &mut domain_map),
                    None => break, // All senders dropped
                }
            }
        }
    }
}

/// Process a single stat message (logging and future socket streaming).
fn process_stat_message(
    msg: &dgaard::StatMessage,
    domain_map: &mut std::collections::HashMap<u64, String>,
) {
    use dgaard::{StatAction, StatBlockReason, StatMessage};

    match msg {
        StatMessage::DomainMapping { hash, domain } => {
            domain_map.insert(*hash, domain.clone());
        }
        StatMessage::Event(event) => {
            // Get domain name from mapping (or use hash as fallback)
            let domain = domain_map
                .get(&event.domain_hash)
                .map(|s| s.as_str())
                .unwrap_or("<unknown>");

            // Format client IP
            let client_ip = format_client_ip(&event.client_ip);

            // Log based on action
            match &event.action {
                StatAction::Blocked(reason) => {
                    let reason_str = match reason {
                        StatBlockReason::StaticBlacklist => "blocklist",
                        StatBlockReason::AbpRule => "abp-rule",
                        StatBlockReason::HighEntropy => "dga",
                        StatBlockReason::LexicalAnalysis => "lexical",
                        StatBlockReason::InvalidStructure => "structure",
                        StatBlockReason::SuspiciousIdn => "idn",
                        StatBlockReason::NrdList => "nrd",
                        StatBlockReason::TldExcluded => "tld",
                    };
                    println!("[BLOCK] {} -> {} ({})", client_ip, domain, reason_str);
                }
                StatAction::Allowed => {
                    // Only log in verbose/debug mode (currently silent)
                }
                StatAction::Proxied => {
                    // Only log in verbose/debug mode (currently silent)
                }
            }
        }
    }
}

/// Format a 16-byte IPv6 address (or IPv4-mapped) for display.
fn format_client_ip(ip_bytes: &[u8; 16]) -> String {
    use std::net::{Ipv4Addr, Ipv6Addr};

    // Check for IPv4-mapped address (::ffff:x.x.x.x)
    if ip_bytes[0..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF] {
        let v4 = Ipv4Addr::new(ip_bytes[12], ip_bytes[13], ip_bytes[14], ip_bytes[15]);
        return v4.to_string();
    }

    // Full IPv6
    let v6 = Ipv6Addr::from(*ip_bytes);
    v6.to_string()
}

pub async fn watch_for_reloads() {
    // Create a SIGHUP signal stream
    let mut stream = signal(SignalKind::hangup()).expect("Failed to bind SIGHUP handler");

    println!("SIGHUP handler initialized (PID: {})", std::process::id());

    while stream.recv().await.is_some() {
        println!("SIGHUP received, reloading configuration...");
        if let Err(e) = reload_config() {
            eprintln!("Reload failed: {}", e);
        }
        reload_lists();
    }
}

/// Reloads the configuration file and filter lists.
///
/// Called in response to a SIGHUP signal. Reads the config file from the
/// path stored at startup, updates the global CONFIG, and rebuilds the
/// filter engine with fresh lists.
///
/// Returns `Ok(())` on success, or an error message on failure.
pub fn reload_config() -> Result<(), String> {
    let config_path = CONFIG_PATH
        .get()
        .ok_or("Config path not set. Server was likely not initialized correctly.")?;

    reload_config_from_path(config_path)
}

/// Internal function to reload config from a specific path.
/// Separated for testability.
fn reload_config_from_path(config_path: &std::path::Path) -> Result<(), String> {
    if config_path.as_os_str().is_empty() {
        return Err("Config path is empty".to_string());
    }

    match crate::config::Config::load(config_path) {
        Ok(new_config) => {
            CONFIG.store(Arc::new(new_config));
            reload_lists();
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

    // -----------------------------------------------------------------------
    // Hot reload tests
    // -----------------------------------------------------------------------

    #[test]
    fn reload_config_from_path_fails_with_empty_path() {
        use std::path::Path;

        let empty_path = Path::new("");
        let result = reload_config_from_path(empty_path);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("empty"));
    }

    #[test]
    fn reload_config_from_path_fails_with_nonexistent_file() {
        use std::path::Path;

        let nonexistent = Path::new("/nonexistent/path/to/config.toml");
        let result = reload_config_from_path(nonexistent);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to reload config"));
    }

    #[test]
    fn reload_config_from_path_succeeds_with_valid_config() {
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

        let result = reload_config_from_path(&config_path);
        assert!(result.is_ok(), "Reload should succeed: {:?}", result);

        // Verify config was updated
        let loaded_config = CONFIG.load();
        assert_eq!(loaded_config.server.listen_addr, "127.0.0.1:5454");
        assert_eq!(loaded_config.upstream.timeout_ms, 3000);

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn reload_config_from_path_fails_with_invalid_toml() {
        use std::env;
        use std::fs;

        let temp_dir =
            env::temp_dir().join(format!("dgaard_reload_invalid_{}", std::process::id()));
        fs::create_dir_all(&temp_dir).expect("Failed to create temp dir");

        let config_path = temp_dir.join("invalid_config.toml");
        let invalid_content = "this is not valid { toml [syntax";
        fs::write(&config_path, invalid_content).expect("Failed to write config");

        let result = reload_config_from_path(&config_path);
        assert!(result.is_err(), "Reload should fail with invalid TOML");
        assert!(result.unwrap_err().contains("Failed to reload config"));

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn reload_config_from_path_updates_global_config() {
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

        let _ = reload_config_from_path(&config_path);
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
        let result = reload_config_from_path(&config_path);
        assert!(result.is_ok());
        assert_eq!(CONFIG.load().upstream.timeout_ms, 5000);

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }
}
