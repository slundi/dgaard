mod shutdown;
mod stat_collector;

use std::{
    net::IpAddr,
    sync::{
        Arc, LazyLock,
        atomic::{AtomicUsize, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use arc_swap::ArcSwapOption;

use crate::{
    CONFIG, CONFIG_PATH, STATS_SENDER,
    config::{Config, IpNet},
    debug::debug_print,
    dns::handle_query,
    filter::reload_lists,
    runtime::{
        shutdown::{ShutdownGuard, TaskGuard, wait_for_tasks},
        stat_collector::stats_collector_task,
    },
    utils::bind_listen_sockets,
};
use crate::{
    stats::{self, StatsReceiver},
    updater::spawn_update_task,
};
use tokio::{
    net::UdpSocket,
    runtime::Builder,
    signal::unix::{SignalKind, signal},
    sync::{
        Semaphore,
        watch::{self, Sender},
    },
};

use crate::GLOBAL_SEED;

/// The client ACL of one configuration, parsed once instead of per packet.
struct ClientAcl {
    /// Configuration the ACL was parsed from: a reload swaps `CONFIG` for a
    /// new `Arc`, which triggers a new parse. Holding it keeps the address
    /// from being reused by another configuration.
    config: Arc<Config>,
    networks: Vec<IpNet>,
    /// `allowed_networks` is empty: every source is accepted. A list whose
    /// entries all fail to parse accepts nobody (fail closed).
    open: bool,
}

impl ClientAcl {
    fn new(config: Arc<Config>) -> Self {
        // `Config::validate` refuses malformed entries at load time.
        let networks = config
            .server
            .allowed_networks
            .iter()
            .filter_map(|cidr| IpNet::parse(cidr))
            .collect();
        let open = config.server.allowed_networks.is_empty();
        Self {
            config,
            networks,
            open,
        }
    }

    fn allows(&self, ip: IpAddr) -> bool {
        self.open || self.networks.iter().any(|net| net.contains(ip))
    }
}

static CLIENT_ACL: LazyLock<ArcSwapOption<ClientAcl>> = LazyLock::new(ArcSwapOption::empty);

/// True when `ip` may query dgaard under the current `server.allowed_networks`.
fn is_client_allowed(ip: IpAddr) -> bool {
    let config = CONFIG.load();
    if let Some(acl) = CLIENT_ACL.load().as_ref()
        && Arc::ptr_eq(&acl.config, &config)
    {
        return acl.allows(ip);
    }
    let acl = Arc::new(ClientAcl::new(Arc::clone(&config)));
    let allowed = acl.allows(ip);
    CLIENT_ACL.store(Some(acl));
    allowed
}

/// Initialize the stats channel and store the sender globally.
/// Returns the receiver for the collector task.
fn init_stats_channel() -> StatsReceiver {
    let (sender, receiver) = stats::channel();
    // Store sender globally for DNS handlers to use
    let _ = STATS_SENDER.set(sender);
    receiver
}

/// Build a minimal DNS SERVFAIL response for `query` without full packet
/// parsing — used in the overload path where spawning a task is not possible.
///
/// Copies the two-byte transaction ID and the question section from the
/// query, sets QR=1 and RCODE=SERVFAIL (2), preserves the RD bit. Strict
/// stub resolvers (e.g. systemd-resolved) drop SERVFAIL responses that
/// don't echo the question, so we include it whenever the query is well
/// formed enough to locate the QNAME terminator.
///
/// Returns `None` if the query is too short to contain a transaction ID.
pub(crate) fn build_minimal_servfail(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 2 {
        return None;
    }
    // Header: 12 bytes echoing the question count from the original query
    // when we can also echo the question section, otherwise zero.
    let question_end = find_question_end(query);
    let qd_count: u16 = if question_end.is_some() { 1 } else { 0 };

    let mut resp = Vec::with_capacity(question_end.unwrap_or(12));
    resp.extend_from_slice(&[
        query[0],
        query[1],
        // QR=1 (response), Opcode=0, AA=0, TC=0, RD preserved from query
        0x80 | (query.get(2).copied().unwrap_or(0) & 0x01),
        // RA=1, RCODE=2 (SERVFAIL)
        0x82,
    ]);
    resp.extend_from_slice(&qd_count.to_be_bytes()); // QDCOUNT
    resp.extend_from_slice(&[0, 0]); // ANCOUNT
    resp.extend_from_slice(&[0, 0]); // NSCOUNT
    resp.extend_from_slice(&[0, 0]); // ARCOUNT
    if let Some(end) = question_end {
        resp.extend_from_slice(&query[12..end]);
    }
    Some(resp)
}

/// Walk the question section starting at byte 12 and return the index just
/// past the QCLASS field. Returns `None` if the QNAME is malformed,
/// uses compression pointers, or is unterminated within the buffer.
fn find_question_end(query: &[u8]) -> Option<usize> {
    if query.len() < 12 {
        return None;
    }
    let mut pos = 12usize;
    while pos < query.len() {
        let len = query[pos] as usize;
        if len == 0 {
            // QTYPE (2) + QCLASS (2) follow the root label.
            let end = pos.checked_add(5)?;
            return if end <= query.len() { Some(end) } else { None };
        }
        if len & 0xc0 != 0 {
            // Compression in the question section is not generated by any
            // sane stub. Reject rather than misparse.
            return None;
        }
        // Bound the QNAME by the RFC 1035 limit of 255 bytes.
        pos = pos.checked_add(1 + len)?;
        if pos.saturating_sub(12) > 255 {
            return None;
        }
    }
    None
}

pub(crate) fn start_with_single_worker() -> Result<(), Box<dyn std::error::Error>> {
    debug_print!("Start with single worker");
    let runtime = Builder::new_current_thread()
        .enable_all()
        .thread_stack_size(CONFIG.load().server.runtime.stack_size)
        .max_blocking_threads(CONFIG.load().server.runtime.max_blocking_threads)
        .build()?;
    runtime.block_on(async {
        // Bind before anything else starts: no listening socket, no server.
        let tokio_socket = bind_listen_sockets(&CONFIG.load().server.listen_addr, 1)?.remove(0);

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        tokio::spawn(watch_for_reloads(shutdown_rx.clone()));
        let guard = ShutdownGuard::new(shutdown_rx.clone());

        // Initial list load (supports both file paths and URLs)
        let initial = reload_lists().await;

        tokio::spawn(spawn_update_task(initial.is_degraded()));

        // Initialize stats channel and spawn collector
        let stats_receiver = init_stats_channel();
        tokio::spawn(stats_collector_task(stats_receiver, shutdown_rx.clone()));

        if let Some(addr) = CONFIG.load().server.metrics_listen.clone() {
            tokio::spawn(crate::metrics::serve(addr, shutdown_rx.clone()));
        }

        if CONFIG.load().security.dnssec.enabled {
            // Both modes validate the answer bytes with the chain validator
            // (`crate::RECURSIVE_DNSSEC`); nothing to start here.
            println!("DNSSEC validation enabled");
        }

        let cache_cfg = CONFIG.load().cache.clone();
        if cache_cfg.enabled {
            let _ =
                crate::RESPONSE_CACHE.set(crate::cache::ResponseCache::new(cache_cfg.max_entries));
            println!(
                "Response cache enabled ({} max entries)",
                cache_cfg.max_entries
            );
        }

        spawn_popularity_persistence(shutdown_rx.clone());
        spawn_prefetch_worker(shutdown_rx.clone());

        let semaphore = Arc::new(Semaphore::new(
            CONFIG.load().server.runtime.max_concurrent_queries,
        ));

        println!("Dgaard listening on {}", CONFIG.load().server.listen_addr);
        spawn_tcp_listener(Arc::clone(&semaphore), shutdown_rx.clone()).await;

        worker_loop(tokio_socket, &guard, &shutdown_tx, semaphore).await;

        // Wait for all active tasks to complete
        wait_for_tasks(&guard).await;
        println!("Graceful shutdown complete.");
        Ok(())
    })
}

pub(crate) fn start_with_workers(cpus: usize) -> Result<(), Box<dyn std::error::Error>> {
    debug_print!("Start with {} worker", cpus);
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
        // One SO_REUSEPORT socket per worker, all bound before anything
        // starts: a bind failure aborts startup instead of leaving workers
        // that exit one by one and a process that serves nothing.
        let sockets = bind_listen_sockets(&CONFIG.load().server.listen_addr, cpus)?;

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let guard = ShutdownGuard::new(shutdown_rx.clone());
        tokio::spawn(watch_for_reloads(shutdown_rx.clone()));

        // Initial list load (supports both file paths and URLs)
        let initial = reload_lists().await;

        tokio::spawn(spawn_update_task(initial.is_degraded()));

        // Initialize stats channel and spawn collector
        let stats_receiver = init_stats_channel();
        tokio::spawn(stats_collector_task(stats_receiver, shutdown_rx.clone()));

        if let Some(addr) = CONFIG.load().server.metrics_listen.clone() {
            tokio::spawn(crate::metrics::serve(addr, shutdown_rx.clone()));
        }

        if CONFIG.load().security.dnssec.enabled {
            // Both modes validate the answer bytes with the chain validator
            // (`crate::RECURSIVE_DNSSEC`); nothing to start here.
            println!("DNSSEC validation enabled");
        }

        let cache_cfg = CONFIG.load().cache.clone();
        if cache_cfg.enabled {
            let _ = crate::RESPONSE_CACHE.set(crate::cache::ResponseCache::new(cache_cfg.max_entries));
            println!("Response cache enabled ({} max entries)", cache_cfg.max_entries);
        }

        spawn_popularity_persistence(shutdown_rx.clone());
        spawn_prefetch_worker(shutdown_rx.clone());

        let semaphore = Arc::new(Semaphore::new(
            CONFIG.load().server.runtime.max_concurrent_queries,
        ));

        spawn_tcp_listener(Arc::clone(&semaphore), shutdown_rx.clone()).await;

        let mut handles = Vec::new();

        for tokio_socket in sockets {
            let worker_guard = guard.clone();
            let worker_semaphore = Arc::clone(&semaphore);
            let mut worker_shutdown_rx = shutdown_rx.clone();

            handles.push(tokio::spawn(async move {
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
                                    if !is_client_allowed(addr.ip()) {
                                        continue;
                                    }
                                    let packet = buf[..len].to_vec();
                                    let socket_inner = Arc::clone(&tokio_socket);
                                    let task_guard = worker_guard.clone();

                                    let permit = match Arc::clone(&worker_semaphore).try_acquire_owned() {
                                        Ok(p) => p,
                                        Err(_) => {
                                            if let Some(resp) = build_minimal_servfail(&packet) {
                                                let _ = tokio_socket.send_to(&resp, addr).await;
                                            }
                                            continue;
                                        }
                                    };

                                    tokio::spawn(async move {
                                        let _permit = permit;
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

        // Wait for shutdown signal (SIGINT or SIGTERM).
        wait_for_shutdown_signal().await;
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

/// Start the DNS-over-TCP listener next to UDP (RFC 7766), with the same
/// client ACL and query semaphore. A bind failure is logged and the server
/// keeps serving UDP.
async fn spawn_tcp_listener(semaphore: Arc<Semaphore>, shutdown_rx: watch::Receiver<bool>) {
    let addr = CONFIG.load().server.listen_addr.clone();
    match tokio::net::TcpListener::bind(&addr).await {
        Ok(listener) => {
            println!("Dgaard listening on {} (TCP)", addr);
            let allowed = Arc::new(is_client_allowed);
            tokio::spawn(crate::dns::tcp::serve(
                listener,
                crate::dns::tcp::TcpLimits::default(),
                allowed,
                semaphore,
                shutdown_rx,
            ));
        }
        Err(e) => eprintln!(
            "warn: TCP listener on {} failed: {} — serving UDP only",
            addr, e
        ),
    }
}

/// Resolves when either SIGINT (Ctrl-C) or SIGTERM is received, whichever
/// comes first.  Used by both the single-worker and multi-worker paths so that
/// `systemd` unit stops (which send SIGTERM) go through the same graceful
/// shutdown path as keyboard interrupts.
async fn wait_for_shutdown_signal() {
    // Degrade gracefully if SIGTERM is already registered globally (e.g. by
    // a linked library); we'll still wake on Ctrl-C.
    match signal(SignalKind::terminate()) {
        Ok(mut sigterm) => {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = sigterm.recv() => {}
            }
        }
        Err(e) => {
            eprintln!("warn: failed to bind SIGTERM handler ({e}); using Ctrl-C only");
            let _ = tokio::signal::ctrl_c().await;
        }
    }
}

async fn worker_loop(
    tokio_socket: Arc<UdpSocket>,
    guard: &ShutdownGuard,
    shutdown_tx: &Sender<bool>,
    semaphore: Arc<Semaphore>,
) {
    // Buffer for incoming DNS packets (DNS over UDP is typically 512 bytes,
    // but can be larger with EDNS0, so 4096 is a safe buffer size).
    let mut sigterm = match signal(SignalKind::terminate()) {
        Ok(s) => Some(s),
        Err(e) => {
            eprintln!("warn: failed to bind SIGTERM handler ({e}); using Ctrl-C only");
            None
        }
    };
    let mut buf = [0u8; 4096];
    loop {
        // Branch the select! based on whether we have a working SIGTERM
        // handler so the unbound case doesn't spin on a dead future.
        let sigterm_fut = async {
            match sigterm.as_mut() {
                Some(s) => {
                    let _ = s.recv().await;
                }
                None => std::future::pending::<()>().await,
            }
        };
        tokio::select! {
            biased;

            _ = tokio::signal::ctrl_c() => {
                println!("\nShutdown signal received, waiting for {} active tasks...", guard.active_count());
                let _ = shutdown_tx.send(true);
                break;
            }

            _ = sigterm_fut => {
                println!("\nShutdown signal received, waiting for {} active tasks...", guard.active_count());
                let _ = shutdown_tx.send(true);
                break;
            }

            result = tokio_socket.recv_from(&mut buf) => {
                match result {
                    Ok((len, addr)) => {
                        if !is_client_allowed(addr.ip()) {
                            continue;
                        }
                        let packet = buf[..len].to_vec();
                        let socket_inner = Arc::clone(&tokio_socket);
                        let task_guard = guard.clone();

                        let permit = match Arc::clone(&semaphore).try_acquire_owned() {
                            Ok(p) => p,
                            Err(_) => {
                                if let Some(resp) = build_minimal_servfail(&packet) {
                                    let _ = tokio_socket.send_to(&resp, addr).await;
                                }
                                continue;
                            }
                        };

                        tokio::spawn(async move {
                            let _permit = permit;
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

pub async fn watch_for_reloads(mut shutdown_rx: watch::Receiver<bool>) {
    // Create a SIGHUP signal stream. If registration fails (e.g. another
    // crate already owns the handler), we silently disable runtime reloads
    // rather than panicking — the operator can still restart the daemon.
    let mut stream = match signal(SignalKind::hangup()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("warn: failed to bind SIGHUP handler ({e}); runtime reload disabled");
            return;
        }
    };

    println!("SIGHUP handler initialized (PID: {})", std::process::id());

    loop {
        tokio::select! {
            biased;
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    return;
                }
            }
            sig = stream.recv() => {
                if sig.is_none() {
                    return;
                }
                println!("SIGHUP received, reloading configuration...");
                if let Err(e) = reload_config().await {
                    eprintln!("Reload failed: {}", e);
                }
            }
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
            // Keep the currently-installed resolver running rather than swap
            // it in under load. Reject reloads whose `[server] mode` differs
            // from the boot-time mode — the resolver type is decided once at
            // startup (see main.rs) because changing it would require
            // reinitialising socket pools and root hints.
            let current_mode = CONFIG.load().server.mode;
            if new_config.server.mode != current_mode {
                return Err(format!(
                    "Refusing reload: [server] mode changed from {:?} to {:?}. \
                     Resolution mode is fixed at startup; restart dgaard to switch.",
                    current_mode, new_config.server.mode
                ));
            }
            if let Err(e) = new_config.validate() {
                return Err(format!("Failed to reload config: {}", e));
            }
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

/// Phase 5 wiring: bring up the prefetch worker and publish its sender
/// so `handle_query` can fire-and-forget refresh requests on near-expiry
/// cache hits. Disabled (no spawn, sender never set) when
/// `[prefetch] enabled = false`, when there is no resolver installed, or
/// when the configured queue capacity / interval would degenerate.
fn spawn_prefetch_worker(shutdown_rx: watch::Receiver<bool>) {
    let cfg = CONFIG.load();
    let pf = &cfg.prefetch;
    if !pf.enabled || pf.queue_capacity == 0 {
        return;
    }
    let Some(resolver) = crate::dns::resolver::UPSTREAM_RESOLVER.get().cloned() else {
        eprintln!("Prefetch: resolver not installed — worker disabled");
        return;
    };

    let (tx, rx) = tokio::sync::mpsc::channel(pf.queue_capacity);
    crate::prefetch::init_global_sender(tx);

    let worker_cfg = crate::prefetch::PrefetchWorkerCfg {
        interval_ms: pf.interval_ms,
    };

    tokio::spawn(crate::prefetch::run_prefetch_worker(
        rx,
        resolver,
        worker_cfg,
        shutdown_rx,
    ));
}

/// Phase 4 wiring: restore the popularity snapshot from disk (if any)
/// and spawn the background save task. Tied to `shutdown_rx` so the
/// task flushes one final write before the runtime exits.
///
/// Disabled at runtime by `save_interval_secs = 0` or an empty
/// `save_path`. Either condition is treated as "operator opted out" —
/// no surprise file writes.
fn spawn_popularity_persistence(shutdown_rx: watch::Receiver<bool>) {
    let cfg = CONFIG.load();
    let rec = &cfg.recursive;

    if rec.save_path.is_empty() {
        return;
    }
    if rec.save_interval_secs == 0 {
        return;
    }

    let path = std::path::PathBuf::from(rec.save_path.clone());
    let task_cfg = crate::popularity::SnapshotTaskCfg {
        interval: std::time::Duration::from_secs(rec.save_interval_secs),
        top_n: rec.save_top_domains,
        half_life_secs: rec.decay_half_life_secs,
    };

    match crate::popularity::restore_into(&crate::POPULARITY_TRACKER, &path) {
        Ok(0) => println!(
            "Popularity: no snapshot at {} (fresh start)",
            path.display()
        ),
        Ok(n) => println!("Popularity: restored {n} entries from {}", path.display()),
        Err(e) => eprintln!(
            "Popularity: ignoring corrupt snapshot at {}: {e}",
            path.display()
        ),
    }

    let tracker = Arc::clone(&crate::POPULARITY_TRACKER);
    tokio::spawn(crate::popularity::run_snapshot_task(
        tracker,
        path,
        task_cfg,
        shutdown_rx,
    ));
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
    use std::sync::{LazyLock, Mutex};

    // -----------------------------------------------------------------------
    // build_minimal_servfail
    // -----------------------------------------------------------------------

    #[test]
    fn servfail_copies_transaction_id() {
        let query = [0xAB, 0xCD, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        let resp = build_minimal_servfail(&query).unwrap();
        assert_eq!(resp[0], 0xAB);
        assert_eq!(resp[1], 0xCD);
    }

    #[test]
    fn servfail_sets_qr_and_rcode() {
        let query = [0x00, 0x01, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]; // RD=1
        let resp = build_minimal_servfail(&query).unwrap();
        assert_eq!(resp[2] & 0x80, 0x80, "QR bit must be set");
        assert_eq!(resp[3] & 0x0F, 2, "RCODE must be SERVFAIL (2)");
    }

    #[test]
    fn servfail_preserves_rd_bit() {
        let mut query = [0x00, 0x01, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        query[2] = 0x01; // RD=1
        let resp_rd = build_minimal_servfail(&query).unwrap();
        assert_eq!(resp_rd[2] & 0x01, 1);

        query[2] = 0x00; // RD=0
        let resp_no_rd = build_minimal_servfail(&query).unwrap();
        assert_eq!(resp_no_rd[2] & 0x01, 0);
    }

    #[test]
    fn servfail_zeroes_record_counts() {
        let query = [
            0xAB, 0xCD, 0x01, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        ];
        let resp = build_minimal_servfail(&query).unwrap();
        assert_eq!(&resp[4..12], &[0u8; 8], "all record counts must be zero");
    }

    #[test]
    fn servfail_returns_none_for_short_input() {
        assert!(build_minimal_servfail(&[]).is_none());
        assert!(build_minimal_servfail(&[0xAB]).is_none());
        assert!(build_minimal_servfail(&[0xAB, 0xCD]).is_some());
    }

    #[test]
    fn servfail_echoes_question_when_present() {
        // Header (12) + QNAME "example.com" (13) + QTYPE A (2) + QCLASS IN (2)
        let mut query = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        query.extend_from_slice(b"\x07example\x03com\x00"); // QNAME
        query.extend_from_slice(&[0x00, 0x01]); // QTYPE A
        query.extend_from_slice(&[0x00, 0x01]); // QCLASS IN

        let resp = build_minimal_servfail(&query).unwrap();
        // Header length + question length
        assert_eq!(resp.len(), 12 + 13 + 4);
        // QDCOUNT must be 1 since we echoed the question.
        assert_eq!(&resp[4..6], &[0x00, 0x01]);
        // Question section is byte-identical to the request.
        assert_eq!(&resp[12..], &query[12..]);
    }

    #[test]
    fn servfail_keeps_qdcount_zero_when_question_malformed() {
        // 12-byte header followed by an unterminated label.
        let mut query = vec![
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        query.extend_from_slice(&[0xff; 8]); // length byte > remaining bytes
        let resp = build_minimal_servfail(&query).unwrap();
        assert_eq!(resp.len(), 12);
        assert_eq!(&resp[4..6], &[0x00, 0x00]);
    }

    #[test]
    fn servfail_rejects_compression_pointer_in_question() {
        // 0xC0 is a compression pointer, illegal in QNAME of an inbound query.
        let mut query = vec![
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        query.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01]);
        let resp = build_minimal_servfail(&query).unwrap();
        // No question included → QDCOUNT must be 0.
        assert_eq!(resp.len(), 12);
        assert_eq!(&resp[4..6], &[0x00, 0x00]);
    }

    // Serialise tests that mutate the global CONFIG via reload_config_from_path.
    static TEST_MUTEX: LazyLock<Mutex<()>> = LazyLock::new(Mutex::default);

    // -----------------------------------------------------------------------
    // Client ACL tests
    // -----------------------------------------------------------------------

    fn acl(cidrs: &[&str]) -> ClientAcl {
        let mut config = Config::default();
        config.server.allowed_networks = cidrs.iter().map(|s| s.to_string()).collect();
        ClientAcl::new(Arc::new(config))
    }

    fn allowed(ip: &str, cidrs: &[&str]) -> bool {
        acl(cidrs).allows(ip.parse().unwrap())
    }

    #[test]
    fn empty_networks_allows_any_ip() {
        assert!(allowed("203.0.113.1", &[]));
    }

    #[test]
    fn ipv4_ranges() {
        let lan = ["127.0.0.1/32", "192.168.1.0/24"];
        assert!(allowed("127.0.0.1", &lan));
        assert!(allowed("192.168.1.0", &lan));
        assert!(allowed("192.168.1.42", &lan));
        assert!(allowed("192.168.1.255", &lan));
        assert!(!allowed("192.168.2.0", &lan));
        assert!(!allowed("203.0.113.1", &lan));
        assert!(allowed("203.0.113.99", &["0.0.0.0/0"]));
    }

    #[test]
    fn ipv6_ranges() {
        assert!(allowed("::1", &["::1/128"]));
        assert!(allowed("2001:db8::42", &["2001:db8::/32"]));
        assert!(!allowed("2001:db9::1", &["2001:db8::/32"]));
        assert!(!allowed("192.168.1.1", &["::1/128"]));
    }

    #[test]
    fn ipv4_mapped_source_matches_ipv4_ranges() {
        // A client of a dual-stack [::] socket shows up IPv4-mapped.
        assert!(allowed("::ffff:192.168.1.7", &["192.168.1.0/24"]));
        assert!(!allowed("::ffff:10.0.0.1", &["192.168.1.0/24"]));
    }

    #[test]
    fn malformed_entries_are_skipped_but_never_open_the_acl() {
        assert!(allowed("10.0.0.1", &["bad/entry", "10.0.0.0/8"]));
        // Only malformed entries: nobody, not everybody.
        assert!(!allowed("10.0.0.1", &["not-a-cidr"]));
    }

    #[test]
    fn acl_is_parsed_once_per_configuration() {
        let _lock = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let previous = CONFIG.load_full();
        let mut config = Config::default();
        config.server.allowed_networks = vec!["10.0.0.0/8".into()];
        CONFIG.store(Arc::new(config));

        assert!(is_client_allowed("10.1.2.3".parse().unwrap()));
        let first = CLIENT_ACL.load_full().expect("cached");
        assert!(!is_client_allowed("192.168.1.1".parse().unwrap()));
        let second = CLIENT_ACL.load_full().expect("cached");
        assert!(Arc::ptr_eq(&first, &second), "same config: no new parse");

        // A reload (new config) is picked up on the next packet.
        let mut reloaded = Config::default();
        reloaded.server.allowed_networks = vec!["192.168.1.0/24".into()];
        CONFIG.store(Arc::new(reloaded));
        assert!(is_client_allowed("192.168.1.1".parse().unwrap()));
        assert!(!is_client_allowed("10.1.2.3".parse().unwrap()));

        CONFIG.store(previous);
    }

    // -----------------------------------------------------------------------
    // Startup binds before serving (review M7)
    // -----------------------------------------------------------------------

    /// Run both startup paths against `listen_addr`; they must fail at once
    /// (before, the multi-worker path kept a process alive serving nothing).
    fn startup_errors(listen_addr: &str) -> (String, String) {
        let _lock = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let previous = CONFIG.load_full();
        let mut config = Config::default();
        config.server.listen_addr = listen_addr.to_string();
        CONFIG.store(Arc::new(config));
        let multi = start_with_workers(2).expect_err("multi-worker must fail");
        let single = start_with_single_worker().expect_err("single worker must fail");
        CONFIG.store(previous);
        (multi.to_string(), single.to_string())
    }

    #[test]
    fn startup_fails_when_the_port_is_taken() {
        let holder = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let (multi, single) = startup_errors(&holder.local_addr().unwrap().to_string());
        assert!(multi.contains("already in use"), "{multi}");
        assert!(single.contains("already in use"), "{single}");
    }

    #[test]
    fn startup_fails_on_an_invalid_listen_addr() {
        let (multi, single) = startup_errors("not-an-address");
        assert!(!multi.is_empty() && !single.is_empty());
    }

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
    #[allow(clippy::await_holding_lock)]
    async fn reload_config_from_path_succeeds_with_valid_config() {
        let _guard = TEST_MUTEX.lock().unwrap();
        use std::env;
        use std::fs;

        let temp_dir = env::temp_dir().join(format!("dgaard_reload_valid_{}", std::process::id()));
        fs::create_dir_all(&temp_dir).expect("Failed to create temp dir");

        let config_path = temp_dir.join("valid_config.toml");
        let config_content = r#"
            [server]
            listen_addr = "127.0.0.1:5454"

            [forwarder]
            servers = ["8.8.8.8:53"]
            timeout_ms = 3000
        "#;
        fs::write(&config_path, config_content).expect("Failed to write config");

        let result = reload_config_from_path(&config_path).await;
        assert!(result.is_ok(), "Reload should succeed: {:?}", result);

        // Verify config was updated
        let loaded_config = CONFIG.load();
        assert_eq!(loaded_config.server.listen_addr, "127.0.0.1:5454");
        assert_eq!(loaded_config.forwarder.timeout_ms, 3000);

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
    #[allow(clippy::await_holding_lock)]
    async fn reload_config_from_path_updates_global_config() {
        let _guard = TEST_MUTEX.lock().unwrap();
        use std::env;
        use std::fs;

        let temp_dir = env::temp_dir().join(format!("dgaard_reload_update_{}", std::process::id()));
        fs::create_dir_all(&temp_dir).expect("Failed to create temp dir");

        // First config
        let config_path = temp_dir.join("config.toml");
        fs::write(
            &config_path,
            r#"
            [forwarder]
            timeout_ms = 1000
        "#,
        )
        .expect("Failed to write config");

        let _ = reload_config_from_path(&config_path).await;
        assert_eq!(CONFIG.load().forwarder.timeout_ms, 1000);

        // Update the config file
        fs::write(
            &config_path,
            r#"
            [forwarder]
            timeout_ms = 5000
        "#,
        )
        .expect("Failed to write updated config");

        // Reload and verify update
        let result = reload_config_from_path(&config_path).await;
        assert!(result.is_ok());
        assert_eq!(CONFIG.load().forwarder.timeout_ms, 5000);

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }
}
