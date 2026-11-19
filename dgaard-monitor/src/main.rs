mod cli;
mod config;
mod custom_flags;
mod headless;
mod lifecycle;

use std::io::IsTerminal;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;

use dgaard_monitor_core::state::{AppState, StateOptions};
use dgaard_monitor_core::{db, error, forwarding, io};

#[cfg(feature = "nats")]
use dgaard_monitor_nats as nats;
#[cfg(feature = "rest")]
use dgaard_monitor_rest as rest;
#[cfg(feature = "tui")]
use dgaard_monitor_tui as tui;

#[tokio::main]
async fn main() {
    let opts = cli::parse();

    // Load config from file, or fall back to compiled-in defaults.
    let mut cfg = match &opts.config {
        Some(path) => match config::Config::load(path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Error loading config {path}: {e}");
                std::process::exit(1);
            }
        },
        None => config::Config::default(),
    };
    // CLI path flags (socket, index, db) win over the config.
    opts.apply_overrides(&mut cfg);
    for warning in &cfg.warnings {
        eprintln!("Warning: config: {warning}");
    }

    // Custom flag labels (bits 16–31) from the engine config, for every output.
    if let Some(path) = &cfg.input.engine_config_path {
        match custom_flags::load(path) {
            Ok(labels) => {
                eprintln!("Loaded {} custom flag labels from {path}", labels.len());
                dgaard_monitor_core::util::set_custom_flag_labels(labels);
            }
            Err(e) => eprintln!(
                "Warning: custom flag labels unavailable ({path}): {e}; showing CUSTOM_BIT_<n>"
            ),
        }
    }

    // Only REST services read the sliding window; skip it otherwise.
    let window_capacity = cfg.window_capacity();

    // Destructure config so each task can take ownership of its section.
    let config::Config {
        input:
            config::InputConfig {
                socket: socket_path,
                index: index_path,
                event_buffer,
                peer_uid,
                ..
            },
        persistence: persistence_cfg,
        tui: tui_cfg,
        forwarding: fwd_cfg,
        server: server_cfg,
        api: api_cfg,
        websocket: ws_cfg,
        mcp: mcp_cfg,
        web: web_cfg,
        nats: nats_cfg,
        stats: stats_cfg,
        warnings: _,
    } = cfg;
    #[cfg(not(feature = "tui"))]
    let _ = tui_cfg;
    #[cfg(not(feature = "rest"))]
    let _ = (server_cfg, api_cfg, ws_cfg, mcp_cfg, web_cfg);
    #[cfg(not(feature = "nats"))]
    let _ = nats_cfg;

    // Warm-up: load host index.
    let domain_map = match io::index::read_host_index(&index_path) {
        Ok(map) => {
            eprintln!("Loaded {} domains from index", map.len());
            map
        }
        Err(error::MonitorError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!(
                "Warning: host index not found at {index_path}, starting without domain names until it is created"
            );
            std::collections::HashMap::new()
        }
        Err(e) => {
            eprintln!("Warning: could not load host index: {e}");
            std::collections::HashMap::new()
        }
    };

    // Open SQLite database (standalone; active regardless of web.enabled).
    let db = open_persistence(&persistence_cfg);

    let state = Arc::new(AppState::with_options(StateOptions {
        window: Duration::from_secs(stats_cfg.window_secs),
        max_window_events: window_capacity,
        event_buffer,
    }));

    // One write lock for the whole index, and kept apart from runtime
    // mappings so later reloads can drop entries removed from the lists.
    state.replace_index(domain_map).await;

    // Shutdown channel: false = running, true = stop.
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Collect task handles so we can wait for a clean exit.
    let mut handles = Vec::new();

    // --- Spawn tasks ---

    // Index watcher — reloads the domain map whenever the file changes.
    {
        let s = Arc::clone(&state);
        let rx = shutdown_rx.clone();
        handles.push(tokio::spawn(async move {
            io::watcher::watch_index(index_path, s, rx).await;
        }));
    }

    // TUI or headless JSON logger — mutually exclusive.
    let headless = run_headless(opts.headless, std::io::stdout().is_terminal());
    if headless && !opts.headless && cfg!(feature = "tui") {
        eprintln!("stdout is not a terminal: running headless (one JSON event per line)");
    }
    let mut ui_task: Option<tokio::task::JoinHandle<()>> = None;
    if headless {
        let s = Arc::clone(&state);
        let rx = shutdown_rx.clone();
        handles.push(tokio::spawn(async move {
            headless::run(s, rx).await;
        }));
    } else {
        // Kept apart from `handles`: the TUI ending (user quit) stops the run.
        #[cfg(feature = "tui")]
        {
            ui_task = Some(tokio::spawn(tui::run(
                tui_cfg,
                Arc::clone(&state),
                shutdown_rx.clone(),
            )));
        }
        #[cfg(not(feature = "tui"))]
        {
            let s = Arc::clone(&state);
            let rx = shutdown_rx.clone();
            handles.push(tokio::spawn(async move {
                headless::run(s, rx).await;
            }));
        }
    }

    // Forwarding sink — only when a file or URL is configured. It never
    // writes to stdout, which belongs to the TUI or the headless JSON stream.
    if fwd_cfg.has_sink() {
        let s = Arc::clone(&state);
        let rx = shutdown_rx.clone();
        handles.push(tokio::spawn(async move {
            forwarding::run(fwd_cfg, s, rx).await;
        }));
    }

    // Optional connectivity services (REST API, WebSocket, MCP, Web UI).
    #[cfg(feature = "rest")]
    {
        let s = Arc::clone(&state);
        let db_clone = db.clone();
        let rx = shutdown_rx.clone();
        handles.push(tokio::spawn(async move {
            rest::serve(
                server_cfg, api_cfg, ws_cfg, mcp_cfg, web_cfg, db_clone, s, rx,
            )
            .await;
        }));
    }

    #[cfg(feature = "nats")]
    if nats_cfg.enabled {
        let s = Arc::clone(&state);
        let rx = shutdown_rx.clone();
        handles.push(tokio::spawn(async move {
            nats::run(nats_cfg, s, rx).await;
        }));
    }

    // Persistence writer — standalone task, active whenever the DB is open.
    // Kept apart: shutdown waits for its final flush first.
    let writer_task = db.as_ref().map(|db_arc| {
        tokio::spawn(db::run_writer(
            Arc::clone(&state),
            Arc::clone(db_arc),
            shutdown_rx.clone(),
        ))
    });

    // Unix socket reader (always running), reconnects with backoff and
    // checks who serves the socket before reading from it. Spawned last: the
    // sinks above subscribe to the event bus when they start, and an event
    // read before a sink subscribed would never reach it.
    let peer_policy = match peer_uid {
        Some(uid) => io::socket::PeerPolicy::Uid(uid),
        None => io::socket::PeerPolicy::Auto,
    };
    handles.push(tokio::spawn(io::socket::run_reader(
        socket_path,
        Arc::clone(&state),
        shutdown_rx.clone(),
        peer_policy,
    )));

    // --- Wait for a termination signal, or for the user to quit the TUI ---

    match lifecycle::wait_for_stop(ui_task.as_mut()).await {
        lifecycle::StopTrigger::Signal(name) => eprintln!("Received {name}, shutting down..."),
        lifecycle::StopTrigger::UiClosed => {
            eprintln!("TUI closed, shutting down...");
            // Already finished: awaiting it again would panic.
            ui_task = None;
        }
    }
    handles.extend(ui_task);

    lifecycle::exit_on_second_signal();
    lifecycle::shutdown(shutdown_tx, writer_task, handles, db).await;

    // Make silent losses visible: events each sink could not keep up with.
    for (sink, dropped) in state.dropped_counts() {
        if dropped > 0 {
            eprintln!("Warning: {sink} dropped {dropped} events");
        }
    }

    eprintln!("All tasks stopped. Bye.");
}

/// Run headless when asked, or when stdout is not a terminal (a container
/// started without `-t`, a systemd unit, a pipe): the TUI cannot draw there,
/// and used to leave the process running with no visible output.
fn run_headless(requested: bool, stdout_is_terminal: bool) -> bool {
    requested || !stdout_is_terminal
}

/// Open the SQLite history, unless `[persistence] enabled = false`. A failure
/// is not fatal: the monitor runs without history and says how to fix it.
fn open_persistence(cfg: &config::PersistenceConfig) -> Option<Arc<db::Database>> {
    if !cfg.enabled {
        eprintln!("Persistence disabled ([persistence] enabled = false)");
        return None;
    }
    match db::Database::open(
        &cfg.db,
        cfg.events_retention_hours,
        cfg.aggregates_retention_days,
    ) {
        Ok(database) => {
            eprintln!("Persistence database opened: {}", cfg.db);
            Some(Arc::new(database))
        }
        Err(e) => {
            eprintln!(
                "Warning: could not open persistence database {}: {e}; set \
                 [persistence] db to a writable path, or enabled = false",
                cfg.db
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn persistence(enabled: bool, db: &std::path::Path) -> config::PersistenceConfig {
        config::PersistenceConfig {
            enabled,
            db: db.to_str().unwrap().to_string(),
            ..config::PersistenceConfig::default()
        }
    }

    /// Regression: persistence could not be turned off, so a non-root user
    /// got a warning about /var/dgaard/stats.sqlite on every start.
    #[test]
    fn headless_when_requested_or_without_a_terminal() {
        assert!(run_headless(true, true));
        assert!(run_headless(true, false));
        assert!(
            run_headless(false, false),
            "no terminal: fall back to headless"
        );
        assert!(!run_headless(false, true), "a terminal and no flag: TUI");
    }

    #[test]
    fn disabled_persistence_opens_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stats.sqlite");
        assert!(open_persistence(&persistence(false, &path)).is_none());
        assert!(!path.exists(), "no database file when disabled");
    }

    #[test]
    fn enabled_persistence_opens_the_database() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stats.sqlite");
        assert!(open_persistence(&persistence(true, &path)).is_some());
        assert!(path.exists());
    }

    #[test]
    fn unwritable_path_runs_without_history() {
        let path = std::path::Path::new("/nonexistent/dir/stats.sqlite");
        assert!(open_persistence(&persistence(true, path)).is_none());
    }
}
