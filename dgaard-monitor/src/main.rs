mod cli;
mod config;
mod headless;
mod lifecycle;

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;

use dgaard_monitor_core::{db, error, forwarding, io, state::AppState};

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

    // Destructure config so each task can take ownership of its section.
    let config::Config {
        input:
            config::InputConfig {
                socket: socket_path,
                index: index_path,
                event_buffer,
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
    let db: Option<std::sync::Arc<db::Database>> = match db::Database::open(
        &persistence_cfg.db,
        persistence_cfg.events_retention_hours,
        persistence_cfg.aggregates_retention_days,
    ) {
        Ok(d) => {
            eprintln!("Persistence database opened: {}", persistence_cfg.db);
            Some(std::sync::Arc::new(d))
        }
        Err(e) => {
            eprintln!(
                "Warning: could not open persistence database {}: {e}",
                persistence_cfg.db
            );
            None
        }
    };

    let state = Arc::new(AppState::with_event_buffer(
        Duration::from_secs(3600),
        event_buffer,
    ));

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

    // Unix socket reader (always running), reconnects with backoff.
    handles.push(tokio::spawn(io::socket::run_reader(
        socket_path,
        Arc::clone(&state),
        shutdown_rx.clone(),
    )));

    // TUI or headless JSON logger — mutually exclusive.
    let mut ui_task: Option<tokio::task::JoinHandle<()>> = None;
    if opts.headless {
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
