mod cli;
mod config;
mod connectivity;
mod db;
mod error;
mod forwarding;
mod io;
mod protocol;
mod state;
mod tui;
mod util;
mod web;

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;

use state::AppState;

use crate::connectivity::{api, mcp, websocket};

#[tokio::main]
async fn main() {
    let opts = cli::parse();

    // Load config from file, or fall back to compiled-in defaults.
    let cfg = match &opts.config {
        Some(path) => match config::Config::load(path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Error loading config {path}: {e}");
                std::process::exit(1);
            }
        },
        None => config::Config {
            input: config::InputConfig::default(),
            persistence: config::PersistenceConfig::default(),
            tui: config::TuiConfig::default(),
            forwarding: config::ForwardingConfig::default(),
            api: config::ConnectivityConfig::default(),
            websocket: config::ConnectivityConfig::default(),
            mcp: config::ConnectivityConfig::default(),
            web: config::WebConfig::default(),
        },
    };

    // CLI flags override config for the two input paths.
    let socket_path = opts
        .socket
        .as_deref()
        .unwrap_or(&cfg.input.socket)
        .to_string();
    let index_path = opts
        .index
        .as_deref()
        .unwrap_or(&cfg.input.index)
        .to_string();

    // Destructure config so each task can take ownership of its section.
    let config::Config {
        input: _,
        persistence: persistence_cfg,
        tui: tui_cfg,
        forwarding: fwd_cfg,
        api: api_cfg,
        websocket: ws_cfg,
        mcp: mcp_cfg,
        web: web_cfg,
    } = cfg;

    // Warm-up: load host index.
    let domain_map = match io::index::read_host_index(&index_path) {
        Ok(map) => {
            println!("Loaded {} domains from index", map.len());
            map
        }
        Err(error::MonitorError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!(
                "Warning: host index not found at {index_path}, starting without domain names"
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
            println!("Persistence database opened: {}", persistence_cfg.db);
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

    let state = Arc::new(AppState::new(Duration::from_secs(3600)));

    for (hash, domain) in domain_map {
        state.insert_domain(hash, domain).await;
    }

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

    // Unix socket listener (always running).
    {
        let s = Arc::clone(&state);
        let mut rx = shutdown_rx.clone();
        handles.push(tokio::spawn(async move {
            loop {
                // Check for shutdown before attempting a (re)connection.
                if *rx.borrow() {
                    break;
                }
                match io::socket::connect(&socket_path).await {
                    Ok(mut stream) => {
                        println!("Connected to {socket_path}");
                        loop {
                            tokio::select! {
                                biased;
                                // Shutdown takes priority over reading.
                                _ = rx.changed() => return,
                                result = io::socket::read_frame(&mut stream) => {
                                    match result {
                                        Ok(protocol::StatMessage::DomainMapping { hash, domain }) => {
                                            s.insert_domain(hash, domain).await;
                                        }
                                        Ok(protocol::StatMessage::Event(event)) => {
                                            s.record_event(event).await;
                                        }
                                        Err(e) => {
                                            eprintln!("Stream error: {e}");
                                            break; // reconnect
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Connection failed: {e}, retrying in 5s...");
                        // Sleep interruptibly so shutdown is not delayed.
                        tokio::select! {
                            biased;
                            _ = rx.changed() => break,
                            _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                        }
                    }
                }
            }
        }));
    }

    // TUI (skipped when --headless).
    if !opts.headless {
        let s = Arc::clone(&state);
        let rx = shutdown_rx.clone();
        handles.push(tokio::spawn(async move {
            tui::run(tui_cfg, s, rx).await;
        }));
    }

    // Forwarding sink (always running).
    {
        let s = Arc::clone(&state);
        let rx = shutdown_rx.clone();
        handles.push(tokio::spawn(async move {
            forwarding::run(fwd_cfg, s, rx).await;
        }));
    }

    // Optional connectivity services.
    if api_cfg.enabled {
        let s = Arc::clone(&state);
        let rx = shutdown_rx.clone();
        handles.push(tokio::spawn(async move {
            api::run(api_cfg, s, rx).await;
        }));
    }

    if ws_cfg.enabled {
        let s = Arc::clone(&state);
        let rx = shutdown_rx.clone();
        handles.push(tokio::spawn(async move {
            websocket::run(ws_cfg, s, rx).await;
        }));
    }

    if mcp_cfg.enabled {
        let s = Arc::clone(&state);
        let rx = shutdown_rx.clone();
        handles.push(tokio::spawn(async move {
            mcp::run(mcp_cfg, s, rx).await;
        }));
    }

    // Persistence writer — standalone task, active whenever the DB is open.
    if let Some(ref db_arc) = db {
        let s = Arc::clone(&state);
        let d = std::sync::Arc::clone(db_arc);
        let rx = shutdown_rx.clone();
        handles.push(tokio::spawn(async move {
            db::run_writer(s, d, rx).await;
        }));
    }

    if web_cfg.enabled {
        let s = Arc::clone(&state);
        let web_state = {
            let ws = web::WebState::new(Arc::clone(&s), web_cfg.history_size).with_beaconing(
                web_cfg.beaconing_min_observations,
                web_cfg.beaconing_cov_threshold,
            );
            match &db {
                Some(d) => ws.with_db(std::sync::Arc::clone(d)),
                None => ws,
            }
        };
        let web_state = std::sync::Arc::new(web_state);
        let rx = shutdown_rx.clone();
        handles.push(tokio::spawn(async move {
            web::start(s, web_state, web_cfg, rx).await;
        }));
    }

    // --- Wait for a termination signal ---

    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut sigterm) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {
                        println!("\nReceived SIGINT, shutting down...");
                    }
                    _ = sigterm.recv() => {
                        println!("Received SIGTERM, shutting down...");
                    }
                }
            }
            Err(e) => {
                eprintln!("warn: SIGTERM handler unavailable ({e}); using Ctrl-C only");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        if let Err(e) = tokio::signal::ctrl_c().await {
            eprintln!("warn: Ctrl-C handler error: {e}");
        }
        println!("\nReceived Ctrl-C, shutting down...");
    }

    // Broadcast shutdown to all tasks.
    let _ = shutdown_tx.send(true);

    // Wait for every task to finish (up to 10 s each).
    for handle in handles {
        let _ = tokio::time::timeout(Duration::from_secs(10), handle).await;
    }

    // Checkpoint the SQLite WAL so the main DB file is up-to-date on disk
    // even if the OS doesn't get a chance to flush before we exit.
    if let Some(db_arc) = db {
        let db_for_checkpoint = std::sync::Arc::clone(&db_arc);
        let _ = tokio::task::spawn_blocking(move || {
            if let Err(e) = db_for_checkpoint.wal_checkpoint() {
                eprintln!("warn: WAL checkpoint on shutdown failed: {e}");
            }
        })
        .await;
    }

    println!("All tasks stopped. Bye.");
}
