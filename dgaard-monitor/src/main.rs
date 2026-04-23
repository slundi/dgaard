mod cli;
mod config;
mod connectivity;
mod error;
mod forwarding;
mod io;
mod protocol;
mod state;
mod tui;

use std::sync::Arc;
use std::time::Duration;

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
        persistence: _,
        tui: tui_cfg,
        forwarding: fwd_cfg,
        api: api_cfg,
        websocket: ws_cfg,
        mcp: mcp_cfg,
    } = cfg;

    // Warm-up: load host index.
    let domain_map = match io::index::read_host_index(&index_path) {
        Ok(map) => {
            println!("Loaded {} domains from index", map.len());
            map
        }
        Err(e) => {
            eprintln!("Warning: could not load host index: {e}");
            std::collections::HashMap::new()
        }
    };

    let state = Arc::new(AppState::new(Duration::from_secs(3600)));

    for (hash, domain) in domain_map {
        state.insert_domain(hash, domain).await;
    }

    // --- Spawn tasks ---

    // Unix socket listener (always running).
    {
        let s = Arc::clone(&state);
        tokio::spawn(async move {
            loop {
                match io::socket::connect(&socket_path) {
                    Ok(mut stream) => {
                        println!("Connected to {socket_path}");
                        loop {
                            match io::socket::read_frame(&mut stream).await {
                                Ok(protocol::StatMessage::DomainMapping { hash, domain }) => {
                                    s.insert_domain(hash, domain).await;
                                }
                                Ok(protocol::StatMessage::Event(event)) => {
                                    s.record_event(event).await;
                                }
                                Err(e) => {
                                    eprintln!("Stream error: {e}");
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Connection failed: {e}, retrying in 5s...");
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                }
            }
        });
    }

    // TUI (skipped when --headless).
    if !opts.headless {
        let s = Arc::clone(&state);
        tokio::spawn(async move {
            tui::run(tui_cfg, s).await;
        });
    }

    // Forwarding sink (always running).
    {
        let s = Arc::clone(&state);
        tokio::spawn(async move {
            forwarding::run(fwd_cfg, s).await;
        });
    }

    // Optional connectivity services.
    if api_cfg.enabled {
        let s = Arc::clone(&state);
        tokio::spawn(async move {
            api::run(api_cfg, s).await;
        });
    }

    if ws_cfg.enabled {
        let s = Arc::clone(&state);
        tokio::spawn(async move {
            websocket::run(ws_cfg, s).await;
        });
    }

    if mcp_cfg.enabled {
        let s = Arc::clone(&state);
        tokio::spawn(async move {
            mcp::run(mcp_cfg, s).await;
        });
    }

    // Park the main task — spawned tasks drive the process.
    // TODO: replace with graceful shutdown on SIGTERM / Ctrl-C.
    std::future::pending::<()>().await;
}
