mod config;
mod error;
mod routes;
mod state;

use std::path::Path;
use std::sync::Arc;

use arc_swap::ArcSwap;
use dgaard_engine::{Config as EngineConfig, FilterEngine};

use config::RestConfig;
use state::AppState;

/// dgaard-rest — HTTP REST API for domain scoring.
///
/// Exposes domain scoring over HTTP/JSON for integration with web services,
/// dashboards, or any tool that speaks HTTP. Does not perform DNS resolution —
/// evaluates domains through the engine's static filters and heuristics.
#[derive(argh::FromArgs)]
struct Args {
    /// path to the REST configuration file (dgaard-rest.toml)
    #[argh(option, short = 'c')]
    config: Option<String>,

    /// print version and exit
    #[argh(switch, short = 'V')]
    version: bool,
}

const VERSION: &str = env!("CARGO_PKG_VERSION");
pub(crate) const HASH_SEED: u64 = 42;

/// Directories searched in order for `dgaard-rest.toml` when `--config` is absent.
const CONFIG_SEARCH_DIRS: &[&str] = &["/etc/dgaard-rest", "."];

fn find_config() -> Option<String> {
    for dir in CONFIG_SEARCH_DIRS {
        let path = format!("{dir}/dgaard-rest.toml");
        if Path::new(&path).exists() {
            return Some(path);
        }
    }
    None
}

fn load_rest_config(path: Option<String>) -> RestConfig {
    let Some(p) = path.or_else(find_config) else {
        return RestConfig::default();
    };
    match std::fs::read_to_string(&p) {
        Ok(content) => RestConfig::load(&content).unwrap_or_else(|e| {
            eprintln!("dgaard-rest: failed to parse {p}: {e}, using defaults");
            RestConfig::default()
        }),
        Err(e) => {
            eprintln!("dgaard-rest: failed to read {p}: {e}, using defaults");
            RestConfig::default()
        }
    }
}

/// Wait for SIGTERM or SIGINT, whichever arrives first.
async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    let mut sigterm = signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            log::info!("Received SIGINT, shutting down");
        }
        _ = sigterm.recv() => {
            log::info!("Received SIGTERM, shutting down");
        }
    }
}

/// Background task: reload engine and config on every SIGHUP.
///
/// If the config file cannot be read or parsed, the current engine is kept
/// and a warning is logged — the server never crashes on a bad reload.
async fn sighup_reload_task(
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

#[tokio::main]
async fn main() {
    let args: Args = argh::from_env();

    if args.version {
        println!("dgaard-rest {VERSION}");
        return;
    }

    let rest_cfg = load_rest_config(args.config);

    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(&rest_cfg.log_level),
    )
    .init();

    log::info!("Loading engine config from {}", rest_cfg.config_file);

    let engine_config = EngineConfig::load(Path::new(&rest_cfg.config_file)).unwrap_or_else(|e| {
        log::warn!("Failed to load engine config: {e}, using defaults");
        EngineConfig::default()
    });

    let engine = FilterEngine::build_from_files(&engine_config, HASH_SEED);
    let state = AppState::new(
        engine,
        engine_config,
        rest_cfg.config_file.clone(),
        rest_cfg.blocked_status_code,
    );

    tokio::spawn(sighup_reload_task(
        state.engine.clone(),
        state.config.clone(),
        state.config_file.clone(),
    ));

    let app = routes::router().with_state(state);

    let listener = tokio::net::TcpListener::bind(&rest_cfg.listen_addr)
        .await
        .unwrap_or_else(|e| {
            log::error!("Failed to bind {}: {e}", rest_cfg.listen_addr);
            std::process::exit(1);
        });

    log::info!(
        "dgaard-rest {VERSION} listening on {}",
        rest_cfg.listen_addr
    );

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap_or_else(|e| {
            log::error!("Server error: {e}");
            std::process::exit(1);
        });

    log::info!("dgaard-rest stopped");
}
