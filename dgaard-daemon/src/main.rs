use std::path::Path;
use std::sync::Arc;

use arc_swap::ArcSwap;
use dgaard_daemon::config::DaemonConfig;
use dgaard_daemon::server::{
    EngineState, HASH_SEED, bind_listener, run_accept_loop, shutdown_signal, sighup_reload_task,
};
use dgaard_engine::{Config as EngineConfig, FilterEngine};

/// dgaard-daemon — Unix socket domain scoring daemon.
///
/// Listens on a Unix socket for domain queries and returns a JSON suspicion
/// score. Does not perform DNS resolution — evaluates the domain string only
/// through the engine's static filters and heuristics.
#[derive(argh::FromArgs)]
struct Args {
    /// path to the daemon configuration file (dgaard-daemon.toml)
    #[argh(option, short = 'c')]
    config: Option<String>,

    /// print version and exit
    #[argh(switch, short = 'V')]
    version: bool,
}

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Directories searched in order for `dgaard-daemon.toml` when `--config` is absent.
const CONFIG_SEARCH_DIRS: &[&str] = &["/etc/dgaard-daemon", "."];

fn find_config() -> Option<String> {
    for dir in CONFIG_SEARCH_DIRS {
        let path = format!("{}/dgaard-daemon.toml", dir);
        if Path::new(&path).exists() {
            return Some(path);
        }
    }
    None
}

fn load_daemon_config(path: Option<String>) -> DaemonConfig {
    let Some(p) = path.or_else(find_config) else {
        return DaemonConfig::default();
    };
    match std::fs::read_to_string(&p) {
        Ok(content) => DaemonConfig::load(&content).unwrap_or_else(|e| {
            eprintln!("dgaard-daemon: failed to parse {p}: {e}, using defaults");
            DaemonConfig::default()
        }),
        Err(e) => {
            eprintln!("dgaard-daemon: failed to read {p}: {e}, using defaults");
            DaemonConfig::default()
        }
    }
}

#[tokio::main]
async fn main() {
    let args: Args = argh::from_env();

    if args.version {
        println!("dgaard-daemon {}", VERSION);
        return;
    }

    let daemon_cfg = load_daemon_config(args.config);

    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(&daemon_cfg.log_level),
    )
    .init();

    log::info!("Loading engine config from {}", daemon_cfg.config_file);

    let engine_config =
        EngineConfig::load(Path::new(&daemon_cfg.config_file)).unwrap_or_else(|e| {
            log::warn!("Failed to load engine config: {e}, using defaults");
            EngineConfig::default()
        });

    let state = Arc::new(ArcSwap::from_pointee(EngineState {
        engine: FilterEngine::build_from_files(&engine_config, HASH_SEED),
        config: engine_config,
    }));

    let listener = bind_listener(&daemon_cfg.socket_path).unwrap_or_else(|e| {
        log::error!("Failed to bind {}: {e}", daemon_cfg.socket_path);
        std::process::exit(1);
    });

    log::info!(
        "dgaard-daemon {} listening on {}",
        VERSION,
        daemon_cfg.socket_path
    );

    // Reload engine and config atomically on SIGHUP
    tokio::spawn(sighup_reload_task(
        Arc::clone(&state),
        daemon_cfg.config_file.clone(),
    ));

    run_accept_loop(listener, state, shutdown_signal()).await;
}
