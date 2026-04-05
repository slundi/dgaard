mod cli;
mod config;
mod dga;
mod dns;
mod filter;
mod model;
mod resolve;
mod runtime;
mod utils;

use std::sync::{Arc, atomic::AtomicU64};

use crate::config::Config;
use crate::{
    filter::{FilterEngine, reload_lists},
    runtime::{init_global_seed, start_with_single_worker, start_with_workers},
};
use arc_swap::ArcSwap;

pub static GLOBAL_SEED: AtomicU64 = AtomicU64::new(0);
pub static CURRENT_ENGINE: std::sync::LazyLock<ArcSwap<FilterEngine>> =
    std::sync::LazyLock::new(|| ArcSwap::from_pointee(FilterEngine::empty()));
pub static CONFIG: std::sync::LazyLock<ArcSwap<Config>> =
    std::sync::LazyLock::new(|| ArcSwap::from_pointee(Config::default()));

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opts = cli::parse();

    let config_path = config::discover_path(opts.config.as_deref()).ok_or("Configuration file not found. Please provide one via --config or place it in /etc/dgaard/config.toml")?;

    let config = config::Config::load(&config_path)?;

    let cpus = match config.server.runtime.worker_threads {
        config::WorkerThreads::Auto => num_cpus::get(),
        config::WorkerThreads::Count(n) => n,
    };

    let shared_config = Arc::new(config);
    CONFIG.store(Arc::clone(&shared_config));

    init_global_seed();
    reload_lists();

    println!("Preparing dgaard runtime with {} thread(s)", cpus);
    if cpus == 1 {
        Ok(start_with_single_worker()?)
    } else {
        Ok(start_with_workers(cpus)?)
    }
}
