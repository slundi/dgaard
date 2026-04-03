use std::sync::{Arc, atomic::AtomicU64};

use crate::{
    filter::{FilterEngine, reload_lists},
    runtime::{init_global_seed, start_with_single_worker, start_with_workers},
};
use arc_swap::ArcSwap;

mod cli;
mod config;
mod dns;
mod filter;
mod model;
mod runtime;
mod utils;

static GLOBAL_SEED: AtomicU64 = AtomicU64::new(0);
static CURRENT_ENGINE: std::sync::LazyLock<ArcSwap<FilterEngine>> =
    std::sync::LazyLock::new(|| ArcSwap::from_pointee(FilterEngine::empty()));

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opts = cli::parse();

    let config_path = config::discover_path(opts.config.as_deref()).ok_or("Configuration file not found. Please provide one via --config or place it in /etc/dgaard/config.toml")?;

    let config = config::Config::load(&config_path)?;

    let cpus = match config.server.runtime.worker_threads {
        config::WorkerThreads::Auto => num_cpus::get(),
        config::WorkerThreads::Count(n) => n,
    };

    init_global_seed();
    reload_lists();

    println!("Preparing dgaard runtime with {} thread(s)", cpus);
    if cpus == 1 {
        Ok(start_with_single_worker(config)?)
    } else {
        Ok(start_with_workers(config, cpus)?)
    }
}
