use std::{
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::config::Config;
use tokio::runtime::Builder;

mod cli;
mod config;
mod filter;

static GLOBAL_SEED: AtomicU64 = AtomicU64::new(0);

fn run(config: Config) {
    println!("Dgaard starting on {}", config.server.listen_addr);
}

fn start_with_single_worker(config: Config) -> Result<(), Box<dyn std::error::Error>> {
    let runtime = Builder::new_current_thread()
        .thread_stack_size(config.server.runtime.stack_size)
        .max_blocking_threads(config.server.runtime.max_blocking_threads)
        .build()?;
    runtime.spawn(async move { run(config) });
    Ok(())
}
fn start_with_workers(config: Config, cpus: usize) -> Result<(), Box<dyn std::error::Error>> {
    let runtime = Builder::new_multi_thread()
        .worker_threads(cpus)
        .thread_name_fn(|| {
            static ATOMIC_ID: AtomicUsize = AtomicUsize::new(0);
            let id = ATOMIC_ID.fetch_add(1, Ordering::SeqCst);
            format!("dgaard-{}", id)
        })
        .thread_stack_size(config.server.runtime.stack_size)
        .max_blocking_threads(config.server.runtime.max_blocking_threads)
        .build()?;
    for _ in 0..cpus {
        let cfg = config.clone();
        runtime.spawn(async move { run(cfg) });
    }
    Ok(())
}

pub fn init_global_seed() {
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opts = cli::parse();

    let config_path = config::discover_path(opts.config.as_deref()).ok_or("Configuration file not found. Please provide one via --config or place it in /etc/dgaard/config.toml")?;

    let config = config::Config::load(&config_path)?;

    let cpus = match config.server.runtime.worker_threads {
        config::WorkerThreads::Auto => num_cpus::get(),
        config::WorkerThreads::Count(n) => n,
    };

    init_global_seed();

    println!("Preparing dgaard runtime with {} thread(s)", cpus);
    if cpus == 1 {
        Ok(start_with_single_worker(config)?)
    } else {
        Ok(start_with_workers(config, cpus)?)
    }
}
