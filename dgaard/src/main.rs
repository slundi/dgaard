mod cache;
mod cli;
mod config;
mod debug;
mod dns;
mod dnssec;
mod filter;
mod metrics;
mod model;
mod popularity;
mod prefetch;
mod resolve;
mod runtime;
mod stats;
mod updater;
mod utils;

use std::{
    path::PathBuf,
    sync::{Arc, atomic::AtomicU64},
};

use crate::cache::ResponseCache;
use crate::popularity::PopularityTracker;
use crate::runtime::{init_global_seed, start_with_single_worker, start_with_workers};
use crate::stats::{StatsCounters, StatsSender};
use crate::{config::Config, filter::engine::FilterEngine};
use arc_swap::ArcSwap;

pub static GLOBAL_SEED: AtomicU64 = AtomicU64::new(0);
pub static CURRENT_ENGINE: std::sync::LazyLock<ArcSwap<FilterEngine>> =
    std::sync::LazyLock::new(|| ArcSwap::from_pointee(FilterEngine::empty()));
pub static CONFIG: std::sync::LazyLock<ArcSwap<Config>> =
    std::sync::LazyLock::new(|| ArcSwap::from_pointee(Config::default()));
/// Stores the configuration file path for hot-reload support (SIGHUP).
pub static CONFIG_PATH: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
/// Global statistics counters for quick metrics access.
pub static STATS_COUNTERS: StatsCounters = StatsCounters::new();
/// Global stats sender for emitting events to the collector.
/// Initialized when the runtime starts.
pub static STATS_SENDER: std::sync::OnceLock<StatsSender> = std::sync::OnceLock::new();
/// TTL-aware LRU response cache.  Initialized at startup when `cache.enabled = true`.
pub static RESPONSE_CACHE: std::sync::OnceLock<ResponseCache> = std::sync::OnceLock::new();
/// Tracks per-domain popularity (decayed hit counts). Updated on every
/// allowed cache hit; consumed by the Phase 4 snapshot writer and the
/// Phase 5 prefetch worker. Always initialised at runtime startup so
/// `handle_query` never has to branch on its absence.
pub static POPULARITY_TRACKER: std::sync::LazyLock<Arc<PopularityTracker>> =
    std::sync::LazyLock::new(|| Arc::new(PopularityTracker::new()));
/// Recursive-mode DNSSEC validator. Always constructed — even in
/// forwarder mode — so tests and future code can reach the same
/// instance through `crate::RECURSIVE_DNSSEC`. In forwarder mode it is
/// simply never invoked (the side-channel path in `crate::dnssec`
/// covers that).
pub static RECURSIVE_DNSSEC: std::sync::LazyLock<dns::dnssec_chain::RecursiveDnssecValidator> =
    std::sync::LazyLock::new(dns::dnssec_chain::RecursiveDnssecValidator::default);

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // rustls 0.23 requires an explicit process-level crypto provider.
    // hyper-rustls is built with the "ring" feature, so install that provider.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls ring crypto provider");

    let opts = cli::parse();

    let config_path = config::discover_path(opts.config.as_deref()).ok_or("Configuration file not found. Please provide one via --config or place it in /etc/dgaard/config.toml")?;

    let config = config::Config::load(&config_path)?;
    // Reject combinations that the current code base cannot serve safely
    // (notably mode = "recursive" + DNSSEC = true, which lands in Phase 6 —
    // see docs/Roadmap-recursive-DNS.md). Validating before opening any
    // sockets means an invalid config never reaches port 53.
    config.validate()?;

    // Install the resolver matching the configured mode. The `match`
    // is the seam handle_query never has to know about — its single
    // call site goes through UPSTREAM_RESOLVER.
    let resolver: std::sync::Arc<dyn dns::resolver::UpstreamResolver> = match config.server.mode {
        config::ResolutionMode::Forwarder => {
            std::sync::Arc::new(dns::resolver::ForwardingResolver::new())
        }
        config::ResolutionMode::Recursive => {
            let cfg = config.recursive.clone();
            let mut r = dns::recursive::RecursiveResolver::from_config(cfg)?;
            // Phase 6 session 2: hook the chain-of-trust validator into
            // the iterative loop when DNSSEC is enabled at startup.
            // We share the same global instance that `handle_query`
            // consults so both ends of the pipeline see the same
            // DNSKEY/DS cache.
            if config.security.dnssec.enabled {
                r = r.with_validator(std::sync::Arc::new(RECURSIVE_DNSSEC.clone()));
            }
            std::sync::Arc::new(r)
        }
    };
    dns::resolver::install(resolver).map_err(|e| e.to_string())?;

    // Store config path for hot-reload (SIGHUP)
    CONFIG_PATH
        .set(config_path.clone())
        .expect("Path already set");

    let cpus = match config.server.runtime.worker_threads {
        config::WorkerThreads::Auto => num_cpus::get(),
        config::WorkerThreads::Count(n) => n,
    };

    let shared_config = Arc::new(config);
    CONFIG.store(Arc::clone(&shared_config));

    init_global_seed();

    println!("Preparing dgaard runtime with {} thread(s)", cpus);
    if cpus == 1 {
        Ok(start_with_single_worker()?)
    } else {
        Ok(start_with_workers(cpus)?)
    }
}
