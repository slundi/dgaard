use std::sync::Arc;

use arc_swap::ArcSwap;
use dgaard_engine::{Config as EngineConfig, FilterEngine};

/// Shared application state injected into every axum handler via `State<AppState>`.
#[derive(Clone)]
pub struct AppState {
    pub engine: Arc<ArcSwap<FilterEngine>>,
    pub config: Arc<ArcSwap<EngineConfig>>,
    /// Path to the dgaard-engine config file — used by the update endpoint to trigger reloads.
    pub config_file: String,
    /// HTTP status code returned for blocked domains: `200` or `403`.
    pub blocked_status_code: u16,
}

impl AppState {
    pub fn new(
        engine: FilterEngine,
        config: EngineConfig,
        config_file: String,
        blocked_status_code: u16,
    ) -> Self {
        Self {
            engine: Arc::new(ArcSwap::from_pointee(engine)),
            config: Arc::new(ArcSwap::from_pointee(config)),
            config_file,
            blocked_status_code,
        }
    }
}
