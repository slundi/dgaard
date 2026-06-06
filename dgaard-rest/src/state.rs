use std::sync::Arc;

use arc_swap::ArcSwap;
use dgaard_engine::{Config as EngineConfig, FilterEngine};

/// Shared application state injected into every axum handler via `State<AppState>`.
#[allow(dead_code)] // fields consumed by Phase R2 route handlers
#[derive(Clone)]
pub struct AppState {
    pub engine: Arc<ArcSwap<FilterEngine>>,
    pub config: Arc<ArcSwap<EngineConfig>>,
}

impl AppState {
    pub fn new(engine: FilterEngine, config: EngineConfig) -> Self {
        Self {
            engine: Arc::new(ArcSwap::from_pointee(engine)),
            config: Arc::new(ArcSwap::from_pointee(config)),
        }
    }
}
