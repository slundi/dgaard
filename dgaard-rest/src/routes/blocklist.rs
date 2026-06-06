use std::path::Path;
use std::sync::Arc;
use std::time::UNIX_EPOCH;

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    routing::{get, post},
};
use dgaard_engine::{Config as EngineConfig, FilterEngine};
use serde::Serialize;

use crate::state::AppState;

#[derive(Debug, Serialize)]
struct BlocklistMeta {
    name: String,
    last_updated: Option<u64>,
    count: u64,
}

/// Compute metadata for a single list file.
///
/// Runs in a blocking task to avoid stalling the async executor on large files.
async fn list_meta(path: String) -> BlocklistMeta {
    tokio::task::spawn_blocking(move || {
        let p = Path::new(&path);

        let last_updated = std::fs::metadata(p)
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs());

        let count = std::fs::read_to_string(p)
            .map(|content| {
                content
                    .lines()
                    .filter(|l| {
                        let t = l.trim();
                        !t.is_empty() && !t.starts_with('#')
                    })
                    .count() as u64
            })
            .unwrap_or(0);

        BlocklistMeta {
            name: path,
            last_updated,
            count,
        }
    })
    .await
    .unwrap_or_else(|_| BlocklistMeta {
        name: String::new(),
        last_updated: None,
        count: 0,
    })
}

/// GET /api/v1/blocklists — list all configured blocklist/whitelist files with metadata.
///
/// Returns a JSON array: `[{"name": str, "last_updated": unix_ts_or_null, "count": u64}]`
async fn get_blocklists(State(state): State<AppState>) -> Json<Vec<BlocklistMeta>> {
    // Collect paths without holding the ArcSwap guard across await points.
    let paths: Vec<String> = {
        let config = state.config.load();
        let sources = &config.sources;
        let mut v: Vec<String> = sources.blacklists.clone();
        v.extend(sources.whitelists.iter().cloned());
        if !sources.nrd_list_path.is_empty() {
            v.push(sources.nrd_list_path.clone());
        }
        v
    };

    let mut lists = Vec::with_capacity(paths.len());
    for path in paths {
        lists.push(list_meta(path).await);
    }
    Json(lists)
}

/// POST /api/v1/blocklists/update — trigger an async blocklist refresh.
///
/// Responds 202 Accepted immediately. The reload runs in a spawned task and
/// atomically swaps `FilterEngine` via arc-swap when complete.
async fn update_blocklists(State(state): State<AppState>) -> StatusCode {
    let config_file = state.config_file.clone();
    let engine = state.engine.clone();
    let config = state.config.clone();

    tokio::spawn(async move {
        match EngineConfig::load(Path::new(&config_file)) {
            Ok(new_cfg) => {
                let new_engine = FilterEngine::build_from_files(&new_cfg, crate::HASH_SEED);
                config.store(Arc::new(new_cfg));
                engine.store(Arc::new(new_engine));
                log::info!("Blocklists reloaded from {config_file}");
            }
            Err(e) => {
                log::warn!("Blocklist reload failed ({e}), keeping current engine");
            }
        }
    });

    StatusCode::ACCEPTED
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/blocklists", get(get_blocklists))
        .route("/api/v1/blocklists/update", post(update_blocklists))
}
