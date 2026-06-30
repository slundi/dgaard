pub mod config;
mod connectivity;
mod web;

use std::sync::Arc;
use tokio::sync::watch;
use dgaard_monitor_core::{db::Database, state::AppState};
use crate::config::{ConnectivityConfig, WebConfig};
pub use web::WebState;

pub async fn serve(
    api_cfg: ConnectivityConfig,
    ws_cfg: ConnectivityConfig,
    mcp_cfg: ConnectivityConfig,
    web_cfg: WebConfig,
    db: Option<Arc<Database>>,
    state: Arc<AppState>,
    mut shutdown: watch::Receiver<bool>,
) {
    use crate::connectivity::{api, mcp, websocket};

    let mut handles = Vec::new();

    if api_cfg.enabled {
        let s = Arc::clone(&state);
        let rx = shutdown.clone();
        handles.push(tokio::spawn(async move { api::run(api_cfg, s, rx).await }));
    }

    if ws_cfg.enabled {
        let s = Arc::clone(&state);
        let rx = shutdown.clone();
        handles.push(tokio::spawn(async move { websocket::run(ws_cfg, s, rx).await }));
    }

    if mcp_cfg.enabled {
        let s = Arc::clone(&state);
        let rx = shutdown.clone();
        handles.push(tokio::spawn(async move { mcp::run(mcp_cfg, s, rx).await }));
    }

    if web_cfg.enabled {
        let s = Arc::clone(&state);
        let web_state = {
            let ws = WebState::new(Arc::clone(&s), web_cfg.history_size).with_beaconing(
                web_cfg.beaconing_min_observations,
                web_cfg.beaconing_cov_threshold,
            );
            match &db {
                Some(d) => ws.with_db(Arc::clone(d)),
                None => ws,
            }
        };
        let web_state = Arc::new(web_state);
        let rx = shutdown.clone();
        handles.push(tokio::spawn(async move { web::start(s, web_state, web_cfg, rx).await }));
    }

    // Wait until shutdown signalled, then cancel subtasks
    let _ = shutdown.changed().await;
    for h in handles {
        h.abort();
    }
}
