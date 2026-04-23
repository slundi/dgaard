use std::sync::Arc;

use tokio::sync::watch;

use crate::config::TuiConfig;
use crate::state::AppState;

/// Run the terminal user interface.
///
/// Reads events from `state` and renders them according to `config`.
/// Must not be called when the process is started with `--headless`.
/// Returns when `shutdown` is signalled.
pub async fn run(_config: TuiConfig, _state: Arc<AppState>, _shutdown: watch::Receiver<bool>) {
    // TODO: implement TUI (ratatui / crossterm)
}
