use std::sync::Arc;

use tokio::sync::watch;

use crate::config::ConnectivityConfig;
use crate::state::AppState;

/// Serve the MCP (Model Context Protocol) endpoint.
///
/// Only called when `config.enabled` is true.
/// Returns when `shutdown` is signalled.
pub async fn run(
    _config: ConnectivityConfig,
    _state: Arc<AppState>,
    _shutdown: watch::Receiver<bool>,
) {
    // TODO: implement MCP server
}
