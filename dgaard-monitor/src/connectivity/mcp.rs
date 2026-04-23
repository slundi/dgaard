use std::sync::Arc;

use crate::config::ConnectivityConfig;
use crate::state::AppState;

/// Serve the MCP (Model Context Protocol) endpoint.
///
/// Only called when `config.enabled` is true.
pub async fn run(_config: ConnectivityConfig, _state: Arc<AppState>) {
    // TODO: implement MCP server
}
