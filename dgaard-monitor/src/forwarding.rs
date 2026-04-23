use std::sync::Arc;

use crate::config::ForwardingConfig;
use crate::state::AppState;

/// Forward enriched events to external sinks (file, stdout, HTTP endpoint).
///
/// Applies the `filter` list from `config` and formats each event using the
/// configured `template` before writing / posting it.
pub async fn run(_config: ForwardingConfig, _state: Arc<AppState>) {
    // TODO: implement forwarding sink
}
