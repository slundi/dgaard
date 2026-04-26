//! TUI entry point.
//!
//! Initialises the terminal in raw mode, drives the tick loop at the rate
//! configured in `TuiConfig::tick_ms`, and dispatches crossterm events through
//! `TuiApp` to the correct tab renderer.  Tears the terminal down cleanly on
//! shutdown or panic.
//!
//! Must not be called when `--headless` is active.

mod app;
mod keys;
mod layout;
mod tabs;
mod widgets;

use std::sync::Arc;
use tokio::sync::watch;
use crate::config::TuiConfig;
use crate::state::AppState;

/// Run the terminal user interface.
///
/// Reads events from `state` and renders them according to `config`.
/// Returns when `shutdown` is signalled.
pub async fn run(_config: TuiConfig, _state: Arc<AppState>, _shutdown: watch::Receiver<bool>) {
    // TODO: setup crossterm raw mode, build TuiApp, enter tick loop
}
