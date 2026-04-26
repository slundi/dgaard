//! Dashboard tab renderer.
//!
//! Displays an at-a-glance summary of DNS activity in the tab body area:
//!   - Total stats block: total queries, active clients, blocked count and
//!     percentage, query-type breakdown (A / AAAA / PTR / TXT / ...).
//!   - Top domains table: up to 20 rows, red for blocked, green for allowed.
//!   - Traffic gauge: queries-per-second bar for the current 60-second window.
//!   - Active blocking flags: count and ratio for each `StatBlockReason` bit.
//!
//! The persistent Live Feed and Flag Distribution widgets that appear in the
//! top-bar Row 3 are rendered by `widgets::live_feed` and `widgets::flag_dist`;
//! this module only owns the body area below the top bar.
//!
//! TODO: implement `render()` with ratatui `Table`, `Gauge`, and `Block` widgets.

#![allow(dead_code)]

/// Render the Dashboard tab body.
///
/// TODO: signature becomes `render(app: &TuiApp, state: &AppState, area: Area, frame: &mut Frame)`.
pub fn render() {
    // TODO: implement with ratatui
}
