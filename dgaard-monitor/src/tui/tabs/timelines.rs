//! Timelines tab renderer — 24 h trend charts.
//!
//! Visualises long-term DNS activity patterns using sparklines and bar charts:
//!   - Total queries per hour over the last 24 hours.
//!   - Per-client activity: overlaid sparklines for the top N clients.
//!
//! Data source: hourly aggregates from the persistence layer (Tier 2 SQLite
//! buckets).  Falls back to the in-memory `RollingStats` window when the
//! database has not yet accumulated enough data.
//!
//! TODO: implement `render()` with ratatui `Sparkline` and `BarChart` widgets.

#![allow(dead_code)]

/// Render the Timelines tab body.
///
/// TODO: signature becomes `render(app: &TuiApp, state: &AppState, area: Area, frame: &mut Frame)`.
pub fn render() {
    // TODO: implement with ratatui
}
