//! Flag Distribution widget — `StatBlockReason` bitmask bar chart.
//!
//! Counts how many times each `StatBlockReason` flag has fired within the
//! current rolling window and renders it as a horizontal bar chart sorted by
//! frequency descending:
//!
//!   StaticBlacklist  ||||||||||||||||....  47 %
//!   AbpRule          ||||||..............  18 %
//!   HighEntropy      ||||................  12 %
//!   ...
//!
//! Shared between two locations:
//!   1. Top-bar Row 3 right pane (40% width, compact view, top `MAX_BARS` flags).
//!   2. Dashboard tab body (full width, expanded view with percentages).
//!
//! TODO: implement `render()` with ratatui `BarChart` widget.

#![allow(dead_code)]

/// Maximum number of flag bars to display (top N by frequency).
pub const MAX_BARS: usize = 8;

/// Render the flag-distribution widget into the provided area.
///
/// TODO: signature becomes `render(state: &AppState, area: Area, frame: &mut Frame)`.
pub fn render() {
    // TODO: implement with ratatui
}
