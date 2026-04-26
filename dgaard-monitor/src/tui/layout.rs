//! Top-bar layout computation.
//!
//! Splits the full terminal area into named regions passed to every renderer
//! so that no rendering function ever hard-codes pixel offsets:
//!
//!   +-----------------------------------------------------------------------+
//!   | Row 1 — Tab bar: Dashboard | Queries | Talkers | Timelines | About    |
//!   |          Status indicators: filter active, frozen, socket connected   |
//!   +-----------------------------------------------------------------------+
//!   | Row 2 — Metrics strip: total queries | blocked % | clients | QPS      |
//!   +-----------------------------------------------------------------------+
//!   | Row 3 — Live Feed (left 60%)          | Flag Distribution (right 40%) |
//!   +-----------------------------------------------------------------------+
//!   |                                                                       |
//!   |                      Active tab body                                  |
//!   |                                                                       |
//!   +-----------------------------------------------------------------------+
//!
//! TODO: implement `compute()` with `ratatui::layout::{Layout, Constraint}`.

#![allow(dead_code)]

/// A rectangular screen region.
///
/// Placeholder for `ratatui::layout::Rect`; will be swapped in once ratatui
/// is added to Cargo.toml.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Area {
    pub x: u16,
    pub y: u16,
    pub width: u16,
    pub height: u16,
}

/// All named regions produced by a single layout pass.
#[derive(Debug, Default, Clone, Copy)]
pub struct Areas {
    /// Row 1: tab bar + status indicators (filter, frozen, socket state).
    pub header: Area,
    /// Row 2: key metrics strip (total, blocked %, active clients, QPS).
    pub metrics: Area,
    /// Row 3 left pane (60%): scrolling live-feed widget.
    pub live_feed: Area,
    /// Row 3 right pane (40%): `StatBlockReason` flag-distribution chart.
    pub flag_dist: Area,
    /// Remaining area below row 3: handed to the active tab renderer.
    pub body: Area,
}

/// Compute layout regions for a terminal of the given dimensions.
///
/// TODO: implement using `ratatui::layout::Layout`.
pub fn compute(_width: u16, _height: u16) -> Areas {
    Areas::default()
}
