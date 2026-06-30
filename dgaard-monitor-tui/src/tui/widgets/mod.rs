//! Shared TUI widgets.
//!
//! Widgets in this module are reused across more than one rendering location:
//!   `live_feed` — rendered in top-bar Row 3 (left 60%) and the Dashboard tab body.
//!   `flag_dist` — rendered in top-bar Row 3 (right 40%) and the Dashboard tab body.
//!
//! Each widget exposes a single `render()` function that accepts a fixed area
//! and a mutable `Frame`; the caller supplies whatever screen slice it owns.

pub mod flag_dist;
pub mod live_feed;
