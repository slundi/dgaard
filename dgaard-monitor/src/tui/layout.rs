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
//!   |         (5 rows tall)                 |                               |
//!   +-----------------------------------------------------------------------+
//!   |                                                                       |
//!   |                      Active tab body                                  |
//!   |                                                                       |
//!   +-----------------------------------------------------------------------+
//!
//! All height/split constants are defined here; no other file hard-codes them.
//!
//! TODO: replace `Area` / `compute()` with `ratatui::layout::{Rect, Layout, Constraint}`
//! once ratatui is added to Cargo.toml.

#![allow(dead_code)]

/// Height of Row 1 (tab bar + status line), in terminal rows.
pub const HEADER_HEIGHT: u16 = 1;

/// Height of Row 2 (metrics strip), in terminal rows.
pub const METRICS_HEIGHT: u16 = 1;

/// Height of Row 3 (live feed / flag distribution), in terminal rows.
pub const ROW3_HEIGHT: u16 = 5;

/// Total fixed overhead consumed by rows 1-3.
pub const FIXED_HEIGHT: u16 = HEADER_HEIGHT + METRICS_HEIGHT + ROW3_HEIGHT;

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
/// Row 3 is split 60/40 (live feed / flag distribution) using integer
/// arithmetic: `live_feed.width = width * 3 / 5`, remainder to flag_dist.
/// Body height saturates to 0 when the terminal is too small to fit all rows.
pub fn compute(width: u16, height: u16) -> Areas {
    let row3_y = HEADER_HEIGHT + METRICS_HEIGHT;
    let body_y = row3_y + ROW3_HEIGHT;

    // 60 % left / 40 % right; integer division floors live_feed, remainder to flag_dist.
    let live_feed_w = width * 3 / 5;
    let flag_dist_w = width - live_feed_w;

    Areas {
        header: Area {
            x: 0,
            y: 0,
            width,
            height: HEADER_HEIGHT,
        },
        metrics: Area {
            x: 0,
            y: HEADER_HEIGHT,
            width,
            height: METRICS_HEIGHT,
        },
        live_feed: Area {
            x: 0,
            y: row3_y,
            width: live_feed_w,
            height: ROW3_HEIGHT,
        },
        flag_dist: Area {
            x: live_feed_w,
            y: row3_y,
            width: flag_dist_w,
            height: ROW3_HEIGHT,
        },
        body: Area {
            x: 0,
            y: body_y,
            width,
            height: height.saturating_sub(FIXED_HEIGHT),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn areas() -> Areas {
        compute(100, 40)
    }

    // --- row positions ---

    #[test]
    fn test_header_starts_at_top() {
        assert_eq!(areas().header.y, 0);
    }

    #[test]
    fn test_metrics_below_header() {
        assert_eq!(areas().metrics.y, HEADER_HEIGHT);
    }

    #[test]
    fn test_row3_below_metrics() {
        assert_eq!(areas().live_feed.y, HEADER_HEIGHT + METRICS_HEIGHT);
        assert_eq!(areas().flag_dist.y, HEADER_HEIGHT + METRICS_HEIGHT);
    }

    #[test]
    fn test_body_below_row3() {
        assert_eq!(areas().body.y, HEADER_HEIGHT + METRICS_HEIGHT + ROW3_HEIGHT);
    }

    // --- widths ---

    #[test]
    fn test_header_metrics_body_span_full_width() {
        let a = areas();
        assert_eq!(a.header.width, 100);
        assert_eq!(a.metrics.width, 100);
        assert_eq!(a.body.width, 100);
    }

    #[test]
    fn test_row3_widths_sum_to_total() {
        let a = areas();
        assert_eq!(a.live_feed.width + a.flag_dist.width, 100);
    }

    #[test]
    fn test_row3_live_feed_wider_than_flag_dist() {
        let a = areas();
        assert!(
            a.live_feed.width > a.flag_dist.width,
            "live_feed ({}) should be wider than flag_dist ({})",
            a.live_feed.width,
            a.flag_dist.width
        );
    }

    #[test]
    fn test_row3_panes_are_horizontally_adjacent() {
        let a = areas();
        assert_eq!(a.live_feed.x + a.live_feed.width, a.flag_dist.x);
    }

    // --- heights ---

    #[test]
    fn test_header_and_metrics_heights() {
        let a = areas();
        assert_eq!(a.header.height, HEADER_HEIGHT);
        assert_eq!(a.metrics.height, METRICS_HEIGHT);
    }

    #[test]
    fn test_row3_height() {
        let a = areas();
        assert_eq!(a.live_feed.height, ROW3_HEIGHT);
        assert_eq!(a.flag_dist.height, ROW3_HEIGHT);
    }

    #[test]
    fn test_body_height_fills_remaining() {
        let a = compute(100, 40);
        assert_eq!(a.body.height, 40 - FIXED_HEIGHT);
    }

    #[test]
    fn test_body_height_saturates_to_zero_when_terminal_too_small() {
        let a = compute(80, 2);
        assert_eq!(a.body.height, 0);
    }

    // --- x origins ---

    #[test]
    fn test_left_column_regions_start_at_x_zero() {
        let a = areas();
        assert_eq!(a.header.x, 0);
        assert_eq!(a.metrics.x, 0);
        assert_eq!(a.live_feed.x, 0);
        assert_eq!(a.body.x, 0);
    }

    #[test]
    fn test_flag_dist_starts_after_live_feed() {
        let a = areas();
        assert_eq!(a.flag_dist.x, a.live_feed.width);
    }
}
