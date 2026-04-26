//! Live Feed widget — real-time scrolling query log.
//!
//! Renders the last N DNS events as a colour-coded single-line list:
//!   Format:  <client_ip>  ->  <domain>  [<action>]
//!   Colours: green (Allowed), red (Blocked), yellow (Suspicious), dim (Proxied).
//!
//! Shared between two locations:
//!   1. Top-bar Row 3 left pane (60% width, ~5 rows visible).
//!   2. Dashboard tab body (full width, ~20 rows visible).
//!
//! The number of entries displayed is derived from the supplied area height;
//! the widget never allocates more than `LIVE_FEED_BUFFER` entries.
//!
//! TODO: implement `render()` with ratatui `List` widget.

#![allow(dead_code)]

/// Maximum number of entries to keep in the live-feed display buffer.
pub const LIVE_FEED_BUFFER: usize = 20;

/// Render the live-feed widget into the provided area.
///
/// TODO: signature becomes `render(state: &AppState, frozen: bool, area: Area, frame: &mut Frame)`.
pub fn render() {
    // TODO: implement with ratatui
}
