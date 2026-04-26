//! Talkers tab renderer — most active client IPs.
//!
//! Displays a sortable table of the top DNS clients observed in the current
//! rolling window:
//!   Columns: Client (IP or resolved hostname) | Requests | Per-flag counts
//!            | First seen | Last seen
//!
//! Hostname resolution: if the monitor can reverse-DNS a local IP the hostname
//! replaces the raw IP address in the Client column.
//!
//! Pressing Enter on a row opens the Talker detail popup:
//!   Title:   "Talker <client>"
//!   Content: most-visited domain, last queried domain, per-flag breakdown,
//!            1-hour activity sparkline.
//!
//! TODO: implement `render()` and `render_popup()` with ratatui `Table` and
//! `Block` widgets.

#![allow(dead_code)]

/// Render the Talkers tab body.
///
/// TODO: signature becomes `render(app: &TuiApp, state: &AppState, area: Area, frame: &mut Frame)`.
pub fn render() {
    // TODO: implement with ratatui
}

/// Render the Talker detail popup over the current frame.
///
/// TODO: signature becomes `render_popup(client: &[u8; 16], state: &AppState, area: Area, frame: &mut Frame)`.
pub fn render_popup() {
    // TODO: implement with ratatui
}
