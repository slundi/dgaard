//! Queries tab renderer — tail-style DNS event log.
//!
//! Displays a scrollable, colour-coded table of recent DNS events:
//!   Columns: Timestamp | Domain | Client IP | Blocking Flags
//!   Row colour: green (Allowed), red (Blocked), yellow (Suspicious), dim (Proxied).
//!
//! Interactive controls (resolved via `KeyMap`):
//!   `f`     — open filter popup (client IP prefix or domain substring).
//!   `s`     — open sort popup (default: newest first).
//!   `z`     — toggle frozen display; the status bar shows a frozen indicator.
//!   `up/dn` — scroll through the virtual list.
//!
//! Virtual scrolling: only visible rows are rendered, allowing a history
//! buffer of 1 000+ entries without layout overhead.
//!
//! TODO: implement `render()` and popups with ratatui `Table` and `Block` widgets.

#![allow(dead_code)]

/// Sort order for the queries list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SortOrder {
    /// Most recent event at the top (default).
    #[default]
    NewestFirst,
    /// Oldest event at the top.
    OldestFirst,
}

/// Render the Queries tab body.
///
/// TODO: signature becomes `render(app: &TuiApp, state: &AppState, area: Area, frame: &mut Frame)`.
pub fn render() {
    // TODO: implement with ratatui
}
