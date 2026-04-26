//! About tab renderer — project metadata and key-map reference.
//!
//! Static content displayed whenever the user navigates to this tab:
//!   - Project name, version (from `CARGO_PKG_VERSION`), repository URL,
//!     and license.
//!   - A two-column key-map table generated at render time from `TuiApp::keymap`,
//!     so it always reflects the active configuration without manual updates.
//!
//! Because this tab only reads `TuiApp` (no live `AppState` queries), its
//! render cost is negligible on every tick.
//!
//! TODO: implement `render()` with ratatui `Paragraph` and `Table` widgets.

#![allow(dead_code)]

/// Render the About tab body.
///
/// TODO: signature becomes `render(app: &TuiApp, area: Area, frame: &mut Frame)`.
pub fn render() {
    // TODO: implement with ratatui
}
