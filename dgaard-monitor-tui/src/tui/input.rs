//! Input handling — what a key press does to the TUI.
//!
//! `KeyMap` (in `keys`) says which `Action` a key triggers; this module
//! applies that action to the state the main loop owns and tells the loop
//! whether to keep going.  Kept out of the loop so it is testable without a
//! terminal.

use crossterm::event::KeyEvent;

use crate::tui::app::TuiApp;
use crate::tui::keys::Action;
use crate::tui::tabs::queries::QueriesState;
use crate::tui::tabs::{Tab, TabStates};

/// What the main loop does after a key press.
#[derive(Debug, PartialEq, Eq)]
pub enum Flow {
    Continue,
    Quit,
}

/// Apply one key press to the TUI state.
///
/// Unbound keys and key releases are ignored.  Scrolling goes to the Queries
/// tab's own state when it is active, `TuiApp::scroll` otherwise.
pub fn handle_key(key: &KeyEvent, app: &mut TuiApp, tabs: &mut TabStates) -> Flow {
    let Some(action) = app.keymap.resolve_event(key) else {
        return Flow::Continue;
    };
    match action {
        Action::Quit => return Flow::Quit,
        Action::ClearStats => tabs.clear(),
        _ => {}
    }
    if app.active_tab == Tab::Queries && scroll_queries(action, &mut tabs.queries) {
        return Flow::Continue;
    }
    app.apply(action);
    Flow::Continue
}

/// Apply a scroll action to the Queries tab; `false` for any other action.
fn scroll_queries(action: Action, queries: &mut QueriesState) -> bool {
    let page = isize::try_from(queries.page_size()).unwrap_or(isize::MAX);
    match action {
        Action::ScrollUp => queries.scroll_by(-1),
        Action::ScrollDown => queries.scroll_by(1),
        Action::PageUp => queries.scroll_by(-page),
        Action::PageDown => queries.scroll_by(page),
        Action::ScrollTop => queries.scroll_to_top(),
        Action::ScrollBottom => queries.scroll_to_bottom(),
        _ => return false,
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TuiConfig;
    use crossterm::event::{KeyCode, KeyEventKind, KeyModifiers};
    use dgaard_monitor_core::protocol::{StatAction, StatEvent};

    fn allowed(timestamp: u64) -> StatEvent {
        StatEvent {
            timestamp,
            domain_hash: 0xbeef,
            client_ip: [0; 16],
            action: StatAction::Allowed,
        }
    }

    fn setup() -> (TuiApp, TabStates) {
        let mut tabs = TabStates::default();
        tabs.push_event(&allowed(1), "example.com");
        (TuiApp::new(&TuiConfig::default()), tabs)
    }

    /// Queries tab active, `rows` events buffered, a 10-row table.
    fn queries_setup(rows: u64) -> (TuiApp, TabStates) {
        let mut app = TuiApp::new(&TuiConfig::default());
        app.active_tab = Tab::Queries;
        let mut tabs = TabStates::default();
        for timestamp in 0..rows {
            tabs.push_event(&allowed(timestamp), "example.com");
        }
        tabs.queries.set_viewport(10);
        (app, tabs)
    }

    fn press(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
        KeyEvent::new(code, modifiers)
    }

    fn key(code: KeyCode) -> KeyEvent {
        press(code, KeyModifiers::NONE)
    }

    #[test]
    fn test_q_quits() {
        let (mut app, mut tabs) = setup();
        let key = press(KeyCode::Char('q'), KeyModifiers::NONE);
        assert_eq!(handle_key(&key, &mut app, &mut tabs), Flow::Quit);
    }

    #[test]
    fn test_ctrl_c_quits_without_clearing() {
        let (mut app, mut tabs) = setup();
        let key = press(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert_eq!(handle_key(&key, &mut app, &mut tabs), Flow::Quit);
        assert_eq!(tabs.dashboard.global_stats().total_queries, 1);
    }

    #[test]
    fn test_c_clears_stats_and_scroll() {
        let (mut app, mut tabs) = setup();
        app.scroll = 3;
        let key = press(KeyCode::Char('c'), KeyModifiers::NONE);
        assert_eq!(handle_key(&key, &mut app, &mut tabs), Flow::Continue);
        assert_eq!(tabs.dashboard.global_stats().total_queries, 0);
        assert!(tabs.dashboard.live_feed().is_empty());
        assert_eq!(tabs.queries.row_count(), 0);
        assert_eq!(app.scroll, 0);
    }

    #[test]
    fn test_other_actions_reach_app() {
        let (mut app, mut tabs) = setup();
        let key = press(KeyCode::Tab, KeyModifiers::NONE);
        assert_eq!(handle_key(&key, &mut app, &mut tabs), Flow::Continue);
        assert_eq!(app.active_tab, Tab::Queries);
        assert_eq!(tabs.dashboard.global_stats().total_queries, 1);
    }

    #[test]
    fn test_unbound_key_is_ignored() {
        let (mut app, mut tabs) = setup();
        let key = press(KeyCode::Char('x'), KeyModifiers::NONE);
        assert_eq!(handle_key(&key, &mut app, &mut tabs), Flow::Continue);
        assert_eq!(app.active_tab, Tab::Dashboard);
        assert_eq!(tabs.dashboard.global_stats().total_queries, 1);
    }

    #[test]
    fn test_release_is_ignored() {
        let (mut app, mut tabs) = setup();
        let key = KeyEvent::new_with_kind(
            KeyCode::Char('c'),
            KeyModifiers::NONE,
            KeyEventKind::Release,
        );
        assert_eq!(handle_key(&key, &mut app, &mut tabs), Flow::Continue);
        assert_eq!(tabs.dashboard.global_stats().total_queries, 1);
    }

    // --- Queries scrolling ---

    #[test]
    fn test_queries_tab_scrolls_its_own_state() {
        let (mut app, mut tabs) = queries_setup(50);
        handle_key(&key(KeyCode::Down), &mut app, &mut tabs);
        handle_key(&key(KeyCode::Down), &mut app, &mut tabs);
        assert_eq!(tabs.queries.scroll(), 2);
        assert_eq!(app.scroll, 0, "generic scroll untouched");
        handle_key(&key(KeyCode::Up), &mut app, &mut tabs);
        assert_eq!(tabs.queries.scroll(), 1);
    }

    #[test]
    fn test_queries_page_keys_move_one_screen() {
        let (mut app, mut tabs) = queries_setup(50);
        handle_key(&key(KeyCode::PageDown), &mut app, &mut tabs);
        assert_eq!(tabs.queries.scroll(), 10);
        handle_key(&key(KeyCode::PageDown), &mut app, &mut tabs);
        handle_key(&key(KeyCode::PageUp), &mut app, &mut tabs);
        assert_eq!(tabs.queries.scroll(), 10);
    }

    #[test]
    fn test_queries_home_end() {
        let (mut app, mut tabs) = queries_setup(50);
        handle_key(&key(KeyCode::End), &mut app, &mut tabs);
        assert_eq!(tabs.queries.scroll(), 40, "last row at the bottom");
        handle_key(&key(KeyCode::Home), &mut app, &mut tabs);
        assert_eq!(tabs.queries.scroll(), 0);
    }

    #[test]
    fn test_queries_scroll_stops_at_last_row() {
        let (mut app, mut tabs) = queries_setup(15);
        for _ in 0..20 {
            handle_key(&key(KeyCode::Down), &mut app, &mut tabs);
        }
        assert_eq!(tabs.queries.scroll(), 5);
    }

    #[test]
    fn test_scroll_on_other_tab_uses_generic_scroll() {
        let (mut app, mut tabs) = queries_setup(50);
        app.active_tab = Tab::Dashboard;
        handle_key(&key(KeyCode::Down), &mut app, &mut tabs);
        assert_eq!(app.scroll, 1);
        assert_eq!(tabs.queries.scroll(), 0);
    }

    #[test]
    fn test_queries_tab_still_handles_other_keys() {
        let (mut app, mut tabs) = queries_setup(5);
        handle_key(&key(KeyCode::Char('z')), &mut app, &mut tabs);
        assert!(app.frozen);
    }
}
