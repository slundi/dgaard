//! Input handling — what a key press does to the TUI.
//!
//! `KeyMap` (in `keys`) says which `Action` a key triggers; this module
//! applies that action to the state the main loop owns and tells the loop
//! whether to keep going.  Kept out of the loop so it is testable without a
//! terminal.

use crossterm::event::KeyEvent;

use crate::tui::app::TuiApp;
use crate::tui::keys::Action;
use crate::tui::tabs::dashboard::DashboardState;

/// What the main loop does after a key press.
#[derive(Debug, PartialEq, Eq)]
pub enum Flow {
    Continue,
    Quit,
}

/// Apply one key press to the TUI state.
///
/// Unbound keys and key releases are ignored.
pub fn handle_key(key: &KeyEvent, app: &mut TuiApp, dashboard: &mut DashboardState) -> Flow {
    let Some(action) = app.keymap.resolve_event(key) else {
        return Flow::Continue;
    };
    match action {
        Action::Quit => return Flow::Quit,
        Action::ClearStats => dashboard.clear(),
        _ => {}
    }
    app.apply(action);
    Flow::Continue
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TuiConfig;
    use crate::tui::tabs::Tab;
    use crossterm::event::{KeyCode, KeyEventKind, KeyModifiers};
    use dgaard_monitor_core::protocol::{StatAction, StatEvent};

    fn setup() -> (TuiApp, DashboardState) {
        let mut dashboard = DashboardState::new();
        dashboard.push_event(
            &StatEvent {
                timestamp: 1,
                domain_hash: 0xbeef,
                client_ip: [0; 16],
                action: StatAction::Allowed,
            },
            "example.com",
        );
        (TuiApp::new(&TuiConfig::default()), dashboard)
    }

    fn press(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
        KeyEvent::new(code, modifiers)
    }

    #[test]
    fn test_q_quits() {
        let (mut app, mut dashboard) = setup();
        let key = press(KeyCode::Char('q'), KeyModifiers::NONE);
        assert_eq!(handle_key(&key, &mut app, &mut dashboard), Flow::Quit);
    }

    #[test]
    fn test_ctrl_c_quits_without_clearing() {
        let (mut app, mut dashboard) = setup();
        let key = press(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert_eq!(handle_key(&key, &mut app, &mut dashboard), Flow::Quit);
        assert_eq!(dashboard.global_stats().total_queries, 1);
    }

    #[test]
    fn test_c_clears_stats_and_scroll() {
        let (mut app, mut dashboard) = setup();
        app.scroll = 3;
        let key = press(KeyCode::Char('c'), KeyModifiers::NONE);
        assert_eq!(handle_key(&key, &mut app, &mut dashboard), Flow::Continue);
        assert_eq!(dashboard.global_stats().total_queries, 0);
        assert!(dashboard.live_feed().is_empty());
        assert_eq!(app.scroll, 0);
    }

    #[test]
    fn test_other_actions_reach_app() {
        let (mut app, mut dashboard) = setup();
        let key = press(KeyCode::Tab, KeyModifiers::NONE);
        assert_eq!(handle_key(&key, &mut app, &mut dashboard), Flow::Continue);
        assert_eq!(app.active_tab, Tab::Queries);
        assert_eq!(dashboard.global_stats().total_queries, 1);
    }

    #[test]
    fn test_unbound_key_is_ignored() {
        let (mut app, mut dashboard) = setup();
        let key = press(KeyCode::Char('x'), KeyModifiers::NONE);
        assert_eq!(handle_key(&key, &mut app, &mut dashboard), Flow::Continue);
        assert_eq!(app.active_tab, Tab::Dashboard);
        assert_eq!(dashboard.global_stats().total_queries, 1);
    }

    #[test]
    fn test_release_is_ignored() {
        let (mut app, mut dashboard) = setup();
        let key = KeyEvent::new_with_kind(
            KeyCode::Char('c'),
            KeyModifiers::NONE,
            KeyEventKind::Release,
        );
        assert_eq!(handle_key(&key, &mut app, &mut dashboard), Flow::Continue);
        assert_eq!(dashboard.global_stats().total_queries, 1);
    }
}
