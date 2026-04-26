//! Central TUI application state.
//!
//! `TuiApp` is the single mutable object threaded through every renderer.
//! It owns all volatile UI state — active tab, scroll offset, freeze flag,
//! filter string — so that each rendering function only needs a shared
//! reference and never touches `AppState` directly for display decisions.

#![allow(dead_code)]

use crate::config::TuiConfig;
use crate::tui::keys::{Action, KeyMap};
use crate::tui::tabs::Tab;

/// All mutable state belonging to the TUI layer.
pub struct TuiApp {
    /// Currently visible tab.
    pub active_tab: Tab,
    /// Vertical scroll offset for the active tab (rows scrolled past the top).
    pub scroll: usize,
    /// When `true` the live feed and queries list stop updating; new events are
    /// still buffered in `AppState` and resume on the next toggle.
    pub frozen: bool,
    /// Active filter: client IP prefix or domain substring, applied in the
    /// Queries and Live Feed widgets.
    pub filter: Option<String>,
    /// Resolved key bindings derived from `TuiConfig` at startup.
    pub keymap: KeyMap,
}

impl TuiApp {
    /// Build a fresh `TuiApp` from the TUI section of the loaded config.
    pub fn new(config: &TuiConfig) -> Self {
        Self {
            active_tab: Tab::default(),
            scroll: 0,
            frozen: false,
            filter: None,
            keymap: KeyMap::from_config(config),
        }
    }

    /// Apply a resolved `Action` to the UI state.
    pub fn apply(&mut self, action: Action) {
        match action {
            Action::TabNext => self.active_tab = self.active_tab.next(),
            Action::TabPrev => self.active_tab = self.active_tab.prev(),
            Action::ScrollUp => self.scroll = self.scroll.saturating_sub(1),
            Action::ScrollDown => self.scroll = self.scroll.saturating_add(1),
            Action::Freeze => self.frozen = !self.frozen,
            Action::ClearFilter => self.filter = None,
            // Handled at a higher level (quit, popups, search mode)
            Action::Quit | Action::Pause | Action::Filter | Action::Sort | Action::Search => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TuiConfig;

    fn default_app() -> TuiApp {
        TuiApp::new(&TuiConfig::default())
    }

    #[test]
    fn test_initial_state() {
        let app = default_app();
        assert_eq!(app.active_tab, Tab::Dashboard);
        assert_eq!(app.scroll, 0);
        assert!(!app.frozen);
        assert!(app.filter.is_none());
    }

    #[test]
    fn test_tab_navigation() {
        let mut app = default_app();
        app.apply(Action::TabNext);
        assert_eq!(app.active_tab, Tab::Queries);
        app.apply(Action::TabPrev);
        assert_eq!(app.active_tab, Tab::Dashboard);
    }

    #[test]
    fn test_tab_wraps_forward() {
        let mut app = default_app();
        // Dashboard -> Queries -> Talkers -> Timelines -> About -> Dashboard
        for _ in 0..5 {
            app.apply(Action::TabNext);
        }
        assert_eq!(app.active_tab, Tab::Dashboard);
    }

    #[test]
    fn test_tab_wraps_backward() {
        let mut app = default_app();
        app.apply(Action::TabPrev);
        assert_eq!(app.active_tab, Tab::About);
    }

    #[test]
    fn test_scroll_down_and_up() {
        let mut app = default_app();
        app.apply(Action::ScrollDown);
        app.apply(Action::ScrollDown);
        assert_eq!(app.scroll, 2);
        app.apply(Action::ScrollUp);
        assert_eq!(app.scroll, 1);
    }

    #[test]
    fn test_scroll_up_saturates_at_zero() {
        let mut app = default_app();
        app.apply(Action::ScrollUp);
        assert_eq!(app.scroll, 0);
    }

    #[test]
    fn test_freeze_toggle() {
        let mut app = default_app();
        app.apply(Action::Freeze);
        assert!(app.frozen);
        app.apply(Action::Freeze);
        assert!(!app.frozen);
    }

    #[test]
    fn test_clear_filter() {
        let mut app = default_app();
        app.filter = Some("192.168.1.1".to_string());
        app.apply(Action::ClearFilter);
        assert!(app.filter.is_none());
    }
}
