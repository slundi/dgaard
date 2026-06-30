//! Key-binding resolution.
//!
//! Parses the free-form key strings from `TuiConfig` (e.g. `"q"`, `"space"`,
//! `"up"`) into a `KeyMap` lookup table.  The rest of the TUI only ever
//! matches on `Action` values — raw key strings never leak beyond this module.
//!
//! Additional bindings that are not yet user-configurable (tab switching,
//! freeze, filter popup) are hard-coded here alongside the configurable ones.

#![allow(dead_code)]

use crate::config::TuiConfig;

/// Every action the TUI can perform, regardless of which physical key triggers it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Exit the application.
    Quit,
    /// Pause / resume the tick loop.
    Pause,
    /// Navigate to the next tab (right).
    TabNext,
    /// Navigate to the previous tab (left).
    TabPrev,
    /// Scroll the active view upward.
    ScrollUp,
    /// Scroll the active view downward.
    ScrollDown,
    /// Toggle frozen display in the Queries and Live Feed views.
    Freeze,
    /// Open the filter popup in the Queries tab (`f`).
    Filter,
    /// Open the sort popup in the Queries tab (`s`).
    Sort,
    /// Enter domain search mode (`/`).
    Search,
    /// Clear the active filter and return to the unfiltered view.
    ClearFilter,
    /// Jump directly to tab 1 (Dashboard).
    Tab1,
    /// Jump directly to tab 2 (Queries).
    Tab2,
    /// Jump directly to tab 3 (Talkers).
    Tab3,
    /// Jump directly to tab 4 (Timelines).
    Tab4,
    /// Jump directly to tab 5 (About).
    Tab5,
}

/// Resolved key bindings built once from `TuiConfig`.
pub struct KeyMap {
    pub quit: String,
    pub pause: String,
    pub scroll_up: String,
    pub scroll_down: String,
}

impl KeyMap {
    /// Build a `KeyMap` from the parsed TOML config section.
    pub fn from_config(config: &TuiConfig) -> Self {
        Self {
            quit: config.key_quit.clone(),
            pause: config.key_pause.clone(),
            scroll_up: config.key_scroll_up.clone(),
            scroll_down: config.key_scroll_down.clone(),
        }
    }

    /// Resolve a raw key string (as produced by crossterm) to an `Action`.
    /// Returns `None` for keys that are not bound.
    ///
    /// Configurable bindings take priority over fixed bindings so that user
    /// config can always override a default.
    pub fn resolve(&self, key: &str) -> Option<Action> {
        // Configurable bindings checked first so user config can override defaults
        if key == self.quit {
            return Some(Action::Quit);
        } else if key == self.pause {
            return Some(Action::Pause);
        } else if key == self.scroll_up {
            return Some(Action::ScrollUp);
        } else if key == self.scroll_down {
            return Some(Action::ScrollDown);
        }
        // Fixed bindings not yet exposed in config
        match key {
            "tab" => Some(Action::TabNext),
            "backtab" => Some(Action::TabPrev),
            "z" => Some(Action::Freeze),
            "f" => Some(Action::Filter),
            "s" => Some(Action::Sort),
            "/" => Some(Action::Search),
            "esc" => Some(Action::ClearFilter),
            "1" => Some(Action::Tab1),
            "2" => Some(Action::Tab2),
            "3" => Some(Action::Tab3),
            "4" => Some(Action::Tab4),
            "5" => Some(Action::Tab5),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TuiConfig;

    fn default_keymap() -> KeyMap {
        KeyMap::from_config(&TuiConfig::default())
    }

    #[test]
    fn test_configurable_quit() {
        let km = default_keymap();
        assert_eq!(km.resolve("q"), Some(Action::Quit));
    }

    #[test]
    fn test_configurable_scroll() {
        let km = default_keymap();
        assert_eq!(km.resolve("up"), Some(Action::ScrollUp));
        assert_eq!(km.resolve("down"), Some(Action::ScrollDown));
    }

    #[test]
    fn test_fixed_tab_bindings() {
        let km = default_keymap();
        assert_eq!(km.resolve("tab"), Some(Action::TabNext));
        assert_eq!(km.resolve("backtab"), Some(Action::TabPrev));
    }

    #[test]
    fn test_fixed_freeze() {
        let km = default_keymap();
        assert_eq!(km.resolve("z"), Some(Action::Freeze));
    }

    #[test]
    fn test_direct_tab_number_keys() {
        let km = default_keymap();
        assert_eq!(km.resolve("1"), Some(Action::Tab1));
        assert_eq!(km.resolve("2"), Some(Action::Tab2));
        assert_eq!(km.resolve("3"), Some(Action::Tab3));
        assert_eq!(km.resolve("4"), Some(Action::Tab4));
        assert_eq!(km.resolve("5"), Some(Action::Tab5));
    }

    #[test]
    fn test_unknown_key_returns_none() {
        let km = default_keymap();
        assert_eq!(km.resolve("x"), None);
        assert_eq!(km.resolve(""), None);
    }

    #[test]
    fn test_custom_quit_key() {
        let config = TuiConfig {
            key_quit: "esc".to_string(),
            ..TuiConfig::default()
        };
        let km = KeyMap::from_config(&config);
        assert_eq!(km.resolve("esc"), Some(Action::Quit));
        assert_eq!(km.resolve("q"), None);
    }
}
