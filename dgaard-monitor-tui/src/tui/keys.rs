//! Key-binding resolution.
//!
//! Parses the free-form key strings from `TuiConfig` (e.g. `"q"`, `"space"`,
//! `"up"`, `"ctrl+x"`) into a `KeyMap` lookup table.  The rest of the TUI only
//! ever matches on `Action` values — raw key strings never leak beyond this
//! module.
//!
//! Additional bindings that are not yet user-configurable (tab switching,
//! freeze, clear stats, filter popup) are hard-coded here alongside the
//! configurable ones.  `Ctrl+c` always quits: raw mode turns off `SIGINT`, so
//! it must stay a way out whatever the config says.

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

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
    /// Scroll one screen up (`pageup`).
    PageUp,
    /// Scroll one screen down (`pagedown`).
    PageDown,
    /// Jump to the first row (`home`).
    ScrollTop,
    /// Jump to the last row (`end`).
    ScrollBottom,
    /// Toggle frozen display in the Queries and Live Feed views.
    Freeze,
    /// Open the filter popup in the Queries tab (`f`).
    Filter,
    /// Open the sort popup in the Queries tab (`s`).
    Sort,
    /// Enter domain search mode (`/`).
    Search,
    /// Cycle the bucket size in the Timelines tab (`t`).
    Zoom,
    /// Clear the active filter and return to the unfiltered view.
    ClearFilter,
    /// Reset the statistics gathered since the TUI started (`c`).
    ClearStats,
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
            "pageup" => Some(Action::PageUp),
            "pagedown" => Some(Action::PageDown),
            "home" => Some(Action::ScrollTop),
            "end" => Some(Action::ScrollBottom),
            "z" => Some(Action::Freeze),
            "c" => Some(Action::ClearStats),
            "f" => Some(Action::Filter),
            "s" => Some(Action::Sort),
            "/" => Some(Action::Search),
            "t" => Some(Action::Zoom),
            "esc" => Some(Action::ClearFilter),
            "1" => Some(Action::Tab1),
            "2" => Some(Action::Tab2),
            "3" => Some(Action::Tab3),
            "4" => Some(Action::Tab4),
            "5" => Some(Action::Tab5),
            _ => None,
        }
    }

    /// Resolve a crossterm key event to an `Action`.
    ///
    /// Key releases are ignored (terminals with the kitty keyboard protocol
    /// and Windows report them), and `Ctrl+c` quits before any lookup.
    pub fn resolve_event(&self, key: &KeyEvent) -> Option<Action> {
        if key.kind == KeyEventKind::Release {
            return None;
        }
        if is_ctrl_c(key) {
            return Some(Action::Quit);
        }
        self.resolve(&key_name(key))
    }
}

fn is_ctrl_c(key: &KeyEvent) -> bool {
    key.modifiers.contains(KeyModifiers::CONTROL)
        && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('C'))
}

/// Name a key event the way bindings are written in the config: `"q"`,
/// `"Q"`, `"space"`, `"up"`, `"f5"`, with a `"ctrl+"` and/or `"alt+"` prefix
/// when those modifiers are held (`"ctrl+alt+x"`).
///
/// Returns an empty string for keys that have no name; no binding matches it.
pub fn key_name(key: &KeyEvent) -> String {
    let base = match key.code {
        KeyCode::Char(' ') => "space".to_string(),
        KeyCode::Char(character) => {
            if key.modifiers.contains(KeyModifiers::SHIFT) {
                character.to_uppercase().to_string()
            } else {
                character.to_string()
            }
        }
        KeyCode::Up => "up".to_string(),
        KeyCode::Down => "down".to_string(),
        KeyCode::Left => "left".to_string(),
        KeyCode::Right => "right".to_string(),
        KeyCode::Tab => "tab".to_string(),
        KeyCode::BackTab => "backtab".to_string(),
        KeyCode::Esc => "esc".to_string(),
        KeyCode::Enter => "enter".to_string(),
        KeyCode::Backspace => "backspace".to_string(),
        KeyCode::Delete => "delete".to_string(),
        KeyCode::Home => "home".to_string(),
        KeyCode::End => "end".to_string(),
        KeyCode::PageUp => "pageup".to_string(),
        KeyCode::PageDown => "pagedown".to_string(),
        KeyCode::F(number) => format!("f{number}"),
        _ => return String::new(),
    };
    let mut name = String::new();
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        name.push_str("ctrl+");
    }
    if key.modifiers.contains(KeyModifiers::ALT) {
        name.push_str("alt+");
    }
    name.push_str(&base);
    name
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
    fn test_fixed_page_bindings() {
        let km = default_keymap();
        assert_eq!(km.resolve("pageup"), Some(Action::PageUp));
        assert_eq!(km.resolve("pagedown"), Some(Action::PageDown));
        assert_eq!(km.resolve("home"), Some(Action::ScrollTop));
        assert_eq!(km.resolve("end"), Some(Action::ScrollBottom));
    }

    #[test]
    fn test_fixed_zoom() {
        let km = default_keymap();
        assert_eq!(km.resolve("t"), Some(Action::Zoom));
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

    // --- key events ---

    fn press(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
        KeyEvent::new(code, modifiers)
    }

    fn release(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
        KeyEvent::new_with_kind(code, modifiers, KeyEventKind::Release)
    }

    #[test]
    fn test_fixed_clear_stats() {
        let km = default_keymap();
        assert_eq!(km.resolve("c"), Some(Action::ClearStats));
    }

    #[test]
    fn test_key_name_plain_and_named_keys() {
        let cases = [
            (KeyCode::Char('q'), "q"),
            (KeyCode::Char(' '), "space"),
            (KeyCode::Char('/'), "/"),
            (KeyCode::Up, "up"),
            (KeyCode::Down, "down"),
            (KeyCode::Left, "left"),
            (KeyCode::Right, "right"),
            (KeyCode::Tab, "tab"),
            (KeyCode::BackTab, "backtab"),
            (KeyCode::Esc, "esc"),
            (KeyCode::Enter, "enter"),
            (KeyCode::Backspace, "backspace"),
            (KeyCode::Delete, "delete"),
            (KeyCode::Home, "home"),
            (KeyCode::End, "end"),
            (KeyCode::PageUp, "pageup"),
            (KeyCode::PageDown, "pagedown"),
            (KeyCode::F(5), "f5"),
        ];
        for (code, expected) in cases {
            assert_eq!(key_name(&press(code, KeyModifiers::NONE)), expected);
        }
    }

    #[test]
    fn test_key_name_shift_uppercases_char() {
        let key = press(KeyCode::Char('q'), KeyModifiers::SHIFT);
        assert_eq!(key_name(&key), "Q");
    }

    #[test]
    fn test_key_name_modifier_prefixes() {
        let ctrl = press(KeyCode::Char('x'), KeyModifiers::CONTROL);
        let alt = press(KeyCode::Up, KeyModifiers::ALT);
        let both = press(
            KeyCode::Char('x'),
            KeyModifiers::CONTROL | KeyModifiers::ALT,
        );
        assert_eq!(key_name(&ctrl), "ctrl+x");
        assert_eq!(key_name(&alt), "alt+up");
        assert_eq!(key_name(&both), "ctrl+alt+x");
    }

    #[test]
    fn test_key_name_unnamed_key_is_empty() {
        let key = press(KeyCode::Null, KeyModifiers::CONTROL);
        assert_eq!(key_name(&key), "");
    }

    #[test]
    fn test_resolve_event_ctrl_c_quits() {
        let km = default_keymap();
        let key = press(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert_eq!(km.resolve_event(&key), Some(Action::Quit));
    }

    #[test]
    fn test_resolve_event_ctrl_c_quits_with_custom_quit_key() {
        let config = TuiConfig {
            key_quit: "x".to_string(),
            ..TuiConfig::default()
        };
        let km = KeyMap::from_config(&config);
        let key = press(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert_eq!(km.resolve_event(&key), Some(Action::Quit));
    }

    #[test]
    fn test_resolve_event_ctrl_shift_c_quits() {
        let km = default_keymap();
        let key = press(
            KeyCode::Char('C'),
            KeyModifiers::CONTROL | KeyModifiers::SHIFT,
        );
        assert_eq!(km.resolve_event(&key), Some(Action::Quit));
    }

    #[test]
    fn test_resolve_event_plain_c_clears_stats() {
        // Before modifiers were named, Ctrl+c and c were the same key.
        let km = default_keymap();
        let key = press(KeyCode::Char('c'), KeyModifiers::NONE);
        assert_eq!(km.resolve_event(&key), Some(Action::ClearStats));
    }

    #[test]
    fn test_resolve_event_q_quits() {
        let km = default_keymap();
        let key = press(KeyCode::Char('q'), KeyModifiers::NONE);
        assert_eq!(km.resolve_event(&key), Some(Action::Quit));
    }

    #[test]
    fn test_resolve_event_ctrl_does_not_match_plain_binding() {
        let km = default_keymap();
        let key = press(KeyCode::Char('q'), KeyModifiers::CONTROL);
        assert_eq!(km.resolve_event(&key), None);
    }

    #[test]
    fn test_resolve_event_custom_ctrl_binding() {
        let config = TuiConfig {
            key_quit: "ctrl+q".to_string(),
            ..TuiConfig::default()
        };
        let km = KeyMap::from_config(&config);
        let key = press(KeyCode::Char('q'), KeyModifiers::CONTROL);
        assert_eq!(km.resolve_event(&key), Some(Action::Quit));
    }

    #[test]
    fn test_resolve_event_ignores_release() {
        let km = default_keymap();
        assert_eq!(
            km.resolve_event(&release(KeyCode::Char('q'), KeyModifiers::NONE)),
            None
        );
        assert_eq!(
            km.resolve_event(&release(KeyCode::Char('c'), KeyModifiers::CONTROL)),
            None
        );
    }

    #[test]
    fn test_resolve_event_accepts_repeat() {
        let km = default_keymap();
        let key = KeyEvent::new_with_kind(KeyCode::Down, KeyModifiers::NONE, KeyEventKind::Repeat);
        assert_eq!(km.resolve_event(&key), Some(Action::ScrollDown));
    }

    #[test]
    fn test_configured_key_overrides_clear_stats() {
        let config = TuiConfig {
            key_pause: "c".to_string(),
            ..TuiConfig::default()
        };
        let km = KeyMap::from_config(&config);
        assert_eq!(km.resolve("c"), Some(Action::Pause));
    }
}
