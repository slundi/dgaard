//! About tab renderer — project metadata and key-map reference.
//!
//! Layout (top to bottom):
//!
//!   dgaard-monitor  v0.1.0
//!   https://codeberg.org/slundi/dgaard
//!   License: Apache 2.0
//!
//!   ────────────────────────────────────────
//!
//!   Key Bindings
//!   ────────────────────────────────────────
//!   Action               Key
//!   ────────────────────────────────────────
//!   Quit                 q
//!   Pause                space
//!   ...
//!
//! The key-map table is generated at render time from `TuiApp::keymap` so it
//! always reflects the active configuration without manual updates.
//!
//! The data layer (`key_bindings`, `content_lines`) is pure Rust and has no
//! ratatui dependency, making it fully unit-testable.
//!
//! TODO: replace `render()` body with ratatui `Paragraph` + `Table` widgets.

use crate::tui::keys::KeyMap;

/// Project display name.
pub const PROJECT_NAME: &str = "dgaard-monitor";

/// Crate version injected at compile time from Cargo.toml.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Canonical repository URL.
pub const REPO_URL: &str = "https://codeberg.org/slundi/dgaard";

/// SPDX license identifier shown in the About tab.
pub const LICENSE: &str = "Apache 2.0";

/// Horizontal rule used to separate sections.
pub const SEPARATOR: &str = "────────────────────────────────────────";

/// A single row in the key-map reference table.
pub struct KeyBinding {
    /// Human-readable action label (left column).
    pub action: &'static str,
    /// The key string that triggers this action (right column).
    pub key: String,
}

/// Build the ordered list of key bindings to display in the About tab.
///
/// Configurable bindings reflect the values from `keymap`; fixed bindings
/// use their literal key strings.  Order mirrors the visual groups in the
/// tab: navigation, view controls, Queries-tab actions.
pub fn key_bindings(keymap: &KeyMap) -> Vec<KeyBinding> {
    vec![
        // Navigation
        KeyBinding {
            action: "Tab Right",
            key: "tab".to_string(),
        },
        KeyBinding {
            action: "Tab Left",
            key: "backtab".to_string(),
        },
        // Configurable global controls
        KeyBinding {
            action: "Quit",
            key: keymap.quit.clone(),
        },
        KeyBinding {
            action: "Pause",
            key: keymap.pause.clone(),
        },
        KeyBinding {
            action: "Scroll Up",
            key: keymap.scroll_up.clone(),
        },
        KeyBinding {
            action: "Scroll Down",
            key: keymap.scroll_down.clone(),
        },
        // View controls (fixed)
        KeyBinding {
            action: "Freeze",
            key: "z".to_string(),
        },
        KeyBinding {
            action: "Search",
            key: "/".to_string(),
        },
        KeyBinding {
            action: "Clear Filter",
            key: "esc".to_string(),
        },
        // Queries-tab specific (fixed)
        KeyBinding {
            action: "Filter",
            key: "f".to_string(),
        },
        KeyBinding {
            action: "Sort",
            key: "s".to_string(),
        },
    ]
}

/// Build the full list of display lines for the About tab.
///
/// Returns plain strings; the ratatui renderer will style and wrap them.
/// Separating data from presentation makes the content unit-testable.
pub fn content_lines(keymap: &KeyMap) -> Vec<String> {
    let mut lines = Vec::new();

    // Metadata header
    lines.push(format!("{PROJECT_NAME}  v{VERSION}"));
    lines.push(REPO_URL.to_string());
    lines.push(format!("License: {LICENSE}"));
    lines.push(String::new());
    lines.push(SEPARATOR.to_string());
    lines.push(String::new());

    // Key bindings section
    lines.push("Key Bindings".to_string());
    lines.push(SEPARATOR.to_string());
    lines.push(format!("{:<20} {}", "Action", "Key"));
    lines.push(SEPARATOR.to_string());
    for kb in key_bindings(keymap) {
        lines.push(format!("{:<20} {}", kb.action, kb.key));
    }

    lines
}

/// Render the About tab body.
///
/// TODO: signature becomes `render(app: &TuiApp, area: Area, frame: &mut Frame)`.
/// Body will use `content_lines(&app.keymap)` as the data source.
pub fn render() {
    // TODO: implement with ratatui Paragraph + Table
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TuiConfig;

    fn default_keymap() -> KeyMap {
        KeyMap::from_config(&TuiConfig::default())
    }

    // --- constants ---

    #[test]
    fn test_project_name() {
        assert_eq!(PROJECT_NAME, "dgaard-monitor");
    }

    #[test]
    fn test_repo_url() {
        assert_eq!(REPO_URL, "https://codeberg.org/slundi/dgaard");
    }

    #[test]
    fn test_license() {
        assert_eq!(LICENSE, "Apache 2.0");
    }

    #[test]
    fn test_version_is_non_empty() {
        assert!(!VERSION.is_empty());
    }

    // --- key_bindings ---

    #[test]
    fn test_key_bindings_count() {
        // 2 nav + 4 configurable + 3 view + 2 queries = 11
        assert_eq!(key_bindings(&default_keymap()).len(), 11);
    }

    #[test]
    fn test_key_bindings_configurable_reflect_keymap() {
        let km = default_keymap();
        let bindings = key_bindings(&km);
        let quit = bindings.iter().find(|b| b.action == "Quit").unwrap();
        let pause = bindings.iter().find(|b| b.action == "Pause").unwrap();
        let up = bindings.iter().find(|b| b.action == "Scroll Up").unwrap();
        let down = bindings.iter().find(|b| b.action == "Scroll Down").unwrap();

        assert_eq!(quit.key, km.quit);
        assert_eq!(pause.key, km.pause);
        assert_eq!(up.key, km.scroll_up);
        assert_eq!(down.key, km.scroll_down);
    }

    #[test]
    fn test_key_bindings_default_configurable_values() {
        let bindings = key_bindings(&default_keymap());
        let quit = bindings.iter().find(|b| b.action == "Quit").unwrap();
        let pause = bindings.iter().find(|b| b.action == "Pause").unwrap();
        assert_eq!(quit.key, "q");
        assert_eq!(pause.key, "space");
    }

    #[test]
    fn test_key_bindings_fixed_navigation() {
        let bindings = key_bindings(&default_keymap());
        let right = bindings.iter().find(|b| b.action == "Tab Right").unwrap();
        let left = bindings.iter().find(|b| b.action == "Tab Left").unwrap();
        assert_eq!(right.key, "tab");
        assert_eq!(left.key, "backtab");
    }

    #[test]
    fn test_key_bindings_fixed_view_controls() {
        let bindings = key_bindings(&default_keymap());
        let freeze = bindings.iter().find(|b| b.action == "Freeze").unwrap();
        let search = bindings.iter().find(|b| b.action == "Search").unwrap();
        let clear = bindings
            .iter()
            .find(|b| b.action == "Clear Filter")
            .unwrap();
        assert_eq!(freeze.key, "z");
        assert_eq!(search.key, "/");
        assert_eq!(clear.key, "esc");
    }

    #[test]
    fn test_key_bindings_fixed_queries_actions() {
        let bindings = key_bindings(&default_keymap());
        let filter = bindings.iter().find(|b| b.action == "Filter").unwrap();
        let sort = bindings.iter().find(|b| b.action == "Sort").unwrap();
        assert_eq!(filter.key, "f");
        assert_eq!(sort.key, "s");
    }

    #[test]
    fn test_key_bindings_custom_quit_key() {
        let config = TuiConfig {
            key_quit: "x".to_string(),
            ..TuiConfig::default()
        };
        let km = KeyMap::from_config(&config);
        let bindings = key_bindings(&km);
        let quit = bindings.iter().find(|b| b.action == "Quit").unwrap();
        assert_eq!(quit.key, "x");
    }

    #[test]
    fn test_key_bindings_all_actions_have_non_empty_key() {
        for kb in key_bindings(&default_keymap()) {
            assert!(!kb.action.is_empty(), "action label is empty");
            assert!(!kb.key.is_empty(), "key for '{}' is empty", kb.action);
        }
    }

    // --- content_lines ---

    #[test]
    fn test_content_lines_first_line_has_name_and_version() {
        let lines = content_lines(&default_keymap());
        assert!(
            lines[0].contains(PROJECT_NAME),
            "first line missing project name: {:?}",
            lines[0]
        );
        assert!(
            lines[0].contains(VERSION),
            "first line missing version: {:?}",
            lines[0]
        );
    }

    #[test]
    fn test_content_lines_contains_repo_url() {
        let lines = content_lines(&default_keymap());
        assert!(lines.iter().any(|l| l.contains(REPO_URL)));
    }

    #[test]
    fn test_content_lines_contains_license() {
        let lines = content_lines(&default_keymap());
        assert!(lines.iter().any(|l| l.contains(LICENSE)));
    }

    #[test]
    fn test_content_lines_contains_separator() {
        let lines = content_lines(&default_keymap());
        assert!(lines.iter().any(|l| l == SEPARATOR));
    }

    #[test]
    fn test_content_lines_contains_key_bindings_header() {
        let lines = content_lines(&default_keymap());
        assert!(lines.iter().any(|l| l.contains("Key Bindings")));
    }

    #[test]
    fn test_content_lines_contains_column_headers() {
        let lines = content_lines(&default_keymap());
        assert!(
            lines
                .iter()
                .any(|l| l.contains("Action") && l.contains("Key"))
        );
    }

    #[test]
    fn test_content_lines_contains_all_binding_entries() {
        let km = default_keymap();
        let lines = content_lines(&km);
        for kb in key_bindings(&km) {
            assert!(
                lines
                    .iter()
                    .any(|l| l.contains(kb.action) && l.contains(&kb.key)),
                "missing binding entry for action '{}'",
                kb.action
            );
        }
    }

    #[test]
    fn test_content_lines_custom_keymap_reflected() {
        let config = TuiConfig {
            key_quit: "x".to_string(),
            ..TuiConfig::default()
        };
        let km = KeyMap::from_config(&config);
        let lines = content_lines(&km);
        assert!(
            lines.iter().any(|l| l.contains("Quit") && l.contains("x")),
            "custom quit key not reflected in content lines"
        );
    }

    #[test]
    fn test_content_lines_has_blank_line_after_metadata() {
        let lines = content_lines(&default_keymap());
        // line 0: name+version, 1: url, 2: license, 3: blank
        assert_eq!(lines[3], "");
    }
}
