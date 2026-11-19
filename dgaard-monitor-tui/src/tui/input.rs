//! Input handling — what a key press does to the TUI.
//!
//! `KeyMap` (in `keys`) says which `Action` a key triggers; this module
//! applies that action to the state the main loop owns and tells the loop
//! whether to keep going.  Kept out of the loop so it is testable without a
//! terminal.

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use crate::tui::app::TuiApp;
use crate::tui::keys::{Action, is_ctrl_c};
use crate::tui::scroll::Scrollable;
use crate::tui::search::SearchPrompt;
use crate::tui::tabs::queries::FilterMode;
use crate::tui::tabs::{Tab, TabStates};

/// What the main loop does after a key press.
#[derive(Debug, PartialEq, Eq)]
pub enum Flow {
    Continue,
    Quit,
}

/// Apply one key press to the TUI state.
///
/// Unbound keys and key releases are ignored.  Scrolling goes to the active
/// tab's own state when it has one (Queries, Talkers, Timelines),
/// `TuiApp::scroll` otherwise.  `s` cycles the sort order on Talkers and
/// Timelines; `t` cycles the Timelines bucket size.  While the search prompt
/// is open, keys edit it instead (`prompt_key`).
pub fn handle_key(key: &KeyEvent, app: &mut TuiApp, tabs: &mut TabStates) -> Flow {
    if app.prompt.is_some() {
        return prompt_key(key, app, tabs);
    }
    let Some(action) = app.keymap.resolve_event(key) else {
        return Flow::Continue;
    };
    match action {
        Action::Quit => return Flow::Quit,
        Action::ClearStats => tabs.clear(),
        Action::Search => {
            app.prompt = Some(SearchPrompt::open(&tabs.queries.filter));
            return Flow::Continue;
        }
        Action::ClearFilter => {
            tabs.queries.set_filter(FilterMode::None);
            return Flow::Continue;
        }
        Action::Sort if app.active_tab == Tab::Talkers => {
            tabs.talkers.sort = tabs.talkers.sort.next();
            return Flow::Continue;
        }
        Action::Sort if app.active_tab == Tab::Timelines => {
            tabs.timelines.cycle_sort();
            return Flow::Continue;
        }
        Action::Zoom if app.active_tab == Tab::Timelines => {
            tabs.timelines.cycle_zoom();
            return Flow::Continue;
        }
        _ => {}
    }
    if let Some(view) = scrollable_tab(app.active_tab, tabs)
        && apply_scroll(action, view)
    {
        return Flow::Continue;
    }
    app.apply(action);
    Flow::Continue
}

/// A key press while the search prompt is open.  Every edit re-applies the
/// filter, so the views narrow down as the user types.
///
/// `enter` keeps the filter, `esc` restores the one from before the prompt,
/// `ctrl+u` erases the line, `ctrl+c` still quits.  Other keys are ignored.
fn prompt_key(key: &KeyEvent, app: &mut TuiApp, tabs: &mut TabStates) -> Flow {
    if key.kind == KeyEventKind::Release {
        return Flow::Continue;
    }
    if is_ctrl_c(key) {
        return Flow::Quit;
    }
    let Some(prompt) = app.prompt.as_mut() else {
        return Flow::Continue;
    };
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    let edited = match key.code {
        KeyCode::Enter => {
            app.prompt = None;
            return Flow::Continue;
        }
        KeyCode::Esc => {
            let previous = std::mem::take(&mut prompt.previous);
            tabs.queries.set_filter(previous);
            app.prompt = None;
            return Flow::Continue;
        }
        KeyCode::Backspace => prompt.text.pop().is_some(),
        KeyCode::Char('u') if ctrl => {
            let had_text = !prompt.text.is_empty();
            prompt.text.clear();
            had_text
        }
        KeyCode::Char(character) if !ctrl && !key.modifiers.contains(KeyModifiers::ALT) => {
            prompt.push(character)
        }
        _ => false,
    };
    if edited {
        tabs.queries.set_filter(prompt.filter());
    }
    Flow::Continue
}

/// The state of `tab` when it scrolls on its own.
fn scrollable_tab(tab: Tab, tabs: &mut TabStates) -> Option<&mut dyn Scrollable> {
    match tab {
        Tab::Queries => Some(&mut tabs.queries),
        Tab::Talkers => Some(&mut tabs.talkers),
        Tab::Timelines => Some(&mut tabs.timelines),
        Tab::Dashboard | Tab::About => None,
    }
}

/// Apply a scroll action to `view`; `false` for any other action.
fn apply_scroll(action: Action, view: &mut dyn Scrollable) -> bool {
    let page = isize::try_from(view.page_size()).unwrap_or(isize::MAX);
    match action {
        Action::ScrollUp => view.scroll_by(-1),
        Action::ScrollDown => view.scroll_by(1),
        Action::PageUp => view.scroll_by(-page),
        Action::PageDown => view.scroll_by(page),
        Action::ScrollTop => view.scroll_to_top(),
        Action::ScrollBottom => view.scroll_to_bottom(),
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
            country: None,
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

    // --- Talkers ---

    /// Talkers tab active, `clients` distinct clients, a 10-row table.
    fn talkers_setup(clients: u8) -> (TuiApp, TabStates) {
        let mut app = TuiApp::new(&TuiConfig::default());
        app.active_tab = Tab::Talkers;
        let mut tabs = TabStates::default();
        for index in 0..clients {
            let mut event = allowed(u64::from(index));
            event.client_ip[15] = index;
            tabs.push_event(&event, "example.com");
        }
        tabs.talkers.set_viewport(10);
        (app, tabs)
    }

    #[test]
    fn test_talkers_tab_scrolls_its_own_state() {
        let (mut app, mut tabs) = talkers_setup(30);
        handle_key(&key(KeyCode::PageDown), &mut app, &mut tabs);
        assert_eq!(tabs.talkers.scroll(), 10);
        handle_key(&key(KeyCode::End), &mut app, &mut tabs);
        assert_eq!(tabs.talkers.scroll(), 20);
        assert_eq!(tabs.queries.scroll(), 0);
        assert_eq!(app.scroll, 0);
    }

    #[test]
    fn test_s_cycles_talkers_sort() {
        use crate::tui::tabs::talkers::TalkerSortBy;
        let (mut app, mut tabs) = talkers_setup(3);
        handle_key(&key(KeyCode::Char('s')), &mut app, &mut tabs);
        assert_eq!(tabs.talkers.sort, TalkerSortBy::LastSeen);
        for _ in 0..3 {
            handle_key(&key(KeyCode::Char('s')), &mut app, &mut tabs);
        }
        assert_eq!(tabs.talkers.sort, TalkerSortBy::Requests);
    }

    #[test]
    fn test_s_elsewhere_leaves_talkers_sort() {
        use crate::tui::tabs::talkers::TalkerSortBy;
        let (mut app, mut tabs) = talkers_setup(3);
        app.active_tab = Tab::Queries;
        handle_key(&key(KeyCode::Char('s')), &mut app, &mut tabs);
        assert_eq!(tabs.talkers.sort, TalkerSortBy::Requests);
    }

    #[test]
    fn test_c_clears_talkers() {
        let (mut app, mut tabs) = talkers_setup(3);
        handle_key(&key(KeyCode::Char('c')), &mut app, &mut tabs);
        assert_eq!(tabs.talkers.client_count(), 0);
    }

    // --- Timelines ---

    fn timelines_setup(hours: u64) -> (TuiApp, TabStates) {
        let mut app = TuiApp::new(&TuiConfig::default());
        app.active_tab = Tab::Timelines;
        let mut tabs = TabStates::default();
        for hour in 0..hours {
            tabs.push_event(&allowed(hour * 3600), "example.com");
        }
        tabs.timelines.set_viewport(10);
        (app, tabs)
    }

    #[test]
    fn test_t_cycles_timelines_zoom() {
        use crate::tui::tabs::timelines::TimeZoom;
        let (mut app, mut tabs) = timelines_setup(3);
        handle_key(&key(KeyCode::Char('t')), &mut app, &mut tabs);
        assert_eq!(tabs.timelines.zoom, TimeZoom::OneDay);
    }

    #[test]
    fn test_t_elsewhere_does_nothing() {
        use crate::tui::tabs::timelines::TimeZoom;
        let (mut app, mut tabs) = timelines_setup(3);
        app.active_tab = Tab::Dashboard;
        handle_key(&key(KeyCode::Char('t')), &mut app, &mut tabs);
        assert_eq!(tabs.timelines.zoom, TimeZoom::OneHour);
        assert_eq!(app.active_tab, Tab::Dashboard);
    }

    #[test]
    fn test_s_toggles_timelines_sort() {
        use crate::tui::tabs::timelines::TimelineSort;
        let (mut app, mut tabs) = timelines_setup(3);
        handle_key(&key(KeyCode::Char('s')), &mut app, &mut tabs);
        assert_eq!(tabs.timelines.sort, TimelineSort::OldestFirst);
    }

    #[test]
    fn test_timelines_tab_scrolls_its_own_state() {
        let (mut app, mut tabs) = timelines_setup(30);
        handle_key(&key(KeyCode::PageDown), &mut app, &mut tabs);
        assert_eq!(tabs.timelines.scroll(), 10);
        handle_key(&key(KeyCode::End), &mut app, &mut tabs);
        assert_eq!(tabs.timelines.scroll(), 20);
        assert_eq!(app.scroll, 0);
    }

    // --- search prompt ---

    /// Queries tab with 10.0.0.2 asking `a.com` and 10.0.0.1 `tracker.net`.
    fn search_setup() -> (TuiApp, TabStates) {
        let mut app = TuiApp::new(&TuiConfig::default());
        app.active_tab = Tab::Queries;
        let mut tabs = TabStates::default();
        for index in 1..=4u8 {
            let mut event = allowed(u64::from(index));
            event.client_ip = std::net::Ipv4Addr::new(10, 0, 0, 1 + (index + 1) % 2)
                .to_ipv6_mapped()
                .octets();
            let domain = if index % 2 == 0 {
                "a.com"
            } else {
                "tracker.net"
            };
            tabs.push_event(&event, domain);
        }
        (app, tabs)
    }

    fn type_text(text: &str, app: &mut TuiApp, tabs: &mut TabStates) {
        for character in text.chars() {
            handle_key(&key(KeyCode::Char(character)), app, tabs);
        }
    }

    #[test]
    fn test_slash_opens_the_prompt_on_any_tab() {
        for tab in Tab::ALL {
            let (mut app, mut tabs) = search_setup();
            app.active_tab = tab;
            handle_key(&key(KeyCode::Char('/')), &mut app, &mut tabs);
            assert!(app.prompt.is_some(), "{tab:?}");
        }
    }

    #[test]
    fn test_typing_filters_live() {
        let (mut app, mut tabs) = search_setup();
        handle_key(&key(KeyCode::Char('/')), &mut app, &mut tabs);
        type_text("TRACK", &mut app, &mut tabs);
        assert_eq!(tabs.queries.filtered_count(), 2);
        assert_eq!(tabs.queries.filter.search_text(), Some("TRACK"));
    }

    #[test]
    fn test_prompt_keys_do_not_trigger_bindings() {
        let (mut app, mut tabs) = search_setup();
        handle_key(&key(KeyCode::Char('/')), &mut app, &mut tabs);
        // q quits, c clears, z freezes, 3 changes tab — not while typing.
        type_text("qcz3", &mut app, &mut tabs);
        assert_eq!(app.prompt.as_ref().unwrap().text, "qcz3");
        assert_eq!(tabs.queries.row_count(), 4);
        assert!(!app.frozen);
        assert_eq!(app.active_tab, Tab::Queries);
    }

    #[test]
    fn test_shifted_characters_are_typed() {
        let (mut app, mut tabs) = search_setup();
        handle_key(&key(KeyCode::Char('/')), &mut app, &mut tabs);
        let shifted = press(KeyCode::Char('A'), KeyModifiers::SHIFT);
        handle_key(&shifted, &mut app, &mut tabs);
        assert_eq!(app.prompt.as_ref().unwrap().text, "A");
    }

    #[test]
    fn test_enter_keeps_the_filter() {
        let (mut app, mut tabs) = search_setup();
        handle_key(&key(KeyCode::Char('/')), &mut app, &mut tabs);
        type_text("10.0.0.2", &mut app, &mut tabs);
        handle_key(&key(KeyCode::Enter), &mut app, &mut tabs);
        assert!(app.prompt.is_none());
        assert_eq!(tabs.queries.filtered_count(), 2);
        // Keys are bindings again.
        handle_key(&key(KeyCode::Char('z')), &mut app, &mut tabs);
        assert!(app.frozen);
    }

    #[test]
    fn test_esc_in_prompt_restores_the_previous_filter() {
        let (mut app, mut tabs) = search_setup();
        tabs.queries.set_filter(FilterMode::search("a.com"));
        handle_key(&key(KeyCode::Char('/')), &mut app, &mut tabs);
        let text = &app.prompt.as_ref().unwrap().text;
        assert_eq!(text, "a.com", "edits the current search");
        type_text("x", &mut app, &mut tabs);
        assert_eq!(tabs.queries.filtered_count(), 0);
        handle_key(&key(KeyCode::Esc), &mut app, &mut tabs);
        assert!(app.prompt.is_none());
        assert_eq!(tabs.queries.filter, FilterMode::search("a.com"));
    }

    #[test]
    fn test_esc_outside_prompt_clears_the_filter() {
        let (mut app, mut tabs) = search_setup();
        tabs.queries.set_filter(FilterMode::search("a.com"));
        handle_key(&key(KeyCode::Esc), &mut app, &mut tabs);
        assert_eq!(tabs.queries.filter, FilterMode::None);
        assert_eq!(tabs.queries.filtered_count(), 4);
    }

    #[test]
    fn test_backspace_and_ctrl_u_edit_the_text() {
        let (mut app, mut tabs) = search_setup();
        handle_key(&key(KeyCode::Char('/')), &mut app, &mut tabs);
        type_text("a.comx", &mut app, &mut tabs);
        assert_eq!(tabs.queries.filtered_count(), 0);
        handle_key(&key(KeyCode::Backspace), &mut app, &mut tabs);
        assert_eq!(tabs.queries.filtered_count(), 2);
        let ctrl_u = press(KeyCode::Char('u'), KeyModifiers::CONTROL);
        handle_key(&ctrl_u, &mut app, &mut tabs);
        assert_eq!(app.prompt.as_ref().unwrap().text, "");
        assert_eq!(tabs.queries.filter, FilterMode::None);
        // Nothing left to erase: harmless.
        handle_key(&key(KeyCode::Backspace), &mut app, &mut tabs);
        handle_key(&ctrl_u, &mut app, &mut tabs);
        assert!(app.prompt.is_some());
    }

    #[test]
    fn test_prompt_ignores_other_keys_and_releases() {
        let (mut app, mut tabs) = search_setup();
        handle_key(&key(KeyCode::Char('/')), &mut app, &mut tabs);
        handle_key(&key(KeyCode::Down), &mut app, &mut tabs);
        let alt_x = press(KeyCode::Char('x'), KeyModifiers::ALT);
        handle_key(&alt_x, &mut app, &mut tabs);
        let release = KeyEvent::new_with_kind(
            KeyCode::Char('y'),
            KeyModifiers::NONE,
            KeyEventKind::Release,
        );
        handle_key(&release, &mut app, &mut tabs);
        assert_eq!(app.prompt.as_ref().unwrap().text, "");
        assert_eq!(tabs.queries.scroll(), 0);
    }

    #[test]
    fn test_ctrl_c_quits_from_the_prompt() {
        let (mut app, mut tabs) = search_setup();
        handle_key(&key(KeyCode::Char('/')), &mut app, &mut tabs);
        let ctrl_c = press(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert_eq!(handle_key(&ctrl_c, &mut app, &mut tabs), Flow::Quit);
    }

    #[test]
    fn test_search_survives_clear_stats() {
        let (mut app, mut tabs) = search_setup();
        tabs.queries.set_filter(FilterMode::search("a.com"));
        handle_key(&key(KeyCode::Char('c')), &mut app, &mut tabs);
        assert_eq!(tabs.queries.filter, FilterMode::search("a.com"));
    }

    // --- country display ---

    #[test]
    fn test_e_toggles_country_display_on_any_tab() {
        use crate::config::CountryDisplay;
        let (mut app, mut tabs) = setup();
        for tab in [Tab::Dashboard, Tab::Queries, Tab::About] {
            app.active_tab = tab;
            let before = app.country_display;
            handle_key(&key(KeyCode::Char('e')), &mut app, &mut tabs);
            assert_ne!(app.country_display, before, "{tab:?}");
        }
        assert_eq!(app.country_display, CountryDisplay::Emoji);
    }
}
