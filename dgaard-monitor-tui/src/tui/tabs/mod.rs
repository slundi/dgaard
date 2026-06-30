//! Tab definitions and render dispatch.
//!
//! `Tab` is the single source of truth for which tabs exist, their display
//! order, and their labels.  The `next()` / `prev()` methods implement
//! wrap-around navigation driven by `TuiApp::apply`.
//!
//! TODO: add a `render()` dispatcher that calls the correct submodule once
//! ratatui `Frame` is available.

#![allow(dead_code)]

pub mod about;
pub mod dashboard;
pub mod queries;
pub mod talkers;
pub mod timelines;

/// The five tabs of the TUI, in left-to-right display order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Tab {
    #[default]
    Dashboard,
    Queries,
    Talkers,
    Timelines,
    About,
}

impl Tab {
    /// All tabs in display order; used to render the tab bar.
    pub const ALL: [Tab; 5] = [
        Tab::Dashboard,
        Tab::Queries,
        Tab::Talkers,
        Tab::Timelines,
        Tab::About,
    ];

    /// Human-readable label shown in the tab bar header.
    pub fn label(self) -> &'static str {
        match self {
            Tab::Dashboard => "Dashboard",
            Tab::Queries => "Queries",
            Tab::Talkers => "Talkers",
            Tab::Timelines => "Timelines",
            Tab::About => "About",
        }
    }

    /// Advance to the next tab, wrapping from About back to Dashboard.
    pub fn next(self) -> Self {
        match self {
            Tab::Dashboard => Tab::Queries,
            Tab::Queries => Tab::Talkers,
            Tab::Talkers => Tab::Timelines,
            Tab::Timelines => Tab::About,
            Tab::About => Tab::Dashboard,
        }
    }

    /// Go back to the previous tab, wrapping from Dashboard to About.
    pub fn prev(self) -> Self {
        match self {
            Tab::Dashboard => Tab::About,
            Tab::Queries => Tab::Dashboard,
            Tab::Talkers => Tab::Queries,
            Tab::Timelines => Tab::Talkers,
            Tab::About => Tab::Timelines,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_tab_is_dashboard() {
        assert_eq!(Tab::default(), Tab::Dashboard);
    }

    #[test]
    fn test_next_wraps_about_to_dashboard() {
        assert_eq!(Tab::About.next(), Tab::Dashboard);
    }

    #[test]
    fn test_prev_wraps_dashboard_to_about() {
        assert_eq!(Tab::Dashboard.prev(), Tab::About);
    }

    #[test]
    fn test_full_forward_cycle_returns_to_start() {
        let mut tab = Tab::Dashboard;
        for _ in 0..Tab::ALL.len() {
            tab = tab.next();
        }
        assert_eq!(tab, Tab::Dashboard);
    }

    #[test]
    fn test_full_backward_cycle_returns_to_start() {
        let mut tab = Tab::Dashboard;
        for _ in 0..Tab::ALL.len() {
            tab = tab.prev();
        }
        assert_eq!(tab, Tab::Dashboard);
    }

    #[test]
    fn test_all_labels_are_non_empty() {
        for tab in Tab::ALL {
            assert!(!tab.label().is_empty(), "{tab:?} has empty label");
        }
    }
}
