//! Tab definitions and render dispatch.
//!
//! `Tab` is the single source of truth for which tabs exist, their display
//! order, and their labels.  The `next()` / `prev()` methods implement
//! wrap-around navigation driven by `TuiApp::apply`.  `TabStates` holds the
//! per-tab data the event stream feeds.

pub mod about;
pub mod dashboard;
pub mod queries;
pub mod talkers;
pub mod timelines;

use dgaard_monitor_core::protocol::StatEvent;

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

/// State of every tab fed by the event stream, owned by the main loop.
#[derive(Default)]
pub struct TabStates {
    pub dashboard: dashboard::DashboardState,
    pub queries: queries::QueriesState,
    pub talkers: talkers::TalkersState,
}

impl TabStates {
    /// Record one event in every tab; `domain` is `""` when unresolved.
    /// Returns `true` when the event came from a client not tracked yet.
    pub fn push_event(&mut self, event: &StatEvent, domain: &str) -> bool {
        self.dashboard.push_event(event, domain);
        self.queries.push_event(event, domain);
        self.talkers.push_event(event)
    }

    /// Forget the session: counters, feeds, the query log and the clients.
    pub fn clear(&mut self) {
        self.dashboard.clear();
        self.queries.clear();
        self.talkers.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dgaard_monitor_core::protocol::StatAction;

    fn allowed(timestamp: u64) -> StatEvent {
        StatEvent {
            timestamp,
            domain_hash: 0xbeef,
            client_ip: [0; 16],
            action: StatAction::Allowed,
        }
    }

    #[test]
    fn test_tab_states_push_feeds_every_tab() {
        let mut states = TabStates::default();
        states.push_event(&allowed(1), "example.com");
        assert_eq!(states.dashboard.global_stats().total_queries, 1);
        assert_eq!(states.queries.row_count(), 1);
        assert_eq!(states.talkers.client_count(), 1);
    }

    #[test]
    fn test_tab_states_push_reports_new_clients_only() {
        let mut states = TabStates::default();
        assert!(states.push_event(&allowed(1), "example.com"));
        assert!(!states.push_event(&allowed(2), "example.com"));
    }

    #[test]
    fn test_tab_states_clear_empties_every_tab() {
        let mut states = TabStates::default();
        states.push_event(&allowed(1), "example.com");
        states.clear();
        assert_eq!(states.dashboard.global_stats().total_queries, 0);
        assert_eq!(states.queries.row_count(), 0);
        assert_eq!(states.talkers.client_count(), 0);
    }

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
