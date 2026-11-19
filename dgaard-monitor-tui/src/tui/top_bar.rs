//! Top bar — the three rows shown above every tab.
//!
//!   Dashboard  Queries  Talkers  Timelines  About                  row 1: tabs
//!   Clients: 12   Queries: 4521   Blocked: 234 (5.2 %)   avg. QPS: 1.2   row 2: metrics
//!   ┌ Live Feed ─────────────────────────┐┌ Flag Distribution ───┐ row 3
//!   │ 14:23:01  192.168.1.5  example.com ││ AbpRule   █████ 48   │
//!   │ ...                                ││ NRD       ██ 17      │
//!   └────────────────────────────────────┘└──────────────────────┘
//!   (active tab content)
//!
//! Row 3 is split 60 / 40 between the live feed (newest first) and a bar
//! chart of the blocking flags that fired most.  It shrinks on short
//! terminals so the tab content keeps `BODY_MIN_HEIGHT` rows, and disappears
//! when it would be too short to show anything.

use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Bar, BarChart, Block, Paragraph, Row, Table, Tabs},
};

use crate::tui::app::TuiApp;
use crate::tui::tabs::Tab;
use crate::tui::tabs::dashboard::{DashboardState, to_ratatui_color};

/// Tallest row 3 gets, borders included.
pub const ROW3_MAX_HEIGHT: u16 = 12;

/// Shortest useful row 3: borders, the table header and two entries.
pub const ROW3_MIN_HEIGHT: u16 = 5;

/// Rows the tab content keeps before row 3 starts shrinking.
pub const BODY_MIN_HEIGHT: u16 = 10;

/// Rows 1 and 2 are one line each.
const FIXED_ROWS: u16 = 2;

/// Where each part of the screen goes.
#[derive(Debug, PartialEq, Eq)]
pub struct ScreenAreas {
    pub tabs: Rect,
    pub metrics: Rect,
    pub live_feed: Rect,
    pub flags: Rect,
    /// What is left for the active tab.
    pub body: Rect,
}

/// Height of row 3 on a terminal `total` rows tall; 0 hides it.
pub fn row3_height(total: u16) -> u16 {
    let height = total
        .saturating_sub(FIXED_ROWS + BODY_MIN_HEIGHT)
        .min(ROW3_MAX_HEIGHT);
    if height < ROW3_MIN_HEIGHT { 0 } else { height }
}

/// Split the whole terminal into the top bar rows and the tab body.
pub fn layout(area: Rect) -> ScreenAreas {
    let [tabs, metrics, row3, body] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(row3_height(area.height)),
        Constraint::Min(0),
    ])
    .areas(area);
    let [live_feed, flags] =
        Layout::horizontal([Constraint::Percentage(60), Constraint::Percentage(40)]).areas(row3);
    ScreenAreas {
        tabs,
        metrics,
        live_feed,
        flags,
        body,
    }
}

/// Draw the three top rows into the areas computed by `layout`.
pub fn render(frame: &mut Frame, areas: &ScreenAreas, app: &TuiApp, dashboard: &DashboardState) {
    render_tabs(frame, areas.tabs, app.active_tab);
    render_metrics(frame, areas.metrics, dashboard);
    if areas.live_feed.height > 0 {
        render_live_feed(frame, areas.live_feed, dashboard);
        render_flags(frame, areas.flags, dashboard);
    }
}

fn render_tabs(frame: &mut Frame, area: Rect, active: Tab) {
    let titles: Vec<Line> = Tab::ALL.iter().map(|t| Line::from(t.label())).collect();
    let active_idx = Tab::ALL.iter().position(|t| *t == active).unwrap_or(0);
    frame.render_widget(
        Tabs::new(titles).select(active_idx).highlight_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        area,
    );
}

fn render_metrics(frame: &mut Frame, area: Rect, dashboard: &DashboardState) {
    let stats = dashboard.global_stats();
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::raw(format!(
                "Clients: {}   Queries: {}   ",
                stats.active_clients, stats.total_queries
            )),
            Span::styled(
                format!("Blocked: {} ({:.1} %)", stats.blocked, stats.blocked_pct),
                Style::new().fg(Color::Red),
            ),
            Span::raw(format!("   avg. QPS: {:.1}", stats.avg_qps)),
        ])),
        area,
    );
}

fn render_live_feed(frame: &mut Frame, area: Rect, dashboard: &DashboardState) {
    let rows: Vec<Row> = dashboard
        .live_feed()
        .iter()
        .rev()
        .map(|e| {
            Row::new([
                e.timestamp.clone(),
                e.client.clone(),
                e.domain.clone(),
                e.action.clone(),
            ])
            .style(Style::new().fg(to_ratatui_color(e.color)))
        })
        .collect();

    frame.render_widget(
        Table::new(
            rows,
            [
                Constraint::Length(8),
                Constraint::Length(17),
                Constraint::Min(20),
                Constraint::Min(12),
            ],
        )
        .block(Block::bordered().title("Live Feed"))
        .header(
            Row::new(["Time", "Client", "Domain", "Action"])
                .style(Style::new().add_modifier(Modifier::BOLD)),
        ),
        area,
    );
}

fn render_flags(frame: &mut Frame, area: Rect, dashboard: &DashboardState) {
    let block = Block::bordered().title("Flag Distribution");
    let distribution = dashboard.flag_distribution();
    if distribution.is_empty() {
        frame.render_widget(Paragraph::new("No blocked queries yet").block(block), area);
        return;
    }

    // One bar per row, as many flags as the box can hold.
    let visible = usize::from(area.height.saturating_sub(2));
    let bars: Vec<Bar> = distribution
        .into_iter()
        .take(visible)
        .map(|flag| {
            Bar::with_label(flag.name, flag.count)
                .text_value(flag.count.to_string())
                .style(Style::new().fg(Color::Red))
        })
        .collect();
    frame.render_widget(
        BarChart::horizontal(bars)
            .block(block)
            .bar_width(1)
            .bar_gap(0),
        area,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TuiConfig;
    use dgaard_monitor_core::protocol::{StatAction, StatBlockReason, StatEvent};
    use ratatui::{Terminal, backend::TestBackend};

    fn event(timestamp: u64, action: StatAction) -> StatEvent {
        StatEvent {
            timestamp,
            domain_hash: 0xbeef,
            client_ip: std::net::Ipv4Addr::new(10, 0, 0, 5)
                .to_ipv6_mapped()
                .octets(),
            action,
        }
    }

    fn blocked(bits: u32) -> StatAction {
        StatAction::Blocked(StatBlockReason::from_bits_retain(bits))
    }

    /// Draw the top bar on a `width` × `height` terminal and return its rows.
    fn draw(width: u16, height: u16, dashboard: &DashboardState) -> Vec<String> {
        let app = TuiApp::new(&TuiConfig::default());
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| {
                let areas = layout(frame.area());
                render(frame, &areas, &app, dashboard);
            })
            .unwrap();
        let buffer = terminal.backend().buffer();
        (0..height)
            .map(|row| {
                (0..width)
                    .map(|column| buffer[(column, row)].symbol())
                    .collect()
            })
            .collect()
    }

    fn screen_contains(lines: &[String], needle: &str) -> bool {
        lines.iter().any(|line| line.contains(needle))
    }

    // --- row3_height / layout ---

    #[test]
    fn test_row3_height_capped_on_tall_terminal() {
        assert_eq!(row3_height(60), ROW3_MAX_HEIGHT);
    }

    #[test]
    fn test_row3_height_shrinks_to_keep_body_rows() {
        // 2 fixed rows + 8 for row 3 + 10 for the body
        assert_eq!(row3_height(20), 8);
    }

    #[test]
    fn test_row3_hidden_when_too_short() {
        let threshold = FIXED_ROWS + BODY_MIN_HEIGHT + ROW3_MIN_HEIGHT;
        assert_eq!(row3_height(threshold), ROW3_MIN_HEIGHT);
        assert_eq!(row3_height(threshold - 1), 0);
        assert_eq!(row3_height(0), 0);
    }

    #[test]
    fn test_layout_stacks_rows_and_splits_row3() {
        let areas = layout(Rect::new(0, 0, 100, 40));
        assert_eq!(areas.tabs, Rect::new(0, 0, 100, 1));
        assert_eq!(areas.metrics, Rect::new(0, 1, 100, 1));
        assert_eq!(areas.live_feed, Rect::new(0, 2, 60, ROW3_MAX_HEIGHT));
        assert_eq!(areas.flags, Rect::new(60, 2, 40, ROW3_MAX_HEIGHT));
        let body_top = 2 + ROW3_MAX_HEIGHT;
        assert_eq!(areas.body, Rect::new(0, body_top, 100, 40 - body_top));
    }

    #[test]
    fn test_layout_small_terminal_gives_row3_space_to_body() {
        let areas = layout(Rect::new(0, 0, 80, 12));
        assert_eq!(areas.live_feed.height, 0);
        assert_eq!(areas.flags.height, 0);
        assert_eq!(areas.body, Rect::new(0, 2, 80, 10));
    }

    // --- render ---

    #[test]
    fn test_render_shows_tabs_metrics_and_row3_titles() {
        let lines = draw(100, 30, &DashboardState::new());
        assert!(lines[0].contains("Dashboard") && lines[0].contains("About"));
        assert!(lines[1].contains("Clients: 0") && lines[1].contains("Blocked: 0"));
        assert!(screen_contains(&lines, "Live Feed"));
        assert!(screen_contains(&lines, "Flag Distribution"));
        assert!(screen_contains(&lines, "No blocked queries yet"));
    }

    #[test]
    fn test_render_live_feed_newest_first() {
        let mut dashboard = DashboardState::new();
        dashboard.push_event(&event(1, StatAction::Allowed), "old.example");
        dashboard.push_event(&event(2, StatAction::Allowed), "new.example");
        let lines = draw(100, 30, &dashboard);
        let row_of = |needle: &str| lines.iter().position(|l| l.contains(needle)).unwrap();
        assert!(row_of("new.example") < row_of("old.example"));
        assert!(screen_contains(&lines, "10.0.0.5"));
    }

    #[test]
    fn test_render_flag_distribution_lists_fired_flags() {
        let mut dashboard = DashboardState::new();
        // ABP_RULE twice, NRD_LIST once
        dashboard.push_event(&event(1, blocked(1 << 1)), "ads.example");
        dashboard.push_event(&event(2, blocked((1 << 1) | (1 << 7))), "nrd.example");
        let lines = draw(100, 30, &dashboard);
        assert!(!screen_contains(&lines, "No blocked queries yet"));
        let row_of = |needle: &str| lines.iter().position(|l| l.contains(needle)).unwrap();
        assert!(row_of("AbpRule") < row_of("NRD"), "most hits on top");
        assert!(lines[1].contains("Blocked: 2"));
    }

    #[test]
    fn test_render_flag_distribution_keeps_what_fits() {
        let mut dashboard = DashboardState::new();
        // 15 different flags, each firing once; row 3 has 8 rows → 6 bars.
        dashboard.push_event(&event(1, blocked(0x7fff)), "all.example");
        let lines = draw(100, 20, &dashboard);
        assert!(screen_contains(&lines, "Blacklist"), "bit 0 first on ties");
        assert!(!screen_contains(&lines, "AsnBlocked"), "bit 14 cut off");
    }

    #[test]
    fn test_render_small_terminal_hides_row3() {
        let lines = draw(80, 12, &DashboardState::new());
        assert!(lines[0].contains("Dashboard"));
        assert!(lines[1].contains("Clients"));
        assert!(!screen_contains(&lines, "Live Feed"));
        assert!(!screen_contains(&lines, "Flag Distribution"));
    }
}
