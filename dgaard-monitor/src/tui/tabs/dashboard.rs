//! Dashboard tab — at-a-glance DNS activity summary.
//!
//! Layout (top → bottom):
//!   ┌──────────────────────────────────────────────────────────────────────┐
//!   │  Clients: 12   Queries: 4 521   Blocked: 234 (5.17 %)   avg. QPS: 1.2  │
//!   ├─────────────────────────────┬────────────────────────────────────────┤
//!   │  Last 50 Domains (scroll)   │  Live Feed                             │
//!   │  ✔ example.com              │  14:23:01  192.168.1.5  example.com ... │
//!   │  ✘ ads.tracker.net          │  ...                                   │
//!   │  ...                        │                                        │
//!   ├─────────────────────────────┴────────────────────────────────────────┤
//!   │  StaticBlacklist                                                     │
//!   │  234                                                                 │
//!   │  87.3 %                                                              │
//!   └──────────────────────────────────────────────────────────────────────┘
//!
//! Panels:
//!   - Header (1–2 lines): `GlobalStats` — active clients, total queries,
//!     blocked count + percentage (in red), average QPS.
//!   - Left (scrollable): last `MAX_RECENT_DOMAINS` domains, colour-coded via
//!     `DomainColor`.
//!   - Center: live feed, newest first — columns: timestamp, client, domain,
//!     action.  Colour-coded via `DomainColor`.
//!   - Footer (3 lines): most-active blocking filter name, hit count,
//!     percentage of all blocked events.
//!
//! The render function uses ratatui `Table`, `List`, `Block`, and `Paragraph`.

#![allow(dead_code)]

use std::collections::{HashSet, VecDeque};
use std::time::Instant;

use crate::protocol::{StatAction, StatBlockReason, StatEvent};
use crate::tui::tabs::queries::{flags_label, format_ip, format_timestamp};
use crate::tui::tabs::talkers::flag_name;
use crate::tui::util::DomainColor;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum entries kept in the left-panel recent-domains list.
pub const MAX_RECENT_DOMAINS: usize = 50;

/// Maximum entries kept in the center live-feed panel.
pub const MAX_LIVE_FEED: usize = 50;

// ── GlobalStats ───────────────────────────────────────────────────────────────

/// Snapshot of global DNS activity metrics shown in the header bar.
pub struct GlobalStats {
    /// Number of distinct client IPs seen since startup.
    pub active_clients: usize,
    /// Total queries seen since startup.
    pub total_queries: u64,
    /// Total blocked queries (Blocked + Suspicious + HighlySuspicious).
    pub blocked: u64,
    /// Percentage of queries that were blocked (0.0 – 100.0).
    /// Rendered in red by the widget.
    pub blocked_pct: f32,
    /// Average queries per second since the first event was recorded.
    pub avg_qps: f32,
}

// ── RecentDomainEntry ─────────────────────────────────────────────────────────

/// One entry in the left-panel scrollable domain list.
pub struct RecentDomainEntry {
    /// Resolved domain name, or `"#<hex>"` when the hash is unknown.
    pub domain: String,
    /// Colour hint for the renderer (`DomainColor`).
    pub color: DomainColor,
}

// ── LiveFeedEntry ─────────────────────────────────────────────────────────────

/// One row in the center live-feed panel.
pub struct LiveFeedEntry {
    /// Formatted timestamp (`HH:MM:SS`).
    pub timestamp: String,
    /// Formatted client IP address.
    pub client: String,
    /// Resolved domain name, or `"#<hex>"` when the hash is unknown.
    pub domain: String,
    /// Short action label (`"Allowed"`, `"Blocked:Blacklist+AbpRule"`, …).
    pub action: String,
    /// Colour hint for the indicator and domain text.
    pub color: DomainColor,
}

// ── TopFilter ─────────────────────────────────────────────────────────────────

/// The most-active blocking filter displayed in the three-line footer.
pub struct TopFilter {
    /// Short display name of the leading `StatBlockReason` flag.
    pub name: String,
    /// Raw hit count for this flag across all blocking events.
    pub count: u64,
    /// Percentage of all blocked events that triggered this flag (0.0 – 100.0).
    pub pct: f32,
}

// ── DashboardState ────────────────────────────────────────────────────────────

/// All mutable state owned by the Dashboard tab.
pub struct DashboardState {
    /// Distinct client IPs seen since startup.
    client_ips: HashSet<[u8; 16]>,
    /// Total queries recorded.
    total_queries: u64,
    /// Total blocking events (Blocked + Suspicious + HighlySuspicious).
    total_blocked: u64,
    /// Monotonic timestamp of the first recorded event; used for avg-QPS.
    first_event: Option<Instant>,
    /// Hit count per `StatBlockReason` flag bit (index 0..=14).
    flag_hits: [u64; 15],
    /// Circular buffer of the most-recent domain entries, oldest at front.
    recent_domains: VecDeque<RecentDomainEntry>,
    /// Circular buffer of the most-recent live-feed rows, oldest at front.
    live_feed: VecDeque<LiveFeedEntry>,
}

impl DashboardState {
    pub fn new() -> Self {
        Self {
            client_ips: HashSet::new(),
            total_queries: 0,
            total_blocked: 0,
            first_event: None,
            flag_hits: [0; 15],
            recent_domains: VecDeque::new(),
            live_feed: VecDeque::new(),
        }
    }

    /// Ingest one `StatEvent` into the dashboard state.
    ///
    /// `domain` is the resolved name for `event.domain_hash`; pass `""` when
    /// the hash is not yet in the domain map — a hex fallback is used.
    pub fn push_event(&mut self, event: &StatEvent, domain: &str) {
        if self.first_event.is_none() {
            self.first_event = Some(Instant::now());
        }

        self.total_queries += 1;
        self.client_ips.insert(event.client_ip);

        let color = DomainColor::from_action(&event.action);

        let is_blocking = matches!(
            event.action,
            StatAction::Blocked(_) | StatAction::Suspicious(_) | StatAction::HighlySuspicious(_)
        );
        if is_blocking {
            self.total_blocked += 1;
            let reasons = match &event.action {
                StatAction::Blocked(r)
                | StatAction::Suspicious(r)
                | StatAction::HighlySuspicious(r) => *r,
                _ => StatBlockReason::empty(),
            };
            self.record_flags(reasons);
        }

        let display_domain = if domain.is_empty() {
            format!("#{:016x}", event.domain_hash)
        } else {
            domain.to_string()
        };

        // Recent domains — cap at MAX_RECENT_DOMAINS
        if self.recent_domains.len() >= MAX_RECENT_DOMAINS {
            self.recent_domains.pop_front();
        }
        self.recent_domains.push_back(RecentDomainEntry {
            domain: display_domain.clone(),
            color,
        });

        // Live feed — cap at MAX_LIVE_FEED
        if self.live_feed.len() >= MAX_LIVE_FEED {
            self.live_feed.pop_front();
        }
        self.live_feed.push_back(LiveFeedEntry {
            timestamp: format_timestamp(event.timestamp),
            client: format_ip(event.client_ip),
            domain: display_domain,
            action: flags_label(&event.action),
            color,
        });
    }

    fn record_flags(&mut self, r: StatBlockReason) {
        for bit in 0..15u32 {
            if r.bits() & (1 << bit) != 0 {
                self.flag_hits[bit as usize] += 1;
            }
        }
    }

    /// Compute a fresh `GlobalStats` snapshot from the current state.
    pub fn global_stats(&self) -> GlobalStats {
        let blocked_pct = if self.total_queries == 0 {
            0.0
        } else {
            self.total_blocked as f32 / self.total_queries as f32 * 100.0
        };

        let avg_qps = match self.first_event {
            None => 0.0,
            Some(start) => {
                let elapsed = start.elapsed().as_secs_f32();
                if elapsed < 0.001 {
                    0.0
                } else {
                    self.total_queries as f32 / elapsed
                }
            }
        };

        GlobalStats {
            active_clients: self.client_ips.len(),
            total_queries: self.total_queries,
            blocked: self.total_blocked,
            blocked_pct,
            avg_qps,
        }
    }

    /// The recent-domains list, oldest entry at index 0, newest at the back.
    ///
    /// The renderer reverses this for a newest-on-top display.
    pub fn recent_domains(&self) -> &VecDeque<RecentDomainEntry> {
        &self.recent_domains
    }

    /// The live-feed entries, oldest at index 0, newest at the back.
    ///
    /// The renderer reverses this for a newest-on-top display.
    pub fn live_feed(&self) -> &VecDeque<LiveFeedEntry> {
        &self.live_feed
    }

    /// The most-active blocking filter, or `None` when no blocking events have
    /// been recorded yet.
    ///
    /// `TopFilter::pct` is the share of all blocked events that triggered this
    /// flag (`flag_count / total_blocked * 100`).
    pub fn top_filter(&self) -> Option<TopFilter> {
        let (bit, &count) = self.flag_hits.iter().enumerate().max_by_key(|(_, c)| **c)?;

        if count == 0 {
            return None;
        }

        let pct = if self.total_blocked == 0 {
            0.0
        } else {
            count as f32 / self.total_blocked as f32 * 100.0
        };

        Some(TopFilter {
            name: flag_name(bit).to_string(),
            count,
            pct,
        })
    }
}

impl Default for DashboardState {
    fn default() -> Self {
        Self::new()
    }
}

// ── Render ────────────────────────────────────────────────────────────────────

/// Map a `DomainColor` to its ratatui terminal colour.
fn to_ratatui_color(color: DomainColor) -> ratatui::style::Color {
    use ratatui::style::Color;
    match color {
        DomainColor::Green => Color::Green,
        DomainColor::Red => Color::Red,
        DomainColor::Yellow => Color::Yellow,
        DomainColor::Dim => Color::DarkGray,
    }
}

/// Render the Dashboard tab body into `area`.
///
/// `scroll` is the vertical scroll offset for the left Recent-Domains panel.
pub fn render(state: &DashboardState, scroll: usize, area: ratatui::layout::Rect, frame: &mut ratatui::Frame) {
    use ratatui::{
        layout::{Constraint, Layout},
        style::{Modifier, Style},
        text::{Line, Span},
        widgets::{Block, List, ListItem, ListState, Paragraph, Row, Table},
    };

    // ── Outer layout: header (2 lines) / body / footer (5 lines) ─────────
    let [header_area, body_area, footer_area] = Layout::vertical([
        Constraint::Length(2),
        Constraint::Min(0),
        Constraint::Length(5),
    ])
    .areas(area);

    // ── Body: recent domains left (30 %) + live feed right (70 %) ─────────
    let [domains_area, feed_area] =
        Layout::horizontal([Constraint::Percentage(30), Constraint::Percentage(70)])
            .areas(body_area);

    // ── Header ────────────────────────────────────────────────────────────
    let stats = state.global_stats();
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(format!(
                "Clients: {}   Queries: {}",
                stats.active_clients, stats.total_queries
            )),
            Line::from(vec![
                Span::styled(
                    format!("Blocked: {} ({:.1} %)", stats.blocked, stats.blocked_pct),
                    Style::new().fg(ratatui::style::Color::Red),
                ),
                Span::raw(format!("   avg. QPS: {:.1}", stats.avg_qps)),
            ]),
        ]),
        header_area,
    );

    // ── Recent domains ─────────────────────────────────────────────────────
    let domain_items: Vec<ListItem> = state
        .recent_domains()
        .iter()
        .rev()
        .map(|e| {
            ListItem::new(Line::styled(
                format!("{} {}", e.color.indicator(), e.domain),
                Style::new().fg(to_ratatui_color(e.color)),
            ))
        })
        .collect();

    let mut list_state = ListState::default().with_offset(scroll);
    frame.render_stateful_widget(
        List::new(domain_items).block(Block::bordered().title("Recent Domains")),
        domains_area,
        &mut list_state,
    );

    // ── Live feed ──────────────────────────────────────────────────────────
    let feed_rows: Vec<Row> = state
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
            feed_rows,
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
        feed_area,
    );

    // ── Footer: top filter ─────────────────────────────────────────────────
    let footer_lines = match state.top_filter() {
        Some(tf) => vec![
            Line::from(tf.name),
            Line::from(tf.count.to_string()),
            Line::from(format!("{:.1} %", tf.pct)),
        ],
        None => vec![
            Line::from("—"),
            Line::from("0"),
            Line::from("0.0 %"),
        ],
    };

    frame.render_widget(
        Paragraph::new(footer_lines).block(Block::bordered().title("Top Filter")),
        footer_area,
    );
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{StatAction, StatBlockReason, StatEvent};

    // ── helpers ───────────────────────────────────────────────────────────────

    fn ev(ts: u64, ip: [u8; 16], action: StatAction) -> StatEvent {
        StatEvent {
            timestamp: ts,
            domain_hash: 0xdead,
            client_ip: ip,
            action,
        }
    }

    fn ev_hash(ts: u64, ip: [u8; 16], hash: u64, action: StatAction) -> StatEvent {
        StatEvent {
            timestamp: ts,
            domain_hash: hash,
            client_ip: ip,
            action,
        }
    }

    fn ipv4(a: u8, b: u8, c: u8, d: u8) -> [u8; 16] {
        [a, b, c, d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    }

    fn blocked(bits: u16) -> StatAction {
        StatAction::Blocked(StatBlockReason::from_bits_truncate(bits))
    }

    fn suspicious(bits: u16) -> StatAction {
        StatAction::Suspicious(StatBlockReason::from_bits_truncate(bits))
    }

    fn highly_suspicious(bits: u16) -> StatAction {
        StatAction::HighlySuspicious(StatBlockReason::from_bits_truncate(bits))
    }

    // ── DashboardState::new ───────────────────────────────────────────────────

    #[test]
    fn test_new_is_empty() {
        let state = DashboardState::new();
        let stats = state.global_stats();
        assert_eq!(stats.active_clients, 0);
        assert_eq!(stats.total_queries, 0);
        assert_eq!(stats.blocked, 0);
        assert_eq!(stats.blocked_pct, 0.0);
        assert_eq!(stats.avg_qps, 0.0);
        assert!(state.recent_domains().is_empty());
        assert!(state.live_feed().is_empty());
        assert!(state.top_filter().is_none());
    }

    // ── push_event — counters ─────────────────────────────────────────────────

    #[test]
    fn test_push_event_increments_total_queries() {
        let mut state = DashboardState::new();
        let ip = ipv4(10, 0, 0, 1);
        state.push_event(&ev(100, ip, StatAction::Allowed), "example.com");
        state.push_event(&ev(101, ip, StatAction::Allowed), "example.com");
        assert_eq!(state.global_stats().total_queries, 2);
    }

    #[test]
    fn test_push_event_tracks_unique_clients() {
        let mut state = DashboardState::new();
        let ip1 = ipv4(10, 0, 0, 1);
        let ip2 = ipv4(10, 0, 0, 2);
        state.push_event(&ev(100, ip1, StatAction::Allowed), "a.com");
        state.push_event(&ev(101, ip1, StatAction::Allowed), "a.com");
        state.push_event(&ev(102, ip2, StatAction::Allowed), "b.com");
        assert_eq!(state.global_stats().active_clients, 2);
    }

    #[test]
    fn test_push_event_counts_blocked() {
        let mut state = DashboardState::new();
        let ip = ipv4(10, 0, 0, 1);
        state.push_event(&ev(100, ip, StatAction::Allowed), "a.com");
        state.push_event(&ev(101, ip, blocked(0)), "b.com");
        state.push_event(&ev(102, ip, suspicious(0)), "c.com");
        state.push_event(&ev(103, ip, highly_suspicious(0)), "d.com");
        let stats = state.global_stats();
        assert_eq!(stats.blocked, 3);
        assert_eq!(stats.total_queries, 4);
    }

    #[test]
    fn test_push_event_proxied_not_counted_as_blocked() {
        let mut state = DashboardState::new();
        let ip = ipv4(10, 0, 0, 1);
        state.push_event(&ev(100, ip, StatAction::Proxied), "a.com");
        let stats = state.global_stats();
        assert_eq!(stats.blocked, 0);
        assert_eq!(stats.total_queries, 1);
    }

    // ── global_stats — blocked_pct ────────────────────────────────────────────

    #[test]
    fn test_blocked_pct_zero_when_no_events() {
        let state = DashboardState::new();
        assert_eq!(state.global_stats().blocked_pct, 0.0);
    }

    #[test]
    fn test_blocked_pct_zero_when_no_blocked() {
        let mut state = DashboardState::new();
        let ip = ipv4(10, 0, 0, 1);
        for _ in 0..5 {
            state.push_event(&ev(100, ip, StatAction::Allowed), "a.com");
        }
        assert_eq!(state.global_stats().blocked_pct, 0.0);
    }

    #[test]
    fn test_blocked_pct_fifty_percent() {
        let mut state = DashboardState::new();
        let ip = ipv4(10, 0, 0, 1);
        for _ in 0..5 {
            state.push_event(&ev(100, ip, StatAction::Allowed), "a.com");
        }
        for _ in 0..5 {
            state.push_event(&ev(101, ip, blocked(0)), "b.com");
        }
        let pct = state.global_stats().blocked_pct;
        assert!((pct - 50.0).abs() < 0.01, "expected 50.0, got {pct}");
    }

    #[test]
    fn test_blocked_pct_hundred_percent() {
        let mut state = DashboardState::new();
        let ip = ipv4(10, 0, 0, 1);
        state.push_event(&ev(100, ip, blocked(0)), "b.com");
        let pct = state.global_stats().blocked_pct;
        assert!((pct - 100.0).abs() < 0.01);
    }

    // ── global_stats — avg_qps ────────────────────────────────────────────────

    #[test]
    fn test_avg_qps_zero_when_no_events() {
        let state = DashboardState::new();
        assert_eq!(state.global_stats().avg_qps, 0.0);
    }

    #[test]
    fn test_avg_qps_finite_and_non_negative_after_events() {
        let mut state = DashboardState::new();
        let ip = ipv4(10, 0, 0, 1);
        for _ in 0..10 {
            state.push_event(&ev(100, ip, StatAction::Allowed), "a.com");
        }
        // The exact value depends on wall-clock elapsed time and may be 0.0
        // when the loop finishes in sub-millisecond time.  We only require it
        // is finite and non-negative.
        let qps = state.global_stats().avg_qps;
        assert!(qps.is_finite(), "avg_qps must be finite, got {qps}");
        assert!(qps >= 0.0, "avg_qps must be non-negative, got {qps}");
    }

    // ── recent_domains ────────────────────────────────────────────────────────

    #[test]
    fn test_recent_domains_grows_up_to_max() {
        let mut state = DashboardState::new();
        let ip = ipv4(10, 0, 0, 1);
        for i in 0..MAX_RECENT_DOMAINS {
            state.push_event(&ev(i as u64, ip, StatAction::Allowed), "a.com");
        }
        assert_eq!(state.recent_domains().len(), MAX_RECENT_DOMAINS);
    }

    #[test]
    fn test_recent_domains_caps_at_max_and_evicts_oldest() {
        let mut state = DashboardState::new();
        let ip = ipv4(10, 0, 0, 1);
        // Push MAX + 5 events; after capping we should still have MAX entries.
        for i in 0..(MAX_RECENT_DOMAINS + 5) {
            state.push_event(&ev(i as u64, ip, StatAction::Allowed), "a.com");
        }
        assert_eq!(state.recent_domains().len(), MAX_RECENT_DOMAINS);
    }

    #[test]
    fn test_recent_domains_newest_at_back() {
        let mut state = DashboardState::new();
        let ip = ipv4(10, 0, 0, 1);
        state.push_event(&ev(100, ip, StatAction::Allowed), "first.com");
        state.push_event(&ev(101, ip, StatAction::Allowed), "last.com");
        let domains = state.recent_domains();
        assert_eq!(domains.front().unwrap().domain, "first.com");
        assert_eq!(domains.back().unwrap().domain, "last.com");
    }

    #[test]
    fn test_recent_domains_color_from_action() {
        let mut state = DashboardState::new();
        let ip = ipv4(10, 0, 0, 1);
        state.push_event(&ev(100, ip, StatAction::Allowed), "a.com");
        state.push_event(&ev(101, ip, blocked(0)), "b.com");
        state.push_event(&ev(102, ip, suspicious(0)), "c.com");
        state.push_event(&ev(103, ip, StatAction::Proxied), "d.com");
        let domains: Vec<_> = state.recent_domains().iter().collect();
        assert_eq!(domains[0].color, DomainColor::Green);
        assert_eq!(domains[1].color, DomainColor::Red);
        assert_eq!(domains[2].color, DomainColor::Yellow);
        assert_eq!(domains[3].color, DomainColor::Dim);
    }

    #[test]
    fn test_recent_domains_hex_fallback_when_domain_empty() {
        let mut state = DashboardState::new();
        let ip = ipv4(10, 0, 0, 1);
        let event = ev_hash(100, ip, 0xdeadbeef_cafebabe, StatAction::Allowed);
        state.push_event(&event, "");
        let domain = &state.recent_domains().back().unwrap().domain;
        assert_eq!(domain, "#deadbeefcafebabe");
    }

    // ── live_feed ─────────────────────────────────────────────────────────────

    #[test]
    fn test_live_feed_grows_up_to_max() {
        let mut state = DashboardState::new();
        let ip = ipv4(10, 0, 0, 1);
        for i in 0..MAX_LIVE_FEED {
            state.push_event(&ev(i as u64, ip, StatAction::Allowed), "a.com");
        }
        assert_eq!(state.live_feed().len(), MAX_LIVE_FEED);
    }

    #[test]
    fn test_live_feed_caps_at_max_and_evicts_oldest() {
        let mut state = DashboardState::new();
        let ip = ipv4(10, 0, 0, 1);
        for i in 0..(MAX_LIVE_FEED + 3) {
            state.push_event(&ev(i as u64, ip, StatAction::Allowed), "a.com");
        }
        assert_eq!(state.live_feed().len(), MAX_LIVE_FEED);
    }

    #[test]
    fn test_live_feed_entry_fields() {
        let mut state = DashboardState::new();
        let ip = ipv4(192, 168, 1, 5);
        // timestamp 3_661 = 01:01:01
        state.push_event(
            &ev_hash(3_661, ip, 0xabc, blocked(1)), // bit 0 = STATIC_BLACKLIST
            "ads.evil.net",
        );
        let entry = state.live_feed().back().unwrap();
        assert_eq!(entry.timestamp, "01:01:01");
        assert_eq!(entry.client, "192.168.1.5");
        assert_eq!(entry.domain, "ads.evil.net");
        assert_eq!(entry.action, "Blocked:Blacklist");
        assert_eq!(entry.color, DomainColor::Red);
    }

    #[test]
    fn test_live_feed_newest_at_back() {
        let mut state = DashboardState::new();
        let ip = ipv4(10, 0, 0, 1);
        state.push_event(&ev(100, ip, StatAction::Allowed), "first.com");
        state.push_event(&ev(200, ip, StatAction::Allowed), "last.com");
        assert_eq!(state.live_feed().front().unwrap().domain, "first.com");
        assert_eq!(state.live_feed().back().unwrap().domain, "last.com");
    }

    #[test]
    fn test_live_feed_hex_fallback_when_domain_empty() {
        let mut state = DashboardState::new();
        let ip = ipv4(10, 0, 0, 1);
        let event = ev_hash(100, ip, 0x1234, StatAction::Allowed);
        state.push_event(&event, "");
        assert_eq!(
            state.live_feed().back().unwrap().domain,
            "#0000000000001234"
        );
    }

    // ── top_filter ────────────────────────────────────────────────────────────

    #[test]
    fn test_top_filter_none_when_no_events() {
        let state = DashboardState::new();
        assert!(state.top_filter().is_none());
    }

    #[test]
    fn test_top_filter_none_when_only_allowed() {
        let mut state = DashboardState::new();
        let ip = ipv4(10, 0, 0, 1);
        for _ in 0..5 {
            state.push_event(&ev(100, ip, StatAction::Allowed), "a.com");
        }
        assert!(state.top_filter().is_none());
    }

    #[test]
    fn test_top_filter_returns_highest_flag() {
        let mut state = DashboardState::new();
        let ip = ipv4(10, 0, 0, 1);
        // bit 0 = STATIC_BLACKLIST (1 hit), bit 1 = ABP_RULE (3 hits)
        state.push_event(&ev(100, ip, blocked(0b01)), "a.com"); // bit 0
        state.push_event(&ev(101, ip, blocked(0b10)), "b.com"); // bit 1
        state.push_event(&ev(102, ip, blocked(0b10)), "b.com"); // bit 1
        state.push_event(&ev(103, ip, blocked(0b10)), "b.com"); // bit 1
        let tf = state.top_filter().unwrap();
        assert_eq!(tf.name, "AbpRule");
        assert_eq!(tf.count, 3);
    }

    #[test]
    fn test_top_filter_pct_of_blocked_events() {
        let mut state = DashboardState::new();
        let ip = ipv4(10, 0, 0, 1);
        // 4 blocked events, all with bit 0 (STATIC_BLACKLIST)
        for _ in 0..4 {
            state.push_event(&ev(100, ip, blocked(0b01)), "a.com");
        }
        let tf = state.top_filter().unwrap();
        // 4 hits out of 4 blocked events = 100 %
        assert!(
            (tf.pct - 100.0).abs() < 0.01,
            "expected 100 %, got {}",
            tf.pct
        );
    }

    #[test]
    fn test_top_filter_pct_partial() {
        let mut state = DashboardState::new();
        let ip = ipv4(10, 0, 0, 1);
        // 2 events with bit 0, 2 with bit 1 — top flag is 50 % of blocked events
        state.push_event(&ev(100, ip, blocked(0b01)), "a.com");
        state.push_event(&ev(101, ip, blocked(0b01)), "a.com");
        state.push_event(&ev(102, ip, blocked(0b10)), "b.com");
        state.push_event(&ev(103, ip, blocked(0b10)), "b.com");
        let tf = state.top_filter().unwrap();
        // Both flags have 2 hits. The winner is whichever max_by_key selects
        // (stable for equal values → bit 0 or bit 1; pct must be 50 %).
        assert!(
            (tf.pct - 50.0).abs() < 0.01,
            "expected 50 %, got {}",
            tf.pct
        );
    }

    #[test]
    fn test_top_filter_counts_suspicious_flags() {
        let mut state = DashboardState::new();
        let ip = ipv4(10, 0, 0, 1);
        // Suspicious events should also contribute to flag_hits
        state.push_event(&ev(100, ip, suspicious(0b100)), "a.com"); // HIGH_ENTROPY = bit 2
        state.push_event(&ev(101, ip, highly_suspicious(0b100)), "b.com");
        let tf = state.top_filter().unwrap();
        assert_eq!(tf.name, "HighEntropy");
        assert_eq!(tf.count, 2);
    }

    #[test]
    fn test_top_filter_name_is_known_flag() {
        let mut state = DashboardState::new();
        let ip = ipv4(10, 0, 0, 1);
        // bit 14 = ASN_BLOCKED
        state.push_event(&ev(100, ip, blocked(1 << 14)), "a.com");
        let tf = state.top_filter().unwrap();
        assert_eq!(tf.name, "AsnBlocked");
    }

    // ── record_flags (via top_filter) ─────────────────────────────────────────

    #[test]
    fn test_multi_flag_event_increments_all_set_bits() {
        let mut state = DashboardState::new();
        let ip = ipv4(10, 0, 0, 1);
        // bits 0 and 2 set simultaneously
        state.push_event(&ev(100, ip, blocked(0b0101)), "a.com");
        // bit 0 = STATIC_BLACKLIST, bit 2 = HIGH_ENTROPY, each count = 1
        assert_eq!(state.flag_hits[0], 1);
        assert_eq!(state.flag_hits[2], 1);
        assert_eq!(state.flag_hits[1], 0);
    }
}
