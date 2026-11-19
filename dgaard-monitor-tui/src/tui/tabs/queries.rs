//! Queries tab — tail-style DNS event log.
//!
//! Displays a scrollable table of recent DNS events, newest on top by default:
//!
//!    Datetime   Domain                         Client IP         Flags
//!   ─────────── ────────────────────────────── ───────────────── ──────────────────────
//!   ✔ 14:23:01  example.com                    192.168.1.5       Allowed
//!   ✘ 14:23:00  ads.tracker.net                192.168.1.3       Blocked:Blacklist+AbpRule
//!   ⚠ 14:22:58  suspicious.xyz                 192.168.1.7       Suspicious:HighEntropy
//!   · 14:22:55  upstream-relay.corp            192.168.1.2       Proxied
//!
//! The indicator column (single char, first) comes from `ActionKind`, the row colour
//! from `DomainColor`:
//!   `✔` green  — Allowed / Override / Cached
//!   `✘` red    — Blocked; HighlySuspicious rows are also highlighted (white on red)
//!                so they stand out among routine list blocks
//!   `⚠` yellow — Suspicious
//!   `·` dim    — Proxied
//!   `!` yellow / red — SERVFAIL: upstream failure / DNSSEC bogus
//!
//! Indicators stay single-width text glyphs, not emoji: emoji are two cells wide
//! (with uneven terminal support for `⚠️`), ignore the row colour, and are missing from
//! console fonts.
//!
//! Interactive controls (`f` / `s` / `z` are global fixed bindings — available on every
//! tab that opts in; the outer event loop dispatches `Action::Filter` / `Action::Sort` to
//! the active tab handler):
//!   `f`     — filter popup: enter a client IP prefix or a flag name (e.g. `"192.168"`,
//!             `"Blacklist"`).
//!   `s`     — sort popup: toggle between newest-first and oldest-first.
//!   `z`     — toggle frozen display; header shows `[FROZEN]`.  New events keep buffering
//!             in `AppState` and appear when unfrozen.
//!   `↑/↓`   — virtual scroll: only the `height` rows around `scroll` are returned by
//!             `visible_rows(height, scroll)`, so 1 000+ buffered entries cause no lag.
//!
//!   `PgUp/PgDn` — one screen up / down; `Home/End` — first / last row.
//!
//! Virtual scrolling detail:
//!   The internal buffer (`VecDeque`) is capped at `MAX_ROWS`.  Eviction is O(1) via
//!   `pop_front`.  `visible_rows(height, scroll)` returns at most `height` rows starting
//!   at `scroll`, read by index when no filter is active — the renderer never touches
//!   more rows than fit on screen.  `render` records the table height so `scroll`
//!   stops at the last row, and the view stays on the same rows while new events
//!   arrive.
//!
//! The data layer (all `pub fn`s, structs, and `QueriesState`) is pure Rust with no
//! ratatui dependency, making it fully unit-testable.
//!
//! TODO: filter and sort popups (`f`, `s`).

use std::collections::VecDeque;

use crate::tui::scroll::{ScrollState, Scrollable, render_scrollbar};
use crate::tui::util::{
    DomainColor, INDICATOR_ALLOWED, INDICATOR_BLOCKED, INDICATOR_ERROR, INDICATOR_PROXIED,
    INDICATOR_SUSPICIOUS, REASON_BITS, flag_label,
};
use dgaard_monitor_core::protocol::{StatAction, StatBlockReason, StatError, StatEvent};
use dgaard_monitor_core::util::format_client_ip;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum rows kept in the display buffer (oldest are dropped when exceeded).
pub const MAX_ROWS: usize = 1_000;

/// Column widths for text formatting (matches the module doc table above).
pub const COL_DATETIME: usize = 8;
pub const COL_DOMAIN: usize = 30;
pub const COL_CLIENT: usize = 17;

// ── SortOrder ─────────────────────────────────────────────────────────────────

/// Display order for the queries list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SortOrder {
    /// Most recent event first (default — newest at the top).
    #[default]
    NewestFirst,
    /// Oldest event first.
    OldestFirst,
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "Queries tab not wired into the TUI yet: it only shows a placeholder"
    )
)]
impl SortOrder {
    /// Human-readable label shown in the sort popup.
    pub fn label(self) -> &'static str {
        match self {
            SortOrder::NewestFirst => "Newest first",
            SortOrder::OldestFirst => "Oldest first",
        }
    }

    /// Toggle between the two sort orders.
    pub fn toggle(self) -> Self {
        match self {
            SortOrder::NewestFirst => SortOrder::OldestFirst,
            SortOrder::OldestFirst => SortOrder::NewestFirst,
        }
    }
}

// ── ActionKind ────────────────────────────────────────────────────────────────

/// Collapsed action category: picks the row's indicator and styling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionKind {
    Allowed,
    Proxied,
    Blocked,
    Suspicious,
    HighlySuspicious,
    Cached,
    Error,
}

impl ActionKind {
    pub fn from_action(action: &StatAction) -> Self {
        match action {
            StatAction::Allowed | StatAction::AllowedWithOverride => Self::Allowed,
            StatAction::Proxied => Self::Proxied,
            StatAction::Blocked(_) => Self::Blocked,
            StatAction::Suspicious(_) => Self::Suspicious,
            StatAction::HighlySuspicious(_) => Self::HighlySuspicious,
            StatAction::Cached => Self::Cached,
            StatAction::Error(_) => Self::Error,
        }
    }

    /// Single-width indicator for the first column, by verdict: a SERVFAIL
    /// gets its own mark instead of borrowing the suspicious or blocked one.
    pub fn indicator(self) -> &'static str {
        match self {
            Self::Allowed | Self::Cached => INDICATOR_ALLOWED,
            Self::Proxied => INDICATOR_PROXIED,
            Self::Blocked | Self::HighlySuspicious => INDICATOR_BLOCKED,
            Self::Suspicious => INDICATOR_SUSPICIOUS,
            Self::Error => INDICATOR_ERROR,
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Format a Unix timestamp (seconds) as `HH:MM:SS`.
pub fn format_timestamp(ts: u64) -> String {
    let secs = ts % 86_400;
    let h = secs / 3_600;
    let m = (secs % 3_600) / 60;
    let s = secs % 60;
    format!("{h:02}:{m:02}:{s:02}")
}

/// Produce the short names of every set flag in `r`, joined by `+`, in bit
/// order (custom bits 16–31 last).  Returns an empty string when `r` is empty.
fn reason_str(r: StatBlockReason) -> String {
    (0..REASON_BITS)
        .filter(|bit| r.bits() & (1 << bit) != 0)
        .map(flag_label)
        .collect::<Vec<_>>()
        .join("+")
}

/// Build the display string for the Flags column from a `StatAction`.
///
/// Format: `"<ActionLabel>"` or `"<ActionLabel>:<FlagA>+<FlagB>"`.
pub fn flags_label(action: &StatAction) -> String {
    match action {
        StatAction::Allowed => "Allowed".to_string(),
        StatAction::AllowedWithOverride => "Override".to_string(),
        StatAction::Proxied => "Proxied".to_string(),
        StatAction::Cached => "Cached".to_string(),
        StatAction::Error(StatError::Upstream) => "ServFail:Upstream".to_string(),
        StatAction::Error(StatError::DnssecBogus) => "ServFail:DNSSEC".to_string(),
        StatAction::Blocked(r) => {
            let s = reason_str(*r);
            if s.is_empty() {
                "Blocked".to_string()
            } else {
                format!("Blocked:{s}")
            }
        }
        StatAction::Suspicious(r) => {
            let s = reason_str(*r);
            if s.is_empty() {
                "Suspicious".to_string()
            } else {
                format!("Suspicious:{s}")
            }
        }
        StatAction::HighlySuspicious(r) => {
            let s = reason_str(*r);
            if s.is_empty() {
                "HighlySusp".to_string()
            } else {
                format!("HighlySusp:{s}")
            }
        }
    }
}

// ── QueryRow ──────────────────────────────────────────────────────────────────

/// One display-ready row in the Queries table.
pub struct QueryRow {
    /// Single-char indicator (`✔` / `✘` / `⚠` / `·` / `!`) — first column.
    pub indicator: &'static str,
    /// Colour hint for the indicator and domain text.
    pub domain_color: DomainColor,
    /// Formatted timestamp (`HH:MM:SS`).
    pub datetime: String,
    /// Resolved domain name, or `"#<hex>"` when the hash is unknown.
    pub domain: String,
    /// Formatted client IP address.
    pub client_ip: String,
    /// Flags column string (`"Allowed"`, `"Blocked:Blacklist+AbpRule"`, …).
    pub flags: String,
    /// Collapsed action kind — picks the indicator and the row style.
    pub action_kind: ActionKind,
    /// Raw bitmask for `FilterMode::ByFlags` matching (empty for Allowed/Proxied).
    pub reasons: StatBlockReason,
}

impl QueryRow {
    /// Build a display row from a raw event and its resolved domain name.
    ///
    /// Pass `domain` as `""` when the hash is not in the domain map; a hex
    /// fallback `"#<hash>"` is used automatically.
    pub fn from_event(event: &StatEvent, domain: &str) -> Self {
        let reasons = match &event.action {
            StatAction::Blocked(r)
            | StatAction::Suspicious(r)
            | StatAction::HighlySuspicious(r) => *r,
            _ => StatBlockReason::empty(),
        };
        let action_kind = ActionKind::from_action(&event.action);
        Self {
            indicator: action_kind.indicator(),
            domain_color: DomainColor::from_action(&event.action),
            datetime: format_timestamp(event.timestamp),
            domain: if domain.is_empty() {
                format!("#{:016x}", event.domain_hash)
            } else {
                domain.to_string()
            },
            client_ip: format_client_ip(&event.client_ip),
            flags: flags_label(&event.action),
            action_kind,
            reasons,
        }
    }
}

// ── FilterMode ────────────────────────────────────────────────────────────────

/// Active filter applied to the queries list.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "Queries tab not wired into the TUI yet: it only shows a placeholder"
    )
)]
pub enum FilterMode {
    /// No filter — all rows are visible.
    #[default]
    None,
    /// Show only rows whose `client_ip` starts with the given prefix.
    ByClient(String),
    /// Show only rows whose `reasons` bitmask intersects the given mask.
    ByFlags(StatBlockReason),
}

impl FilterMode {
    /// Returns `true` if `row` passes the current filter.
    pub fn matches(&self, row: &QueryRow) -> bool {
        match self {
            FilterMode::None => true,
            FilterMode::ByClient(prefix) => row.client_ip.starts_with(prefix.as_str()),
            FilterMode::ByFlags(mask) => row.reasons.intersects(*mask),
        }
    }
}

// ── QueriesState ──────────────────────────────────────────────────────────────

/// All mutable state owned by the Queries tab, its scroll position included.
#[derive(Default)]
pub struct QueriesState {
    /// Internal buffer in insertion order (oldest front, newest back).
    /// `VecDeque` gives O(1) front-eviction when the cap is reached.
    rows: VecDeque<QueryRow>,
    /// Currently active filter.
    pub filter: FilterMode,
    /// Current sort order.
    pub sort: SortOrder,
    /// When `true`, `push_event` is a no-op; the buffer stays fixed.
    pub frozen: bool,
    /// Top row on screen and table height, bounded by the filtered rows.
    scroll: ScrollState,
}

impl QueriesState {
    /// Append a new event to the buffer.
    ///
    /// Does nothing when `frozen` is `true`.  When the buffer reaches
    /// `MAX_ROWS`, the oldest row is dropped in O(1) via `pop_front`.
    ///
    /// When the view is scrolled away from the top, it keeps showing the same
    /// rows: a row arriving above it (newest first) or leaving above it
    /// (oldest first) moves `scroll` along.
    pub fn push_event(&mut self, event: &StatEvent, domain: &str) {
        if self.frozen {
            return;
        }
        let row = QueryRow::from_event(event, domain);
        let added = self.filter.matches(&row);
        let evicted = self.rows.len() >= MAX_ROWS
            && self
                .rows
                .pop_front()
                .is_some_and(|oldest| self.filter.matches(&oldest));
        self.rows.push_back(row);

        if self.scroll() > 0 {
            match self.sort {
                SortOrder::NewestFirst if added => self.scroll_by(1),
                SortOrder::OldestFirst if evicted => self.scroll_by(-1),
                // The list may have lost its last row.
                _ => self.scroll_by(0),
            }
        }
    }

    /// Return up to `height` rows starting at `scroll`, after applying
    /// the current filter and sort.
    ///
    /// Virtual scrolling: only the returned rows are materialised.  Without a
    /// filter they are read by index, so the cost does not depend on the
    /// buffer size; with one, rows are matched lazily up to the last needed.
    ///
    /// * `NewestFirst` — index 0 = most recent; scrolling down shows older rows.
    /// * `OldestFirst` — index 0 = oldest; scrolling down shows newer rows.
    ///
    /// A `scroll` past the last row returns nothing.
    pub fn visible_rows(&self, height: usize, scroll: usize) -> Vec<&QueryRow> {
        if self.filter == FilterMode::None {
            let len = self.rows.len();
            let start = scroll.min(len);
            let end = scroll.saturating_add(height).min(len);
            return match self.sort {
                SortOrder::NewestFirst => self.rows.range(len - end..len - start).rev().collect(),
                SortOrder::OldestFirst => self.rows.range(start..end).collect(),
            };
        }
        let matching = |row: &&QueryRow| self.filter.matches(row);
        match self.sort {
            SortOrder::NewestFirst => self
                .rows
                .iter()
                .rev()
                .filter(matching)
                .skip(scroll)
                .take(height)
                .collect(),
            SortOrder::OldestFirst => self
                .rows
                .iter()
                .filter(matching)
                .skip(scroll)
                .take(height)
                .collect(),
        }
    }

    /// Total rows currently in the buffer (unfiltered).
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// Rows that pass the current filter.
    pub fn filtered_count(&self) -> usize {
        match self.filter {
            FilterMode::None => self.rows.len(),
            _ => self.rows.iter().filter(|r| self.filter.matches(r)).count(),
        }
    }

    /// Drop all buffered rows.
    pub fn clear(&mut self) {
        self.rows.clear();
        self.scroll.jump_to_top();
    }
}

impl Scrollable for QueriesState {
    fn scroll_state(&self) -> &ScrollState {
        &self.scroll
    }

    fn scroll_state_mut(&mut self) -> &mut ScrollState {
        &mut self.scroll
    }

    fn scroll_len(&self) -> usize {
        self.filtered_count()
    }
}

// ── Render ────────────────────────────────────────────────────────────────────

/// Style of a whole table row: the verdict colour, plus a full-row highlight
/// for highly suspicious queries so they stand out among routine list blocks.
pub fn row_style(row: &QueryRow) -> ratatui::style::Style {
    use ratatui::style::{Color, Modifier, Style};

    use crate::tui::tabs::dashboard::to_ratatui_color;

    let color = to_ratatui_color(row.domain_color);
    match row.action_kind {
        ActionKind::HighlySuspicious => Style::new()
            .fg(Color::White)
            .bg(color)
            .add_modifier(Modifier::BOLD),
        _ => Style::new().fg(color),
    }
}

/// Render the Queries tab body: only the rows that fit are built.
///
/// Takes the state mutably to record the table height (`set_viewport`),
/// which bounds scrolling.  `frozen` adds `[FROZEN]` to the title.
pub fn render(
    state: &mut QueriesState,
    frozen: bool,
    area: ratatui::layout::Rect,
    frame: &mut ratatui::Frame,
) {
    use ratatui::{
        layout::Constraint,
        style::{Modifier, Style},
        widgets::{Block, Row, Table},
    };

    let filtered = state.filtered_count();
    let title = format!(
        "Queries {filtered}/{} · {}{}",
        state.row_count(),
        state.sort.label(),
        if frozen { " [FROZEN]" } else { "" }
    );
    let block = Block::bordered().title(title);

    // The table header takes one row of the block.
    let viewport = usize::from(block.inner(area).height.saturating_sub(1));
    state.set_viewport(viewport);

    let rows: Vec<Row> = state
        .visible_rows(viewport, state.scroll())
        .into_iter()
        .map(|row| {
            Row::new([
                row.indicator.to_string(),
                row.datetime.clone(),
                row.domain.clone(),
                row.client_ip.clone(),
                row.flags.clone(),
            ])
            .style(row_style(row))
        })
        .collect();

    frame.render_widget(
        Table::new(
            rows,
            [
                Constraint::Length(1),
                Constraint::Length(COL_DATETIME as u16),
                Constraint::Min(COL_DOMAIN as u16),
                Constraint::Length(COL_CLIENT as u16),
                Constraint::Min(10),
            ],
        )
        .block(block)
        .header(
            Row::new(["", "Time", "Domain", "Client IP", "Flags"])
                .style(Style::new().add_modifier(Modifier::BOLD)),
        ),
        area,
    );

    render_scrollbar(state, area, frame);
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use dgaard_monitor_core::protocol::{StatAction, StatBlockReason, StatEvent};

    fn ev(ts: u64, ip: [u8; 16], action: StatAction) -> StatEvent {
        StatEvent {
            timestamp: ts,
            domain_hash: 0xdead,
            client_ip: ip,
            action,
        }
    }

    /// IPv4 client as dgaard sends it: IPv4-mapped IPv6.
    fn ipv4(a: u8, b: u8, c: u8, d: u8) -> [u8; 16] {
        std::net::Ipv4Addr::new(a, b, c, d)
            .to_ipv6_mapped()
            .octets()
    }

    #[test]
    fn test_flags_label_shows_custom_bits() {
        let r = StatBlockReason::from_bits_retain(1 << 23) | StatBlockReason::NRD_LIST;
        assert_eq!(
            flags_label(&StatAction::Blocked(r)),
            "Blocked:NRD+CUSTOM_BIT_23"
        );
    }

    #[test]
    fn test_flags_label_shows_geo_ip_bit() {
        // Bit 15 used to be missing from the Flags column.
        let r = StatBlockReason::SUSPICIOUS_GEO_IP | StatBlockReason::ABP_RULE;
        assert_eq!(
            flags_label(&StatAction::Blocked(r)),
            "Blocked:AbpRule+SuspGeoIP"
        );
    }

    // --- format_timestamp ---

    #[test]
    fn test_format_timestamp_midnight() {
        assert_eq!(format_timestamp(0), "00:00:00");
    }

    #[test]
    fn test_format_timestamp_noon() {
        assert_eq!(format_timestamp(12 * 3600), "12:00:00");
    }

    #[test]
    fn test_format_timestamp_wraps_24h() {
        assert_eq!(format_timestamp(25 * 3600), "01:00:00");
    }

    #[test]
    fn test_format_timestamp_specific() {
        assert_eq!(format_timestamp(51781), "14:23:01");
    }

    // --- flags_label ---

    #[test]
    fn test_flags_label_allowed() {
        assert_eq!(flags_label(&StatAction::Allowed), "Allowed");
    }

    #[test]
    fn test_flags_label_proxied() {
        assert_eq!(flags_label(&StatAction::Proxied), "Proxied");
    }

    #[test]
    fn test_flags_label_blocked_no_reason() {
        assert_eq!(
            flags_label(&StatAction::Blocked(StatBlockReason::empty())),
            "Blocked"
        );
    }

    #[test]
    fn test_flags_label_blocked_single_flag() {
        assert_eq!(
            flags_label(&StatAction::Blocked(StatBlockReason::STATIC_BLACKLIST)),
            "Blocked:Blacklist"
        );
    }

    #[test]
    fn test_flags_label_blocked_multi_flag() {
        let r = StatBlockReason::STATIC_BLACKLIST | StatBlockReason::ABP_RULE;
        assert_eq!(
            flags_label(&StatAction::Blocked(r)),
            "Blocked:Blacklist+AbpRule"
        );
    }

    #[test]
    fn test_flags_label_suspicious() {
        assert_eq!(
            flags_label(&StatAction::Suspicious(StatBlockReason::HIGH_ENTROPY)),
            "Suspicious:HighEntropy"
        );
    }

    #[test]
    fn test_flags_label_highly_suspicious() {
        assert_eq!(
            flags_label(&StatAction::HighlySuspicious(
                StatBlockReason::CNAME_CLOAKING
            )),
            "HighlySusp:CnameCloaking"
        );
    }

    // --- QueryRow::from_event ---

    #[test]
    fn test_query_row_allowed_fields() {
        let event = ev(51781, ipv4(192, 168, 1, 5), StatAction::Allowed);
        let row = QueryRow::from_event(&event, "example.com");
        assert_eq!(row.datetime, "14:23:01");
        assert_eq!(row.domain, "example.com");
        assert_eq!(row.client_ip, "192.168.1.5");
        assert_eq!(row.flags, "Allowed");
        assert_eq!(row.action_kind, ActionKind::Allowed);
        assert_eq!(row.domain_color, DomainColor::Green);
        assert_eq!(row.indicator, INDICATOR_ALLOWED);
        assert!(row.reasons.is_empty());
    }

    #[test]
    fn test_query_row_blocked_indicator_and_color() {
        let event = ev(
            0,
            ipv4(1, 2, 3, 4),
            StatAction::Blocked(StatBlockReason::STATIC_BLACKLIST),
        );
        let row = QueryRow::from_event(&event, "bad.com");
        assert_eq!(row.domain_color, DomainColor::Red);
        assert_eq!(row.indicator, INDICATOR_BLOCKED);
    }

    #[test]
    fn test_query_row_suspicious_indicator_and_color() {
        let event = ev(
            0,
            ipv4(1, 2, 3, 4),
            StatAction::Suspicious(StatBlockReason::HIGH_ENTROPY),
        );
        let row = QueryRow::from_event(&event, "odd.com");
        assert_eq!(row.domain_color, DomainColor::Yellow);
        assert_eq!(row.indicator, INDICATOR_SUSPICIOUS);
    }

    #[test]
    fn test_query_row_proxied_indicator_and_color() {
        let event = ev(0, ipv4(1, 2, 3, 4), StatAction::Proxied);
        let row = QueryRow::from_event(&event, "relay.corp");
        assert_eq!(row.domain_color, DomainColor::Dim);
        assert_eq!(row.indicator, INDICATOR_PROXIED);
    }

    // --- action styling ---

    const ALL_KINDS: [ActionKind; 7] = [
        ActionKind::Allowed,
        ActionKind::Proxied,
        ActionKind::Blocked,
        ActionKind::Suspicious,
        ActionKind::HighlySuspicious,
        ActionKind::Cached,
        ActionKind::Error,
    ];

    fn row_for(action: StatAction) -> QueryRow {
        QueryRow::from_event(&ev(0, ipv4(1, 2, 3, 4), action), "x.com")
    }

    #[test]
    fn test_indicator_per_action_kind() {
        let cases = [
            (ActionKind::Allowed, INDICATOR_ALLOWED),
            (ActionKind::Cached, INDICATOR_ALLOWED),
            (ActionKind::Proxied, INDICATOR_PROXIED),
            (ActionKind::Blocked, INDICATOR_BLOCKED),
            (ActionKind::HighlySuspicious, INDICATOR_BLOCKED),
            (ActionKind::Suspicious, INDICATOR_SUSPICIOUS),
            (ActionKind::Error, INDICATOR_ERROR),
        ];
        for (kind, indicator) in cases {
            assert_eq!(kind.indicator(), indicator, "{kind:?}");
        }
    }

    #[test]
    fn test_indicators_are_single_cell_text() {
        // Emoji are two cells wide and ignore the row colour; keep the column at 1.
        for kind in ALL_KINDS {
            let width = ratatui::text::Span::raw(kind.indicator()).width();
            assert_eq!(width, 1, "{kind:?} indicator {:?}", kind.indicator());
        }
    }

    #[test]
    fn test_servfail_rows_get_error_indicator_not_threat() {
        let upstream = row_for(StatAction::Error(StatError::Upstream));
        let dnssec = row_for(StatAction::Error(StatError::DnssecBogus));
        assert_eq!(upstream.indicator, INDICATOR_ERROR);
        assert_eq!(upstream.domain_color, DomainColor::Yellow);
        assert_eq!(dnssec.indicator, INDICATOR_ERROR);
        assert_eq!(dnssec.domain_color, DomainColor::Red);
    }

    #[test]
    fn test_cached_and_override_rows_are_allowed() {
        for action in [StatAction::Cached, StatAction::AllowedWithOverride] {
            let row = row_for(action);
            assert_eq!(row.indicator, INDICATOR_ALLOWED);
            assert_eq!(row.domain_color, DomainColor::Green);
        }
    }

    #[test]
    fn test_highly_suspicious_row_is_highlighted() {
        use ratatui::style::{Color, Modifier};
        let row = row_for(StatAction::HighlySuspicious(StatBlockReason::NRD_LIST));
        let style = row_style(&row);
        assert_eq!(style.bg, Some(Color::Red));
        assert_eq!(style.fg, Some(Color::White));
        assert!(style.add_modifier.contains(Modifier::BOLD));
        assert_eq!(row.indicator, INDICATOR_BLOCKED);
    }

    #[test]
    fn test_other_rows_only_take_the_verdict_colour() {
        use ratatui::style::Color;
        let cases = [
            (StatAction::Allowed, Color::Green),
            (StatAction::Blocked(StatBlockReason::ABP_RULE), Color::Red),
            (
                StatAction::Suspicious(StatBlockReason::HIGH_ENTROPY),
                Color::Yellow,
            ),
            (StatAction::Proxied, Color::DarkGray),
            (StatAction::Error(StatError::Upstream), Color::Yellow),
        ];
        for (action, color) in cases {
            let style = row_style(&row_for(action));
            assert_eq!(style.fg, Some(color));
            assert_eq!(style.bg, None, "no highlight for {color:?}");
        }
    }

    #[test]
    fn test_query_row_domain_fallback_when_empty() {
        let event = ev(0, ipv4(10, 0, 0, 1), StatAction::Proxied);
        let row = QueryRow::from_event(&event, "");
        assert!(
            row.domain.starts_with('#'),
            "fallback domain: {}",
            row.domain
        );
    }

    #[test]
    fn test_query_row_reasons_populated_for_blocked() {
        let reason = StatBlockReason::STATIC_BLACKLIST | StatBlockReason::HIGH_ENTROPY;
        let row = QueryRow::from_event(
            &ev(0, ipv4(1, 2, 3, 4), StatAction::Blocked(reason)),
            "b.com",
        );
        assert_eq!(row.reasons, reason);
    }

    #[test]
    fn test_query_row_reasons_empty_for_allowed() {
        let row = QueryRow::from_event(&ev(0, ipv4(1, 2, 3, 4), StatAction::Allowed), "ok.com");
        assert!(row.reasons.is_empty());
    }

    // --- FilterMode::matches ---

    fn blocked_row(ip: [u8; 16], reasons: StatBlockReason) -> QueryRow {
        QueryRow::from_event(&ev(0, ip, StatAction::Blocked(reasons)), "test.com")
    }

    #[test]
    fn test_filter_none_matches_all() {
        let row = blocked_row(ipv4(1, 2, 3, 4), StatBlockReason::STATIC_BLACKLIST);
        assert!(FilterMode::None.matches(&row));
    }

    #[test]
    fn test_filter_by_client_prefix_match() {
        let row = blocked_row(ipv4(192, 168, 1, 5), StatBlockReason::empty());
        assert!(FilterMode::ByClient("192.168".to_string()).matches(&row));
    }

    #[test]
    fn test_filter_by_client_prefix_no_match() {
        let row = blocked_row(ipv4(10, 0, 0, 1), StatBlockReason::empty());
        assert!(!FilterMode::ByClient("192.168".to_string()).matches(&row));
    }

    #[test]
    fn test_filter_by_flags_intersection_match() {
        let row = blocked_row(
            ipv4(1, 2, 3, 4),
            StatBlockReason::STATIC_BLACKLIST | StatBlockReason::HIGH_ENTROPY,
        );
        assert!(FilterMode::ByFlags(StatBlockReason::HIGH_ENTROPY).matches(&row));
    }

    #[test]
    fn test_filter_by_flags_no_intersection() {
        let row = blocked_row(ipv4(1, 2, 3, 4), StatBlockReason::STATIC_BLACKLIST);
        assert!(!FilterMode::ByFlags(StatBlockReason::NRD_LIST).matches(&row));
    }

    #[test]
    fn test_filter_by_flags_no_match_on_allowed_row() {
        let row = QueryRow::from_event(&ev(0, ipv4(1, 1, 1, 1), StatAction::Allowed), "ok.com");
        assert!(!FilterMode::ByFlags(StatBlockReason::STATIC_BLACKLIST).matches(&row));
    }

    // --- QueriesState ---

    fn push_n(s: &mut QueriesState, n: u64) {
        for ts in 0..n {
            s.push_event(&ev(ts, ipv4(1, 1, 1, 1), StatAction::Allowed), "a.com");
        }
    }

    #[test]
    fn test_push_adds_row() {
        let mut s = QueriesState::default();
        s.push_event(&ev(0, ipv4(1, 1, 1, 1), StatAction::Allowed), "a.com");
        assert_eq!(s.row_count(), 1);
    }

    #[test]
    fn test_push_frozen_does_not_add() {
        let mut s = QueriesState {
            frozen: true,
            ..QueriesState::default()
        };
        s.push_event(&ev(0, ipv4(1, 1, 1, 1), StatAction::Allowed), "a.com");
        assert_eq!(s.row_count(), 0);
    }

    #[test]
    fn test_push_evicts_oldest_at_max_rows() {
        let mut s = QueriesState::default();
        for i in 0..MAX_ROWS {
            s.push_event(
                &ev(i as u64, ipv4(1, 1, 1, 1), StatAction::Allowed),
                "a.com",
            );
        }
        assert_eq!(s.row_count(), MAX_ROWS);
        s.push_event(
            &ev(MAX_ROWS as u64, ipv4(1, 1, 1, 1), StatAction::Allowed),
            "a.com",
        );
        assert_eq!(s.row_count(), MAX_ROWS);
        // oldest (ts=0) evicted; front is now ts=1
        assert_eq!(s.rows[0].datetime, "00:00:01");
    }

    // --- visible_rows: sort order ---

    #[test]
    fn test_visible_rows_newest_first_order() {
        let mut s = QueriesState::default();
        push_n(&mut s, 5);
        s.sort = SortOrder::NewestFirst;
        let rows = s.visible_rows(5, 0);
        assert_eq!(rows[0].datetime, format_timestamp(4));
        assert_eq!(rows[4].datetime, format_timestamp(0));
    }

    #[test]
    fn test_visible_rows_oldest_first_order() {
        let mut s = QueriesState::default();
        push_n(&mut s, 5);
        s.sort = SortOrder::OldestFirst;
        let rows = s.visible_rows(5, 0);
        assert_eq!(rows[0].datetime, format_timestamp(0));
        assert_eq!(rows[4].datetime, format_timestamp(4));
    }

    // --- visible_rows: virtual scroll ---

    #[test]
    fn test_visible_rows_height_limit() {
        let mut s = QueriesState::default();
        push_n(&mut s, 10);
        assert_eq!(s.visible_rows(3, 0).len(), 3);
    }

    #[test]
    fn test_visible_rows_scroll_newest_first() {
        let mut s = QueriesState::default();
        push_n(&mut s, 5); // ts 0..4
        s.sort = SortOrder::NewestFirst;
        // scroll=0: [ts4, ts3, ts2]; scroll=1: [ts3, ts2, ts1]; scroll=2: [ts2, ts1, ts0]
        assert_eq!(s.visible_rows(3, 0)[0].datetime, format_timestamp(4));
        assert_eq!(s.visible_rows(3, 1)[0].datetime, format_timestamp(3));
        assert_eq!(s.visible_rows(3, 2)[0].datetime, format_timestamp(2));
    }

    #[test]
    fn test_visible_rows_scroll_oldest_first() {
        let mut s = QueriesState::default();
        push_n(&mut s, 5); // ts 0..4
        s.sort = SortOrder::OldestFirst;
        // scroll=0: [ts0, ts1, ts2]; scroll=1: [ts1, ts2, ts3]; scroll=2: [ts2, ts3, ts4]
        assert_eq!(s.visible_rows(3, 0)[0].datetime, format_timestamp(0));
        assert_eq!(s.visible_rows(3, 1)[0].datetime, format_timestamp(1));
        assert_eq!(s.visible_rows(3, 2)[0].datetime, format_timestamp(2));
    }

    #[test]
    fn test_visible_rows_scroll_past_end_returns_empty() {
        let mut s = QueriesState::default();
        push_n(&mut s, 3);
        // scroll beyond all 3 rows → empty
        assert!(s.visible_rows(3, 10).is_empty());
    }

    // --- visible_rows: filter ---

    #[test]
    fn test_visible_rows_with_filter() {
        let mut s = QueriesState::default();
        s.push_event(&ev(0, ipv4(192, 168, 1, 1), StatAction::Allowed), "a.com");
        s.push_event(&ev(1, ipv4(10, 0, 0, 1), StatAction::Allowed), "b.com");
        s.push_event(&ev(2, ipv4(192, 168, 1, 2), StatAction::Allowed), "c.com");
        s.filter = FilterMode::ByClient("192.168".to_string());
        assert_eq!(s.visible_rows(10, 0).len(), 2);
    }

    #[test]
    fn test_clear_empties_buffer() {
        let mut s = QueriesState::default();
        push_n(&mut s, 3);
        s.clear();
        assert_eq!(s.row_count(), 0);
    }

    // --- virtual scrolling ---

    /// `count` events at timestamps 0.., alternating 10.0.0.1 / 10.0.0.2.
    fn alternating(count: u64) -> QueriesState {
        let mut s = QueriesState::default();
        for ts in 0..count {
            let ip = ipv4(10, 0, 0, 1 + (ts % 2) as u8);
            s.push_event(&ev(ts, ip, StatAction::Allowed), "a.com");
        }
        s
    }

    fn timestamps(rows: &[&QueryRow]) -> Vec<String> {
        rows.iter().map(|row| row.datetime.clone()).collect()
    }

    #[test]
    fn test_visible_rows_partial_last_page() {
        let mut s = QueriesState::default();
        push_n(&mut s, 5);
        assert_eq!(
            timestamps(&s.visible_rows(10, 3)),
            ["00:00:01", "00:00:00"],
            "newest first: the two oldest"
        );
        s.sort = SortOrder::OldestFirst;
        assert_eq!(timestamps(&s.visible_rows(10, 3)), ["00:00:03", "00:00:04"]);
    }

    #[test]
    fn test_visible_rows_huge_scroll_and_height_do_not_overflow() {
        let mut s = QueriesState::default();
        push_n(&mut s, 5);
        assert!(s.visible_rows(usize::MAX, usize::MAX).is_empty());
        assert_eq!(s.visible_rows(usize::MAX, 0).len(), 5);
    }

    #[test]
    fn test_visible_rows_full_buffer_returns_only_height() {
        let mut s = QueriesState::default();
        push_n(&mut s, MAX_ROWS as u64 + 200);
        let rows = s.visible_rows(20, 500);
        assert_eq!(rows.len(), 20);
        // Newest is ts MAX_ROWS+199; index 500 is 500 rows older.
        assert_eq!(
            rows[0].datetime,
            format_timestamp(MAX_ROWS as u64 + 199 - 500)
        );
    }

    #[test]
    fn test_visible_rows_filtered_skips_in_filtered_space() {
        let mut s = alternating(10); // .1 at even ts, .2 at odd ts
        s.filter = FilterMode::ByClient("10.0.0.2".to_string());
        assert_eq!(
            timestamps(&s.visible_rows(2, 1)),
            ["00:00:07", "00:00:05"],
            "second and third .2 rows, newest first"
        );
        s.sort = SortOrder::OldestFirst;
        assert_eq!(timestamps(&s.visible_rows(2, 1)), ["00:00:03", "00:00:05"]);
    }

    #[test]
    fn test_filtered_count() {
        let mut s = alternating(10);
        assert_eq!(s.filtered_count(), 10);
        s.filter = FilterMode::ByClient("10.0.0.1".to_string());
        assert_eq!(s.filtered_count(), 5);
        assert_eq!(s.row_count(), 10);
    }

    #[test]
    fn test_scroll_clamped_to_last_full_page() {
        let mut s = alternating(30);
        s.set_viewport(10);
        assert_eq!(s.max_scroll(), 20);
        s.scroll_by(100);
        assert_eq!(s.scroll(), 20);
        s.scroll_by(-5);
        assert_eq!(s.scroll(), 15);
        s.scroll_by(-100);
        assert_eq!(s.scroll(), 0);
    }

    #[test]
    fn test_scroll_to_top_and_bottom() {
        let mut s = alternating(30);
        s.set_viewport(10);
        s.scroll_to_bottom();
        assert_eq!(s.scroll(), 20);
        s.scroll_to_top();
        assert_eq!(s.scroll(), 0);
    }

    #[test]
    fn test_short_list_does_not_scroll() {
        let mut s = alternating(5);
        s.set_viewport(10);
        s.scroll_by(3);
        assert_eq!(s.scroll(), 0);
        assert_eq!(s.max_scroll(), 0);
    }

    #[test]
    fn test_taller_viewport_pulls_scroll_back() {
        let mut s = alternating(30);
        s.set_viewport(10);
        s.scroll_to_bottom();
        s.set_viewport(25);
        assert_eq!(s.scroll(), 5);
    }

    #[test]
    fn test_filter_shrinking_list_is_clamped_on_next_viewport() {
        let mut s = alternating(30);
        s.set_viewport(10);
        s.scroll_to_bottom();
        s.filter = FilterMode::ByClient("10.0.0.1".to_string()); // 15 rows
        s.set_viewport(10);
        assert_eq!(s.scroll(), 5);
    }

    #[test]
    fn test_page_size_is_viewport_and_never_zero() {
        let mut s = QueriesState::default();
        assert_eq!(s.page_size(), 1);
        s.set_viewport(12);
        assert_eq!(s.page_size(), 12);
    }

    #[test]
    fn test_clear_resets_scroll() {
        let mut s = alternating(30);
        s.set_viewport(10);
        s.scroll_by(7);
        s.clear();
        assert_eq!(s.scroll(), 0);
    }

    #[test]
    fn test_newest_first_view_stays_put_when_scrolled() {
        let mut s = alternating(30);
        s.set_viewport(10);
        s.scroll_by(5);
        let before = timestamps(&s.visible_rows(10, s.scroll()));
        s.push_event(&ev(100, ipv4(10, 0, 0, 1), StatAction::Allowed), "new.com");
        assert_eq!(s.scroll(), 6);
        assert_eq!(timestamps(&s.visible_rows(10, s.scroll())), before);
    }

    #[test]
    fn test_newest_first_at_top_follows_new_rows() {
        let mut s = alternating(30);
        s.set_viewport(10);
        s.push_event(&ev(100, ipv4(10, 0, 0, 1), StatAction::Allowed), "new.com");
        assert_eq!(s.scroll(), 0);
        assert_eq!(s.visible_rows(1, 0)[0].domain, "new.com");
    }

    #[test]
    fn test_newest_first_filtered_out_row_does_not_shift() {
        let mut s = alternating(30);
        s.filter = FilterMode::ByClient("10.0.0.1".to_string());
        s.set_viewport(5);
        s.scroll_by(3);
        s.push_event(
            &ev(100, ipv4(10, 0, 0, 2), StatAction::Allowed),
            "hidden.com",
        );
        assert_eq!(s.scroll(), 3);
    }

    #[test]
    fn test_oldest_first_view_stays_put_on_eviction() {
        let mut s = QueriesState {
            sort: SortOrder::OldestFirst,
            ..QueriesState::default()
        };
        push_n(&mut s, MAX_ROWS as u64);
        s.set_viewport(10);
        s.scroll_by(50);
        let before = timestamps(&s.visible_rows(10, s.scroll()));
        s.push_event(&ev(5_000, ipv4(1, 1, 1, 1), StatAction::Allowed), "a.com");
        assert_eq!(s.scroll(), 49, "oldest row evicted above the view");
        assert_eq!(timestamps(&s.visible_rows(10, s.scroll())), before);
    }

    #[test]
    fn test_oldest_first_new_row_does_not_shift() {
        let mut s = QueriesState {
            sort: SortOrder::OldestFirst,
            ..QueriesState::default()
        };
        push_n(&mut s, 30);
        s.set_viewport(10);
        s.scroll_by(5);
        s.push_event(&ev(100, ipv4(1, 1, 1, 1), StatAction::Allowed), "a.com");
        assert_eq!(s.scroll(), 5);
    }

    // --- render ---

    /// Draw the tab on a `width` × `height` terminal and return its rows.
    fn draw(s: &mut QueriesState, frozen: bool, width: u16, height: u16) -> Vec<String> {
        use ratatui::{Terminal, backend::TestBackend};
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| render(s, frozen, frame.area(), frame))
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

    #[test]
    fn test_render_records_viewport_from_area() {
        let mut s = alternating(50);
        // 12 rows - 2 borders - 1 header = 9 table rows
        draw(&mut s, false, 100, 12);
        assert_eq!(s.page_size(), 9);
        assert_eq!(s.max_scroll(), 41);
    }

    #[test]
    fn test_render_draws_only_the_visible_window() {
        let mut s = alternating(50);
        draw(&mut s, false, 100, 12);
        s.scroll_by(10);
        let lines = draw(&mut s, false, 100, 12);
        let shown: Vec<&String> = lines.iter().filter(|l| l.contains("a.com")).collect();
        assert_eq!(shown.len(), 9);
        // Newest is ts 49; scrolled 10 rows: ts 39 down to 31.
        assert!(shown[0].contains("00:00:39"));
        assert!(shown[8].contains("00:00:31"));
        assert!(!lines.iter().any(|l| l.contains("00:00:40")));
    }

    #[test]
    fn test_render_title_counts_sort_and_frozen() {
        let mut s = alternating(10);
        s.filter = FilterMode::ByClient("10.0.0.1".to_string());
        let lines = draw(&mut s, true, 100, 12);
        assert!(lines[0].contains("Queries 5/10"), "{}", lines[0]);
        assert!(lines[0].contains("Newest first"));
        assert!(lines[0].contains("[FROZEN]"));
        let lines = draw(&mut s, false, 100, 12);
        assert!(!lines[0].contains("[FROZEN]"));
    }

    #[test]
    fn test_render_header_and_row_columns() {
        let mut s = QueriesState::default();
        s.push_event(
            &ev(3_661, ipv4(192, 168, 1, 5), StatAction::Allowed),
            "example.com",
        );
        let lines = draw(&mut s, false, 100, 8);
        assert!(lines[1].contains("Time") && lines[1].contains("Flags"));
        let row = &lines[2];
        for cell in [
            INDICATOR_ALLOWED,
            "01:01:01",
            "example.com",
            "192.168.1.5",
            "Allowed",
        ] {
            assert!(row.contains(cell), "missing {cell:?} in {row:?}");
        }
    }

    #[test]
    fn test_render_scrollbar_only_when_list_overflows() {
        // The scrollbar replaces the right border column between the corners.
        let right_border = |lines: &[String]| -> String {
            lines[1..lines.len() - 1]
                .iter()
                .map(|l| l.chars().last().unwrap())
                .collect()
        };
        let mut short = alternating(3);
        let lines = draw(&mut short, false, 60, 12);
        assert!(right_border(&lines).chars().all(|c| c == '│'));

        let mut long = alternating(50);
        let lines = draw(&mut long, false, 60, 12);
        assert!(right_border(&lines).chars().any(|c| c != '│'));
    }

    #[test]
    fn test_render_empty_buffer() {
        let mut s = QueriesState::default();
        let lines = draw(&mut s, false, 80, 10);
        assert!(lines[0].contains("Queries 0/0"));
        assert_eq!(s.scroll(), 0);
    }

    #[test]
    fn test_render_highlights_whole_highly_suspicious_row() {
        use ratatui::{Terminal, backend::TestBackend, style::Color};
        let mut s = QueriesState::default();
        let ip = ipv4(10, 0, 0, 1);
        s.push_event(
            &ev(1, ip, StatAction::Blocked(StatBlockReason::ABP_RULE)),
            "ads.example",
        );
        s.push_event(
            &ev(
                2,
                ip,
                StatAction::HighlySuspicious(StatBlockReason::NRD_LIST),
            ),
            "evil.example",
        );
        let mut terminal = Terminal::new(TestBackend::new(80, 8)).unwrap();
        terminal
            .draw(|frame| render(&mut s, false, frame.area(), frame))
            .unwrap();
        let buffer = terminal.backend().buffer();
        // Row 2: newest (highly suspicious); row 3: the plain block.
        // Columns 1..79 are inside the borders: every cell, gaps included.
        for column in 1..79 {
            assert_eq!(buffer[(column, 2)].bg, Color::Red, "column {column}");
            assert_eq!(buffer[(column, 3)].bg, Color::Reset, "column {column}");
            assert_eq!(buffer[(column, 3)].fg, Color::Red, "column {column}");
        }
    }

    // --- SortOrder ---

    #[test]
    fn test_sort_order_toggle() {
        assert_eq!(SortOrder::NewestFirst.toggle(), SortOrder::OldestFirst);
        assert_eq!(SortOrder::OldestFirst.toggle(), SortOrder::NewestFirst);
    }

    #[test]
    fn test_sort_order_default_is_newest_first() {
        assert_eq!(SortOrder::default(), SortOrder::NewestFirst);
    }

    #[test]
    fn test_sort_order_labels_non_empty() {
        assert!(!SortOrder::NewestFirst.label().is_empty());
        assert!(!SortOrder::OldestFirst.label().is_empty());
    }
}
