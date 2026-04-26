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
//! The indicator column (single char, first) and domain colour are driven by `DomainColor`:
//!   `✔` green  — Allowed
//!   `✘` red    — Blocked / HighlySuspicious
//!   `⚠` yellow — Suspicious
//!   `·` dim    — Proxied
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
//! Virtual scrolling detail:
//!   The internal buffer (`VecDeque`) is capped at `MAX_ROWS`.  Eviction is O(1) via
//!   `pop_front`.  `visible_rows(height, scroll)` iterates the filtered+sorted slice once
//!   and returns at most `height` rows starting at `scroll` — the renderer never touches
//!   more rows than fit on screen.
//!
//! The data layer (all `pub fn`s, structs, and `QueriesState`) is pure Rust with no
//! ratatui dependency, making it fully unit-testable.
//!
//! TODO: implement `render()` with ratatui `Table` + `Block` + popup `Paragraph`.

#![allow(dead_code)]

use std::collections::VecDeque;

use crate::protocol::{StatAction, StatBlockReason, StatEvent};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum rows kept in the display buffer (oldest are dropped when exceeded).
pub const MAX_ROWS: usize = 1_000;

/// Column widths for text formatting (matches the module doc table above).
pub const COL_DATETIME: usize = 8;
pub const COL_DOMAIN: usize = 30;
pub const COL_CLIENT: usize = 17;

// ── Indicator symbols ─────────────────────────────────────────────────────────

pub const INDICATOR_ALLOWED: &str = "✔";
pub const INDICATOR_BLOCKED: &str = "✘";
pub const INDICATOR_SUSPICIOUS: &str = "⚠";
pub const INDICATOR_PROXIED: &str = "·";

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

/// Collapsed action category used for colour-coding in the renderer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionKind {
    Allowed,
    Proxied,
    Blocked,
    Suspicious,
    HighlySuspicious,
}

impl ActionKind {
    pub fn from_action(action: &StatAction) -> Self {
        match action {
            StatAction::Allowed => Self::Allowed,
            StatAction::Proxied => Self::Proxied,
            StatAction::Blocked(_) => Self::Blocked,
            StatAction::Suspicious(_) => Self::Suspicious,
            StatAction::HighlySuspicious(_) => Self::HighlySuspicious,
        }
    }
}

// ── DomainColor ───────────────────────────────────────────────────────────────

/// Colour hint for the Domain column and the single-char indicator.
///
/// The renderer maps these to actual ratatui `Color` values; keeping them
/// as an enum here avoids a ratatui dependency in the data layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainColor {
    /// Green  — `Allowed`.
    Green,
    /// Red    — `Blocked` or `HighlySuspicious`.
    Red,
    /// Yellow — `Suspicious`.
    Yellow,
    /// Dim    — `Proxied` (pass-through, no verdict).
    Dim,
}

impl DomainColor {
    pub fn from_action(action: &StatAction) -> Self {
        match action {
            StatAction::Allowed => Self::Green,
            StatAction::Proxied => Self::Dim,
            StatAction::Blocked(_) | StatAction::HighlySuspicious(_) => Self::Red,
            StatAction::Suspicious(_) => Self::Yellow,
        }
    }

    /// The single-char indicator to display before the timestamp.
    pub fn indicator(self) -> &'static str {
        match self {
            Self::Green => INDICATOR_ALLOWED,
            Self::Red => INDICATOR_BLOCKED,
            Self::Yellow => INDICATOR_SUSPICIOUS,
            Self::Dim => INDICATOR_PROXIED,
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Format a 16-byte client IP for display.
///
/// * IPv4-mapped IPv6 (`::ffff:a.b.c.d`) → `"a.b.c.d"`
/// * IPv4 in first 4 bytes, rest zero    → `"a.b.c.d"`
/// * Anything else                        → compact IPv6 hex groups
pub fn format_ip(ip: [u8; 16]) -> String {
    if ip[..10] == [0u8; 10] && ip[10] == 0xff && ip[11] == 0xff {
        return format!("{}.{}.{}.{}", ip[12], ip[13], ip[14], ip[15]);
    }
    if ip[4..] == [0u8; 12] {
        return format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
    }
    ip.chunks(2)
        .map(|c| format!("{:04x}", u16::from_be_bytes([c[0], c[1]])))
        .collect::<Vec<_>>()
        .join(":")
}

/// Format a Unix timestamp (seconds) as `HH:MM:SS`.
pub fn format_timestamp(ts: u64) -> String {
    let secs = ts % 86_400;
    let h = secs / 3_600;
    let m = (secs % 3_600) / 60;
    let s = secs % 60;
    format!("{h:02}:{m:02}:{s:02}")
}

/// Produce the short names of every set flag in `r`, joined by `+`.
/// Returns an empty string when `r` is empty.
fn reason_str(r: StatBlockReason) -> String {
    const FLAGS: &[(StatBlockReason, &str)] = &[
        (StatBlockReason::STATIC_BLACKLIST, "Blacklist"),
        (StatBlockReason::ABP_RULE, "AbpRule"),
        (StatBlockReason::HIGH_ENTROPY, "HighEntropy"),
        (StatBlockReason::LEXICAL_ANALYSIS, "Lexical"),
        (StatBlockReason::BANNED_KEYWORD, "BannedKw"),
        (StatBlockReason::INVALID_STRUCTURE, "InvalidStruct"),
        (StatBlockReason::SUSPICIOUS_IDN, "SuspIDN"),
        (StatBlockReason::NRD_LIST, "NRD"),
        (StatBlockReason::TLD_EXCLUDED, "TLD"),
        (StatBlockReason::SUSPICIOUS, "Suspicious"),
        (StatBlockReason::CNAME_CLOAKING, "CnameCloaking"),
        (StatBlockReason::FORBIDDEN_QTYPE, "ForbidQtype"),
        (StatBlockReason::DNS_REBINDING, "DnsRebinding"),
        (StatBlockReason::LOW_TTL, "LowTTL"),
        (StatBlockReason::ASN_BLOCKED, "AsnBlocked"),
    ];
    let parts: Vec<&str> = FLAGS
        .iter()
        .filter(|(flag, _)| r.contains(*flag))
        .map(|(_, name)| *name)
        .collect();
    if parts.is_empty() {
        String::new()
    } else {
        parts.join("+")
    }
}

/// Build the display string for the Flags column from a `StatAction`.
///
/// Format: `"<ActionLabel>"` or `"<ActionLabel>:<FlagA>+<FlagB>"`.
pub fn flags_label(action: &StatAction) -> String {
    match action {
        StatAction::Allowed => "Allowed".to_string(),
        StatAction::Proxied => "Proxied".to_string(),
        StatAction::Blocked(r) => {
            let s = reason_str(*r);
            if s.is_empty() { "Blocked".to_string() } else { format!("Blocked:{s}") }
        }
        StatAction::Suspicious(r) => {
            let s = reason_str(*r);
            if s.is_empty() { "Suspicious".to_string() } else { format!("Suspicious:{s}") }
        }
        StatAction::HighlySuspicious(r) => {
            let s = reason_str(*r);
            if s.is_empty() { "HighlySusp".to_string() } else { format!("HighlySusp:{s}") }
        }
    }
}

// ── QueryRow ──────────────────────────────────────────────────────────────────

/// One display-ready row in the Queries table.
pub struct QueryRow {
    /// Single-char indicator (`✔` / `✘` / `⚠` / `·`) — first column.
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
    /// Collapsed action kind — cross-checks colour decisions in tests.
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
        let color = DomainColor::from_action(&event.action);
        Self {
            indicator: color.indicator(),
            domain_color: color,
            datetime: format_timestamp(event.timestamp),
            domain: if domain.is_empty() {
                format!("#{:016x}", event.domain_hash)
            } else {
                domain.to_string()
            },
            client_ip: format_ip(event.client_ip),
            flags: flags_label(&event.action),
            action_kind: ActionKind::from_action(&event.action),
            reasons,
        }
    }
}

// ── FilterMode ────────────────────────────────────────────────────────────────

/// Active filter applied to the queries list.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
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

/// All mutable state owned by the Queries tab.
///
/// `TuiApp` holds one of these alongside the generic scroll offset.
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
}

impl Default for QueriesState {
    fn default() -> Self {
        Self {
            rows: VecDeque::new(),
            filter: FilterMode::default(),
            sort: SortOrder::default(),
            frozen: false,
        }
    }
}

impl QueriesState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a new event to the buffer.
    ///
    /// Does nothing when `frozen` is `true`.  When the buffer reaches
    /// `MAX_ROWS`, the oldest row is dropped in O(1) via `pop_front`.
    pub fn push_event(&mut self, event: &StatEvent, domain: &str) {
        if self.frozen {
            return;
        }
        if self.rows.len() >= MAX_ROWS {
            self.rows.pop_front();
        }
        self.rows.push_back(QueryRow::from_event(event, domain));
    }

    /// Return up to `height` rows starting at `scroll`, after applying
    /// the current filter and sort.
    ///
    /// Virtual scrolling: only `height` rows are materialised — the rest of
    /// the buffer is never visited by the renderer regardless of buffer size.
    ///
    /// * `NewestFirst` — index 0 = most recent; scrolling down shows older rows.
    /// * `OldestFirst` — index 0 = oldest; scrolling down shows newer rows.
    ///
    /// `scroll` is silently clamped so it never goes past the last row.
    pub fn visible_rows(&self, height: usize, scroll: usize) -> Vec<&QueryRow> {
        let filtered: Vec<&QueryRow> =
            self.rows.iter().filter(|r| self.filter.matches(r)).collect();
        match self.sort {
            SortOrder::NewestFirst => {
                filtered.iter().rev().skip(scroll).take(height).copied().collect()
            }
            SortOrder::OldestFirst => {
                filtered.iter().skip(scroll).take(height).copied().collect()
            }
        }
    }

    /// Total rows currently in the buffer (unfiltered).
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// Drop all buffered rows.
    pub fn clear(&mut self) {
        self.rows.clear();
    }
}

// ── Render stub ───────────────────────────────────────────────────────────────

/// Render the Queries tab body.
///
/// TODO: signature becomes
/// `render(state: &QueriesState, scroll: usize, area: Area, frame: &mut Frame)`.
pub fn render() {
    // TODO: implement with ratatui Table + Block
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{StatAction, StatBlockReason, StatEvent};

    fn ev(ts: u64, ip: [u8; 16], action: StatAction) -> StatEvent {
        StatEvent { timestamp: ts, domain_hash: 0xdead, client_ip: ip, action }
    }

    fn ipv4(a: u8, b: u8, c: u8, d: u8) -> [u8; 16] {
        [a, b, c, d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    }

    fn ipv4_mapped(a: u8, b: u8, c: u8, d: u8) -> [u8; 16] {
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, a, b, c, d]
    }

    // --- format_ip ---

    #[test]
    fn test_format_ip_ipv4() {
        assert_eq!(format_ip(ipv4(192, 168, 1, 5)), "192.168.1.5");
    }

    #[test]
    fn test_format_ip_ipv4_mapped() {
        assert_eq!(format_ip(ipv4_mapped(10, 0, 0, 1)), "10.0.0.1");
    }

    #[test]
    fn test_format_ip_full_ipv6() {
        let ip = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(format_ip(ip), "2001:0db8:0000:0000:0000:0000:0000:0001");
    }

    #[test]
    fn test_format_ip_loopback_ipv4() {
        assert_eq!(format_ip(ipv4(127, 0, 0, 1)), "127.0.0.1");
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
        assert_eq!(flags_label(&StatAction::Blocked(StatBlockReason::empty())), "Blocked");
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
        assert_eq!(flags_label(&StatAction::Blocked(r)), "Blocked:Blacklist+AbpRule");
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
            flags_label(&StatAction::HighlySuspicious(StatBlockReason::CNAME_CLOAKING)),
            "HighlySusp:CnameCloaking"
        );
    }

    // --- DomainColor / indicator ---

    #[test]
    fn test_domain_color_allowed_is_green() {
        assert_eq!(DomainColor::from_action(&StatAction::Allowed), DomainColor::Green);
    }

    #[test]
    fn test_domain_color_proxied_is_dim() {
        assert_eq!(DomainColor::from_action(&StatAction::Proxied), DomainColor::Dim);
    }

    #[test]
    fn test_domain_color_blocked_is_red() {
        assert_eq!(
            DomainColor::from_action(&StatAction::Blocked(StatBlockReason::empty())),
            DomainColor::Red
        );
    }

    #[test]
    fn test_domain_color_highly_suspicious_is_red() {
        assert_eq!(
            DomainColor::from_action(&StatAction::HighlySuspicious(StatBlockReason::empty())),
            DomainColor::Red
        );
    }

    #[test]
    fn test_domain_color_suspicious_is_yellow() {
        assert_eq!(
            DomainColor::from_action(&StatAction::Suspicious(StatBlockReason::empty())),
            DomainColor::Yellow
        );
    }

    #[test]
    fn test_indicator_symbols() {
        assert_eq!(DomainColor::Green.indicator(), INDICATOR_ALLOWED);
        assert_eq!(DomainColor::Red.indicator(), INDICATOR_BLOCKED);
        assert_eq!(DomainColor::Yellow.indicator(), INDICATOR_SUSPICIOUS);
        assert_eq!(DomainColor::Dim.indicator(), INDICATOR_PROXIED);
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
        let event = ev(0, ipv4(1, 2, 3, 4), StatAction::Blocked(StatBlockReason::STATIC_BLACKLIST));
        let row = QueryRow::from_event(&event, "bad.com");
        assert_eq!(row.domain_color, DomainColor::Red);
        assert_eq!(row.indicator, INDICATOR_BLOCKED);
    }

    #[test]
    fn test_query_row_suspicious_indicator_and_color() {
        let event = ev(0, ipv4(1, 2, 3, 4), StatAction::Suspicious(StatBlockReason::HIGH_ENTROPY));
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

    #[test]
    fn test_query_row_domain_fallback_when_empty() {
        let event = ev(0, ipv4(10, 0, 0, 1), StatAction::Proxied);
        let row = QueryRow::from_event(&event, "");
        assert!(row.domain.starts_with('#'), "fallback domain: {}", row.domain);
    }

    #[test]
    fn test_query_row_reasons_populated_for_blocked() {
        let reason = StatBlockReason::STATIC_BLACKLIST | StatBlockReason::HIGH_ENTROPY;
        let row = QueryRow::from_event(&ev(0, ipv4(1, 2, 3, 4), StatAction::Blocked(reason)), "b.com");
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
        let mut s = QueriesState::new();
        s.push_event(&ev(0, ipv4(1, 1, 1, 1), StatAction::Allowed), "a.com");
        assert_eq!(s.row_count(), 1);
    }

    #[test]
    fn test_push_frozen_does_not_add() {
        let mut s = QueriesState::new();
        s.frozen = true;
        s.push_event(&ev(0, ipv4(1, 1, 1, 1), StatAction::Allowed), "a.com");
        assert_eq!(s.row_count(), 0);
    }

    #[test]
    fn test_push_evicts_oldest_at_max_rows() {
        let mut s = QueriesState::new();
        for i in 0..MAX_ROWS {
            s.push_event(&ev(i as u64, ipv4(1, 1, 1, 1), StatAction::Allowed), "a.com");
        }
        assert_eq!(s.row_count(), MAX_ROWS);
        s.push_event(&ev(MAX_ROWS as u64, ipv4(1, 1, 1, 1), StatAction::Allowed), "a.com");
        assert_eq!(s.row_count(), MAX_ROWS);
        // oldest (ts=0) evicted; front is now ts=1
        assert_eq!(s.rows[0].datetime, "00:00:01");
    }

    // --- visible_rows: sort order ---

    #[test]
    fn test_visible_rows_newest_first_order() {
        let mut s = QueriesState::new();
        push_n(&mut s, 5);
        s.sort = SortOrder::NewestFirst;
        let rows = s.visible_rows(5, 0);
        assert_eq!(rows[0].datetime, format_timestamp(4));
        assert_eq!(rows[4].datetime, format_timestamp(0));
    }

    #[test]
    fn test_visible_rows_oldest_first_order() {
        let mut s = QueriesState::new();
        push_n(&mut s, 5);
        s.sort = SortOrder::OldestFirst;
        let rows = s.visible_rows(5, 0);
        assert_eq!(rows[0].datetime, format_timestamp(0));
        assert_eq!(rows[4].datetime, format_timestamp(4));
    }

    // --- visible_rows: virtual scroll ---

    #[test]
    fn test_visible_rows_height_limit() {
        let mut s = QueriesState::new();
        push_n(&mut s, 10);
        assert_eq!(s.visible_rows(3, 0).len(), 3);
    }

    #[test]
    fn test_visible_rows_scroll_newest_first() {
        let mut s = QueriesState::new();
        push_n(&mut s, 5); // ts 0..4
        s.sort = SortOrder::NewestFirst;
        // scroll=0: [ts4, ts3, ts2]; scroll=1: [ts3, ts2, ts1]; scroll=2: [ts2, ts1, ts0]
        assert_eq!(s.visible_rows(3, 0)[0].datetime, format_timestamp(4));
        assert_eq!(s.visible_rows(3, 1)[0].datetime, format_timestamp(3));
        assert_eq!(s.visible_rows(3, 2)[0].datetime, format_timestamp(2));
    }

    #[test]
    fn test_visible_rows_scroll_oldest_first() {
        let mut s = QueriesState::new();
        push_n(&mut s, 5); // ts 0..4
        s.sort = SortOrder::OldestFirst;
        // scroll=0: [ts0, ts1, ts2]; scroll=1: [ts1, ts2, ts3]; scroll=2: [ts2, ts3, ts4]
        assert_eq!(s.visible_rows(3, 0)[0].datetime, format_timestamp(0));
        assert_eq!(s.visible_rows(3, 1)[0].datetime, format_timestamp(1));
        assert_eq!(s.visible_rows(3, 2)[0].datetime, format_timestamp(2));
    }

    #[test]
    fn test_visible_rows_scroll_past_end_returns_empty() {
        let mut s = QueriesState::new();
        push_n(&mut s, 3);
        // scroll beyond all 3 rows → empty
        assert!(s.visible_rows(3, 10).is_empty());
    }

    // --- visible_rows: filter ---

    #[test]
    fn test_visible_rows_with_filter() {
        let mut s = QueriesState::new();
        s.push_event(&ev(0, ipv4(192, 168, 1, 1), StatAction::Allowed), "a.com");
        s.push_event(&ev(1, ipv4(10, 0, 0, 1), StatAction::Allowed), "b.com");
        s.push_event(&ev(2, ipv4(192, 168, 1, 2), StatAction::Allowed), "c.com");
        s.filter = FilterMode::ByClient("192.168".to_string());
        assert_eq!(s.visible_rows(10, 0).len(), 2);
    }

    #[test]
    fn test_clear_empties_buffer() {
        let mut s = QueriesState::new();
        push_n(&mut s, 3);
        s.clear();
        assert_eq!(s.row_count(), 0);
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
