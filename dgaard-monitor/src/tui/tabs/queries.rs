//! Queries tab — tail-style DNS event log.
//!
//! Displays a scrollable table of recent DNS events, newest on top by default:
//!
//!   Timestamp    Domain                         Client IP         Flags
//!   ──────────── ────────────────────────────── ───────────────── ─────────────────────
//!   14:23:01     example.com                    192.168.1.5       Allowed
//!   14:23:00     ads.tracker.net                192.168.1.3       Blocked:Blacklist+AbpRule
//!   14:22:58     suspicious.xyz                 192.168.1.7       Suspicious:HighEntropy
//!
//! Interactive controls:
//!   `f`     — open filter popup: enter a client IP prefix or a flag name
//!             (e.g. `"192.168"` or `"Blacklist"`).
//!   `s`     — open sort popup: toggle between newest-first and oldest-first.
//!   `z`     — toggle frozen display; the header shows `[FROZEN]` while active.
//!             New events continue to buffer in `AppState`; they appear when unfrozen.
//!   `up/dn` — scroll through the virtual list (only when not frozen at tail).
//!
//! Virtual scrolling: `visible_rows(height)` returns at most `height` display rows,
//! applying the active filter and sort.  The internal buffer is capped at `MAX_ROWS`.
//!
//! The data layer (all `pub fn`s, structs, and `QueriesState`) is pure Rust with no
//! ratatui dependency, making it fully unit-testable.
//!
//! TODO: implement `render()` with ratatui `Table` + `Block` + popup `Paragraph`.

#![allow(dead_code)]

use crate::protocol::{StatAction, StatBlockReason, StatEvent};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum rows kept in the display buffer (oldest are dropped when exceeded).
pub const MAX_ROWS: usize = 1_000;

/// Column widths used for text formatting (matches the module doc example).
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

    /// Short uppercase label used in the Flags column when there are no reasons.
    pub fn label(self) -> &'static str {
        match self {
            Self::Allowed => "Allowed",
            Self::Proxied => "Proxied",
            Self::Blocked => "Blocked",
            Self::Suspicious => "Suspicious",
            Self::HighlySuspicious => "HighlySusp",
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Format a 16-byte client IP for display.
///
/// Handles three encodings:
/// * IPv4-mapped IPv6 (`::ffff:a.b.c.d`) → `"a.b.c.d"`
/// * IPv4 in first 4 bytes, rest zero  → `"a.b.c.d"`
/// * Anything else                      → compact IPv6 hex groups
pub fn format_ip(ip: [u8; 16]) -> String {
    // IPv4-mapped: 10 zero bytes, 0xff, 0xff, then 4 address bytes
    if ip[..10] == [0u8; 10] && ip[10] == 0xff && ip[11] == 0xff {
        return format!("{}.{}.{}.{}", ip[12], ip[13], ip[14], ip[15]);
    }
    // IPv4 in first 4 bytes, remaining 12 bytes zero
    if ip[4..] == [0u8; 12] {
        return format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
    }
    // Full IPv6
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
    /// Formatted timestamp (`HH:MM:SS`).
    pub datetime: String,
    /// Resolved domain name, or `"#<hex>"` when the hash is unknown.
    pub domain: String,
    /// Formatted client IP address.
    pub client_ip: String,
    /// Flags column string (`"Allowed"`, `"Blocked:Blacklist+AbpRule"`, …).
    pub flags: String,
    /// Collapsed action kind — drives the row colour in the renderer.
    pub action_kind: ActionKind,
    /// Raw bitmask for `FilterMode::ByFlags` matching.
    /// Empty for `Allowed` / `Proxied`.
    pub reasons: StatBlockReason,
}

impl QueryRow {
    /// Build a display row from a raw event and its resolved domain name.
    ///
    /// Pass `domain` as `""` or a pre-formatted `"#<hex>"` fallback when
    /// the hash is not in the domain map.
    pub fn from_event(event: &StatEvent, domain: &str) -> Self {
        let reasons = match &event.action {
            StatAction::Blocked(r)
            | StatAction::Suspicious(r)
            | StatAction::HighlySuspicious(r) => *r,
            _ => StatBlockReason::empty(),
        };
        Self {
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
#[derive(Default)]
pub struct QueriesState {
    /// Internal buffer in insertion order (oldest index 0, newest last).
    rows: Vec<QueryRow>,
    /// Currently active filter.
    pub filter: FilterMode,
    /// Current sort order.
    pub sort: SortOrder,
    /// When `true`, `push_event` is a no-op; the buffer stays fixed.
    pub frozen: bool,
}

impl QueriesState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a new event to the buffer.
    ///
    /// Does nothing when `frozen` is `true`.  When the buffer exceeds
    /// `MAX_ROWS`, the oldest row is dropped.
    pub fn push_event(&mut self, event: &StatEvent, domain: &str) {
        if self.frozen {
            return;
        }
        if self.rows.len() >= MAX_ROWS {
            self.rows.remove(0);
        }
        self.rows.push(QueryRow::from_event(event, domain));
    }

    /// Return up to `height` rows after applying the current filter and sort.
    ///
    /// `NewestFirst`: most recent row at index 0 of the returned slice.
    /// `OldestFirst`: oldest row at index 0.
    pub fn visible_rows(&self, height: usize) -> Vec<&QueryRow> {
        let filtered: Vec<&QueryRow> = self
            .rows
            .iter()
            .filter(|r| self.filter.matches(r))
            .collect();
        match self.sort {
            SortOrder::NewestFirst => filtered.iter().rev().take(height).copied().collect(),
            SortOrder::OldestFirst => filtered.iter().take(height).copied().collect(),
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
/// TODO: signature becomes `render(app: &TuiApp, state: &QueriesState, area: Area, frame: &mut Frame)`.
pub fn render() {
    // TODO: implement with ratatui Table + Block
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{StatAction, StatBlockReason, StatEvent};

    fn ev(ts: u64, ip: [u8; 16], action: StatAction) -> StatEvent {
        StatEvent {
            timestamp: ts,
            domain_hash: 0xdead,
            client_ip: ip,
            action,
        }
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
        // 25 h = 1 h into next day → 01:00:00
        assert_eq!(format_timestamp(25 * 3600), "01:00:00");
    }

    #[test]
    fn test_format_timestamp_specific() {
        // 14*3600 + 23*60 + 01 = 51781
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
        let label = flags_label(&StatAction::Blocked(StatBlockReason::STATIC_BLACKLIST));
        assert_eq!(label, "Blocked:Blacklist");
    }

    #[test]
    fn test_flags_label_blocked_multi_flag() {
        let r = StatBlockReason::STATIC_BLACKLIST | StatBlockReason::ABP_RULE;
        let label = flags_label(&StatAction::Blocked(r));
        assert_eq!(label, "Blocked:Blacklist+AbpRule");
    }

    #[test]
    fn test_flags_label_suspicious() {
        let label = flags_label(&StatAction::Suspicious(StatBlockReason::HIGH_ENTROPY));
        assert_eq!(label, "Suspicious:HighEntropy");
    }

    #[test]
    fn test_flags_label_highly_suspicious() {
        let label = flags_label(&StatAction::HighlySuspicious(
            StatBlockReason::CNAME_CLOAKING,
        ));
        assert_eq!(label, "HighlySusp:CnameCloaking");
    }

    // --- QueryRow::from_event ---

    #[test]
    fn test_query_row_domain_resolved() {
        let event = ev(51781, ipv4(192, 168, 1, 5), StatAction::Allowed);
        let row = QueryRow::from_event(&event, "example.com");
        assert_eq!(row.datetime, "14:23:01");
        assert_eq!(row.domain, "example.com");
        assert_eq!(row.client_ip, "192.168.1.5");
        assert_eq!(row.flags, "Allowed");
        assert_eq!(row.action_kind, ActionKind::Allowed);
        assert!(row.reasons.is_empty());
    }

    #[test]
    fn test_query_row_domain_fallback_when_empty() {
        let event = ev(0, ipv4(10, 0, 0, 1), StatAction::Proxied);
        let row = QueryRow::from_event(&event, "");
        assert!(
            row.domain.starts_with('#'),
            "fallback domain should start with '#': {}",
            row.domain
        );
    }

    #[test]
    fn test_query_row_reasons_populated_for_blocked() {
        let reason = StatBlockReason::STATIC_BLACKLIST | StatBlockReason::HIGH_ENTROPY;
        let event = ev(0, ipv4(1, 2, 3, 4), StatAction::Blocked(reason));
        let row = QueryRow::from_event(&event, "bad.com");
        assert_eq!(row.reasons, reason);
        assert_eq!(row.action_kind, ActionKind::Blocked);
    }

    #[test]
    fn test_query_row_reasons_empty_for_allowed() {
        let event = ev(0, ipv4(1, 2, 3, 4), StatAction::Allowed);
        let row = QueryRow::from_event(&event, "ok.com");
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
        // Allowed rows have empty reasons, so no flags filter will match
        assert!(!FilterMode::ByFlags(StatBlockReason::STATIC_BLACKLIST).matches(&row));
    }

    // --- QueriesState ---

    fn make_state() -> QueriesState {
        QueriesState::new()
    }

    #[test]
    fn test_push_adds_row() {
        let mut s = make_state();
        s.push_event(&ev(0, ipv4(1, 1, 1, 1), StatAction::Allowed), "a.com");
        assert_eq!(s.row_count(), 1);
    }

    #[test]
    fn test_push_frozen_does_not_add() {
        let mut s = make_state();
        s.frozen = true;
        s.push_event(&ev(0, ipv4(1, 1, 1, 1), StatAction::Allowed), "a.com");
        assert_eq!(s.row_count(), 0);
    }

    #[test]
    fn test_push_evicts_oldest_at_max_rows() {
        let mut s = make_state();
        for i in 0..MAX_ROWS {
            s.push_event(
                &ev(i as u64, ipv4(1, 1, 1, 1), StatAction::Allowed),
                "a.com",
            );
        }
        assert_eq!(s.row_count(), MAX_ROWS);
        // Push one more — oldest (ts=0) should be gone
        s.push_event(
            &ev(MAX_ROWS as u64, ipv4(1, 1, 1, 1), StatAction::Allowed),
            "a.com",
        );
        assert_eq!(s.row_count(), MAX_ROWS);
        // The first row now has ts=1 (formatted 00:00:01)
        assert_eq!(s.rows[0].datetime, "00:00:01");
    }

    #[test]
    fn test_visible_rows_newest_first_order() {
        let mut s = make_state();
        for ts in 0..5u64 {
            s.push_event(&ev(ts, ipv4(1, 1, 1, 1), StatAction::Allowed), "a.com");
        }
        s.sort = SortOrder::NewestFirst;
        let rows = s.visible_rows(5);
        assert_eq!(rows[0].datetime, format_timestamp(4));
        assert_eq!(rows[4].datetime, format_timestamp(0));
    }

    #[test]
    fn test_visible_rows_oldest_first_order() {
        let mut s = make_state();
        for ts in 0..5u64 {
            s.push_event(&ev(ts, ipv4(1, 1, 1, 1), StatAction::Allowed), "a.com");
        }
        s.sort = SortOrder::OldestFirst;
        let rows = s.visible_rows(5);
        assert_eq!(rows[0].datetime, format_timestamp(0));
        assert_eq!(rows[4].datetime, format_timestamp(4));
    }

    #[test]
    fn test_visible_rows_height_limit() {
        let mut s = make_state();
        for ts in 0..10u64 {
            s.push_event(&ev(ts, ipv4(1, 1, 1, 1), StatAction::Allowed), "a.com");
        }
        assert_eq!(s.visible_rows(3).len(), 3);
    }

    #[test]
    fn test_visible_rows_with_filter() {
        let mut s = make_state();
        s.push_event(&ev(0, ipv4(192, 168, 1, 1), StatAction::Allowed), "a.com");
        s.push_event(&ev(1, ipv4(10, 0, 0, 1), StatAction::Allowed), "b.com");
        s.push_event(&ev(2, ipv4(192, 168, 1, 2), StatAction::Allowed), "c.com");
        s.filter = FilterMode::ByClient("192.168".to_string());
        assert_eq!(s.visible_rows(10).len(), 2);
    }

    #[test]
    fn test_clear_empties_buffer() {
        let mut s = make_state();
        s.push_event(&ev(0, ipv4(1, 1, 1, 1), StatAction::Allowed), "a.com");
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
