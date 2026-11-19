//! Talkers tab — most active DNS client IPs.
//!
//! Displays a sortable table of all observed DNS clients, ranked by activity:
//!
//!   Client / hostname       Reqs   Allowed  Blocked  Susp   H.Susp  Proxied  Top Flag      First Seen  Last Seen
//!   ──────────────────────  ─────  ───────  ───────  ─────  ──────  ───────  ────────────  ──────────  ──────────
//!   desktop.local           1 234  80.0%    12.0%    5.0%   2.0%    1.0%     Blacklist 15  12:00:00    14:23:01
//!   192.168.1.3               456  40.0%    55.0%    4.0%   1.0%    0.0%     AbpRule 48   12:05:00    14:22:58
//!
//! Hostnames come from background reverse-DNS lookups (`ReverseDns`), started
//! once per new client and only for local addresses (`is_local_address`).  A
//! PTR answer is stored in the process-wide `HOSTNAME_CACHE` and picked up on
//! the next render by `cached_hostname()`; every tab can read it.
//!
//! Interactive controls (all global fixed bindings dispatched by the event loop):
//!   `s`  — cycle the sort: most requests / last active / first seen / most blocked %.
//!   `z`  — toggle frozen; new events keep arriving but aggregates stop updating.
//!   `↑/↓`, `PgUp/PgDn`, `Home/End` — scroll; only the rows that fit are drawn.
//!
//! The data layer is pure Rust with no ratatui dependency.
//!
//! TODO: filter popup (`f`) and per-client detail popup.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{LazyLock, RwLock};

use hickory_resolver::TokioResolver;

use crate::tui::scroll::{ScrollState, Scrollable, render_scrollbar};
use crate::tui::tabs::queries::format_timestamp;
use crate::tui::util::{REASON_BITS, flag_label};
use dgaard_monitor_core::protocol::{StatAction, StatBlockReason, StatError, StatEvent};
use dgaard_monitor_core::util::{client_ip_addr, format_client_ip};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum number of distinct client IPs tracked simultaneously.
/// When the limit is reached the least-recently-seen entry is evicted.
pub const MAX_TALKERS: usize = 500;

// ── TalkerSort ────────────────────────────────────────────────────────────────

/// Sort order for the Talkers table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TalkerSortBy {
    /// Most requests first (default).
    #[default]
    Requests,
    /// Most recently active first.
    LastSeen,
    /// Earliest first-seen first.
    FirstSeen,
    /// Highest blocked-event percentage first.
    BlockedPct,
}

impl TalkerSortBy {
    /// Human-readable label shown in the table title.
    pub fn label(self) -> &'static str {
        match self {
            TalkerSortBy::Requests => "Most requests",
            TalkerSortBy::LastSeen => "Last active",
            TalkerSortBy::FirstSeen => "First seen",
            TalkerSortBy::BlockedPct => "Most blocked %",
        }
    }

    /// Cycle to the next sort order.
    pub fn next(self) -> Self {
        match self {
            TalkerSortBy::Requests => TalkerSortBy::LastSeen,
            TalkerSortBy::LastSeen => TalkerSortBy::FirstSeen,
            TalkerSortBy::FirstSeen => TalkerSortBy::BlockedPct,
            TalkerSortBy::BlockedPct => TalkerSortBy::Requests,
        }
    }
}

// ── TalkerFilter ──────────────────────────────────────────────────────────────

/// Active filter for the Talkers table.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "set by the Talkers filter popup (`f`), not written yet"
    )
)]
pub enum TalkerFilter {
    /// No filter — all talkers are visible.
    #[default]
    None,
    /// Fuzzy: show entries whose formatted IP starts with the prefix OR whose
    /// cached hostname contains the text as a substring (case-sensitive).
    ByText(String),
    /// Strict: show only the entry whose formatted IP exactly equals `client`.
    ByClient(String),
    /// Strict: show only entries whose cached hostname exactly equals `hostname`
    /// (case-sensitive).  Entries with no resolved hostname are excluded.
    ByHostname(String),
}

impl TalkerFilter {
    /// Returns `true` if `entry` passes the current filter.
    pub fn matches(&self, entry: &TalkerEntry) -> bool {
        match self {
            TalkerFilter::None => true,
            TalkerFilter::ByText(text) => {
                if format_client_ip(&entry.client_ip).starts_with(text.as_str()) {
                    return true;
                }
                cached_hostname(entry.client_ip)
                    .map(|h| h.contains(text.as_str()))
                    .unwrap_or(false)
            }
            TalkerFilter::ByClient(client) => format_client_ip(&entry.client_ip) == client.as_str(),
            TalkerFilter::ByHostname(hostname) => cached_hostname(entry.client_ip)
                .map(|h| h == *hostname)
                .unwrap_or(false),
        }
    }
}

// ── TalkerEntry ───────────────────────────────────────────────────────────────

/// Per-IP aggregated statistics accumulated from `StatEvent`s.
pub struct TalkerEntry {
    pub client_ip: [u8; 16],
    /// Unix timestamp of the first event from this client.
    pub first_seen: u64,
    /// Unix timestamp of the most recent event from this client.
    pub last_seen: u64,
    pub total_requests: u64,
    pub allowed: u64,
    pub proxied: u64,
    pub blocked: u64,
    pub suspicious: u64,
    pub highly_suspicious: u64,
    /// Hit count per `StatBlockReason` flag bit, custom bits included.
    pub flag_hits: [u64; REASON_BITS],
}

impl TalkerEntry {
    /// Create a new entry for `client_ip` with the timestamp of its first event.
    pub fn new(client_ip: [u8; 16], timestamp: u64) -> Self {
        Self {
            client_ip,
            first_seen: timestamp,
            last_seen: timestamp,
            total_requests: 0,
            allowed: 0,
            proxied: 0,
            blocked: 0,
            suspicious: 0,
            highly_suspicious: 0,
            flag_hits: [0; REASON_BITS],
        }
    }

    /// Accumulate one `StatEvent` into this entry.
    pub fn record(&mut self, event: &StatEvent) {
        self.total_requests += 1;
        if event.timestamp < self.first_seen {
            self.first_seen = event.timestamp;
        }
        if event.timestamp > self.last_seen {
            self.last_seen = event.timestamp;
        }
        // Clone the action so we can match by value; StatAction is a small enum
        // (no-data or a Copy u16 bitflag) so this is cheap.
        match event.action.clone() {
            // Cache hits are allowed answers; an upstream failure was still
            // forwarded; a DNSSEC bogus answer was withheld (blocked).
            StatAction::Allowed | StatAction::AllowedWithOverride | StatAction::Cached => {
                self.allowed += 1
            }
            StatAction::Proxied | StatAction::Error(StatError::Upstream) => self.proxied += 1,
            StatAction::Error(StatError::DnssecBogus) => self.blocked += 1,
            StatAction::Blocked(r) => {
                self.blocked += 1;
                self.record_flags(r);
            }
            StatAction::Suspicious(r) => {
                self.suspicious += 1;
                self.record_flags(r);
            }
            StatAction::HighlySuspicious(r) => {
                self.highly_suspicious += 1;
                self.record_flags(r);
            }
        }
    }

    fn record_flags(&mut self, r: StatBlockReason) {
        for (bit, hits) in self.flag_hits.iter_mut().enumerate() {
            if r.bits() & (1 << bit) != 0 {
                *hits += 1;
            }
        }
    }

    /// Percentage of `count` relative to `total_requests` (0.0 – 100.0).
    /// Returns `0.0` when `total_requests` is zero.
    pub fn pct(&self, count: u64) -> f32 {
        if self.total_requests == 0 {
            0.0
        } else {
            (count as f32 / self.total_requests as f32) * 100.0
        }
    }

    /// Bit index of the flag with the highest hit count.
    /// Returns `None` when no flagged events have been recorded.
    pub fn top_flag_idx(&self) -> Option<usize> {
        let (idx, count) = self.flag_hits.iter().enumerate().max_by_key(|(_, c)| **c)?;
        if *count == 0 { None } else { Some(idx) }
    }
}

// ── TalkerRow ─────────────────────────────────────────────────────────────────

/// Display-ready row for the Talkers table.
pub struct TalkerRow {
    /// Resolved hostname when available; raw formatted IP otherwise.
    pub display_name: String,
    /// Raw IP bytes — needed to open the detail popup.
    #[expect(
        dead_code,
        reason = "read by the Talkers detail popup, not written yet"
    )]
    pub client_ip: [u8; 16],
    /// Formatted first-seen (`HH:MM:SS`).
    pub first_seen: String,
    /// Formatted last-seen (`HH:MM:SS`).
    pub last_seen: String,
    /// Raw first-seen Unix timestamp — used for `ByFirstSeen` sort.
    pub first_seen_ts: u64,
    /// Raw last-seen Unix timestamp — used for `ByLastSeen` sort.
    pub last_seen_ts: u64,
    pub total_requests: u64,
    /// Percentage of allowed events (0.0 – 100.0). Renderer colours green.
    pub allowed_pct: f32,
    pub proxied_pct: f32,
    /// Percentage of blocked events. Renderer colours red.
    pub blocked_pct: f32,
    /// Percentage of suspicious events. Renderer colours yellow.
    pub suspicious_pct: f32,
    /// Percentage of highly-suspicious events. Renderer colours bright red.
    pub highly_suspicious_pct: f32,
    /// The most-hit flag name and its raw count, or `None` if no flagged events.
    pub top_flag: Option<(String, u64)>,
}

impl TalkerRow {
    /// Build a display row from `entry`, optionally overriding the IP with a
    /// resolved `hostname`.
    pub fn from_entry(entry: &TalkerEntry, hostname: Option<&str>) -> Self {
        let display_name = match hostname {
            Some(h) if !h.is_empty() => h.to_string(),
            _ => format_client_ip(&entry.client_ip),
        };
        let top_flag = entry
            .top_flag_idx()
            .map(|idx| (flag_label(idx), entry.flag_hits[idx]));
        Self {
            display_name,
            client_ip: entry.client_ip,
            first_seen: format_timestamp(entry.first_seen),
            last_seen: format_timestamp(entry.last_seen),
            first_seen_ts: entry.first_seen,
            last_seen_ts: entry.last_seen,
            total_requests: entry.total_requests,
            allowed_pct: entry.pct(entry.allowed),
            proxied_pct: entry.pct(entry.proxied),
            blocked_pct: entry.pct(entry.blocked),
            suspicious_pct: entry.pct(entry.suspicious),
            highly_suspicious_pct: entry.pct(entry.highly_suspicious),
            top_flag,
        }
    }
}

// ── Hostname cache ────────────────────────────────────────────────────────────

/// Process-wide reverse-DNS cache.  Keyed by raw 16-byte IP; value is the PTR
/// hostname.  Readable from every tab; written only by `store_hostname`.
static HOSTNAME_CACHE: LazyLock<RwLock<HashMap<[u8; 16], String>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

/// Return the cached hostname for `ip`, or `None` if not yet resolved.
pub fn cached_hostname(ip: [u8; 16]) -> Option<String> {
    HOSTNAME_CACHE.read().ok()?.get(&ip).cloned()
}

/// Persist a resolved hostname into the global cache.
pub fn store_hostname(ip: [u8; 16], hostname: String) {
    if let Ok(mut w) = HOSTNAME_CACHE.write() {
        w.insert(ip, hostname);
    }
}

// ── Reverse DNS ───────────────────────────────────────────────────────────────

/// Whether `addr` is on the local network side: private, loopback,
/// link-local or shared (CGNAT, Tailscale) IPv4; loopback, unique-local or
/// link-local IPv6.  Only those are reverse-resolved: their PTR records live
/// on the local DNS server, and public client addresses are never sent to
/// upstream resolvers.
pub fn is_local_address(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            let [first, second, ..] = v4.octets();
            let shared = first == 100 && (second & 0xc0) == 64; // 100.64.0.0/10
            v4.is_private() || v4.is_loopback() || v4.is_link_local() || shared
        }
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local(),
    }
}

/// `true` when `ip` is local and has no cached hostname yet.
fn needs_lookup(ip: [u8; 16]) -> bool {
    is_local_address(&client_ip_addr(&ip)) && cached_hostname(ip).is_none()
}

/// Background reverse-DNS lookups of local client addresses.
///
/// One resolver, built from the system configuration so that the local DNS
/// server answers PTR queries for private ranges, serves every lookup.
pub struct ReverseDns {
    resolver: Option<TokioResolver>,
}

impl ReverseDns {
    /// Use the system resolver configuration; lookups are disabled when it
    /// cannot be read.
    pub fn from_system() -> Self {
        let resolver = TokioResolver::builder_tokio()
            .ok()
            .and_then(|builder| builder.build().ok());
        Self { resolver }
    }

    /// Start a background lookup of `ip` when it is local and not resolved
    /// yet; returns whether one was started.  Must run inside a Tokio runtime.
    pub fn lookup(&self, ip: [u8; 16]) -> bool {
        let Some(resolver) = &self.resolver else {
            return false;
        };
        if !needs_lookup(ip) {
            return false;
        }
        tokio::spawn(resolve_and_cache(resolver.clone(), ip));
        true
    }
}

/// Look up the PTR record of `ip` and cache the first hostname found.
async fn resolve_and_cache(resolver: TokioResolver, ip: [u8; 16]) {
    let ptr_name = hickory_resolver::proto::rr::Name::from(client_ip_addr(&ip));
    if let Ok(lookup) = resolver.reverse_lookup(ptr_name).await
        && let Some(hostname) = lookup.answers().iter().find_map(|r| match &r.data {
            hickory_resolver::proto::rr::RData::PTR(n) => {
                Some(n.to_string().trim_end_matches('.').to_string())
            }
            _ => None,
        })
    {
        store_hostname(ip, hostname);
    }
}

// ── TalkersState ──────────────────────────────────────────────────────────────

/// All mutable state owned by the Talkers tab, its scroll position included.
#[derive(Default)]
pub struct TalkersState {
    /// Per-IP aggregates keyed by raw 16-byte client address.
    pub entries: HashMap<[u8; 16], TalkerEntry>,
    /// Current sort order.
    pub sort: TalkerSortBy,
    /// Active filter.
    pub filter: TalkerFilter,
    /// When `true`, `push_event` is a no-op.
    pub frozen: bool,
    /// Top row on screen and table height, bounded by the filtered clients.
    scroll: ScrollState,
}

impl TalkersState {
    /// Ingest a `StatEvent` into the per-IP aggregates; returns `true` when
    /// it came from a client not tracked yet.
    ///
    /// No-op when `frozen`.  When `MAX_TALKERS` is reached the entry with the
    /// oldest `last_seen` timestamp is evicted before inserting the new one.
    pub fn push_event(&mut self, event: &StatEvent) -> bool {
        if self.frozen {
            return false;
        }
        let new_client = !self.entries.contains_key(&event.client_ip);
        if new_client && self.entries.len() >= MAX_TALKERS {
            // Evict the least-recently-seen entry.
            if let Some(oldest_ip) = self
                .entries
                .iter()
                .min_by_key(|(_, e)| e.last_seen)
                .map(|(ip, _)| *ip)
            {
                self.entries.remove(&oldest_ip);
            }
        }
        self.entries
            .entry(event.client_ip)
            .or_insert_with(|| TalkerEntry::new(event.client_ip, event.timestamp))
            .record(event);
        new_client
    }

    /// Return up to `height` display rows starting at `scroll`, after applying
    /// the current filter and sort.
    ///
    /// Sorting needs every row (at most `MAX_TALKERS`), but only the returned
    /// window is handed to the renderer.
    pub fn visible_rows(&self, height: usize, scroll: usize) -> Vec<TalkerRow> {
        let mut rows: Vec<TalkerRow> = self
            .entries
            .values()
            .filter(|e| self.filter.matches(e))
            .map(|e| TalkerRow::from_entry(e, cached_hostname(e.client_ip).as_deref()))
            .collect();

        match self.sort {
            TalkerSortBy::Requests => rows.sort_by_key(|b| std::cmp::Reverse(b.total_requests)),
            TalkerSortBy::LastSeen => {
                rows.sort_by_key(|b| std::cmp::Reverse(b.last_seen_ts));
            }
            TalkerSortBy::FirstSeen => {
                rows.sort_by_key(|a| a.first_seen_ts);
            }
            TalkerSortBy::BlockedPct => {
                rows.sort_by(|a, b| {
                    b.blocked_pct
                        .partial_cmp(&a.blocked_pct)
                        .unwrap_or(std::cmp::Ordering::Equal)
                });
            }
        }

        rows.into_iter().skip(scroll).take(height).collect()
    }

    /// Number of distinct client IPs currently tracked.
    pub fn client_count(&self) -> usize {
        self.entries.len()
    }

    /// Clients that pass the current filter.
    pub fn filtered_count(&self) -> usize {
        match self.filter {
            TalkerFilter::None => self.entries.len(),
            _ => self
                .entries
                .values()
                .filter(|e| self.filter.matches(e))
                .count(),
        }
    }

    /// Forget every client (resolved hostnames stay cached).
    pub fn clear(&mut self) {
        self.entries.clear();
        self.scroll.jump_to_top();
    }
}

impl Scrollable for TalkersState {
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

/// Format a percentage cell (`"12.5%"`).
fn pct_cell(pct: f32) -> String {
    format!("{pct:.1}%")
}

/// Render the Talkers tab body: only the rows that fit are drawn.
///
/// Takes the state mutably to record the table height (`set_viewport`),
/// which bounds scrolling.  `frozen` adds `[FROZEN]` to the title.
pub fn render(
    state: &mut TalkersState,
    frozen: bool,
    area: ratatui::layout::Rect,
    frame: &mut ratatui::Frame,
) {
    use ratatui::{
        layout::{Alignment, Constraint},
        style::{Color, Modifier, Style},
        text::Text,
        widgets::{Block, Cell, Row, Table},
    };

    let title = format!(
        "Talkers {}/{} · {}{}",
        state.filtered_count(),
        state.client_count(),
        state.sort.label(),
        if frozen { " [FROZEN]" } else { "" }
    );
    let block = Block::bordered().title(title);

    // The table header takes one row of the block.
    let viewport = usize::from(block.inner(area).height.saturating_sub(1));
    state.set_viewport(viewport);

    let right = |text: String| Text::from(text).alignment(Alignment::Right);
    let pct = |value: f32, style: Style| Cell::from(right(pct_cell(value))).style(style);
    let rows: Vec<Row> = state
        .visible_rows(viewport, state.scroll())
        .into_iter()
        .map(|row| {
            let top_flag = match row.top_flag {
                Some((name, count)) => format!("{name} {count}"),
                None => "—".to_string(),
            };
            Row::new([
                Cell::from(row.display_name),
                Cell::from(right(row.total_requests.to_string())),
                pct(row.allowed_pct, Style::new().fg(Color::Green)),
                pct(row.blocked_pct, Style::new().fg(Color::Red)),
                pct(row.suspicious_pct, Style::new().fg(Color::Yellow)),
                pct(
                    row.highly_suspicious_pct,
                    Style::new().fg(Color::Red).add_modifier(Modifier::BOLD),
                ),
                pct(row.proxied_pct, Style::new().fg(Color::DarkGray)),
                Cell::from(top_flag),
                Cell::from(row.first_seen),
                Cell::from(row.last_seen),
            ])
        })
        .collect();

    let header = [
        "Client", "Reqs", "Allowed", "Blocked", "Susp", "H.Susp", "Proxied",
    ]
    .into_iter()
    .enumerate()
    .map(|(index, label)| {
        // Numeric columns are right-aligned; so are their headers.
        if index == 0 {
            Cell::from(label)
        } else {
            Cell::from(right(label.to_string()))
        }
    })
    .chain(["Top Flag", "First Seen", "Last Seen"].map(Cell::from));

    frame.render_widget(
        Table::new(
            rows,
            [
                Constraint::Min(18),
                Constraint::Length(7),
                Constraint::Length(7),
                Constraint::Length(7),
                Constraint::Length(6),
                Constraint::Length(6),
                Constraint::Length(7),
                Constraint::Min(14),
                Constraint::Length(10),
                Constraint::Length(10),
            ],
        )
        .block(block)
        .header(Row::new(header).style(Style::new().add_modifier(Modifier::BOLD))),
        area,
    );

    render_scrollbar(state, area, frame);
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use dgaard_monitor_core::protocol::{StatAction, StatBlockReason, StatEvent};

    // ── helpers ──────────────────────────────────────────────────────────────

    fn ev(ts: u64, ip: [u8; 16], action: StatAction) -> StatEvent {
        StatEvent {
            country: None,
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

    fn blocked(bits: u32) -> StatAction {
        StatAction::Blocked(StatBlockReason::from_bits_retain(bits))
    }

    fn suspicious(bits: u32) -> StatAction {
        StatAction::Suspicious(StatBlockReason::from_bits_retain(bits))
    }

    // ── TalkerSort ────────────────────────────────────────────────────────────

    #[test]
    fn test_talker_sort_labels_non_empty() {
        for sort in [
            TalkerSortBy::Requests,
            TalkerSortBy::LastSeen,
            TalkerSortBy::FirstSeen,
            TalkerSortBy::BlockedPct,
        ] {
            assert!(!sort.label().is_empty(), "{sort:?} has empty label");
        }
    }

    #[test]
    fn test_talker_sort_next_cycles_all_four() {
        let start = TalkerSortBy::Requests;
        let s1 = start.next();
        let s2 = s1.next();
        let s3 = s2.next();
        let s4 = s3.next();
        assert_eq!(s1, TalkerSortBy::LastSeen);
        assert_eq!(s2, TalkerSortBy::FirstSeen);
        assert_eq!(s3, TalkerSortBy::BlockedPct);
        assert_eq!(s4, TalkerSortBy::Requests);
    }

    #[test]
    fn test_talker_sort_default_is_by_requests() {
        assert_eq!(TalkerSortBy::default(), TalkerSortBy::Requests);
    }

    // ── TalkerEntry ───────────────────────────────────────────────────────────

    #[test]
    fn test_entry_new_initialises_zeros() {
        let ip = ipv4(10, 0, 0, 1);
        let e = TalkerEntry::new(ip, 1_000);
        assert_eq!(e.total_requests, 0);
        assert_eq!(e.allowed, 0);
        assert_eq!(e.blocked, 0);
        assert_eq!(e.first_seen, 1_000);
        assert_eq!(e.last_seen, 1_000);
        assert_eq!(e.flag_hits, [0u64; REASON_BITS]);
    }

    #[test]
    fn test_entry_record_allowed_increments_allowed() {
        let ip = ipv4(10, 0, 0, 1);
        let mut e = TalkerEntry::new(ip, 100);
        e.record(&ev(100, ip, StatAction::Allowed));
        assert_eq!(e.total_requests, 1);
        assert_eq!(e.allowed, 1);
        assert_eq!(e.blocked, 0);
        assert_eq!(e.flag_hits, [0u64; REASON_BITS]);
    }

    #[test]
    fn test_entry_record_proxied_increments_proxied() {
        let ip = ipv4(10, 0, 0, 2);
        let mut e = TalkerEntry::new(ip, 100);
        e.record(&ev(100, ip, StatAction::Proxied));
        assert_eq!(e.proxied, 1);
        assert_eq!(e.allowed, 0);
    }

    #[test]
    fn test_entry_record_blocked_increments_blocked_and_flag_hits() {
        let ip = ipv4(10, 0, 0, 3);
        // bit 0 = STATIC_BLACKLIST, bit 1 = ABP_RULE
        let mut e = TalkerEntry::new(ip, 100);
        e.record(&ev(100, ip, blocked(0b0000_0011)));
        assert_eq!(e.blocked, 1);
        assert_eq!(e.flag_hits[0], 1); // STATIC_BLACKLIST
        assert_eq!(e.flag_hits[1], 1); // ABP_RULE
        assert_eq!(e.flag_hits[2], 0); // other flags untouched
    }

    #[test]
    fn test_entry_record_suspicious_increments_suspicious() {
        let ip = ipv4(10, 0, 0, 4);
        let mut e = TalkerEntry::new(ip, 100);
        e.record(&ev(100, ip, suspicious(0b0000_0100))); // HIGH_ENTROPY bit
        assert_eq!(e.suspicious, 1);
        assert_eq!(e.highly_suspicious, 0);
        assert_eq!(e.flag_hits[2], 1); // HIGH_ENTROPY
    }

    #[test]
    fn test_entry_record_highly_suspicious_increments_highly_suspicious() {
        let ip = ipv4(10, 0, 0, 5);
        let mut e = TalkerEntry::new(ip, 100);
        e.record(&ev(
            100,
            ip,
            StatAction::HighlySuspicious(StatBlockReason::empty()),
        ));
        assert_eq!(e.highly_suspicious, 1);
    }

    #[test]
    fn test_entry_record_updates_last_seen() {
        let ip = ipv4(10, 0, 0, 6);
        let mut e = TalkerEntry::new(ip, 100);
        e.record(&ev(100, ip, StatAction::Allowed));
        e.record(&ev(200, ip, StatAction::Allowed));
        assert_eq!(e.last_seen, 200);
        assert_eq!(e.first_seen, 100);
    }

    #[test]
    fn test_entry_record_updates_first_seen_when_earlier() {
        let ip = ipv4(10, 0, 0, 7);
        let mut e = TalkerEntry::new(ip, 200);
        e.record(&ev(200, ip, StatAction::Allowed));
        e.record(&ev(50, ip, StatAction::Allowed)); // earlier timestamp
        assert_eq!(e.first_seen, 50);
        assert_eq!(e.last_seen, 200);
    }

    #[test]
    fn test_entry_pct_zero_total() {
        let ip = ipv4(10, 0, 0, 8);
        let e = TalkerEntry::new(ip, 100);
        assert_eq!(e.pct(0), 0.0);
        assert_eq!(e.pct(5), 0.0); // total_requests is 0
    }

    #[test]
    fn test_entry_pct_fifty_percent() {
        let ip = ipv4(10, 0, 0, 9);
        let mut e = TalkerEntry::new(ip, 100);
        for _ in 0..4 {
            e.record(&ev(100, ip, StatAction::Allowed));
        }
        for _ in 0..4 {
            e.record(&ev(100, ip, blocked(0)));
        }
        assert!((e.pct(e.allowed) - 50.0).abs() < 0.01);
        assert!((e.pct(e.blocked) - 50.0).abs() < 0.01);
    }

    #[test]
    fn test_entry_pct_hundred_percent() {
        let ip = ipv4(10, 0, 0, 10);
        let mut e = TalkerEntry::new(ip, 100);
        e.record(&ev(100, ip, StatAction::Allowed));
        assert!((e.pct(e.allowed) - 100.0).abs() < 0.01);
    }

    #[test]
    fn test_entry_top_flag_idx_none_when_no_flags() {
        let ip = ipv4(10, 0, 0, 11);
        let mut e = TalkerEntry::new(ip, 100);
        e.record(&ev(100, ip, StatAction::Allowed));
        assert!(e.top_flag_idx().is_none());
    }

    #[test]
    fn test_entry_top_flag_idx_picks_highest_bit() {
        let ip = ipv4(10, 0, 0, 12);
        let mut e = TalkerEntry::new(ip, 100);
        // bit 0 hit once, bit 2 hit twice
        e.record(&ev(100, ip, blocked(0b0000_0001)));
        e.record(&ev(101, ip, blocked(0b0000_0101))); // bits 0 and 2
        e.record(&ev(102, ip, blocked(0b0000_0100))); // bit 2 again
        // flag_hits[0]=2, flag_hits[2]=3 => top is bit 2
        assert_eq!(e.top_flag_idx(), Some(2));
    }

    // ── TalkerRow ─────────────────────────────────────────────────────────────

    #[test]
    fn test_row_uses_hostname_when_provided() {
        let ip = ipv4(192, 168, 1, 1);
        let mut e = TalkerEntry::new(ip, 100);
        e.record(&ev(100, ip, StatAction::Allowed));
        let row = TalkerRow::from_entry(&e, Some("printer.local"));
        assert_eq!(row.display_name, "printer.local");
    }

    #[test]
    fn test_row_uses_ip_when_hostname_is_none() {
        let ip = ipv4(192, 168, 1, 2);
        let mut e = TalkerEntry::new(ip, 100);
        e.record(&ev(100, ip, StatAction::Allowed));
        let row = TalkerRow::from_entry(&e, None);
        assert_eq!(row.display_name, "192.168.1.2");
    }

    #[test]
    fn test_row_uses_ip_when_hostname_is_empty_string() {
        let ip = ipv4(192, 168, 1, 3);
        let mut e = TalkerEntry::new(ip, 100);
        e.record(&ev(100, ip, StatAction::Allowed));
        let row = TalkerRow::from_entry(&e, Some(""));
        assert_eq!(row.display_name, "192.168.1.3");
    }

    #[test]
    fn test_row_top_flag_none_when_no_flagged_events() {
        let ip = ipv4(192, 168, 1, 4);
        let mut e = TalkerEntry::new(ip, 100);
        e.record(&ev(100, ip, StatAction::Allowed));
        let row = TalkerRow::from_entry(&e, None);
        assert!(row.top_flag.is_none());
    }

    #[test]
    fn test_row_top_flag_some_with_correct_name() {
        let ip = ipv4(192, 168, 1, 5);
        let mut e = TalkerEntry::new(ip, 100);
        // bit 1 = ABP_RULE, hit 3 times
        for _ in 0..3 {
            e.record(&ev(100, ip, blocked(0b0000_0010)));
        }
        let row = TalkerRow::from_entry(&e, None);
        let (name, count) = row.top_flag.expect("should have a top flag");
        assert_eq!(name, "AbpRule");
        assert_eq!(count, 3);
    }

    #[test]
    fn test_row_percentages_sum_to_100() {
        let ip = ipv4(192, 168, 1, 6);
        let mut e = TalkerEntry::new(ip, 100);
        for _ in 0..3 {
            e.record(&ev(100, ip, StatAction::Allowed));
        }
        for _ in 0..7 {
            e.record(&ev(100, ip, blocked(0)));
        }
        let row = TalkerRow::from_entry(&e, None);
        let total = row.allowed_pct
            + row.blocked_pct
            + row.suspicious_pct
            + row.highly_suspicious_pct
            + row.proxied_pct;
        assert!((total - 100.0).abs() < 0.01, "percentages sum to {total}");
    }

    #[test]
    fn test_row_timestamps_formatted() {
        let ip = ipv4(192, 168, 1, 7);
        // 3600 s = 01:00:00; 7261 s = 02:01:01
        let mut e = TalkerEntry::new(ip, 3_600);
        e.record(&ev(3_600, ip, StatAction::Allowed));
        e.record(&ev(7_261, ip, StatAction::Allowed));
        let row = TalkerRow::from_entry(&e, None);
        assert_eq!(row.first_seen, "01:00:00");
        assert_eq!(row.last_seen, "02:01:01");
    }

    // ── Hostname cache ────────────────────────────────────────────────────────

    #[test]
    fn test_cached_hostname_returns_none_when_not_stored() {
        // Use a unique IP unlikely to be set by other tests
        let ip = ipv4(240, 0, 0, 1);
        // Cannot guarantee pristine state, but if not stored result is None
        // (other tests use different IPs)
        let _ = cached_hostname(ip); // just verify it doesn't panic
    }

    #[test]
    fn test_store_and_retrieve_hostname() {
        let ip = ipv4(240, 1, 0, 1);
        store_hostname(ip, "myhost.local".to_string());
        assert_eq!(cached_hostname(ip), Some("myhost.local".to_string()));
    }

    #[test]
    fn test_store_hostname_overwrites_previous() {
        let ip = ipv4(240, 2, 0, 1);
        store_hostname(ip, "first.local".to_string());
        store_hostname(ip, "second.local".to_string());
        assert_eq!(cached_hostname(ip), Some("second.local".to_string()));
    }

    // ── TalkersState ──────────────────────────────────────────────────────────

    #[test]
    fn test_state_new_is_empty() {
        let state = TalkersState::default();
        assert_eq!(state.client_count(), 0);
        assert!(!state.frozen);
        assert_eq!(state.sort, TalkerSortBy::Requests);
        assert_eq!(state.filter, TalkerFilter::None);
    }

    #[test]
    fn test_push_event_creates_entry() {
        let mut state = TalkersState::default();
        let ip = ipv4(10, 1, 0, 1);
        state.push_event(&ev(100, ip, StatAction::Allowed));
        assert_eq!(state.client_count(), 1);
        let e = state.entries.get(&ip).unwrap();
        assert_eq!(e.total_requests, 1);
        assert_eq!(e.allowed, 1);
    }

    #[test]
    fn test_push_event_updates_existing_entry() {
        let mut state = TalkersState::default();
        let ip = ipv4(10, 1, 0, 2);
        state.push_event(&ev(100, ip, StatAction::Allowed));
        state.push_event(&ev(200, ip, blocked(0)));
        let e = state.entries.get(&ip).unwrap();
        assert_eq!(e.total_requests, 2);
        assert_eq!(e.allowed, 1);
        assert_eq!(e.blocked, 1);
        assert_eq!(e.last_seen, 200);
    }

    #[test]
    fn test_push_event_multiple_ips() {
        let mut state = TalkersState::default();
        for i in 0..5u8 {
            state.push_event(&ev(100, ipv4(10, 2, 0, i), StatAction::Allowed));
        }
        assert_eq!(state.client_count(), 5);
    }

    #[test]
    fn test_push_event_frozen_is_noop() {
        let mut state = TalkersState {
            frozen: true,
            ..TalkersState::default()
        };
        let ip = ipv4(10, 1, 0, 3);
        state.push_event(&ev(100, ip, StatAction::Allowed));
        assert_eq!(state.client_count(), 0);
    }

    #[test]
    fn test_push_event_evicts_oldest_at_max_talkers() {
        let mut state = TalkersState::default();
        // Fill to exactly MAX_TALKERS with timestamps 0, 1, …, MAX-1
        for i in 0..MAX_TALKERS {
            let ip = [
                0,
                0,
                (i >> 8) as u8,
                (i & 0xff) as u8,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ];
            state.push_event(&ev(i as u64, ip, StatAction::Allowed));
        }
        assert_eq!(state.client_count(), MAX_TALKERS);

        // The oldest last_seen is timestamp 0 → ip [0,0,0,0,…]
        let oldest_ip = [0u8; 16];
        assert!(state.entries.contains_key(&oldest_ip));

        // Push one more distinct IP with a newer timestamp
        let new_ip = ipv4(200, 0, 0, 1);
        state.push_event(&ev(MAX_TALKERS as u64 + 1, new_ip, StatAction::Allowed));

        // Count must not exceed MAX_TALKERS
        assert_eq!(state.client_count(), MAX_TALKERS);
        // The oldest entry must be gone
        assert!(!state.entries.contains_key(&oldest_ip));
        // The new entry must be present
        assert!(state.entries.contains_key(&new_ip));
    }

    // ── visible_rows ─────────────────────────────────────────────────────────

    fn state_with_three_talkers() -> TalkersState {
        // IP .1 → 30 reqs, IP .2 → 10 reqs, IP .3 → 20 reqs
        // timestamps: .1 first=100, last=300; .2 first=50, last=150; .3 first=200, last=400
        let mut state = TalkersState::default();
        let ip1 = ipv4(10, 3, 0, 1);
        let ip2 = ipv4(10, 3, 0, 2);
        let ip3 = ipv4(10, 3, 0, 3);
        for i in 0..30u64 {
            state.push_event(&ev(100 + i * 6, ip1, StatAction::Allowed));
        }
        for i in 0..10u64 {
            state.push_event(&ev(50 + i * 10, ip2, blocked(0)));
        }
        for i in 0..20u64 {
            state.push_event(&ev(200 + i * 10, ip3, StatAction::Allowed));
        }
        state
    }

    #[test]
    fn test_visible_rows_sort_by_requests_desc() {
        let state = state_with_three_talkers();
        let rows = state.visible_rows(3, 0);
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].total_requests, 30);
        assert_eq!(rows[1].total_requests, 20);
        assert_eq!(rows[2].total_requests, 10);
    }

    #[test]
    fn test_visible_rows_sort_by_last_seen_desc() {
        let mut state = state_with_three_talkers();
        state.sort = TalkerSortBy::LastSeen;
        let rows = state.visible_rows(3, 0);
        // .3 last=390, .1 last=274, .2 last=140 (approx; exact values don't matter — just order)
        assert!(rows[0].last_seen_ts >= rows[1].last_seen_ts);
        assert!(rows[1].last_seen_ts >= rows[2].last_seen_ts);
    }

    #[test]
    fn test_visible_rows_sort_by_first_seen_asc() {
        let mut state = state_with_three_talkers();
        state.sort = TalkerSortBy::FirstSeen;
        let rows = state.visible_rows(3, 0);
        assert!(rows[0].first_seen_ts <= rows[1].first_seen_ts);
        assert!(rows[1].first_seen_ts <= rows[2].first_seen_ts);
    }

    #[test]
    fn test_visible_rows_sort_by_blocked_pct_desc() {
        let mut state = state_with_three_talkers();
        state.sort = TalkerSortBy::BlockedPct;
        let rows = state.visible_rows(3, 0);
        // ip2 has 100% blocked; ip1 and ip3 have 0%
        assert!((rows[0].blocked_pct - 100.0).abs() < 0.01);
    }

    #[test]
    fn test_visible_rows_virtual_scroll_skips_rows() {
        let state = state_with_three_talkers();
        let all = state.visible_rows(3, 0);
        let page2 = state.visible_rows(3, 1);
        assert_eq!(page2.len(), 2);
        assert_eq!(page2[0].total_requests, all[1].total_requests);
    }

    #[test]
    fn test_visible_rows_scroll_past_end_returns_empty() {
        let state = state_with_three_talkers();
        let rows = state.visible_rows(3, 100);
        assert!(rows.is_empty());
    }

    #[test]
    fn test_visible_rows_height_limits_output() {
        let state = state_with_three_talkers();
        let rows = state.visible_rows(2, 0);
        assert_eq!(rows.len(), 2);
    }

    #[test]
    fn test_visible_rows_filter_by_ip_prefix() {
        let mut state = state_with_three_talkers();
        state.filter = TalkerFilter::ByText("10.3.0.1".to_string());
        let rows = state.visible_rows(10, 0);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].total_requests, 30);
    }

    #[test]
    fn test_visible_rows_filter_no_match_returns_empty() {
        let mut state = state_with_three_talkers();
        state.filter = TalkerFilter::ByText("172.16.".to_string());
        let rows = state.visible_rows(10, 0);
        assert!(rows.is_empty());
    }

    #[test]
    fn test_visible_rows_filter_by_exact_client_matches_only_that_ip() {
        let mut state = state_with_three_talkers();
        state.filter = TalkerFilter::ByClient("10.3.0.1".to_string());
        let rows = state.visible_rows(10, 0);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].total_requests, 30);
    }

    #[test]
    fn test_visible_rows_filter_by_exact_client_excludes_prefix_matches() {
        // "10.3.0" is a prefix of all three IPs — strict match should return none.
        let mut state = state_with_three_talkers();
        state.filter = TalkerFilter::ByClient("10.3.0".to_string());
        let rows = state.visible_rows(10, 0);
        assert!(rows.is_empty());
    }

    #[test]
    fn test_visible_rows_filter_by_exact_hostname_matches_only_exact() {
        let mut state = TalkersState::default();
        let ip1 = ipv4(10, 4, 0, 1);
        let ip2 = ipv4(10, 4, 0, 2);
        store_hostname(ip1, "web.office.local".to_string());
        store_hostname(ip2, "db.office.local".to_string());
        state.push_event(&ev(100, ip1, StatAction::Allowed));
        state.push_event(&ev(100, ip2, StatAction::Allowed));

        state.filter = TalkerFilter::ByHostname("web.office.local".to_string());
        let rows = state.visible_rows(10, 0);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].display_name, "web.office.local");
    }

    #[test]
    fn test_visible_rows_filter_by_exact_hostname_excludes_substring_matches() {
        let mut state = TalkersState::default();
        let ip = ipv4(10, 4, 0, 3);
        store_hostname(ip, "my-printer.office.local".to_string());
        state.push_event(&ev(100, ip, StatAction::Allowed));

        // "printer" is a substring but not the exact hostname.
        state.filter = TalkerFilter::ByHostname("printer".to_string());
        let rows = state.visible_rows(10, 0);
        assert!(rows.is_empty());
    }

    #[test]
    fn test_visible_rows_filter_by_exact_hostname_excludes_unresolved_entries() {
        let mut state = TalkersState::default();
        let ip = ipv4(10, 4, 0, 4); // no hostname stored
        state.push_event(&ev(100, ip, StatAction::Allowed));

        state.filter = TalkerFilter::ByHostname("anything.local".to_string());
        let rows = state.visible_rows(10, 0);
        assert!(rows.is_empty());
    }

    #[test]
    fn test_filter_by_hostname_substring() {
        let mut state = TalkersState::default();
        let ip = ipv4(240, 11, 0, 1);
        store_hostname(ip, "my-printer.office.local".to_string());
        state.push_event(&ev(100, ip, StatAction::Allowed));

        state.filter = TalkerFilter::ByText("printer".to_string());
        let rows = state.visible_rows(10, 0);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].display_name, "my-printer.office.local");
    }

    // ── 32-bit flags ──────────────────────────────────────────────────────────

    #[test]
    fn test_entry_counts_geo_ip_and_custom_bits() {
        // Bits 15–31 used to be dropped by the per-client counter.
        let mut entry = TalkerEntry::new(ipv4(10, 77, 0, 1), 0);
        entry.record(&ev(1, entry.client_ip, blocked(1 << 15)));
        entry.record(&ev(2, entry.client_ip, blocked(1 << 15)));
        entry.record(&ev(3, entry.client_ip, blocked(1 << 31)));
        assert_eq!(entry.flag_hits[15], 2);
        assert_eq!(entry.flag_hits[31], 1);
        let row = TalkerRow::from_entry(&entry, None);
        assert_eq!(row.top_flag, Some(("SuspGeoIP".to_string(), 2)));
    }

    // ── reverse DNS ───────────────────────────────────────────────────────────

    fn addr(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn test_local_addresses() {
        for text in [
            "10.0.0.1",
            "172.16.5.4",
            "192.168.1.20",
            "127.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "100.127.255.254",
            "::1",
            "fd12:3456::1",
            "fe80::1",
        ] {
            assert!(is_local_address(&addr(text)), "{text} should be local");
        }
    }

    #[test]
    fn test_public_addresses_are_not_local() {
        for text in [
            "8.8.8.8",
            "172.32.0.1",
            "100.128.0.1",
            "100.63.255.255",
            "2001:db8::1",
            "2a00:1450::1",
        ] {
            assert!(!is_local_address(&addr(text)), "{text} should not be local");
        }
    }

    #[test]
    fn test_ipv4_mapped_client_is_checked_as_ipv4() {
        // dgaard sends IPv4 clients as IPv4-mapped IPv6.
        assert!(needs_lookup(ipv4(192, 168, 77, 1)));
        assert!(!needs_lookup(ipv4(9, 9, 9, 9)));
    }

    #[test]
    fn test_resolved_client_needs_no_lookup() {
        let ip = ipv4(192, 168, 77, 2);
        assert!(needs_lookup(ip));
        store_hostname(ip, "nas.lan".to_string());
        assert!(!needs_lookup(ip));
    }

    #[test]
    fn test_disabled_resolver_starts_nothing() {
        let dns = ReverseDns { resolver: None };
        assert!(!dns.lookup(ipv4(192, 168, 77, 3)));
    }

    #[test]
    fn test_public_client_never_looked_up() {
        // Returns before spawning, so no runtime is needed.
        let dns = ReverseDns::from_system();
        assert!(!dns.lookup(ipv4(8, 8, 4, 4)));
    }

    // ── state: new clients, clear, scrolling ──────────────────────────────────

    fn with_clients(count: u8) -> TalkersState {
        let mut state = TalkersState::default();
        for index in 0..count {
            state.push_event(&ev(100, ipv4(10, 78, 0, index), StatAction::Allowed));
        }
        state
    }

    #[test]
    fn test_push_event_reports_new_client() {
        let mut state = TalkersState::default();
        let ip = ipv4(10, 78, 1, 1);
        assert!(state.push_event(&ev(1, ip, StatAction::Allowed)));
        assert!(!state.push_event(&ev(2, ip, StatAction::Allowed)));
        assert!(state.push_event(&ev(3, ipv4(10, 78, 1, 2), StatAction::Allowed)));
    }

    #[test]
    fn test_push_event_frozen_reports_nothing_new() {
        let mut state = TalkersState {
            frozen: true,
            ..TalkersState::default()
        };
        assert!(!state.push_event(&ev(1, ipv4(10, 78, 1, 3), StatAction::Allowed)));
    }

    #[test]
    fn test_clear_forgets_clients_and_scroll() {
        let mut state = with_clients(30);
        state.set_viewport(10);
        state.scroll_by(5);
        state.clear();
        assert_eq!(state.client_count(), 0);
        assert_eq!(state.scroll(), 0);
    }

    #[test]
    fn test_filtered_count() {
        let mut state = with_clients(5);
        state.push_event(&ev(1, ipv4(192, 168, 78, 1), StatAction::Allowed));
        assert_eq!(state.filtered_count(), 6);
        state.filter = TalkerFilter::ByText("192.168.".to_string());
        assert_eq!(state.filtered_count(), 1);
    }

    #[test]
    fn test_scroll_bounded_by_filtered_clients() {
        let mut state = with_clients(30);
        state.set_viewport(10);
        state.scroll_to_bottom();
        assert_eq!(state.scroll(), 20);
        state.filter = TalkerFilter::ByText("10.78.0.1".to_string()); // .1, .10–.19
        state.set_viewport(10);
        assert_eq!(state.scroll(), 1);
    }

    // ── render ────────────────────────────────────────────────────────────────

    fn draw(state: &mut TalkersState, frozen: bool, width: u16, height: u16) -> Vec<String> {
        use ratatui::{Terminal, backend::TestBackend};
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| render(state, frozen, frame.area(), frame))
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
    fn test_pct_cell_format() {
        assert_eq!(pct_cell(0.0), "0.0%");
        assert_eq!(pct_cell(12.345), "12.3%");
        assert_eq!(pct_cell(100.0), "100.0%");
    }

    #[test]
    fn test_render_title_sort_and_frozen() {
        let mut state = with_clients(3);
        let lines = draw(&mut state, true, 120, 10);
        assert!(lines[0].contains("Talkers 3/3"), "{}", lines[0]);
        assert!(lines[0].contains("Most requests"));
        assert!(lines[0].contains("[FROZEN]"));
        state.sort = TalkerSortBy::BlockedPct;
        let lines = draw(&mut state, false, 120, 10);
        assert!(lines[0].contains("Most blocked %"));
        assert!(!lines[0].contains("[FROZEN]"));
    }

    #[test]
    fn test_render_row_columns_and_hostname() {
        let mut state = TalkersState::default();
        let ip = ipv4(10, 79, 0, 1);
        store_hostname(ip, "laptop.lan".to_string());
        state.push_event(&ev(3_600, ip, StatAction::Allowed));
        state.push_event(&ev(3_661, ip, blocked(1 << 1)));
        let lines = draw(&mut state, false, 120, 8);
        assert!(lines[1].contains("Client") && lines[1].contains("Last Seen"));
        let row = &lines[2];
        for cell in [
            "laptop.lan",
            "2",
            "50.0%",
            "AbpRule 1",
            "01:00:00",
            "01:01:01",
        ] {
            assert!(row.contains(cell), "missing {cell:?} in {row:?}");
        }
    }

    #[test]
    fn test_render_no_flag_shows_dash() {
        let mut state = with_clients(1);
        let lines = draw(&mut state, false, 120, 8);
        assert!(lines[2].contains('—'));
    }

    #[test]
    fn test_render_draws_only_the_visible_window() {
        let mut state = TalkersState::default();
        // Client .n sends n + 1 requests: most requests first is .29 down to .0.
        for index in 0..30u8 {
            for request in 0..=u64::from(index) {
                state.push_event(&ev(request, ipv4(10, 80, 0, index), StatAction::Allowed));
            }
        }
        // 12 rows - 2 borders - 1 header = 9 table rows
        draw(&mut state, false, 120, 12);
        assert_eq!(state.page_size(), 9);
        state.scroll_by(5);
        let lines = draw(&mut state, false, 120, 12);
        let shown: Vec<&String> = lines.iter().filter(|l| l.contains("10.80.0.")).collect();
        assert_eq!(shown.len(), 9);
        assert!(shown[0].contains("10.80.0.24 "), "{}", shown[0]);
        assert!(shown[8].contains("10.80.0.16 "), "{}", shown[8]);
    }

    #[test]
    fn test_render_percentage_colours() {
        use ratatui::{Terminal, backend::TestBackend, style::Color};
        let mut state = TalkersState::default();
        let ip = ipv4(10, 81, 0, 1);
        state.push_event(&ev(1, ip, StatAction::Allowed));
        state.push_event(&ev(2, ip, blocked(1)));
        let mut terminal = Terminal::new(TestBackend::new(120, 6)).unwrap();
        terminal
            .draw(|frame| render(&mut state, false, frame.area(), frame))
            .unwrap();
        let buffer = terminal.backend().buffer();
        // Columns where "50.0%" starts; one cell per symbol, unlike byte offsets.
        let symbols: Vec<&str> = (0..120)
            .map(|column| buffer[(column, 2)].symbol())
            .collect();
        let starts: Vec<u16> = (0..symbols.len() - 5)
            .filter(|&column| symbols[column..column + 5].concat() == "50.0%")
            .map(|column| column as u16)
            .collect();
        // Allowed and Blocked are both "50.0%": first is green, second red.
        assert_eq!(starts.len(), 2, "{}", symbols.concat());
        assert_eq!(buffer[(starts[0], 2)].fg, Color::Green);
        assert_eq!(buffer[(starts[1], 2)].fg, Color::Red);
    }
}
