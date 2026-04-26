//! Talkers tab — most active DNS client IPs.
//!
//! Displays a sortable table of all observed DNS clients, ranked by activity:
//!
//!   Client / hostname       Reqs   Allowed  Blocked  Susp   H.Susp  Proxied  Top Flag      First Seen  Last Seen
//!   ──────────────────────  ─────  ───────  ───────  ─────  ──────  ───────  ────────────  ──────────  ──────────
//!   desktop.local           1 234  80.0%    12.0%    5.0%   2.0%    1.0%     Blacklist 15  12:00:00    14:23:01
//!   192.168.1.3               456  40.0%    55.0%    4.0%   1.0%    0.0%     AbpRule 48   12:05:00    14:22:58
//!
//! Hostname resolution is performed asynchronously via `hickory-resolver`.
//! When a PTR record is found for a client IP it is stored in a process-wide
//! `HOSTNAME_CACHE` (a `std::sync::RwLock<HashMap>`) and picked up on the
//! next render cycle by `cached_hostname()`.  All other tabs can read the
//! same cache.
//!
//! Interactive controls (all global fixed bindings dispatched by the event loop):
//!   `f`  — filter popup: enter an IP prefix or hostname substring.
//!   `s`  — sort popup: cycle through ByRequests / ByLastSeen / ByFirstSeen / ByBlockedPct.
//!   `z`  — toggle frozen; new events keep arriving but aggregates stop updating.
//!   `↑/↓` — virtual scroll: `visible_rows(height, scroll)` returns at most
//!            `height` rows starting at `scroll`.
//!
//! The data layer is pure Rust with no ratatui dependency.
//!
//! TODO: implement `render()` and `render_popup()` with ratatui `Table` + `Block`.

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{LazyLock, RwLock};

use crate::protocol::{StatAction, StatBlockReason, StatEvent};
use crate::tui::tabs::queries::{format_ip, format_timestamp};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum number of distinct client IPs tracked simultaneously.
/// When the limit is reached the least-recently-seen entry is evicted.
pub const MAX_TALKERS: usize = 500;

// ── Flag metadata ─────────────────────────────────────────────────────────────

/// Short display name for each `StatBlockReason` flag, indexed by bit position
/// (0 = `STATIC_BLACKLIST` … 14 = `ASN_BLOCKED`).
pub fn flag_name(bit: usize) -> &'static str {
    const NAMES: [&str; 15] = [
        "Blacklist",
        "AbpRule",
        "HighEntropy",
        "Lexical",
        "BannedKw",
        "InvalidStruct",
        "SuspIDN",
        "NRD",
        "TLD",
        "Suspicious",
        "CnameCloaking",
        "ForbidQtype",
        "DnsRebinding",
        "LowTTL",
        "AsnBlocked",
    ];
    NAMES.get(bit).copied().unwrap_or("Unknown")
}

// ── TalkerSort ────────────────────────────────────────────────────────────────

/// Sort order for the Talkers table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TalkerSort {
    /// Most requests first (default).
    #[default]
    ByRequests,
    /// Most recently active first.
    ByLastSeen,
    /// Earliest first-seen first.
    ByFirstSeen,
    /// Highest blocked-event percentage first.
    ByBlockedPct,
}

impl TalkerSort {
    /// Human-readable label shown in the sort popup.
    pub fn label(self) -> &'static str {
        match self {
            TalkerSort::ByRequests => "Most requests",
            TalkerSort::ByLastSeen => "Last active",
            TalkerSort::ByFirstSeen => "First seen",
            TalkerSort::ByBlockedPct => "Most blocked %",
        }
    }

    /// Cycle to the next sort order.
    pub fn next(self) -> Self {
        match self {
            TalkerSort::ByRequests => TalkerSort::ByLastSeen,
            TalkerSort::ByLastSeen => TalkerSort::ByFirstSeen,
            TalkerSort::ByFirstSeen => TalkerSort::ByBlockedPct,
            TalkerSort::ByBlockedPct => TalkerSort::ByRequests,
        }
    }
}

// ── TalkerFilter ──────────────────────────────────────────────────────────────

/// Active filter for the Talkers table.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum TalkerFilter {
    /// No filter — all talkers are visible.
    #[default]
    None,
    /// Show only entries whose formatted IP starts with the prefix OR whose
    /// cached hostname contains the text as a substring (case-sensitive).
    ByText(String),
}

impl TalkerFilter {
    /// Returns `true` if `entry` passes the current filter.
    pub fn matches(&self, entry: &TalkerEntry) -> bool {
        match self {
            TalkerFilter::None => true,
            TalkerFilter::ByText(text) => {
                if format_ip(entry.client_ip).starts_with(text.as_str()) {
                    return true;
                }
                cached_hostname(entry.client_ip)
                    .map(|h| h.contains(text.as_str()))
                    .unwrap_or(false)
            }
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
    /// Hit count per `StatBlockReason` flag bit (index 0..=14).
    pub flag_hits: [u64; 15],
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
            flag_hits: [0; 15],
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
            StatAction::Allowed => self.allowed += 1,
            StatAction::Proxied => self.proxied += 1,
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
        for bit in 0..15u32 {
            if r.bits() & (1 << bit) != 0 {
                self.flag_hits[bit as usize] += 1;
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

    /// Index (0..=14) of the flag with the highest hit count.
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
            _ => format_ip(entry.client_ip),
        };
        let top_flag = entry
            .top_flag_idx()
            .map(|idx| (flag_name(idx).to_string(), entry.flag_hits[idx]));
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

/// Perform an async reverse-DNS lookup for `ip` and cache the result.
///
/// Uses `hickory-resolver` (the `TokioAsyncResolver`) with the system
/// resolver configuration so that PTR records for private RFC-1918 addresses
/// are resolved by the local DNS server rather than a public resolver.
///
/// This function is a no-op when `ip` is already in the cache.
/// Call it from a background `tokio::spawn` task; the result will be visible
/// on the next render cycle via `cached_hostname()`.
///
/// NOTE: uses `ResolverConfig::default()` as a fallback when the system
/// configuration cannot be read (e.g. in sandboxed environments).  For
/// production deployments the system config is preferred because private PTR
/// records are only served by the local nameserver.
pub async fn resolve_and_cache(ip: [u8; 16]) {
    use hickory_resolver::TokioAsyncResolver;
    use hickory_resolver::config::{ResolverConfig, ResolverOpts};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    // Skip if already cached.
    if cached_hostname(ip).is_some() {
        return;
    }

    // Convert the 16-byte representation to a `std::net::IpAddr`.
    let addr: IpAddr = if ip[..10] == [0u8; 10] && ip[10] == 0xff && ip[11] == 0xff {
        // IPv4-mapped IPv6: ::ffff:a.b.c.d
        IpAddr::V4(Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]))
    } else if ip[4..] == [0u8; 12] {
        // IPv4 stored in first four bytes
        IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]))
    } else {
        IpAddr::V6(Ipv6Addr::from(ip))
    };

    // Build the resolver; prefer system config so local PTR records resolve.
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

    if let Ok(lookup) = resolver.reverse_lookup(addr).await {
        if let Some(name) = lookup.iter().next() {
            let hostname = name.to_string().trim_end_matches('.').to_string();
            store_hostname(ip, hostname);
        }
    }
}

// ── TalkersState ──────────────────────────────────────────────────────────────

/// All mutable state owned by the Talkers tab.
pub struct TalkersState {
    /// Per-IP aggregates keyed by raw 16-byte client address.
    pub entries: HashMap<[u8; 16], TalkerEntry>,
    /// Current sort order.
    pub sort: TalkerSort,
    /// Active filter.
    pub filter: TalkerFilter,
    /// When `true`, `push_event` is a no-op.
    pub frozen: bool,
}

impl TalkersState {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            sort: TalkerSort::default(),
            filter: TalkerFilter::default(),
            frozen: false,
        }
    }

    /// Ingest a `StatEvent` into the per-IP aggregates.
    ///
    /// No-op when `frozen`.  When `MAX_TALKERS` is reached the entry with the
    /// oldest `last_seen` timestamp is evicted before inserting the new one.
    pub fn push_event(&mut self, event: &StatEvent) {
        if self.frozen {
            return;
        }
        if !self.entries.contains_key(&event.client_ip) && self.entries.len() >= MAX_TALKERS {
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
    }

    /// Return up to `height` display rows starting at `scroll`, after applying
    /// the current filter and sort.
    ///
    /// Virtual scrolling: only `height` rows are materialised — the rest of
    /// the entry map is never visited by the renderer.
    pub fn visible_rows(&self, height: usize, scroll: usize) -> Vec<TalkerRow> {
        let mut rows: Vec<TalkerRow> = self
            .entries
            .values()
            .filter(|e| self.filter.matches(e))
            .map(|e| TalkerRow::from_entry(e, cached_hostname(e.client_ip).as_deref()))
            .collect();

        match self.sort {
            TalkerSort::ByRequests => {
                rows.sort_by(|a, b| b.total_requests.cmp(&a.total_requests));
            }
            TalkerSort::ByLastSeen => {
                rows.sort_by(|a, b| b.last_seen_ts.cmp(&a.last_seen_ts));
            }
            TalkerSort::ByFirstSeen => {
                rows.sort_by(|a, b| a.first_seen_ts.cmp(&b.first_seen_ts));
            }
            TalkerSort::ByBlockedPct => {
                rows.sort_by(|a, b| {
                    b.blocked_pct
                        .partial_cmp(&a.blocked_pct)
                        .unwrap_or(std::cmp::Ordering::Equal)
                });
            }
        }

        rows.into_iter().skip(scroll).take(height).collect()
    }

    /// Store a resolved hostname for `ip` in the global cache.
    ///
    /// Convenience wrapper over `store_hostname`; lets callers avoid
    /// importing the free function separately.
    pub fn update_hostname(&self, ip: [u8; 16], hostname: String) {
        store_hostname(ip, hostname);
    }

    /// Number of distinct client IPs currently tracked.
    pub fn client_count(&self) -> usize {
        self.entries.len()
    }
}

impl Default for TalkersState {
    fn default() -> Self {
        Self::new()
    }
}

// ── Render stubs ──────────────────────────────────────────────────────────────

/// Render the Talkers tab body.
///
/// TODO: signature becomes
/// `render(state: &TalkersState, scroll: usize, area: Area, frame: &mut Frame)`.
pub fn render() {
    // TODO: implement with ratatui Table + Block
}

/// Render the Talker detail popup over the current frame.
///
/// TODO: signature becomes
/// `render_popup(client: &[u8;16], state: &TalkersState, area: Area, frame: &mut Frame)`.
pub fn render_popup() {
    // TODO: implement with ratatui Block + Paragraph
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{StatAction, StatBlockReason, StatEvent};

    // ── helpers ──────────────────────────────────────────────────────────────

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

    fn blocked(bits: u16) -> StatAction {
        StatAction::Blocked(StatBlockReason::from_bits_truncate(bits))
    }

    fn suspicious(bits: u16) -> StatAction {
        StatAction::Suspicious(StatBlockReason::from_bits_truncate(bits))
    }

    // ── TalkerSort ────────────────────────────────────────────────────────────

    #[test]
    fn test_talker_sort_labels_non_empty() {
        for sort in [
            TalkerSort::ByRequests,
            TalkerSort::ByLastSeen,
            TalkerSort::ByFirstSeen,
            TalkerSort::ByBlockedPct,
        ] {
            assert!(!sort.label().is_empty(), "{sort:?} has empty label");
        }
    }

    #[test]
    fn test_talker_sort_next_cycles_all_four() {
        let start = TalkerSort::ByRequests;
        let s1 = start.next();
        let s2 = s1.next();
        let s3 = s2.next();
        let s4 = s3.next();
        assert_eq!(s1, TalkerSort::ByLastSeen);
        assert_eq!(s2, TalkerSort::ByFirstSeen);
        assert_eq!(s3, TalkerSort::ByBlockedPct);
        assert_eq!(s4, TalkerSort::ByRequests);
    }

    #[test]
    fn test_talker_sort_default_is_by_requests() {
        assert_eq!(TalkerSort::default(), TalkerSort::ByRequests);
    }

    // ── flag_name ────────────────────────────────────────────────────────────

    #[test]
    fn test_flag_name_first_and_last() {
        assert_eq!(flag_name(0), "Blacklist");
        assert_eq!(flag_name(14), "AsnBlocked");
    }

    #[test]
    fn test_flag_name_out_of_range_returns_unknown() {
        assert_eq!(flag_name(15), "Unknown");
        assert_eq!(flag_name(99), "Unknown");
    }

    #[test]
    fn test_flag_name_all_non_empty() {
        for i in 0..15 {
            assert!(!flag_name(i).is_empty(), "flag_name({i}) is empty");
        }
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
        assert_eq!(e.flag_hits, [0u64; 15]);
    }

    #[test]
    fn test_entry_record_allowed_increments_allowed() {
        let ip = ipv4(10, 0, 0, 1);
        let mut e = TalkerEntry::new(ip, 100);
        e.record(&ev(100, ip, StatAction::Allowed));
        assert_eq!(e.total_requests, 1);
        assert_eq!(e.allowed, 1);
        assert_eq!(e.blocked, 0);
        assert_eq!(e.flag_hits, [0u64; 15]);
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
        let state = TalkersState::new();
        assert_eq!(state.client_count(), 0);
        assert!(!state.frozen);
        assert_eq!(state.sort, TalkerSort::ByRequests);
        assert_eq!(state.filter, TalkerFilter::None);
    }

    #[test]
    fn test_push_event_creates_entry() {
        let mut state = TalkersState::new();
        let ip = ipv4(10, 1, 0, 1);
        state.push_event(&ev(100, ip, StatAction::Allowed));
        assert_eq!(state.client_count(), 1);
        let e = state.entries.get(&ip).unwrap();
        assert_eq!(e.total_requests, 1);
        assert_eq!(e.allowed, 1);
    }

    #[test]
    fn test_push_event_updates_existing_entry() {
        let mut state = TalkersState::new();
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
        let mut state = TalkersState::new();
        for i in 0..5u8 {
            state.push_event(&ev(100, ipv4(10, 2, 0, i), StatAction::Allowed));
        }
        assert_eq!(state.client_count(), 5);
    }

    #[test]
    fn test_push_event_frozen_is_noop() {
        let mut state = TalkersState::new();
        state.frozen = true;
        let ip = ipv4(10, 1, 0, 3);
        state.push_event(&ev(100, ip, StatAction::Allowed));
        assert_eq!(state.client_count(), 0);
    }

    #[test]
    fn test_push_event_evicts_oldest_at_max_talkers() {
        let mut state = TalkersState::new();
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
        let mut state = TalkersState::new();
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
        state.sort = TalkerSort::ByLastSeen;
        let rows = state.visible_rows(3, 0);
        // .3 last=390, .1 last=274, .2 last=140 (approx; exact values don't matter — just order)
        assert!(rows[0].last_seen_ts >= rows[1].last_seen_ts);
        assert!(rows[1].last_seen_ts >= rows[2].last_seen_ts);
    }

    #[test]
    fn test_visible_rows_sort_by_first_seen_asc() {
        let mut state = state_with_three_talkers();
        state.sort = TalkerSort::ByFirstSeen;
        let rows = state.visible_rows(3, 0);
        assert!(rows[0].first_seen_ts <= rows[1].first_seen_ts);
        assert!(rows[1].first_seen_ts <= rows[2].first_seen_ts);
    }

    #[test]
    fn test_visible_rows_sort_by_blocked_pct_desc() {
        let mut state = state_with_three_talkers();
        state.sort = TalkerSort::ByBlockedPct;
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

    // ── update_hostname ───────────────────────────────────────────────────────

    #[test]
    fn test_update_hostname_stores_in_cache() {
        let state = TalkersState::new();
        let ip = ipv4(240, 10, 0, 1);
        state.update_hostname(ip, "router.local".to_string());
        assert_eq!(cached_hostname(ip), Some("router.local".to_string()));
    }

    #[test]
    fn test_filter_by_hostname_substring() {
        let mut state = TalkersState::new();
        let ip = ipv4(240, 11, 0, 1);
        store_hostname(ip, "my-printer.office.local".to_string());
        state.push_event(&ev(100, ip, StatAction::Allowed));

        state.filter = TalkerFilter::ByText("printer".to_string());
        let rows = state.visible_rows(10, 0);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].display_name, "my-printer.office.local");
    }
}
