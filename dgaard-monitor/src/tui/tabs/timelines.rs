//! Timelines tab — scrollable bucketed DNS activity timeline.
//!
//! Displays a table where each row represents one time bucket:
//!
//!   Time            Queries  [bar]                          Clients
//!   ────────────    ───────  ──────────────────────────     ───────
//!   14:00            1 234   ██████████▓▓▓░░░░░░░░░░░░░        42
//!   15:00              456   ████▓░░░░░░░░░░░░░░░░░░░░░        17
//!
//! Bar segments are coloured by action type (renderer responsibility):
//!   green  = Allowed   (`DomainColor::Green`)
//!   dim    = Proxied   (`DomainColor::Dim`)
//!   yellow = Suspicious / HighlySuspicious (`DomainColor::Yellow`)
//!   red    = Blocked   (`DomainColor::Red`)
//!
//! Bucket granularity cycles with the `t` key:
//!   1d → 1h → 30m → 15m → 1m → 1d …
//! Default is 1 hour.  Changing the zoom clears all accumulated buckets.
//!
//! Rows with no events are still shown (empty bar) so the timeline has no gaps
//! between the earliest and latest observed event.  Up to `MAX_BUCKETS` (256)
//! rows are kept; the oldest bucket is evicted when the limit is exceeded.
//!
//! Only timestamp-based ordering is supported (`t` key toggles newest/oldest).
//!
//! The data layer is pure Rust with no ratatui dependency.
//!
//! TODO: implement `render()` with ratatui `Table` + `Block`.

#![allow(dead_code)]

use std::collections::{HashMap, HashSet};

use crate::protocol::{StatAction, StatEvent};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum number of time buckets retained simultaneously.
/// Scrolling is capped at this many lines.
pub const MAX_BUCKETS: usize = 256;

// ── TimeZoom ──────────────────────────────────────────────────────────────────

/// Granularity of each time bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TimeZoom {
    /// One-minute buckets.
    OneMin,
    /// Fifteen-minute buckets.
    FifteenMin,
    /// Thirty-minute buckets.
    ThirtyMin,
    /// One-hour buckets (default).
    #[default]
    OneHour,
    /// One-day buckets.
    OneDay,
}

impl TimeZoom {
    /// Duration of one bucket in seconds.
    pub fn seconds(self) -> u64 {
        match self {
            Self::OneMin => 60,
            Self::FifteenMin => 900,
            Self::ThirtyMin => 1_800,
            Self::OneHour => 3_600,
            Self::OneDay => 86_400,
        }
    }

    /// Short human-readable label shown in the status bar.
    pub fn label(self) -> &'static str {
        match self {
            Self::OneMin => "1m",
            Self::FifteenMin => "15m",
            Self::ThirtyMin => "30m",
            Self::OneHour => "1h",
            Self::OneDay => "1d",
        }
    }

    /// Cycle: 1h → 1d → 1h → 30m → 15m → 1m → 1d …
    /// (pressing `t` from the default 1h goes to 1d, then wraps around)
    pub fn next(self) -> Self {
        match self {
            Self::OneHour => Self::OneDay,
            Self::OneDay => Self::ThirtyMin,
            Self::ThirtyMin => Self::FifteenMin,
            Self::FifteenMin => Self::OneMin,
            Self::OneMin => Self::OneHour,
        }
    }
}

// ── TimelineSort ──────────────────────────────────────────────────────────────

/// Sort direction for the timeline table (timestamp only).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TimelineSort {
    /// Newest bucket at the top (default).
    #[default]
    NewestFirst,
    /// Oldest bucket at the top.
    OldestFirst,
}

impl TimelineSort {
    pub fn label(self) -> &'static str {
        match self {
            Self::NewestFirst => "newest first",
            Self::OldestFirst => "oldest first",
        }
    }

    pub fn next(self) -> Self {
        match self {
            Self::NewestFirst => Self::OldestFirst,
            Self::OldestFirst => Self::NewestFirst,
        }
    }
}

// ── Bucket label formatting ───────────────────────────────────────────────────

/// Format a bucket start Unix timestamp for the given zoom level.
///
/// * `OneDay`   → `"YYYY-MM-DD"` (Gregorian calendar, no external crate).
/// * `OneMin`   → `"HH:MM:SS"` (seconds precision).
/// * others     → `"HH:MM"`.
pub fn format_bucket_label(ts: u64, zoom: TimeZoom) -> String {
    match zoom {
        TimeZoom::OneDay => epoch_to_date(ts),
        TimeZoom::OneMin => {
            let secs = ts % 86_400;
            let h = secs / 3_600;
            let m = (secs % 3_600) / 60;
            let s = secs % 60;
            format!("{h:02}:{m:02}:{s:02}")
        }
        _ => {
            let secs = ts % 86_400;
            let h = secs / 3_600;
            let m = (secs % 3_600) / 60;
            format!("{h:02}:{m:02}")
        }
    }
}

/// Convert a Unix timestamp to `"YYYY-MM-DD"` using the proleptic Gregorian
/// calendar algorithm by Howard Hinnant (public domain).
pub fn epoch_to_date(ts: u64) -> String {
    let days = (ts / 86_400) as i64;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

// ── BucketEntry ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
struct BucketEntry {
    allowed: u64,
    proxied: u64,
    blocked: u64,
    suspicious: u64,
    highly_suspicious: u64,
    clients: HashSet<[u8; 16]>,
}

impl BucketEntry {
    fn record(&mut self, event: &StatEvent) {
        match event.action.clone() {
            StatAction::Allowed => self.allowed += 1,
            StatAction::Proxied => self.proxied += 1,
            StatAction::Blocked(_) => self.blocked += 1,
            StatAction::Suspicious(_) => self.suspicious += 1,
            StatAction::HighlySuspicious(_) => self.highly_suspicious += 1,
        }
        self.clients.insert(event.client_ip);
    }

    fn total(&self) -> u64 {
        self.allowed + self.proxied + self.blocked + self.suspicious + self.highly_suspicious
    }
}

// ── TimelineRow ───────────────────────────────────────────────────────────────

/// A single displayable row in the Timelines table.
#[derive(Debug, Clone)]
pub struct TimelineRow {
    /// Formatted bucket start label (e.g. `"14:00"` or `"2024-01-15"`).
    pub bucket_label: String,
    /// Raw bucket start timestamp; used for sort stability checks.
    pub bucket_ts: u64,
    pub allowed: u64,
    pub proxied: u64,
    pub blocked: u64,
    pub suspicious: u64,
    pub highly_suspicious: u64,
    /// Total queries across all action types.
    pub total: u64,
    /// Distinct client IPs observed in this bucket.
    pub client_count: usize,
}

impl TimelineRow {
    fn from_bucket(ts: u64, entry: &BucketEntry, zoom: TimeZoom) -> Self {
        Self {
            bucket_label: format_bucket_label(ts, zoom),
            bucket_ts: ts,
            allowed: entry.allowed,
            proxied: entry.proxied,
            blocked: entry.blocked,
            suspicious: entry.suspicious,
            highly_suspicious: entry.highly_suspicious,
            total: entry.total(),
            client_count: entry.clients.len(),
        }
    }

    fn empty(ts: u64, zoom: TimeZoom) -> Self {
        Self {
            bucket_label: format_bucket_label(ts, zoom),
            bucket_ts: ts,
            allowed: 0,
            proxied: 0,
            blocked: 0,
            suspicious: 0,
            highly_suspicious: 0,
            total: 0,
            client_count: 0,
        }
    }
}

// ── TimelinesState ────────────────────────────────────────────────────────────

/// Mutable state for the Timelines tab.
pub struct TimelinesState {
    /// Aggregated per-bucket data, keyed by bucket start timestamp.
    buckets: HashMap<u64, BucketEntry>,
    /// Active time granularity.
    pub zoom: TimeZoom,
    /// Active sort direction.
    pub sort: TimelineSort,
    /// When frozen, `push_event` is a no-op.
    pub frozen: bool,
}

impl TimelinesState {
    pub fn new() -> Self {
        Self {
            buckets: HashMap::new(),
            zoom: TimeZoom::default(),
            sort: TimelineSort::default(),
            frozen: false,
        }
    }

    /// Ingest one event into the appropriate time bucket.
    ///
    /// No-op when `frozen`.  Evicts the oldest bucket (smallest timestamp)
    /// when `MAX_BUCKETS` would be exceeded.
    pub fn push_event(&mut self, event: &StatEvent) {
        if self.frozen {
            return;
        }
        let zoom_secs = self.zoom.seconds();
        let key = (event.timestamp / zoom_secs) * zoom_secs;
        if !self.buckets.contains_key(&key)
            && self.buckets.len() >= MAX_BUCKETS
            && let Some(&oldest) = self.buckets.keys().min()
        {
            self.buckets.remove(&oldest);
        }
        self.buckets.entry(key).or_default().record(event);
    }

    /// Advance to the next zoom level and clear all accumulated buckets.
    ///
    /// Buckets are cleared because they were built at the old granularity and
    /// cannot be reused.
    pub fn cycle_zoom(&mut self) {
        self.zoom = self.zoom.next();
        self.buckets.clear();
    }

    /// Toggle sort direction between newest-first and oldest-first.
    pub fn cycle_sort(&mut self) {
        self.sort = self.sort.next();
    }

    /// Toggle the frozen flag.
    pub fn toggle_frozen(&mut self) {
        self.frozen = !self.frozen;
    }

    /// Return at most `height` rows starting at `scroll`.
    ///
    /// The full row set spans every bucket between the earliest and latest
    /// observed timestamp (inclusive), filling gaps with empty rows so the
    /// display has no holes.  The list is capped at `MAX_BUCKETS` entries
    /// before paging.
    pub fn visible_rows(&self, height: usize, scroll: usize) -> Vec<TimelineRow> {
        if self.buckets.is_empty() {
            return Vec::new();
        }

        let zoom_secs = self.zoom.seconds();
        let &min_ts = self.buckets.keys().min().unwrap();
        let &max_ts = self.buckets.keys().max().unwrap();
        let span = (max_ts - min_ts) / zoom_secs;

        let mut rows: Vec<TimelineRow> = (0..=span)
            .map(|i| {
                let ts = min_ts + i * zoom_secs;
                match self.buckets.get(&ts) {
                    Some(entry) => TimelineRow::from_bucket(ts, entry, self.zoom),
                    None => TimelineRow::empty(ts, self.zoom),
                }
            })
            .take(MAX_BUCKETS)
            .collect();

        match self.sort {
            TimelineSort::NewestFirst => {
                rows.sort_unstable_by(|a, b| b.bucket_ts.cmp(&a.bucket_ts))
            }
            TimelineSort::OldestFirst => {
                rows.sort_unstable_by(|a, b| a.bucket_ts.cmp(&b.bucket_ts))
            }
        }

        rows.into_iter().skip(scroll).take(height).collect()
    }

    /// Total number of rows in the dense timeline (including empty gap buckets),
    /// capped at `MAX_BUCKETS`.
    pub fn total_rows(&self) -> usize {
        if self.buckets.is_empty() {
            return 0;
        }
        let zoom_secs = self.zoom.seconds();
        let &min_ts = self.buckets.keys().min().unwrap();
        let &max_ts = self.buckets.keys().max().unwrap();
        ((max_ts - min_ts) / zoom_secs + 1).min(MAX_BUCKETS as u64) as usize
    }

    /// Number of buckets that have at least one event.
    pub fn active_bucket_count(&self) -> usize {
        self.buckets.len()
    }

    /// Maximum total query count across all buckets (used by the renderer to
    /// scale bar widths).
    pub fn max_queries(&self) -> u64 {
        self.buckets.values().map(|e| e.total()).max().unwrap_or(0)
    }

    /// Maximum distinct client count across all buckets (used by the renderer
    /// to scale the client bar).
    pub fn max_clients(&self) -> usize {
        self.buckets
            .values()
            .map(|e| e.clients.len())
            .max()
            .unwrap_or(0)
    }
}

impl Default for TimelinesState {
    fn default() -> Self {
        Self::new()
    }
}

/// Render the Timelines tab body.
///
/// TODO: signature becomes `render(app: &TuiApp, state: &TimelinesState, area: Rect, frame: &mut Frame)`.
/// Body will draw a `Table` whose rows come from `state.visible_rows(height, scroll)`.
/// Bar cells are built by splitting a fixed-width cell into coloured spans
/// proportional to `allowed / total`, `proxied / total`, etc., using
/// `DomainColor` constants from `crate::tui::util`.
pub fn render() {
    // TODO: implement with ratatui Table + Block
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{StatBlockReason, StatEvent};

    // ── helpers ──────────────────────────────────────────────────────────────

    fn make_event(ts: u64, action: StatAction) -> StatEvent {
        StatEvent {
            timestamp: ts,
            domain_hash: 0,
            client_ip: [192, 168, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            action,
        }
    }

    fn make_event_ip(ts: u64, action: StatAction, ip: [u8; 16]) -> StatEvent {
        StatEvent {
            timestamp: ts,
            domain_hash: 0,
            client_ip: ip,
            action,
        }
    }

    fn allowed(ts: u64) -> StatEvent {
        make_event(ts, StatAction::Allowed)
    }
    fn blocked(ts: u64) -> StatEvent {
        make_event(ts, StatAction::Blocked(StatBlockReason::empty()))
    }
    fn suspicious(ts: u64) -> StatEvent {
        make_event(ts, StatAction::Suspicious(StatBlockReason::empty()))
    }
    fn highly_suspicious(ts: u64) -> StatEvent {
        make_event(ts, StatAction::HighlySuspicious(StatBlockReason::empty()))
    }
    fn proxied(ts: u64) -> StatEvent {
        make_event(ts, StatAction::Proxied)
    }

    // ── TimeZoom ─────────────────────────────────────────────────────────────

    #[test]
    fn test_zoom_seconds() {
        assert_eq!(TimeZoom::OneMin.seconds(), 60);
        assert_eq!(TimeZoom::FifteenMin.seconds(), 900);
        assert_eq!(TimeZoom::ThirtyMin.seconds(), 1_800);
        assert_eq!(TimeZoom::OneHour.seconds(), 3_600);
        assert_eq!(TimeZoom::OneDay.seconds(), 86_400);
    }

    #[test]
    fn test_zoom_labels() {
        assert_eq!(TimeZoom::OneMin.label(), "1m");
        assert_eq!(TimeZoom::FifteenMin.label(), "15m");
        assert_eq!(TimeZoom::ThirtyMin.label(), "30m");
        assert_eq!(TimeZoom::OneHour.label(), "1h");
        assert_eq!(TimeZoom::OneDay.label(), "1d");
    }

    #[test]
    fn test_zoom_default_is_one_hour() {
        assert_eq!(TimeZoom::default(), TimeZoom::OneHour);
    }

    #[test]
    fn test_zoom_next_cycles_fully() {
        let mut z = TimeZoom::default(); // 1h
        z = z.next();
        assert_eq!(z, TimeZoom::OneDay);
        z = z.next();
        assert_eq!(z, TimeZoom::ThirtyMin);
        z = z.next();
        assert_eq!(z, TimeZoom::FifteenMin);
        z = z.next();
        assert_eq!(z, TimeZoom::OneMin);
        z = z.next();
        assert_eq!(z, TimeZoom::OneHour); // wraps back
    }

    // ── TimelineSort ─────────────────────────────────────────────────────────

    #[test]
    fn test_sort_default_is_newest_first() {
        assert_eq!(TimelineSort::default(), TimelineSort::NewestFirst);
    }

    #[test]
    fn test_sort_next_toggles() {
        assert_eq!(TimelineSort::NewestFirst.next(), TimelineSort::OldestFirst);
        assert_eq!(TimelineSort::OldestFirst.next(), TimelineSort::NewestFirst);
    }

    #[test]
    fn test_sort_labels() {
        assert_eq!(TimelineSort::NewestFirst.label(), "newest first");
        assert_eq!(TimelineSort::OldestFirst.label(), "oldest first");
    }

    // ── epoch_to_date ─────────────────────────────────────────────────────────

    #[test]
    fn test_epoch_to_date_unix_epoch() {
        assert_eq!(epoch_to_date(0), "1970-01-01");
    }

    #[test]
    fn test_epoch_to_date_known_date() {
        // 2024-01-15 00:00:00 UTC
        // Days from epoch: 19723 (to 2024-01-01) + 14 = 19737
        let ts = 19737_u64 * 86_400;
        assert_eq!(epoch_to_date(ts), "2024-01-15");
    }

    #[test]
    fn test_epoch_to_date_leap_year() {
        // 2000-02-29 exists (leap year divisible by 400)
        // Days from 1970-01-01 to 2000-02-29: 30 years roughly
        // 2000-01-01 is day 10957; Feb 29 is day 10957 + 31 + 28 = 11016 (+1 for 0-index)
        // Actually let's compute: 1970→2000 = 30 years, leap years: 1972,76,80,84,88,92,96 = 7
        // 23*365 + 7*366 = 8395 + 2562 = 10957 days to 2000-01-01
        // + 31 (Jan) + 28 (Feb 1-28) + 1 (Feb 29) = 60 extra days
        let ts = (10957 + 31 + 28) as u64 * 86_400;
        assert_eq!(epoch_to_date(ts), "2000-02-29");
    }

    #[test]
    fn test_epoch_to_date_end_of_year() {
        // 2023-12-31 00:00:00 UTC
        // Days from epoch to 2023-01-01: 19358 (approx)
        // 2023-01-01: 53 years from 1970; leaps: 72,76,80,84,88,92,96,00,04,08,12,16,20 = 13
        // 40*365 + 13*366 = 14600 + 4758 = 19358 days
        // + 364 days to Dec 31
        let ts = (19358 + 364) as u64 * 86_400;
        assert_eq!(epoch_to_date(ts), "2023-12-31");
    }

    #[test]
    fn test_epoch_to_date_mid_timestamp() {
        // Timestamp mid-day should still give the correct date
        let ts = 19737_u64 * 86_400 + 43200; // noon on 2024-01-15
        assert_eq!(epoch_to_date(ts), "2024-01-15");
    }

    // ── format_bucket_label ───────────────────────────────────────────────────

    #[test]
    fn test_format_bucket_label_one_day() {
        let ts = 0; // 1970-01-01
        assert_eq!(format_bucket_label(ts, TimeZoom::OneDay), "1970-01-01");
    }

    #[test]
    fn test_format_bucket_label_one_hour() {
        // 14:00:00 = 14*3600 = 50400 seconds into a day
        let ts = 50400;
        assert_eq!(format_bucket_label(ts, TimeZoom::OneHour), "14:00");
    }

    #[test]
    fn test_format_bucket_label_thirty_min() {
        let ts = 50400 + 1800; // 14:30
        assert_eq!(format_bucket_label(ts, TimeZoom::ThirtyMin), "14:30");
    }

    #[test]
    fn test_format_bucket_label_fifteen_min() {
        let ts = 50400 + 900; // 14:15
        assert_eq!(format_bucket_label(ts, TimeZoom::FifteenMin), "14:15");
    }

    #[test]
    fn test_format_bucket_label_one_min_has_seconds() {
        let ts = 50400 + 60; // 14:01:00
        assert_eq!(format_bucket_label(ts, TimeZoom::OneMin), "14:01:00");
    }

    // ── push_event / bucket aggregation ──────────────────────────────────────

    #[test]
    fn test_push_event_creates_bucket() {
        let mut s = TimelinesState::new();
        s.push_event(&allowed(3600));
        assert_eq!(s.active_bucket_count(), 1);
    }

    #[test]
    fn test_push_event_same_bucket_accumulates() {
        let mut s = TimelinesState::new();
        s.push_event(&allowed(3600));
        s.push_event(&allowed(3601));
        s.push_event(&blocked(7199));
        assert_eq!(s.active_bucket_count(), 1);
        assert_eq!(s.max_queries(), 3);
    }

    #[test]
    fn test_push_event_two_buckets() {
        let mut s = TimelinesState::new();
        s.push_event(&allowed(3600)); // bucket 3600
        s.push_event(&allowed(7200)); // bucket 7200
        assert_eq!(s.active_bucket_count(), 2);
    }

    #[test]
    fn test_push_event_all_action_types() {
        let mut s = TimelinesState::new();
        s.push_event(&allowed(3600));
        s.push_event(&proxied(3601));
        s.push_event(&blocked(3602));
        s.push_event(&suspicious(3603));
        s.push_event(&highly_suspicious(3604));
        let rows = s.visible_rows(10, 0);
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.allowed, 1);
        assert_eq!(row.proxied, 1);
        assert_eq!(row.blocked, 1);
        assert_eq!(row.suspicious, 1);
        assert_eq!(row.highly_suspicious, 1);
        assert_eq!(row.total, 5);
    }

    #[test]
    fn test_push_event_frozen_no_op() {
        let mut s = TimelinesState::new();
        s.frozen = true;
        s.push_event(&allowed(3600));
        assert_eq!(s.active_bucket_count(), 0);
    }

    #[test]
    fn test_push_event_evicts_oldest_at_limit() {
        let mut s = TimelinesState::new();
        let zoom = TimeZoom::OneHour.seconds();
        // Fill exactly MAX_BUCKETS
        for i in 0..MAX_BUCKETS as u64 {
            s.push_event(&allowed(i * zoom));
        }
        assert_eq!(s.active_bucket_count(), MAX_BUCKETS);

        // Adding one more should evict the oldest (ts=0)
        let new_ts = MAX_BUCKETS as u64 * zoom;
        s.push_event(&allowed(new_ts));
        assert_eq!(s.active_bucket_count(), MAX_BUCKETS);
        // Oldest bucket should be gone
        assert!(!s.buckets.contains_key(&0));
        assert!(s.buckets.contains_key(&new_ts));
    }

    // ── cycle_zoom ────────────────────────────────────────────────────────────

    #[test]
    fn test_cycle_zoom_advances() {
        let mut s = TimelinesState::new();
        assert_eq!(s.zoom, TimeZoom::OneHour);
        s.cycle_zoom();
        assert_eq!(s.zoom, TimeZoom::OneDay);
    }

    #[test]
    fn test_cycle_zoom_clears_buckets() {
        let mut s = TimelinesState::new();
        s.push_event(&allowed(3600));
        assert_eq!(s.active_bucket_count(), 1);
        s.cycle_zoom();
        assert_eq!(s.active_bucket_count(), 0);
    }

    // ── cycle_sort / toggle_frozen ────────────────────────────────────────────

    #[test]
    fn test_cycle_sort_toggles() {
        let mut s = TimelinesState::new();
        assert_eq!(s.sort, TimelineSort::NewestFirst);
        s.cycle_sort();
        assert_eq!(s.sort, TimelineSort::OldestFirst);
        s.cycle_sort();
        assert_eq!(s.sort, TimelineSort::NewestFirst);
    }

    #[test]
    fn test_toggle_frozen() {
        let mut s = TimelinesState::new();
        assert!(!s.frozen);
        s.toggle_frozen();
        assert!(s.frozen);
        s.toggle_frozen();
        assert!(!s.frozen);
    }

    // ── visible_rows ─────────────────────────────────────────────────────────

    #[test]
    fn test_visible_rows_empty_state() {
        let s = TimelinesState::new();
        assert!(s.visible_rows(10, 0).is_empty());
    }

    #[test]
    fn test_visible_rows_single_bucket() {
        let mut s = TimelinesState::new();
        s.push_event(&allowed(3600));
        let rows = s.visible_rows(10, 0);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].bucket_ts, 3600);
        assert_eq!(rows[0].total, 1);
    }

    #[test]
    fn test_visible_rows_fills_empty_gaps() {
        let mut s = TimelinesState::new();
        // Two events two hours apart — should produce 3 rows (14:00, 15:00, 16:00)
        s.push_event(&allowed(3600 * 14));
        s.push_event(&allowed(3600 * 16));
        let rows = s.visible_rows(10, 0);
        assert_eq!(rows.len(), 3, "gap bucket should be included");
        // Middle bucket is empty
        let gap = rows.iter().find(|r| r.bucket_ts == 3600 * 15).unwrap();
        assert_eq!(gap.total, 0);
        assert_eq!(gap.client_count, 0);
    }

    #[test]
    fn test_visible_rows_newest_first_order() {
        let mut s = TimelinesState::new();
        s.push_event(&allowed(3600));
        s.push_event(&allowed(7200));
        let rows = s.visible_rows(10, 0);
        assert_eq!(s.sort, TimelineSort::NewestFirst);
        assert!(rows[0].bucket_ts > rows[1].bucket_ts);
    }

    #[test]
    fn test_visible_rows_oldest_first_order() {
        let mut s = TimelinesState::new();
        s.cycle_sort(); // -> OldestFirst
        s.push_event(&allowed(7200));
        s.push_event(&allowed(3600));
        let rows = s.visible_rows(10, 0);
        assert!(rows[0].bucket_ts < rows[1].bucket_ts);
    }

    #[test]
    fn test_visible_rows_height_limits_output() {
        let mut s = TimelinesState::new();
        for i in 0..5u64 {
            s.push_event(&allowed(3600 * (i + 1)));
        }
        let rows = s.visible_rows(3, 0);
        assert_eq!(rows.len(), 3);
    }

    #[test]
    fn test_visible_rows_scroll_offsets() {
        let mut s = TimelinesState::new();
        s.cycle_sort(); // oldest first so order is deterministic
        for i in 1u64..=5 {
            s.push_event(&allowed(3600 * i));
        }
        let rows = s.visible_rows(2, 2);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].bucket_ts, 3600 * 3);
        assert_eq!(rows[1].bucket_ts, 3600 * 4);
    }

    #[test]
    fn test_visible_rows_scroll_past_end_returns_empty() {
        let mut s = TimelinesState::new();
        s.push_event(&allowed(3600));
        let rows = s.visible_rows(10, 999);
        assert!(rows.is_empty());
    }

    #[test]
    fn test_visible_rows_labels_match_zoom() {
        let mut s = TimelinesState::new();
        s.push_event(&allowed(3600 * 14)); // 14:00
        let rows = s.visible_rows(1, 0);
        assert_eq!(rows[0].bucket_label, "14:00");
    }

    #[test]
    fn test_visible_rows_capped_at_max_buckets() {
        let mut s = TimelinesState::new();
        // Create a span of MAX_BUCKETS + 10 contiguous 1h buckets by pushing
        // two events far apart.  Only MAX_BUCKETS rows should be returned.
        let span_secs = (MAX_BUCKETS as u64 + 10) * 3600;
        s.push_event(&allowed(0));
        s.push_event(&allowed(span_secs));
        let rows = s.visible_rows(usize::MAX, 0);
        assert!(rows.len() <= MAX_BUCKETS);
    }

    // ── client_count in rows ──────────────────────────────────────────────────

    #[test]
    fn test_client_count_distinct_ips() {
        let mut s = TimelinesState::new();
        let ip1 = [10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let ip2 = [10, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        s.push_event(&make_event_ip(3600, StatAction::Allowed, ip1));
        s.push_event(&make_event_ip(3601, StatAction::Allowed, ip1));
        s.push_event(&make_event_ip(3602, StatAction::Allowed, ip2));
        let rows = s.visible_rows(10, 0);
        assert_eq!(rows[0].client_count, 2);
    }

    #[test]
    fn test_empty_row_has_zero_client_count() {
        let mut s = TimelinesState::new();
        s.push_event(&allowed(3600 * 10));
        s.push_event(&allowed(3600 * 12));
        let rows = s.visible_rows(10, 0);
        // Middle bucket (11:00) should be empty
        let gap = rows.iter().find(|r| r.bucket_ts == 3600 * 11).unwrap();
        assert_eq!(gap.client_count, 0);
    }

    // ── max_queries / max_clients ─────────────────────────────────────────────

    #[test]
    fn test_max_queries_empty() {
        let s = TimelinesState::new();
        assert_eq!(s.max_queries(), 0);
    }

    #[test]
    fn test_max_queries_returns_busiest_bucket() {
        let mut s = TimelinesState::new();
        s.push_event(&allowed(3600));
        s.push_event(&allowed(3601));
        s.push_event(&allowed(7200)); // different bucket, only 1 event
        assert_eq!(s.max_queries(), 2);
    }

    #[test]
    fn test_max_clients_empty() {
        let s = TimelinesState::new();
        assert_eq!(s.max_clients(), 0);
    }

    #[test]
    fn test_max_clients_single_bucket_two_ips() {
        let mut s = TimelinesState::new();
        let ip1 = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let ip2 = [2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        s.push_event(&make_event_ip(3600, StatAction::Allowed, ip1));
        s.push_event(&make_event_ip(3601, StatAction::Allowed, ip2));
        assert_eq!(s.max_clients(), 2);
    }

    // ── total_rows / active_bucket_count ─────────────────────────────────────

    #[test]
    fn test_total_rows_empty() {
        let s = TimelinesState::new();
        assert_eq!(s.total_rows(), 0);
    }

    #[test]
    fn test_total_rows_includes_gaps() {
        let mut s = TimelinesState::new();
        s.push_event(&allowed(3600 * 10));
        s.push_event(&allowed(3600 * 12));
        // Three buckets: 10:00, 11:00, 12:00
        assert_eq!(s.total_rows(), 3);
        assert_eq!(s.active_bucket_count(), 2);
    }

    #[test]
    fn test_total_rows_single_bucket() {
        let mut s = TimelinesState::new();
        s.push_event(&allowed(3600));
        assert_eq!(s.total_rows(), 1);
    }

    // ── bucket key alignment ──────────────────────────────────────────────────

    #[test]
    fn test_bucket_key_aligned_to_zoom() {
        let mut s = TimelinesState::new();
        // ts=3661 in 1h zoom should map to bucket 3600
        s.push_event(&allowed(3661));
        assert!(s.buckets.contains_key(&3600));
        assert!(!s.buckets.contains_key(&3661));
    }

    #[test]
    fn test_bucket_key_aligned_fifteen_min() {
        let mut s = TimelinesState::new();
        s.cycle_zoom(); // 1h -> 1d
        s.cycle_zoom(); // 1d -> 30m
        s.cycle_zoom(); // 30m -> 15m
        assert_eq!(s.zoom, TimeZoom::FifteenMin);
        // ts=1000 → floor to 900 (15*60)
        s.push_event(&allowed(1000));
        assert!(s.buckets.contains_key(&900));
    }
}
