//! Timelines tab — scrollable bucketed DNS activity timeline.
//!
//! Displays a table where each row represents one time bucket:
//!
//!   Time        Queries  Activity                          Clients
//!   ──────────  ───────  ────────────────────────────────  ───────  ────────────
//!   14:00         1 234  ██████████████▓▓▓▓░░░░                 42  ██████████
//!   15:00           456  █████▓░                                17  ████
//!
//! The activity bar is scaled to the busiest bucket in view and stacked by
//! verdict: green allowed, grey proxied, yellow suspicious, light red highly
//! suspicious, red blocked.  The client bar is scaled to the busiest bucket's
//! distinct clients.
//!
//! Bucket granularity cycles with the `t` key: 1h → 1d → 30m → 15m → 1m → 1h …
//! (default 1h).  Every level is aggregated as events arrive, so switching is
//! instant and keeps the history; each level keeps up to `MAX_BUCKETS` buckets
//! (about 4 h of 1-minute buckets, 10 days of hourly ones).  `s` toggles
//! newest/oldest first.
//!
//! Rows with no events are still shown (empty bar) so the timeline has no gaps.
//! The view spans the newest `MAX_BUCKETS` buckets up to the latest event.
//!
//! The data layer is pure Rust with no ratatui dependency.

use std::collections::{HashMap, HashSet};

use crate::tui::scroll::{ScrollState, Scrollable, render_scrollbar};
use dgaard_monitor_core::protocol::{StatAction, StatError, StatEvent};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum number of time buckets retained per zoom level, and rows in view.
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
    /// Every level, finest first; `index` positions a level in this list.
    pub const ALL: [TimeZoom; 5] = [
        Self::OneMin,
        Self::FifteenMin,
        Self::ThirtyMin,
        Self::OneHour,
        Self::OneDay,
    ];

    /// Position in `ALL`.
    fn index(self) -> usize {
        match self {
            Self::OneMin => 0,
            Self::FifteenMin => 1,
            Self::ThirtyMin => 2,
            Self::OneHour => 3,
            Self::OneDay => 4,
        }
    }

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

    /// Short human-readable label shown in the table title.
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
            // Same buckets as the talkers tab: cached → allowed, upstream
            // failure → proxied, DNSSEC bogus → blocked.
            StatAction::Allowed | StatAction::AllowedWithOverride | StatAction::Cached => {
                self.allowed += 1
            }
            StatAction::Proxied | StatAction::Error(StatError::Upstream) => self.proxied += 1,
            StatAction::Blocked(_) | StatAction::Error(StatError::DnssecBogus) => self.blocked += 1,
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

// ── Bars ──────────────────────────────────────────────────────────────────────

/// Cells for `value` in a bar where `max` fills `width`: rounded, and at least
/// one cell for any non-zero value so quiet buckets stay visible.
pub fn scaled_width(value: u64, max: u64, width: usize) -> usize {
    if value == 0 || max == 0 || width == 0 {
        return 0;
    }
    let cells = (u128::from(value) * width as u128 + u128::from(max) / 2) / u128::from(max);
    (cells as usize).clamp(1, width)
}

/// Cell widths of the stacked activity bar for `row`, in display order:
/// allowed, proxied, suspicious, highly suspicious, blocked.
///
/// The bar is `scaled_width(row.total, max_total, width)` cells long, shared
/// by largest remainder so the segments always add up to it.
pub fn bar_segments(row: &TimelineRow, max_total: u64, width: usize) -> [usize; 5] {
    let counts = [
        row.allowed,
        row.proxied,
        row.suspicious,
        row.highly_suspicious,
        row.blocked,
    ];
    let length = scaled_width(row.total, max_total, width);
    let mut cells = [0usize; 5];
    if length == 0 {
        return cells;
    }
    let total = u128::from(row.total);
    let mut remainders = [(0u128, 0usize); 5];
    for (index, &count) in counts.iter().enumerate() {
        let exact = u128::from(count) * length as u128;
        cells[index] = (exact / total) as usize;
        remainders[index] = (exact % total, index);
    }
    // Hand the leftover cells to the largest remainders (lower index on ties).
    remainders.sort_by(|left, right| right.0.cmp(&left.0).then(left.1.cmp(&right.1)));
    let leftover = length - cells.iter().sum::<usize>();
    for &(_, index) in remainders.iter().take(leftover) {
        cells[index] += 1;
    }
    cells
}

// ── TimelinesState ────────────────────────────────────────────────────────────

/// Mutable state for the Timelines tab, its scroll position included.
#[derive(Default)]
pub struct TimelinesState {
    /// Per-bucket aggregates for every zoom level, indexed like
    /// `TimeZoom::ALL`, each keyed by bucket start timestamp.
    levels: [HashMap<u64, BucketEntry>; 5],
    /// Active time granularity.
    pub zoom: TimeZoom,
    /// Active sort direction.
    pub sort: TimelineSort,
    /// When frozen, `push_event` is a no-op.
    pub frozen: bool,
    /// Top row on screen and table height, bounded by the rows in view.
    scroll: ScrollState,
}

impl TimelinesState {
    /// Ingest one event into its bucket at every zoom level.
    ///
    /// No-op when `frozen`.  Each level evicts its oldest bucket (smallest
    /// timestamp) when `MAX_BUCKETS` would be exceeded.
    pub fn push_event(&mut self, event: &StatEvent) {
        if self.frozen {
            return;
        }
        for zoom in TimeZoom::ALL {
            let buckets = &mut self.levels[zoom.index()];
            let key = (event.timestamp / zoom.seconds()) * zoom.seconds();
            if !buckets.contains_key(&key)
                && buckets.len() >= MAX_BUCKETS
                && let Some(&oldest) = buckets.keys().min()
            {
                buckets.remove(&oldest);
            }
            buckets.entry(key).or_default().record(event);
        }
    }

    /// Buckets of the active zoom level.
    fn buckets(&self) -> &HashMap<u64, BucketEntry> {
        &self.levels[self.zoom.index()]
    }

    /// Advance to the next zoom level; its buckets are already aggregated.
    pub fn cycle_zoom(&mut self) {
        self.zoom = self.zoom.next();
        self.scroll.jump_to_top();
    }

    /// Toggle sort direction between newest-first and oldest-first.
    pub fn cycle_sort(&mut self) {
        self.sort = self.sort.next();
    }

    /// Forget every bucket at every level.
    pub fn clear(&mut self) {
        for buckets in &mut self.levels {
            buckets.clear();
        }
        self.scroll.jump_to_top();
    }

    /// First bucket timestamp and number of rows in view: every bucket from
    /// the oldest one stored, or `MAX_BUCKETS - 1` before the newest when
    /// that is later, up to the newest.  `None` without any event.
    fn window(&self) -> Option<(u64, usize)> {
        let buckets = self.buckets();
        let zoom_secs = self.zoom.seconds();
        let &oldest = buckets.keys().min()?;
        let &newest = buckets.keys().max()?;
        let first = oldest.max(newest.saturating_sub((MAX_BUCKETS as u64 - 1) * zoom_secs));
        Some((first, ((newest - first) / zoom_secs) as usize + 1))
    }

    /// Return at most `height` rows starting at `scroll`.
    ///
    /// Rows span every bucket in `window()`, gaps filled with empty rows so
    /// the display has no holes.  Only the returned rows are built.
    pub fn visible_rows(&self, height: usize, scroll: usize) -> Vec<TimelineRow> {
        let Some((first, count)) = self.window() else {
            return Vec::new();
        };
        let zoom_secs = self.zoom.seconds();
        let row_at = |index: usize| {
            let ts = first + index as u64 * zoom_secs;
            match self.buckets().get(&ts) {
                Some(entry) => TimelineRow::from_bucket(ts, entry, self.zoom),
                None => TimelineRow::empty(ts, self.zoom),
            }
        };
        match self.sort {
            TimelineSort::NewestFirst => (0..count)
                .rev()
                .skip(scroll)
                .take(height)
                .map(row_at)
                .collect(),
            TimelineSort::OldestFirst => (0..count).skip(scroll).take(height).map(row_at).collect(),
        }
    }

    /// Total number of rows in view (including empty gap buckets), at most
    /// `MAX_BUCKETS`.
    pub fn total_rows(&self) -> usize {
        self.window().map_or(0, |(_, count)| count)
    }

    /// Buckets of the active zoom inside the rows in view.
    fn buckets_in_view(&self) -> impl Iterator<Item = &BucketEntry> {
        let first = self.window().map_or(0, |(first, _)| first);
        self.buckets()
            .iter()
            .filter(move |&(&ts, _)| ts >= first)
            .map(|(_, entry)| entry)
    }

    /// Maximum total query count across the buckets in view (used by the
    /// renderer to scale bar widths).
    pub fn max_queries(&self) -> u64 {
        self.buckets_in_view().map(|e| e.total()).max().unwrap_or(0)
    }

    /// Maximum distinct client count across the buckets in view (used by the
    /// renderer to scale the client bar).
    pub fn max_clients(&self) -> usize {
        self.buckets_in_view()
            .map(|e| e.clients.len())
            .max()
            .unwrap_or(0)
    }
}

impl Scrollable for TimelinesState {
    fn scroll_state(&self) -> &ScrollState {
        &self.scroll
    }

    fn scroll_state_mut(&mut self) -> &mut ScrollState {
        &mut self.scroll
    }

    fn scroll_len(&self) -> usize {
        self.total_rows()
    }
}

// ── Render ────────────────────────────────────────────────────────────────────

/// Fixed column widths; the activity bar takes what is left.
const COL_TIME: u16 = 10;
const COL_QUERIES: u16 = 8;
const COL_CLIENTS: u16 = 7;
const COL_CLIENT_BAR: u16 = 12;
/// Gaps between the five columns (one cell each, ratatui's default).
const COLUMN_GAPS: u16 = 4;

/// Colours of the `bar_segments` cells, in the same order.
const SEGMENT_COLORS: [ratatui::style::Color; 5] = [
    ratatui::style::Color::Green,
    ratatui::style::Color::DarkGray,
    ratatui::style::Color::Yellow,
    ratatui::style::Color::LightRed,
    ratatui::style::Color::Red,
];

/// Width left for the activity bar in a table `inner_width` cells wide.
pub fn activity_bar_width(inner_width: u16) -> u16 {
    inner_width.saturating_sub(COL_TIME + COL_QUERIES + COL_CLIENTS + COL_CLIENT_BAR + COLUMN_GAPS)
}

/// Render the Timelines tab body: only the rows that fit are built.
///
/// Takes the state mutably to record the table height (`set_viewport`),
/// which bounds scrolling.  `frozen` adds `[FROZEN]` to the title.
pub fn render(
    state: &mut TimelinesState,
    frozen: bool,
    area: ratatui::layout::Rect,
    frame: &mut ratatui::Frame,
) {
    use ratatui::{
        layout::{Alignment, Constraint},
        style::{Color, Modifier, Style},
        text::{Line, Span, Text},
        widgets::{Block, Cell, Row, Table},
    };

    let title = format!(
        "Timelines · {} buckets · {}{}",
        state.zoom.label(),
        state.sort.label(),
        if frozen { " [FROZEN]" } else { "" }
    );
    let block = Block::bordered().title(title);
    let inner = block.inner(area);

    // The table header takes one row of the block.
    let viewport = usize::from(inner.height.saturating_sub(1));
    state.set_viewport(viewport);

    let bar_width = activity_bar_width(inner.width);
    let max_queries = state.max_queries();
    let max_clients = state.max_clients() as u64;
    let right = |text: String| Text::from(text).alignment(Alignment::Right);
    let rows: Vec<Row> = state
        .visible_rows(viewport, state.scroll())
        .into_iter()
        .map(|row| {
            let segments = bar_segments(&row, max_queries, usize::from(bar_width));
            let activity: Vec<Span> = segments
                .iter()
                .zip(SEGMENT_COLORS)
                .filter(|(cells, _)| **cells > 0)
                .map(|(cells, color)| Span::styled("█".repeat(*cells), Style::new().fg(color)))
                .collect();
            let client_cells = scaled_width(
                row.client_count as u64,
                max_clients,
                usize::from(COL_CLIENT_BAR),
            );
            Row::new([
                Cell::from(row.bucket_label),
                Cell::from(right(row.total.to_string())),
                Cell::from(Line::from(activity)),
                Cell::from(right(row.client_count.to_string())),
                Cell::from("█".repeat(client_cells)).style(Style::new().fg(Color::Cyan)),
            ])
        })
        .collect();

    let header = Row::new([
        Cell::from("Time"),
        Cell::from(right("Queries".to_string())),
        Cell::from("Activity"),
        Cell::from(right("Clients".to_string())),
        Cell::from(""),
    ])
    .style(Style::new().add_modifier(Modifier::BOLD));

    frame.render_widget(
        Table::new(
            rows,
            [
                Constraint::Length(COL_TIME),
                Constraint::Length(COL_QUERIES),
                Constraint::Length(bar_width),
                Constraint::Length(COL_CLIENTS),
                Constraint::Length(COL_CLIENT_BAR),
            ],
        )
        .block(block)
        .header(header),
        area,
    );

    render_scrollbar(state, area, frame);
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use dgaard_monitor_core::protocol::{StatBlockReason, StatEvent};

    // ── helpers ──────────────────────────────────────────────────────────────

    fn make_event(ts: u64, action: StatAction) -> StatEvent {
        StatEvent {
            country: None,
            timestamp: ts,
            domain_hash: 0,
            client_ip: [192, 168, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            action,
        }
    }

    fn make_event_ip(ts: u64, action: StatAction, ip: [u8; 16]) -> StatEvent {
        StatEvent {
            country: None,
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
        let mut s = TimelinesState::default();
        s.push_event(&allowed(3600));
        assert_eq!(s.buckets().len(), 1);
    }

    #[test]
    fn test_push_event_same_bucket_accumulates() {
        let mut s = TimelinesState::default();
        s.push_event(&allowed(3600));
        s.push_event(&allowed(3601));
        s.push_event(&blocked(7199));
        assert_eq!(s.buckets().len(), 1);
        assert_eq!(s.max_queries(), 3);
    }

    #[test]
    fn test_push_event_two_buckets() {
        let mut s = TimelinesState::default();
        s.push_event(&allowed(3600)); // bucket 3600
        s.push_event(&allowed(7200)); // bucket 7200
        assert_eq!(s.buckets().len(), 2);
    }

    #[test]
    fn test_push_event_all_action_types() {
        let mut s = TimelinesState::default();
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
        let mut s = TimelinesState {
            frozen: true,
            ..TimelinesState::default()
        };
        s.push_event(&allowed(3600));
        assert_eq!(s.buckets().len(), 0);
    }

    #[test]
    fn test_push_event_evicts_oldest_at_limit() {
        let mut s = TimelinesState::default();
        let zoom = TimeZoom::OneHour.seconds();
        // Fill exactly MAX_BUCKETS
        for i in 0..MAX_BUCKETS as u64 {
            s.push_event(&allowed(i * zoom));
        }
        assert_eq!(s.buckets().len(), MAX_BUCKETS);

        // Adding one more should evict the oldest (ts=0)
        let new_ts = MAX_BUCKETS as u64 * zoom;
        s.push_event(&allowed(new_ts));
        assert_eq!(s.buckets().len(), MAX_BUCKETS);
        // Oldest bucket should be gone
        assert!(!s.buckets().contains_key(&0));
        assert!(s.buckets().contains_key(&new_ts));
    }

    // ── cycle_zoom ────────────────────────────────────────────────────────────

    #[test]
    fn test_cycle_zoom_advances() {
        let mut s = TimelinesState::default();
        assert_eq!(s.zoom, TimeZoom::OneHour);
        s.cycle_zoom();
        assert_eq!(s.zoom, TimeZoom::OneDay);
    }

    #[test]
    fn test_cycle_zoom_keeps_history() {
        let mut s = TimelinesState::default();
        s.push_event(&allowed(3600));
        s.push_event(&allowed(3600 * 30)); // next day
        assert_eq!(s.buckets().len(), 2);
        s.cycle_zoom(); // 1h -> 1d
        assert_eq!(s.zoom, TimeZoom::OneDay);
        assert_eq!(s.buckets().len(), 2, "two days");
        s.cycle_zoom(); // 1d -> 30m
        assert_eq!(s.buckets().len(), 2);
        assert_eq!(s.max_queries(), 1);
    }

    // ── cycle_sort ────────────────────────────────────────────────────────────

    #[test]
    fn test_cycle_sort_toggles() {
        let mut s = TimelinesState::default();
        assert_eq!(s.sort, TimelineSort::NewestFirst);
        s.cycle_sort();
        assert_eq!(s.sort, TimelineSort::OldestFirst);
        s.cycle_sort();
        assert_eq!(s.sort, TimelineSort::NewestFirst);
    }

    // ── visible_rows ─────────────────────────────────────────────────────────

    #[test]
    fn test_visible_rows_empty_state() {
        let s = TimelinesState::default();
        assert!(s.visible_rows(10, 0).is_empty());
    }

    #[test]
    fn test_visible_rows_single_bucket() {
        let mut s = TimelinesState::default();
        s.push_event(&allowed(3600));
        let rows = s.visible_rows(10, 0);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].bucket_label, "01:00");
        assert_eq!(rows[0].total, 1);
    }

    #[test]
    fn test_visible_rows_fills_empty_gaps() {
        let mut s = TimelinesState::default();
        // Two events two hours apart — should produce 3 rows (14:00, 15:00, 16:00)
        s.push_event(&allowed(3600 * 14));
        s.push_event(&allowed(3600 * 16));
        let rows = s.visible_rows(10, 0);
        assert_eq!(rows.len(), 3, "gap bucket should be included");
        // Middle bucket is empty
        let gap = rows.iter().find(|r| r.bucket_label == "15:00").unwrap();
        assert_eq!(gap.total, 0);
        assert_eq!(gap.client_count, 0);
    }

    #[test]
    fn test_visible_rows_newest_first_order() {
        let mut s = TimelinesState::default();
        s.push_event(&allowed(3600));
        s.push_event(&allowed(7200));
        let rows = s.visible_rows(10, 0);
        assert_eq!(s.sort, TimelineSort::NewestFirst);
        assert!(rows[0].bucket_label > rows[1].bucket_label);
    }

    #[test]
    fn test_visible_rows_oldest_first_order() {
        let mut s = TimelinesState::default();
        s.cycle_sort(); // -> OldestFirst
        s.push_event(&allowed(7200));
        s.push_event(&allowed(3600));
        let rows = s.visible_rows(10, 0);
        assert!(rows[0].bucket_label < rows[1].bucket_label);
    }

    #[test]
    fn test_visible_rows_height_limits_output() {
        let mut s = TimelinesState::default();
        for i in 0..5u64 {
            s.push_event(&allowed(3600 * (i + 1)));
        }
        let rows = s.visible_rows(3, 0);
        assert_eq!(rows.len(), 3);
    }

    #[test]
    fn test_visible_rows_scroll_offsets() {
        let mut s = TimelinesState::default();
        s.cycle_sort(); // oldest first so order is deterministic
        for i in 1u64..=5 {
            s.push_event(&allowed(3600 * i));
        }
        let rows = s.visible_rows(2, 2);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].bucket_label, "03:00");
        assert_eq!(rows[1].bucket_label, "04:00");
    }

    #[test]
    fn test_visible_rows_scroll_past_end_returns_empty() {
        let mut s = TimelinesState::default();
        s.push_event(&allowed(3600));
        let rows = s.visible_rows(10, 999);
        assert!(rows.is_empty());
    }

    #[test]
    fn test_visible_rows_labels_match_zoom() {
        let mut s = TimelinesState::default();
        s.push_event(&allowed(3600 * 14)); // 14:00
        let rows = s.visible_rows(1, 0);
        assert_eq!(rows[0].bucket_label, "14:00");
    }

    #[test]
    fn test_visible_rows_capped_at_max_buckets() {
        let mut s = TimelinesState::default();
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
        let mut s = TimelinesState::default();
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
        let mut s = TimelinesState::default();
        s.push_event(&allowed(3600 * 10));
        s.push_event(&allowed(3600 * 12));
        let rows = s.visible_rows(10, 0);
        // Middle bucket (11:00) should be empty
        let gap = rows.iter().find(|r| r.bucket_label == "11:00").unwrap();
        assert_eq!(gap.client_count, 0);
    }

    // ── max_queries / max_clients ─────────────────────────────────────────────

    #[test]
    fn test_max_queries_empty() {
        let s = TimelinesState::default();
        assert_eq!(s.max_queries(), 0);
    }

    #[test]
    fn test_max_queries_returns_busiest_bucket() {
        let mut s = TimelinesState::default();
        s.push_event(&allowed(3600));
        s.push_event(&allowed(3601));
        s.push_event(&allowed(7200)); // different bucket, only 1 event
        assert_eq!(s.max_queries(), 2);
    }

    #[test]
    fn test_max_clients_empty() {
        let s = TimelinesState::default();
        assert_eq!(s.max_clients(), 0);
    }

    #[test]
    fn test_max_clients_single_bucket_two_ips() {
        let mut s = TimelinesState::default();
        let ip1 = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let ip2 = [2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        s.push_event(&make_event_ip(3600, StatAction::Allowed, ip1));
        s.push_event(&make_event_ip(3601, StatAction::Allowed, ip2));
        assert_eq!(s.max_clients(), 2);
    }

    // ── total_rows ────────────────────────────────────────────────────────────

    #[test]
    fn test_total_rows_empty() {
        let s = TimelinesState::default();
        assert_eq!(s.total_rows(), 0);
    }

    #[test]
    fn test_total_rows_includes_gaps() {
        let mut s = TimelinesState::default();
        s.push_event(&allowed(3600 * 10));
        s.push_event(&allowed(3600 * 12));
        // Three buckets: 10:00, 11:00, 12:00
        assert_eq!(s.total_rows(), 3);
        assert_eq!(s.buckets().len(), 2);
    }

    #[test]
    fn test_total_rows_single_bucket() {
        let mut s = TimelinesState::default();
        s.push_event(&allowed(3600));
        assert_eq!(s.total_rows(), 1);
    }

    // ── bucket key alignment ──────────────────────────────────────────────────

    #[test]
    fn test_bucket_key_aligned_to_zoom() {
        let mut s = TimelinesState::default();
        // ts=3661 in 1h zoom should map to bucket 3600
        s.push_event(&allowed(3661));
        assert!(s.buckets().contains_key(&3600));
        assert!(!s.buckets().contains_key(&3661));
    }

    #[test]
    fn test_bucket_key_aligned_fifteen_min() {
        let mut s = TimelinesState::default();
        s.cycle_zoom(); // 1h -> 1d
        s.cycle_zoom(); // 1d -> 30m
        s.cycle_zoom(); // 30m -> 15m
        assert_eq!(s.zoom, TimeZoom::FifteenMin);
        // ts=1000 → floor to 900 (15*60)
        s.push_event(&allowed(1000));
        assert!(s.buckets().contains_key(&900));
    }

    // ── every zoom level ──────────────────────────────────────────────────────

    #[test]
    fn test_push_event_aggregates_every_level() {
        let mut s = TimelinesState::default();
        // Three minutes in the same hour and day.
        for minute in 0..3u64 {
            s.push_event(&allowed(3600 + minute * 60));
        }
        let buckets_at = |zoom: TimeZoom| s.levels[zoom.index()].len();
        assert_eq!(buckets_at(TimeZoom::OneMin), 3);
        assert_eq!(buckets_at(TimeZoom::FifteenMin), 1);
        assert_eq!(buckets_at(TimeZoom::OneHour), 1);
        assert_eq!(buckets_at(TimeZoom::OneDay), 1);
    }

    #[test]
    fn test_zoom_index_matches_all() {
        for (position, zoom) in TimeZoom::ALL.into_iter().enumerate() {
            assert_eq!(zoom.index(), position, "{zoom:?}");
        }
    }

    #[test]
    fn test_levels_evict_independently() {
        let mut s = TimelinesState::default();
        // MAX_BUCKETS + 1 minutes: the minute level evicts, the hour level does not.
        for minute in 0..=MAX_BUCKETS as u64 {
            s.push_event(&allowed(minute * 60));
        }
        assert_eq!(s.levels[TimeZoom::OneMin.index()].len(), MAX_BUCKETS);
        assert!(!s.levels[TimeZoom::OneMin.index()].contains_key(&0));
        let hours = (MAX_BUCKETS as u64 * 60) / 3600 + 1;
        assert_eq!(s.levels[TimeZoom::OneHour.index()].len() as u64, hours);
    }

    #[test]
    fn test_cycle_zoom_resets_scroll() {
        let mut s = TimelinesState::default();
        for hour in 0..30u64 {
            s.push_event(&allowed(hour * 3600));
        }
        s.set_viewport(10);
        s.scroll_by(5);
        s.cycle_zoom();
        assert_eq!(s.scroll(), 0);
    }

    #[test]
    fn test_clear_empties_every_level() {
        let mut s = TimelinesState::default();
        for hour in 0..30u64 {
            s.push_event(&allowed(hour * 3600));
        }
        s.set_viewport(10);
        s.scroll_by(5);
        s.clear();
        assert!(s.levels.iter().all(HashMap::is_empty));
        assert_eq!(s.total_rows(), 0);
        assert_eq!(s.scroll(), 0);
    }

    // ── window: the newest buckets ────────────────────────────────────────────

    #[test]
    fn test_long_span_keeps_the_newest_buckets() {
        let mut s = TimelinesState::default();
        let newest = (MAX_BUCKETS as u64 + 10) * 3600;
        s.push_event(&allowed(0));
        s.push_event(&allowed(newest));
        assert_eq!(s.total_rows(), MAX_BUCKETS);

        let top = &s.visible_rows(1, 0)[0];
        assert_eq!(
            top.bucket_label,
            format_bucket_label(newest, TimeZoom::OneHour)
        );
        assert_eq!(top.total, 1, "the latest event is on screen");

        s.cycle_sort();
        let oldest_in_view = newest - (MAX_BUCKETS as u64 - 1) * 3600;
        let top = &s.visible_rows(1, 0)[0];
        assert_eq!(
            top.bucket_label,
            format_bucket_label(oldest_in_view, TimeZoom::OneHour)
        );
    }

    #[test]
    fn test_bar_scale_ignores_buckets_out_of_view() {
        let mut s = TimelinesState::default();
        // A spike at hour 0, then quiet hours far later: the spike is out of view.
        for _ in 0..50 {
            s.push_event(&allowed(0));
        }
        let later = (MAX_BUCKETS as u64 + 5) * 3600;
        s.push_event(&make_event_ip(later, StatAction::Allowed, [1; 16]));
        s.push_event(&make_event_ip(later, StatAction::Allowed, [2; 16]));
        assert_eq!(s.max_queries(), 2);
        assert_eq!(s.max_clients(), 2);
    }

    #[test]
    fn test_scroll_bounded_by_rows_in_view() {
        let mut s = TimelinesState::default();
        for hour in 0..30u64 {
            s.push_event(&allowed(hour * 3600));
        }
        s.set_viewport(10);
        s.scroll_to_bottom();
        assert_eq!(s.scroll(), 20);
        s.scroll_by(100);
        assert_eq!(s.scroll(), 20);
    }

    // ── bars ──────────────────────────────────────────────────────────────────

    fn row(allowed: u64, proxied: u64, suspicious: u64, highly: u64, blocked: u64) -> TimelineRow {
        TimelineRow {
            bucket_label: String::new(),
            allowed,
            proxied,
            blocked,
            suspicious,
            highly_suspicious: highly,
            total: allowed + proxied + suspicious + highly + blocked,
            client_count: 0,
        }
    }

    #[test]
    fn test_scaled_width() {
        assert_eq!(scaled_width(0, 10, 20), 0);
        assert_eq!(scaled_width(5, 0, 20), 0);
        assert_eq!(scaled_width(5, 10, 0), 0);
        assert_eq!(scaled_width(10, 10, 20), 20);
        assert_eq!(scaled_width(5, 10, 20), 10);
        assert_eq!(scaled_width(1, 1_000, 20), 1, "never vanishes");
        assert_eq!(scaled_width(3, 8, 10), 4, "rounded: 3.75");
        assert_eq!(scaled_width(20, 10, 10), 10, "clamped to the width");
        assert_eq!(scaled_width(u64::MAX, u64::MAX, 30), 30, "no overflow");
    }

    #[test]
    fn test_bar_segments_add_up_to_scaled_length() {
        for (counts, max, width) in [
            ((1, 1, 1, 0, 0), 3, 10),
            ((7, 0, 2, 1, 3), 20, 33),
            ((1, 1, 1, 1, 1), 5, 7),
            ((100, 3, 0, 0, 1), 104, 50),
        ] {
            let bucket = row(counts.0, counts.1, counts.2, counts.3, counts.4);
            let cells = bar_segments(&bucket, max, width);
            assert_eq!(
                cells.iter().sum::<usize>(),
                scaled_width(bucket.total, max, width),
                "{counts:?}"
            );
        }
    }

    #[test]
    fn test_bar_segments_order_and_proportions() {
        // allowed 6, proxied 0, suspicious 2, highly 0, blocked 2 over 10 cells.
        let cells = bar_segments(&row(6, 0, 2, 0, 2), 10, 10);
        assert_eq!(cells, [6, 0, 2, 0, 2]);
    }

    #[test]
    fn test_bar_segments_leftover_goes_to_largest_remainder() {
        // 3 cells for 1/1/1 of 3: one each.  2 cells: lower index wins the tie.
        assert_eq!(bar_segments(&row(1, 1, 1, 0, 0), 3, 3), [1, 1, 1, 0, 0]);
        assert_eq!(bar_segments(&row(1, 1, 1, 0, 0), 3, 2), [1, 1, 0, 0, 0]);
    }

    #[test]
    fn test_bar_segments_empty_row() {
        assert_eq!(bar_segments(&row(0, 0, 0, 0, 0), 10, 20), [0; 5]);
    }

    #[test]
    fn test_activity_bar_width() {
        assert_eq!(activity_bar_width(100), 100 - 41);
        assert_eq!(activity_bar_width(10), 0);
    }

    // ── render ────────────────────────────────────────────────────────────────

    fn draw(
        s: &mut TimelinesState,
        frozen: bool,
        width: u16,
        height: u16,
    ) -> ratatui::buffer::Buffer {
        use ratatui::{Terminal, backend::TestBackend};
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| render(s, frozen, frame.area(), frame))
            .unwrap();
        terminal.backend().buffer().clone()
    }

    fn line(buffer: &ratatui::buffer::Buffer, row: u16) -> String {
        (0..buffer.area.width)
            .map(|column| buffer[(column, row)].symbol())
            .collect()
    }

    #[test]
    fn test_render_title_zoom_sort_frozen() {
        let mut s = TimelinesState::default();
        s.push_event(&allowed(3600));
        let buffer = draw(&mut s, true, 100, 8);
        let title = line(&buffer, 0);
        assert!(title.contains("1h buckets"), "{title}");
        assert!(title.contains("newest first"));
        assert!(title.contains("[FROZEN]"));
        s.cycle_zoom();
        s.cycle_sort();
        let title = line(&draw(&mut s, false, 100, 8), 0);
        assert!(title.contains("1d buckets") && title.contains("oldest first"));
        assert!(!title.contains("[FROZEN]"));
    }

    #[test]
    fn test_render_rows_label_counts_and_bars() {
        use ratatui::style::Color;
        let mut s = TimelinesState::default();
        // 14:00: 3 allowed + 1 blocked from 2 clients; 15:00: 2 allowed.
        s.push_event(&make_event_ip(3600 * 14, StatAction::Allowed, [1; 16]));
        s.push_event(&make_event_ip(3600 * 14, StatAction::Allowed, [1; 16]));
        s.push_event(&make_event_ip(3600 * 14, StatAction::Allowed, [2; 16]));
        s.push_event(&make_event_ip(
            3600 * 14,
            StatAction::Blocked(StatBlockReason::empty()),
            [2; 16],
        ));
        s.push_event(&make_event_ip(3600 * 15, StatAction::Allowed, [1; 16]));
        s.push_event(&make_event_ip(3600 * 15, StatAction::Allowed, [1; 16]));

        // 100 wide: inner 98, bar 57 cells.
        let buffer = draw(&mut s, false, 100, 8);
        let header = line(&buffer, 1);
        assert!(header.contains("Time") && header.contains("Clients"));
        let newest = line(&buffer, 2);
        let older = line(&buffer, 3);
        assert!(newest.starts_with("│15:00"), "{newest}");
        assert!(older.starts_with("│14:00"), "{older}");

        let count = |row: u16, color: Color| {
            (0..100)
                .filter(|&column| buffer[(column, row)].symbol() == "█")
                .filter(|&column| buffer[(column, row)].fg == color)
                .count()
        };
        // 14:00 is the busiest: full 57-cell bar, 3/4 green, 1/4 red.
        assert_eq!(count(3, Color::Green), 43);
        assert_eq!(count(3, Color::Red), 14);
        // 15:00: 2 of 4 queries → half the bar, all green.
        assert_eq!(count(2, Color::Green), 29);
        assert_eq!(count(2, Color::Red), 0);
        // Client bars: 2 clients fill 12 cells, 1 client half.
        assert_eq!(count(3, Color::Cyan), 12);
        assert_eq!(count(2, Color::Cyan), 6);
    }

    #[test]
    fn test_render_draws_only_the_visible_window() {
        let mut s = TimelinesState::default();
        for hour in 0..30u64 {
            s.push_event(&allowed(hour * 3600));
        }
        // 12 rows - 2 borders - 1 header = 9 table rows
        draw(&mut s, false, 100, 12);
        assert_eq!(s.page_size(), 9);
        s.scroll_by(3);
        let buffer = draw(&mut s, false, 100, 12);
        // Newest is 05:00 the next day (hour 29); 3 rows down: hour 26 = 02:00.
        assert!(
            line(&buffer, 2).starts_with("│02:00"),
            "{}",
            line(&buffer, 2)
        );
        assert!(
            line(&buffer, 10).starts_with("│18:00"),
            "{}",
            line(&buffer, 10)
        );
    }

    #[test]
    fn test_render_empty_state() {
        let mut s = TimelinesState::default();
        let buffer = draw(&mut s, false, 80, 8);
        assert!(line(&buffer, 0).contains("Timelines"));
        assert_eq!(s.total_rows(), 0);
    }
}
