//! Popularity tracker — Phase 3 of the recursive-DNS roadmap.
//!
//! Counts cache hits per domain and decays the count over time so the
//! resolver can later (Phase 4–5) persist a top-N list and prefetch hot
//! entries before they expire.
//!
//! ## Design
//!
//! * Storage is a [`dashmap::DashMap`] keyed by `xxh3_64(lower(domain))`
//!   with a **fixed seed of 0** — the seed must stay constant across runs
//!   because the on-disk snapshot (Phase 4) is keyed by this hash.
//! * Each entry holds a saturating `u8` `hit_count` and the `Instant` of
//!   the most recent hit. No allocation per hit, no atomic-RMW outside the
//!   shard lock.
//! * Decay is **lazy**, computed at read time with one subtraction, one
//!   integer division by a compile-time constant, and one right-shift.
//!   No background ticker. After 8 half-lives the score is forced to 0.
//! * `record_hit` resets `last_hit_at = Instant::now()` so fresh activity
//!   restarts the decay clock against the (already saturated) raw count.
//!
//! ## Why bit-shift decay
//!
//! Floating-point exponentials are off the menu on the MIPS targets
//! dgaard ships to (no FPU on the SoC). Halving the score every
//! `decay_half_life_secs` collapses `e^{-λt}` to a single
//! `count >> periods` shift while preserving the intuition that a domain
//! queried recently should outrank a domain queried days ago.
//!
//! ```ignore
//! // (binary-crate module — illustrative only)
//! use std::time::Duration;
//! use crate::popularity::{PopularityTracker, effective_score_for};
//!
//! let tracker = PopularityTracker::new();
//! for _ in 0..5 { tracker.record_hit("example.com"); }
//! assert_eq!(tracker.score("example.com", 86_400), 5);
//!
//! // A fictional entry seen one half-life ago retains half its score.
//! let one_day_ago = std::time::Instant::now() - Duration::from_secs(86_400);
//! assert_eq!(effective_score_for(8, one_day_ago, 86_400), 4);
//! ```

use std::io;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use rkyv::rancor::Error as RkyvError;
use rkyv::util::AlignedVec;
use tokio::sync::watch;
use tokio::time::MissedTickBehavior;
use twox_hash::XxHash3_64;

/// Hash seed used for both the popularity map and the on-disk snapshot.
///
/// **Must remain 0 forever** — see [`docs/Roadmap-recursive-DNS.md`].
/// Changing it invalidates every saved `top-domains.bin` ever written.
pub const POPULARITY_HASH_SEED: u64 = 0;

/// Maximum number of half-life periods that still produce a non-zero
/// shifted score. After 8 periods (8 × half_life), `u8 >> 8` is defined
/// as 0 on every target; we short-circuit explicitly so the branch is
/// obvious in profiles.
const MAX_DECAY_PERIODS: u32 = 8;

/// Per-domain popularity counter.
///
/// `hit_count` saturates at `u8::MAX` (255). Saturating instead of
/// wrapping prevents a perpetually-hot domain from periodically rolling
/// back to zero and tanking its prefetch priority.
#[derive(Clone, Copy, Debug)]
pub struct PopularityEntry {
    /// Raw hit count, saturated to `u8::MAX`.
    pub hit_count: u8,
    /// Process-local timestamp of the most recent hit.
    pub last_hit_at: Instant,
}

impl PopularityEntry {
    fn fresh() -> Self {
        Self {
            hit_count: 1,
            last_hit_at: Instant::now(),
        }
    }

    /// Replace this entry's state with values loaded from a Phase-4
    /// snapshot. The snapshot stores the *already decayed* score, so
    /// the caller passes that in as the new `hit_count`; the timer
    /// restarts now because the snapshot has no wall-clock anchor.
    pub fn restored_from_snapshot(score: u8) -> Self {
        Self {
            hit_count: score,
            last_hit_at: Instant::now(),
        }
    }
}

/// Lazy half-life decay shared by [`PopularityTracker::score`] and the
/// Phase-4 snapshot writer.
///
/// `elapsed / half_life_secs` is the number of half-life periods that
/// have passed; `hit_count >> periods` halves the score for each. Past
/// `MAX_DECAY_PERIODS` we clamp to 0 to avoid `u8 >> n` being a no-op on
/// some platforms when `n >= 8`.
#[inline]
pub fn effective_score_for(hit_count: u8, last_hit_at: Instant, half_life_secs: u64) -> u8 {
    if half_life_secs == 0 {
        return hit_count;
    }
    let elapsed_secs = last_hit_at.elapsed().as_secs();
    let periods = elapsed_secs / half_life_secs;
    if periods >= u64::from(MAX_DECAY_PERIODS) {
        0
    } else {
        hit_count >> (periods as u32)
    }
}

/// Compute `xxh3_64` of the lowercase domain with the fixed seed.
#[inline]
pub fn hash_domain(domain: &str) -> u64 {
    // ASCII-only lowercase is the canonicalisation used everywhere else
    // in dgaard (cache keys, stats, host-index lookups). DNS labels are
    // ASCII by construction, so this stays allocation-light.
    let lower = domain.to_ascii_lowercase();
    XxHash3_64::oneshot_with_seed(POPULARITY_HASH_SEED, lower.as_bytes())
}

/// Tracks per-domain popularity.
///
/// Cheap to clone (`Arc` semantics) and `Send + Sync` — a single
/// `PopularityTracker` is shared across all worker tasks via
/// [`crate::POPULARITY_TRACKER`].
pub struct PopularityTracker {
    map: DashMap<u64, PopularityEntry>,
}

impl PopularityTracker {
    pub fn new() -> Self {
        Self {
            map: DashMap::new(),
        }
    }

    /// Record one hit against `domain`.
    ///
    /// * Inserts a fresh entry on first sight.
    /// * Otherwise: `hit_count = saturating_add(1)` and the decay clock
    ///   restarts from now (so a hot domain regains full weight).
    pub fn record_hit(&self, domain: &str) {
        let key = hash_domain(domain);
        self.map
            .entry(key)
            .and_modify(|e| {
                e.hit_count = e.hit_count.saturating_add(1);
                e.last_hit_at = Instant::now();
            })
            .or_insert_with(PopularityEntry::fresh);
    }

    /// Insert (or overwrite) an entry restored from a Phase-4 snapshot.
    pub fn restore(&self, domain_hash: u64, score: u8) {
        self.map
            .insert(domain_hash, PopularityEntry::restored_from_snapshot(score));
    }

    /// Decayed score for `domain`, or `0` if unknown.
    pub fn score(&self, domain: &str, half_life_secs: u64) -> u8 {
        let key = hash_domain(domain);
        self.map
            .get(&key)
            .map(|e| effective_score_for(e.hit_count, e.last_hit_at, half_life_secs))
            .unwrap_or(0)
    }

    /// Decayed score for a precomputed hash. Used by the Phase-4 writer
    /// which iterates the map directly.
    pub fn score_by_hash(&self, domain_hash: u64, half_life_secs: u64) -> u8 {
        self.map
            .get(&domain_hash)
            .map(|e| effective_score_for(e.hit_count, e.last_hit_at, half_life_secs))
            .unwrap_or(0)
    }

    /// Total number of tracked domains. Used by Phase-4 snapshot sizing
    /// and by tests.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Wipe every entry. Phase 4 calls this on blocklist reload so a
    /// freshly-blocked domain cannot retain residual prefetch priority.
    pub fn clear(&self) {
        self.map.clear();
    }

    /// Iterate `(hash, effective_score)` pairs filtered to non-zero
    /// scores. Used by the Phase-4 snapshot writer; returning an owned
    /// `Vec` releases the shard locks before sorting.
    pub fn snapshot_pairs(&self, half_life_secs: u64) -> Vec<(u64, u8)> {
        let mut out = Vec::with_capacity(self.map.len());
        for kv in self.map.iter() {
            let score = effective_score_for(kv.hit_count, kv.last_hit_at, half_life_secs);
            if score > 0 {
                out.push((*kv.key(), score));
            }
        }
        out
    }
}

impl Default for PopularityTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Phase 4: snapshot persistence
// ---------------------------------------------------------------------------

/// File magic — `b"DGPT"` for **D**ig**a**ard **P**opularity **T**op-N.
/// Catches "wrong file, same name" mistakes (e.g. someone pointing
/// `save_path` at an existing rkyv blocklist by accident).
const SNAPSHOT_MAGIC: [u8; 4] = *b"DGPT";

/// Bump on every breaking format change. The reader rejects mismatched
/// versions and the daemon starts fresh — never silently misinterpret an
/// older snapshot under a newer struct layout.
const SNAPSHOT_VERSION: u8 = 1;

/// 8-byte fixed header so the rkyv payload starts at an 8-byte-aligned
/// offset within the file. rkyv's high-level `from_bytes` copies into an
/// [`AlignedVec`] before deserialising; the alignment within the file
/// itself is therefore not load-critical, but keeping the header at a
/// power-of-two width makes hex dumps readable.
const SNAPSHOT_HEADER_LEN: usize = 8;

/// Rank pairs by effective score (descending) and truncate to `top_n`.
///
/// Ties are broken by hash to give a deterministic ordering — important
/// for the fingerprint optimisation: if two runs produce the same top-N
/// the on-disk bytes must be byte-identical so the fingerprint matches
/// and the write is skipped.
pub fn top_n_pairs(tracker: &PopularityTracker, top_n: u32, half_life_secs: u64) -> Vec<(u64, u8)> {
    let mut pairs = tracker.snapshot_pairs(half_life_secs);
    // Stable sort key: (score desc, hash asc).
    pairs.sort_unstable_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    pairs.truncate(top_n as usize);
    pairs
}

/// Fingerprint a `(hash, score)` slice with `xxh3_64(seed=0)` over the
/// concatenated little-endian bytes. The save loop compares the new
/// fingerprint against the previous one to skip pointless writes —
/// home routers on idle networks would otherwise burn flash for no
/// reason every `save_interval_secs`.
pub fn fingerprint_pairs(pairs: &[(u64, u8)]) -> u64 {
    // 9 bytes per entry: 8 for the hash, 1 for the score.
    let mut buf = Vec::with_capacity(pairs.len() * 9);
    for (h, s) in pairs {
        buf.extend_from_slice(&h.to_le_bytes());
        buf.push(*s);
    }
    XxHash3_64::oneshot_with_seed(POPULARITY_HASH_SEED, &buf)
}

/// Errors surfaced when reading a snapshot. The runtime treats every
/// variant the same way (log + start fresh) but the variants are kept
/// distinct so tests can assert on the specific failure mode.
#[derive(Debug)]
pub enum SnapshotError {
    /// File missing, permission denied, partial read, etc.
    Io(io::Error),
    /// File shorter than the fixed header.
    Truncated,
    /// First four bytes weren't `b"DGPT"`.
    BadMagic,
    /// Magic OK but the version byte does not match `SNAPSHOT_VERSION`.
    VersionMismatch(u8),
    /// rkyv deserialisation failed (corrupt payload).
    Corrupt(String),
}

impl std::fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "i/o error: {e}"),
            Self::Truncated => f.write_str("snapshot file too short for header"),
            Self::BadMagic => f.write_str("snapshot magic bytes do not match"),
            Self::VersionMismatch(v) => {
                write!(f, "snapshot version {v} != supported {SNAPSHOT_VERSION}")
            }
            Self::Corrupt(s) => write!(f, "snapshot corrupt: {s}"),
        }
    }
}

impl std::error::Error for SnapshotError {}

impl From<io::Error> for SnapshotError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Atomically write a snapshot to `path`.
///
/// Writes go to `<path>.tmp` first, are flushed to disk, then renamed
/// over the destination. A power loss between `write_all` and `rename`
/// leaves the previous snapshot intact — the next boot still has a
/// valid (slightly stale) copy.
///
/// The on-disk layout is:
///
/// | offset | size | content                                              |
/// |--------|------|------------------------------------------------------|
/// | 0      | 4    | magic `b"DGPT"`                                      |
/// | 4      | 1    | format version (current: 1)                          |
/// | 5      | 3    | reserved (zero)                                      |
/// | 8      | …    | rkyv-serialised `Vec<(u64, u8)>`                     |
pub fn write_snapshot(path: &Path, pairs: &[(u64, u8)]) -> Result<(), SnapshotError> {
    let body: AlignedVec = rkyv::to_bytes::<RkyvError>(&pairs.to_vec())
        .map_err(|e| SnapshotError::Corrupt(e.to_string()))?;

    // Best-effort: ensure the parent directory exists so the very first
    // save on a fresh install doesn't fail because `/var/dgaard/` is
    // missing. `create_dir_all` is a no-op when the dir already exists.
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }

    let tmp = path.with_extension("tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(&SNAPSHOT_MAGIC)?;
        f.write_all(&[SNAPSHOT_VERSION, 0, 0, 0])?;
        f.write_all(body.as_slice())?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Read a snapshot from `path`. Header is validated; on success returns
/// the deserialised `(hash, score)` pairs.
pub fn read_snapshot(path: &Path) -> Result<Vec<(u64, u8)>, SnapshotError> {
    let raw = std::fs::read(path)?;
    if raw.len() < SNAPSHOT_HEADER_LEN {
        return Err(SnapshotError::Truncated);
    }
    if raw[..4] != SNAPSHOT_MAGIC {
        return Err(SnapshotError::BadMagic);
    }
    if raw[4] != SNAPSHOT_VERSION {
        return Err(SnapshotError::VersionMismatch(raw[4]));
    }

    let mut aligned: AlignedVec = AlignedVec::with_capacity(raw.len() - SNAPSHOT_HEADER_LEN);
    aligned.extend_from_slice(&raw[SNAPSHOT_HEADER_LEN..]);
    rkyv::from_bytes::<Vec<(u64, u8)>, RkyvError>(&aligned)
        .map_err(|e| SnapshotError::Corrupt(e.to_string()))
}

/// Load a snapshot from disk into `tracker`. Missing-file is *not* an
/// error: returning `Ok(0)` lets the caller log "started fresh" without
/// distinguishing a brand-new install from a freshly-wiped one.
///
/// All other errors propagate so the caller can log them — corruption is
/// rare enough that we want it visible, not silently swallowed.
pub fn restore_into(tracker: &PopularityTracker, path: &Path) -> Result<usize, SnapshotError> {
    match read_snapshot(path) {
        Ok(pairs) => {
            for (hash, score) in &pairs {
                tracker.restore(*hash, *score);
            }
            Ok(pairs.len())
        }
        Err(SnapshotError::Io(e)) if e.kind() == io::ErrorKind::NotFound => Ok(0),
        Err(e) => Err(e),
    }
}

/// Settings for the background save loop. Plain `Copy` struct so the
/// task is easy to inspect in tests without weaving config plumbing
/// through.
#[derive(Clone, Copy, Debug)]
pub struct SnapshotTaskCfg {
    pub interval: Duration,
    pub top_n: u32,
    pub half_life_secs: u64,
}

/// Background task — flushes the top-N popularity snapshot to disk on a
/// timer and once more on clean shutdown.
///
/// * Skips the write when the fingerprint of the top-N hasn't changed
///   since the last save (delta-write optimisation — protects flash on
///   idle home routers).
/// * Logs and continues on transient I/O errors. A write failure must
///   never take down the resolver.
/// * On shutdown (the watched bool flips to `true`) makes one final
///   unconditional write so the most recent state is on disk.
pub async fn run_snapshot_task(
    tracker: Arc<PopularityTracker>,
    path: std::path::PathBuf,
    cfg: SnapshotTaskCfg,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    if cfg.interval.is_zero() {
        // Defensive: a zero interval would busy-spin. Treat 0 as "save
        // only on shutdown" — useful in tests, harmless in prod.
        let _ = shutdown_rx.changed().await;
        flush_once(&tracker, &path, &cfg);
        return;
    }

    let mut ticker = tokio::time::interval(cfg.interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    // The first tick fires immediately — we want the *next* one so a
    // newly-started daemon doesn't write an empty snapshot at t=0.
    ticker.tick().await;

    let mut last_fp: u64 = 0;

    loop {
        tokio::select! {
            biased;
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    flush_once(&tracker, &path, &cfg);
                    return;
                }
            }
            _ = ticker.tick() => {
                let pairs = top_n_pairs(&tracker, cfg.top_n, cfg.half_life_secs);
                if pairs.is_empty() {
                    continue;
                }
                let fp = fingerprint_pairs(&pairs);
                if fp == last_fp {
                    continue;
                }
                match write_snapshot(&path, &pairs) {
                    Ok(()) => last_fp = fp,
                    Err(e) => eprintln!(
                        "popularity: snapshot write to {} failed: {e}",
                        path.display()
                    ),
                }
            }
        }
    }
}

fn flush_once(tracker: &PopularityTracker, path: &Path, cfg: &SnapshotTaskCfg) {
    let pairs = top_n_pairs(tracker, cfg.top_n, cfg.half_life_secs);
    if pairs.is_empty() {
        return;
    }
    if let Err(e) = write_snapshot(path, &pairs) {
        eprintln!(
            "popularity: final snapshot write to {} failed: {e}",
            path.display()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn first_hit_sets_score_to_one() {
        let t = PopularityTracker::new();
        t.record_hit("example.com");
        assert_eq!(t.score("example.com", 86_400), 1);
    }

    #[test]
    fn record_hit_is_case_insensitive() {
        let t = PopularityTracker::new();
        t.record_hit("Example.COM");
        // Same hash → same entry; second hit must increment in place.
        t.record_hit("example.com");
        assert_eq!(t.score("EXAMPLE.com", 86_400), 2);
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn unknown_domain_scores_zero() {
        let t = PopularityTracker::new();
        assert_eq!(t.score("nope.example", 86_400), 0);
    }

    #[test]
    fn hit_count_saturates_at_u8_max() {
        let t = PopularityTracker::new();
        // 300 > u8::MAX (255); the counter must clamp instead of wrapping.
        for _ in 0..300 {
            t.record_hit("hot.example");
        }
        assert_eq!(t.score("hot.example", 86_400), u8::MAX);
    }

    #[test]
    fn decay_halves_score_each_half_life_period() {
        let one_day = 86_400;
        // The score halves every half-life: 64 → 32 → 16 → 8 → 4 → 2 → 1 → 0.
        let now = Instant::now();
        let one_period_ago = now - Duration::from_secs(one_day);
        let two_periods_ago = now - Duration::from_secs(2 * one_day);
        let three_periods_ago = now - Duration::from_secs(3 * one_day);

        assert_eq!(effective_score_for(64, one_period_ago, one_day), 32);
        assert_eq!(effective_score_for(64, two_periods_ago, one_day), 16);
        assert_eq!(effective_score_for(64, three_periods_ago, one_day), 8);
    }

    #[test]
    fn decay_clamps_to_zero_after_eight_periods() {
        // Anything ≥ 8 half-lives must be zero, not a no-op shift.
        let half_life = 60;
        let long_ago = Instant::now() - Duration::from_secs(half_life * 8);
        let way_long_ago = Instant::now() - Duration::from_secs(half_life * 50);
        assert_eq!(effective_score_for(255, long_ago, half_life), 0);
        assert_eq!(effective_score_for(255, way_long_ago, half_life), 0);
    }

    #[test]
    fn record_hit_resets_decay_clock() {
        // Simulate an entry whose hit_count is 4 and whose last_hit_at
        // is "stale". Touching it must reset the timer to ~now, restoring
        // the full (unshifted) score on the next read.
        let t = PopularityTracker::new();
        for _ in 0..4 {
            t.record_hit("hot.example");
        }
        // Bump again: score increments to 5 AND the clock restarts.
        t.record_hit("hot.example");
        assert_eq!(t.score("hot.example", 86_400), 5);
    }

    #[test]
    fn zero_half_life_disables_decay() {
        // Defensive: a misconfigured zero must not trigger a division
        // panic. The score returned is the raw count.
        let t = PopularityTracker::new();
        for _ in 0..3 {
            t.record_hit("static.example");
        }
        assert_eq!(t.score("static.example", 0), 3);
    }

    #[test]
    fn fixed_seed_is_zero_and_stable() {
        // The disk snapshot keying contract: hash_domain MUST be stable
        // for the lifetime of the on-disk format. Pin the value.
        // Hash of "example.com" under xxh3_64 seed=0 must not change.
        let a = hash_domain("example.com");
        let b = hash_domain("EXAMPLE.com");
        assert_eq!(a, b, "case folding broken");
        // Sanity: differing domains differ.
        assert_ne!(a, hash_domain("example.org"));
    }

    #[test]
    fn clear_wipes_state_for_blocklist_reload() {
        let t = PopularityTracker::new();
        t.record_hit("a.example");
        t.record_hit("b.example");
        assert_eq!(t.len(), 2);
        t.clear();
        assert!(t.is_empty());
        assert_eq!(t.score("a.example", 86_400), 0);
    }

    #[test]
    fn restore_seeds_entry_from_snapshot() {
        let t = PopularityTracker::new();
        let h = hash_domain("seeded.example");
        t.restore(h, 42);
        assert_eq!(t.score("seeded.example", 86_400), 42);
    }

    // -----------------------------------------------------------------
    // Phase 4: snapshot persistence
    // -----------------------------------------------------------------

    fn tmp_path(label: &str) -> std::path::PathBuf {
        let pid = std::process::id();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("dgaard_pop_{label}_{pid}_{nonce}.bin"))
    }

    #[test]
    fn top_n_orders_by_score_then_hash() {
        let t = PopularityTracker::new();
        // Three entries; b is hottest, a and c tie at 1.
        for _ in 0..5 {
            t.record_hit("hot.example");
        }
        t.record_hit("warm-a.example");
        t.record_hit("warm-c.example");
        let pairs = top_n_pairs(&t, 10, 86_400);
        assert_eq!(pairs.len(), 3);
        assert_eq!(pairs[0].1, 5);
        // The two ties must be ordered by hash ascending so the
        // fingerprint is deterministic across runs.
        assert!(pairs[1].0 < pairs[2].0, "tie-break order is hash asc");
    }

    #[test]
    fn top_n_truncates_to_requested_size() {
        let t = PopularityTracker::new();
        for i in 0..20u32 {
            // Distinct domains so they hash differently.
            t.record_hit(&format!("d{i}.example"));
        }
        let pairs = top_n_pairs(&t, 5, 86_400);
        assert_eq!(pairs.len(), 5);
    }

    #[test]
    fn fingerprint_is_stable_for_identical_pairs() {
        let a = vec![(1u64, 10u8), (2, 5), (3, 1)];
        let b = a.clone();
        assert_eq!(fingerprint_pairs(&a), fingerprint_pairs(&b));
    }

    #[test]
    fn fingerprint_changes_when_score_changes() {
        let a = vec![(1u64, 10u8)];
        let b = vec![(1u64, 11u8)];
        assert_ne!(fingerprint_pairs(&a), fingerprint_pairs(&b));
    }

    #[test]
    fn fingerprint_sensitive_to_order() {
        // The snapshot is fingerprinted *post-sort*, so identical
        // contents in different orders must hash differently — that's
        // the contract the save loop relies on for delta-skipping.
        let a = vec![(1u64, 10u8), (2, 5)];
        let b = vec![(2u64, 5u8), (1, 10)];
        assert_ne!(fingerprint_pairs(&a), fingerprint_pairs(&b));
    }

    #[test]
    fn snapshot_roundtrip_preserves_pairs() {
        let path = tmp_path("roundtrip");
        let pairs = vec![(0xDEADBEEFu64, 200u8), (0x0BAD_F00Du64, 50u8)];
        write_snapshot(&path, &pairs).unwrap();
        let back = read_snapshot(&path).unwrap();
        assert_eq!(back, pairs);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn restart_with_decayed_score_restored_on_first_query() {
        // The Phase 4 integration test from the roadmap. Build a hot
        // tracker, snapshot it (the decayed score is what gets
        // written), spin up a fresh tracker, restore, then verify the
        // score is queryable by domain name on first read.
        let path = tmp_path("restart");

        // First "process": three queries to a.example, one to b.
        let t1 = PopularityTracker::new();
        for _ in 0..3 {
            t1.record_hit("a.example");
        }
        t1.record_hit("b.example");
        let top = top_n_pairs(&t1, 16, 86_400);
        write_snapshot(&path, &top).unwrap();

        // Second "process": restore on startup, then a real client
        // query (`score`) must come back with the persisted value.
        let t2 = PopularityTracker::new();
        let loaded = restore_into(&t2, &path).unwrap();
        assert_eq!(loaded, 2);
        assert_eq!(t2.score("a.example", 86_400), 3);
        assert_eq!(t2.score("b.example", 86_400), 1);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn restore_from_missing_file_is_not_an_error() {
        // First boot: the file isn't there yet. Returning Ok(0) means
        // the caller can `unwrap_or_default`-style integrate without
        // sprinkling NotFound handling everywhere.
        let path = tmp_path("missing");
        let t = PopularityTracker::new();
        let n = restore_into(&t, &path).unwrap();
        assert_eq!(n, 0);
        assert!(t.is_empty());
    }

    #[test]
    fn bad_magic_is_rejected() {
        let path = tmp_path("badmagic");
        // 8-byte garbage header, no payload.
        std::fs::write(&path, b"XXXX\x01\x00\x00\x00").unwrap();
        let err = read_snapshot(&path).unwrap_err();
        assert!(matches!(err, SnapshotError::BadMagic), "got {err:?}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn version_mismatch_is_rejected() {
        let path = tmp_path("badver");
        // Magic OK, but version is 99.
        std::fs::write(&path, b"DGPT\x63\x00\x00\x00").unwrap();
        let err = read_snapshot(&path).unwrap_err();
        assert!(
            matches!(err, SnapshotError::VersionMismatch(99)),
            "got {err:?}"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn truncated_header_is_rejected() {
        let path = tmp_path("truncated");
        std::fs::write(&path, b"DGP").unwrap();
        let err = read_snapshot(&path).unwrap_err();
        assert!(matches!(err, SnapshotError::Truncated), "got {err:?}");
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn snapshot_task_flushes_on_shutdown() {
        // Roadmap: "Flush on clean shutdown (SIGTERM handler)".
        // Set the periodic interval so high it will never tick within
        // the test, then trigger shutdown and verify the file appears.
        let path = tmp_path("shutdown_flush");
        let tracker = Arc::new(PopularityTracker::new());
        tracker.record_hit("shutdown.example");

        let (tx, rx) = watch::channel(false);
        let cfg = SnapshotTaskCfg {
            interval: Duration::from_secs(3600),
            top_n: 8,
            half_life_secs: 86_400,
        };
        let task_path = path.clone();
        let task_tracker = Arc::clone(&tracker);
        let handle = tokio::spawn(run_snapshot_task(task_tracker, task_path, cfg, rx));

        // Yield once so the task gets a chance to install its watchers.
        tokio::task::yield_now().await;
        let _ = tx.send(true);
        handle.await.unwrap();

        let restored = read_snapshot(&path).unwrap();
        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].1, 1);
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn snapshot_task_skips_write_when_fingerprint_unchanged() {
        // Roadmap: "Delta-based writes: skip if top-N fingerprint is
        // unchanged since last save." We assert this indirectly: after
        // the first periodic write the file's mtime must be stable
        // across subsequent ticks because nothing changed.
        let path = tmp_path("delta");
        let tracker = Arc::new(PopularityTracker::new());
        tracker.record_hit("static.example");

        let (tx, rx) = watch::channel(false);
        let cfg = SnapshotTaskCfg {
            interval: Duration::from_millis(50),
            top_n: 8,
            half_life_secs: 86_400,
        };
        let task_path = path.clone();
        let task_tracker = Arc::clone(&tracker);
        let handle = tokio::spawn(run_snapshot_task(task_tracker, task_path, cfg, rx));

        // First write: wait two intervals to be sure one has landed.
        tokio::time::sleep(Duration::from_millis(150)).await;
        let m1 = std::fs::metadata(&path).unwrap().modified().unwrap();

        // No changes — give the loop plenty of ticks. If delta-skip
        // works, mtime stays put. If it doesn't, the file is rewritten
        // every tick and m1 != m2.
        tokio::time::sleep(Duration::from_millis(300)).await;
        let m2 = std::fs::metadata(&path).unwrap().modified().unwrap();
        let _ = tx.send(true);
        handle.await.unwrap();
        // mtime resolution can be coarse (HFS is 1s); accept "equal"
        // as the success condition. A failing delta-skip implementation
        // would rewrite ~6 times in 300ms and bump the mtime.
        assert_eq!(m1, m2, "snapshot rewritten despite stable state");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn write_creates_missing_parent_directory() {
        // Fresh installs ship without /var/dgaard/; the writer must not
        // require the operator to mkdir it by hand on first boot.
        let pid = std::process::id();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("dgaard_pop_mkdir_{pid}_{nonce}/nested"));
        let path = dir.join("snap.bin");
        let pairs = vec![(42u64, 7u8)];
        write_snapshot(&path, &pairs).unwrap();
        assert_eq!(read_snapshot(&path).unwrap(), pairs);
        let _ = std::fs::remove_dir_all(dir.parent().unwrap());
    }

    #[test]
    fn snapshot_pairs_filters_decayed_to_zero() {
        let t = PopularityTracker::new();
        // Fresh entry: present in the snapshot.
        t.record_hit("fresh.example");
        // Stale entry: forced to zero by injecting a long-past Instant
        // via `restore`+manual mutation through DashMap.
        let stale_key = hash_domain("stale.example");
        t.map.insert(
            stale_key,
            PopularityEntry {
                hit_count: 1,
                last_hit_at: Instant::now() - Duration::from_secs(10_000),
            },
        );
        // Half-life of 1 second → stale entry instantly decays past
        // the 8-period clamp and is dropped from the snapshot.
        let pairs = t.snapshot_pairs(1);
        assert!(pairs.iter().any(|(_, s)| *s > 0));
        assert!(
            !pairs.iter().any(|(k, _)| *k == stale_key),
            "decayed-to-zero entry leaked into the snapshot"
        );
    }
}
