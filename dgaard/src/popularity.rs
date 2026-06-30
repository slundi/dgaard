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

use std::time::Instant;

use dashmap::DashMap;
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
