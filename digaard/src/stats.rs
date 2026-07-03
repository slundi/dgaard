//! End-of-run latency summary emitted under `--stats` when batching.
//!
//! We keep every latency sample rather than an approximation histogram: with a
//! practical fan-out cap of a few thousand queries per invocation the cost is
//! negligible (a few tens of KB) and the percentile math stays exact.

/// One query's outcome for the stats summary.
#[derive(Debug, Clone, Copy)]
pub enum Sample {
    Ok { elapsed_ms: u64 },
    Err,
}

/// Accumulated stats over a batch.
#[derive(Debug, Default)]
pub struct Stats {
    samples: Vec<Sample>,
}

impl Stats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_ok(&mut self, elapsed_ms: u64) {
        self.samples.push(Sample::Ok { elapsed_ms });
    }

    pub fn record_err(&mut self) {
        self.samples.push(Sample::Err);
    }

    pub fn len(&self) -> usize {
        self.samples.len()
    }

    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    /// Compute min / avg / p50 / p95 / max over successful samples, plus
    /// success count, error count, and error rate.
    pub fn summary(&self) -> Summary {
        let mut oks: Vec<u64> = self
            .samples
            .iter()
            .filter_map(|s| match *s {
                Sample::Ok { elapsed_ms } => Some(elapsed_ms),
                Sample::Err => None,
            })
            .collect();
        oks.sort_unstable();

        let errors = self.samples.len() - oks.len();
        let total = self.samples.len();

        if oks.is_empty() {
            return Summary {
                total,
                ok: 0,
                errors,
                error_rate: if total == 0 { 0.0 } else { 1.0 },
                min_ms: None,
                avg_ms: None,
                p50_ms: None,
                p95_ms: None,
                max_ms: None,
            };
        }

        let sum: u128 = oks.iter().map(|v| *v as u128).sum();
        let avg = (sum / oks.len() as u128) as u64;

        Summary {
            total,
            ok: oks.len(),
            errors,
            error_rate: if total == 0 {
                0.0
            } else {
                errors as f64 / total as f64
            },
            min_ms: oks.first().copied(),
            avg_ms: Some(avg),
            p50_ms: Some(percentile(&oks, 50)),
            p95_ms: Some(percentile(&oks, 95)),
            max_ms: oks.last().copied(),
        }
    }
}

/// Nearest-rank percentile on a sorted slice. `pct` must be in [0, 100].
fn percentile(sorted: &[u64], pct: u8) -> u64 {
    assert!(!sorted.is_empty());
    // Nearest-rank: rank = ceil(pct/100 * N), 1-indexed.
    let n = sorted.len();
    let rank = (pct as usize * n).div_ceil(100);
    let idx = rank.saturating_sub(1).min(n - 1);
    sorted[idx]
}

/// Immutable rollup emitted at end of run.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Summary {
    pub total: usize,
    pub ok: usize,
    pub errors: usize,
    pub min_ms: Option<u64>,
    pub avg_ms: Option<u64>,
    pub p50_ms: Option<u64>,
    pub p95_ms: Option<u64>,
    pub max_ms: Option<u64>,
    pub error_rate: f64,
}

impl Summary {
    /// Human-readable one-block summary intended for stderr.
    pub fn to_stderr_lines(&self) -> String {
        let ms = |v: Option<u64>| match v {
            Some(v) => format!("{v}"),
            None => "-".to_string(),
        };
        format!(
            ";; --- stats ---\n\
             ;; queries: {total} (ok: {ok}, errors: {errors}, error rate: {rate:.1}%)\n\
             ;; latency ms: min={min} avg={avg} p50={p50} p95={p95} max={max}\n",
            total = self.total,
            ok = self.ok,
            errors = self.errors,
            rate = self.error_rate * 100.0,
            min = ms(self.min_ms),
            avg = ms(self.avg_ms),
            p50 = ms(self.p50_ms),
            p95 = ms(self.p95_ms),
            max = ms(self.max_ms),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_stats_returns_zeros() {
        let s = Stats::new();
        let sum = s.summary();
        assert_eq!(sum.total, 0);
        assert_eq!(sum.errors, 0);
        assert_eq!(sum.error_rate, 0.0);
        assert!(sum.min_ms.is_none());
    }

    #[test]
    fn all_errors_reports_100_percent_error_rate() {
        let mut s = Stats::new();
        s.record_err();
        s.record_err();
        let sum = s.summary();
        assert_eq!(sum.total, 2);
        assert_eq!(sum.ok, 0);
        assert_eq!(sum.errors, 2);
        assert_eq!(sum.error_rate, 1.0);
    }

    #[test]
    fn percentiles_over_uniform_distribution() {
        let mut s = Stats::new();
        for i in 1..=100u64 {
            s.record_ok(i);
        }
        let sum = s.summary();
        assert_eq!(sum.min_ms, Some(1));
        assert_eq!(sum.max_ms, Some(100));
        // avg = 50.5 → truncated to 50
        assert_eq!(sum.avg_ms, Some(50));
        // Nearest-rank p50 = value at ceil(50 * 100 / 100) = 50th → 50
        assert_eq!(sum.p50_ms, Some(50));
        // p95 → rank 95 → 95
        assert_eq!(sum.p95_ms, Some(95));
    }

    #[test]
    fn mixed_ok_and_errors() {
        let mut s = Stats::new();
        s.record_ok(10);
        s.record_ok(20);
        s.record_ok(30);
        s.record_err();
        let sum = s.summary();
        assert_eq!(sum.total, 4);
        assert_eq!(sum.ok, 3);
        assert_eq!(sum.errors, 1);
        // 1 error out of 4 → 0.25
        assert!((sum.error_rate - 0.25).abs() < 1e-9);
        assert_eq!(sum.min_ms, Some(10));
        assert_eq!(sum.max_ms, Some(30));
    }

    #[test]
    fn summary_prints_lines() {
        let mut s = Stats::new();
        s.record_ok(5);
        let out = s.summary().to_stderr_lines();
        assert!(out.contains("queries: 1"));
        assert!(out.contains("ok: 1"));
        assert!(out.contains("min=5"));
        assert!(out.contains("p95=5"));
    }

    #[test]
    fn percentile_of_singleton() {
        assert_eq!(percentile(&[42], 50), 42);
        assert_eq!(percentile(&[42], 95), 42);
    }
}
