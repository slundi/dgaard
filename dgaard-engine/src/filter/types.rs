use hickory_resolver::proto::ProtoError;
use std::collections::HashSet;
use thiserror::Error;

use crate::config::{Config, IdnMode};

#[derive(Error, Debug)]
pub enum ListError<'a> {
    #[error("Invalid domain {1}: {0}")]
    InvalidDomain(#[source] ProtoError, &'a str),
    #[error("Failed to parse line: {1}, format: {2}. Internal error: {0}")]
    ParseError(#[source] std::io::Error, &'a str, &'a str),
    #[error("Line skipped (empty or comment)")]
    Skip,
    #[error("Browser-only rule (cosmetic/scriptlet): {0}")]
    BrowserRule(&'a str),
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ListFormat {
    Hosts,
    Dnsmasq,
    Plain,
    Abp,
    Unknown,
}

/// Load-time entropy thresholds used to drop DGA-looking blacklist entries.
///
/// Values mirror the subset of [`crate::config::IntelligenceConfig`] required
/// to evaluate a domain's SLD at parse time.
#[derive(Debug, Clone)]
pub struct EntropyThresholds {
    pub threshold: f32,
    pub fast: bool,
    pub min_word_length: usize,
    pub consonant_ratio_threshold: f32,
    pub max_consonant_sequence: usize,
}

/// Constraints applied at list-load time to drop blacklist entries that are
/// already covered by cheaper query-time filters (structural sanity, TLD
/// exclusion, entropy heuristics).
///
/// The filter is **only** applied to non-whitelist entries — legitimate
/// whitelist entries that happen to trip a heuristic must still be kept so
/// they can override blacklists at query time.
#[derive(Debug, Clone)]
pub struct LoadFilter {
    pub max_subdomain_depth: u8,
    pub max_domain_length: u16,
    /// Precomputed hashes of `tld.exclude` entries (lower-cased, no leading dot).
    pub tld_exclude_hashes: HashSet<u64>,
    /// Only `Some` when `intelligence.enabled` and
    /// `intelligence.ignore_entry_matching_entropy` are both true.
    pub entropy_check: Option<EntropyThresholds>,
    /// Drop blacklist entries whose domain contains Punycode (`xn--`) labels
    /// or non-ASCII characters at load time, because the query-time IDN filter
    /// will block them anyway.
    ///
    /// Set when `server.block_idn` is `true` or `security.idn.mode` is not `Off`.
    pub skip_idn: bool,
}

impl LoadFilter {
    /// Build a `LoadFilter` from the resolved configuration.
    ///
    /// `seed` must match the seed used for domain hashing so TLD-exclude
    /// lookups are consistent with the rest of the engine.
    pub fn from_config(config: &Config, seed: u64) -> Self {
        let structure = &config.security.structure;
        let intel = &config.security.intelligence;

        let tld_exclude_hashes = config
            .tld
            .exclude
            .iter()
            .map(|tld| {
                let clean = tld.strip_prefix('.').unwrap_or(tld).to_ascii_lowercase();
                twox_hash::XxHash64::oneshot(seed, clean.as_bytes())
            })
            .collect();

        let entropy_check =
            (intel.enabled && intel.ignore_entry_matching_entropy).then_some(EntropyThresholds {
                threshold: intel.entropy_threshold,
                fast: intel.entropy_fast,
                min_word_length: intel.min_word_length,
                consonant_ratio_threshold: intel.consonant_ratio_threshold,
                max_consonant_sequence: intel.max_consonant_sequence,
            });

        let skip_idn = config.server.block_idn || config.security.idn.mode != IdnMode::Off;

        Self {
            max_subdomain_depth: structure.max_subdomain_depth,
            max_domain_length: structure.max_domain_length,
            tld_exclude_hashes,
            entropy_check,
            skip_idn,
        }
    }
}
