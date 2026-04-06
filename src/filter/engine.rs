use aho_corasick::AhoCorasick;
use core::sync::atomic::Ordering;
use regex::Regex;
use std::collections::{HashMap, HashSet};

use crate::{
    CONFIG, GLOBAL_SEED,
    filter::io::load_list_file,
    model::{DomainEntry, DomainEntryFlags},
};

pub struct FilterEngine {
    // Exact match (WL & BL without wildcards)
    // u64 is xxh3 of complete domain name
    pub fast_map: HashMap<u64, u8>,

    // For TLD & Wildcards (sorted by depth then hash)
    pub hierarchical_list: Vec<DomainEntry>,

    // Heavy data
    pub regex_pool: Vec<Regex>, // compiled regex so regex.is_match(domain) to check
    pub wildcard_patterns: Vec<String>, // TODO: transform regex into wildcard when possible

    // Lexical analysis (parental control)
    // Aho-Corasick automaton for efficient multi-keyword matching
    pub keyword_automaton: Option<AhoCorasick>,
    // Original keywords for BlockReason (indexed by automaton pattern_id)
    pub keyword_patterns: Vec<String>,
    // xxh3 hashes of suspicious TLDs (without leading dot, lowercase)
    pub suspicious_tld_hashes: HashSet<u64>,
    // Strict matching mode (label-aware vs substring)
    pub lexical_strict: bool,
}
impl FilterEngine {
    pub fn empty() -> Self {
        Self {
            fast_map: HashMap::with_capacity(0),
            hierarchical_list: Vec::with_capacity(0),
            regex_pool: Vec::with_capacity(0),
            wildcard_patterns: Vec::with_capacity(0),
            keyword_automaton: None,
            keyword_patterns: Vec::with_capacity(0),
            suspicious_tld_hashes: HashSet::with_capacity(0),
            lexical_strict: true,
        }
    }

    pub fn build_from_files() -> Self {
        let cfg = CONFIG.load();
        let sources = &cfg.sources;

        let mut fast_map: HashMap<u64, u8> = HashMap::new();
        let mut hierarchical_list: Vec<DomainEntry> = Vec::new();
        let mut regex_pool: Vec<Regex> = Vec::new();
        let mut wildcard_patterns: Vec<String> = Vec::new();

        // Load blacklists
        for path in &sources.blacklists {
            if let Err(e) = load_list_file(
                path,
                DomainEntryFlags::NONE,
                &mut fast_map,
                &mut hierarchical_list,
                &mut wildcard_patterns,
                &mut regex_pool,
            ) {
                eprintln!("Warning: Failed to load blacklist {}: {}", path, e);
            }
        }

        // Load whitelists (with WHITELIST flag)
        for path in &sources.whitelists {
            if let Err(e) = load_list_file(
                path,
                DomainEntryFlags::WHITELIST,
                &mut fast_map,
                &mut hierarchical_list,
                &mut wildcard_patterns,
                &mut regex_pool,
            ) {
                eprintln!("Warning: Failed to load whitelist {}: {}", path, e);
            }
        }

        // Load NRD list if path is set
        if !sources.nrd_list_path.is_empty()
            && let Err(e) = load_list_file(
                &sources.nrd_list_path,
                DomainEntryFlags::NONE,
                &mut fast_map,
                &mut hierarchical_list,
                &mut wildcard_patterns,
                &mut regex_pool,
            )
        {
            eprintln!(
                "Warning: Failed to load NRD list {}: {}",
                sources.nrd_list_path, e
            );
        }

        // Sort hierarchical list by depth then hash for binary search
        hierarchical_list.sort_by(|a, b| a.depth.cmp(&b.depth).then(a.hash.cmp(&b.hash)));

        Self {
            fast_map,
            hierarchical_list,
            regex_pool,
            wildcard_patterns,
            keyword_automaton: None,
            keyword_patterns: Vec::new(),
            suspicious_tld_hashes: HashSet::new(),
            lexical_strict: true,
        }
    }

    /// Load TLD exclusion filters from configuration.
    ///
    /// TLDs in `cfg.tld.exclude` (e.g., `".xyz"`, `".top"`) are added to the
    /// hierarchical list with `depth: 0` and `WILDCARD` flag, so any domain
    /// under that TLD will be blocked by `is_suffix_blocked`.
    pub fn load_tld_filters(&mut self) {
        let cfg = CONFIG.load();
        for tld in &cfg.tld.exclude {
            // Strip leading dot if present (config stores ".xyz", lookup uses "xyz")
            let tld_clean = tld.strip_prefix('.').unwrap_or(tld);
            self.hierarchical_list.push(DomainEntry {
                hash: twox_hash::XxHash64::oneshot(
                    GLOBAL_SEED.load(Ordering::Relaxed),
                    tld_clean.to_ascii_lowercase().as_bytes(),
                ),
                depth: 0,
                data_idx: 0,
                flags: DomainEntryFlags::WILDCARD,
            });
        }
    }

    /// Load lexical filters (keyword blocking for parental control).
    ///
    /// Builds an Aho-Corasick automaton from `cfg.security.lexical.banned_keywords`
    /// for efficient multi-pattern matching. Suspicious TLDs are stored as xxh3
    /// hashes for O(1) lookup.
    pub fn load_lexical_filters(&mut self) {
        let cfg = CONFIG.load();
        let lexical = &cfg.security.lexical;

        if !lexical.enabled || lexical.banned_keywords.is_empty() {
            return;
        }

        // Store original keywords (lowercase) for BlockReason
        self.keyword_patterns = lexical
            .banned_keywords
            .iter()
            .map(|k| k.to_lowercase())
            .collect();

        // Build Aho-Corasick automaton for efficient multi-pattern matching
        self.keyword_automaton = AhoCorasick::new(&self.keyword_patterns).ok();

        // Hash suspicious TLDs without leading dot for O(1) lookup
        let seed = GLOBAL_SEED.load(Ordering::Relaxed);
        self.suspicious_tld_hashes = lexical
            .suspicious_tlds
            .iter()
            .map(|tld| {
                let tld_clean = tld.strip_prefix('.').unwrap_or(tld).to_ascii_lowercase();
                twox_hash::XxHash64::oneshot(seed, tld_clean.as_bytes())
            })
            .collect();

        self.lexical_strict = lexical.strict_keyword_matching;
    }

    /// Check if a TLD hash is in the suspicious set.
    #[inline]
    pub fn is_suspicious_tld(&self, tld: &str) -> bool {
        if self.suspicious_tld_hashes.is_empty() {
            return true; // No TLD restriction = all TLDs suspicious
        }
        let hash = twox_hash::XxHash64::oneshot(
            GLOBAL_SEED.load(Ordering::Relaxed),
            tld.to_ascii_lowercase().as_bytes(),
        );
        self.suspicious_tld_hashes.contains(&hash)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::{filter::tests::init_seed, model::DomainEntryFlags};

    // --- Tests for load_tld_filters ---

    #[test]
    fn test_load_tld_filters_adds_entries_with_depth_zero() {
        init_seed();
        let mut engine = FilterEngine::empty();

        // Manually set TLD config for test
        let mut cfg = crate::config::Config::default();
        cfg.tld.exclude = vec![String::from(".xyz"), String::from(".top")];
        CONFIG.store(Arc::new(cfg));

        engine.load_tld_filters();

        assert_eq!(engine.hierarchical_list.len(), 2);
        for entry in &engine.hierarchical_list {
            assert_eq!(entry.depth, 0, "TLD entries should have depth 0");
            assert!(
                entry.flags.contains(DomainEntryFlags::WILDCARD),
                "TLD entries should have WILDCARD flag"
            );
        }
    }

    #[test]
    fn test_load_tld_filters_strips_leading_dot() {
        init_seed();
        let mut engine = FilterEngine::empty();

        let mut cfg = crate::config::Config::default();
        cfg.tld.exclude = vec![String::from(".xyz")];
        CONFIG.store(Arc::new(cfg));

        engine.load_tld_filters();

        // Hash should be for "xyz" not ".xyz"
        let expected_hash = twox_hash::XxHash64::oneshot(42, "xyz".as_bytes());
        assert_eq!(engine.hierarchical_list.len(), 1);
        assert_eq!(
            engine.hierarchical_list[0].hash, expected_hash,
            "Hash should be for 'xyz' without leading dot"
        );
    }

    #[test]
    fn test_load_tld_filters_handles_no_leading_dot() {
        init_seed();
        let mut engine = FilterEngine::empty();

        let mut cfg = crate::config::Config::default();
        cfg.tld.exclude = vec![String::from("bid")]; // No leading dot
        CONFIG.store(Arc::new(cfg));

        engine.load_tld_filters();

        let expected_hash = twox_hash::XxHash64::oneshot(42, "bid".as_bytes());
        assert_eq!(engine.hierarchical_list[0].hash, expected_hash);
    }

    #[test]
    fn test_load_tld_filters_lowercases_tld() {
        init_seed();
        let mut engine = FilterEngine::empty();

        let mut cfg = crate::config::Config::default();
        cfg.tld.exclude = vec![String::from(".XYZ"), String::from(".Top")];
        CONFIG.store(Arc::new(cfg));

        engine.load_tld_filters();

        // Hashes should be for lowercase versions
        let hash_xyz = twox_hash::XxHash64::oneshot(42, "xyz".as_bytes());
        let hash_top = twox_hash::XxHash64::oneshot(42, "top".as_bytes());

        let hashes: Vec<u64> = engine.hierarchical_list.iter().map(|e| e.hash).collect();
        assert!(hashes.contains(&hash_xyz), "Should contain hash for 'xyz'");
        assert!(hashes.contains(&hash_top), "Should contain hash for 'top'");
    }

    #[test]
    fn test_load_tld_filters_empty_list() {
        init_seed();
        let mut engine = FilterEngine::empty();

        let mut cfg = crate::config::Config::default();
        cfg.tld.exclude = vec![];
        CONFIG.store(Arc::new(cfg));

        engine.load_tld_filters();

        assert!(
            engine.hierarchical_list.is_empty(),
            "Empty exclude list should produce no entries"
        );
    }
}
