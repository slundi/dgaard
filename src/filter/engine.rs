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

    // ASN IP-range filtering: pre-parsed (network_bits, mask_bits) pairs
    // for zero-allocation hot-path matching.
    pub blocked_asn_v4: Vec<(u32, u32)>, // IPv4 (network, mask)
    pub blocked_asn_v6: Vec<([u8; 16], [u8; 16])>, // IPv6 (network, mask)
}
/// Parse an IPv4 CIDR string (e.g. `"203.0.113.0/24"`) into a `(network, mask)` pair.
///
/// Both values are returned as host-endian `u32`. A `/32` mask covers exactly
/// one address; `/0` covers the entire address space.
fn parse_cidr_v4(s: &str) -> Option<(u32, u32)> {
    let (ip_str, prefix_str) = s.split_once('/')?;
    let ip: std::net::Ipv4Addr = ip_str.parse().ok()?;
    let prefix: u32 = prefix_str.parse().ok()?;
    if prefix > 32 {
        return None;
    }
    let mask = if prefix == 0 {
        0u32
    } else {
        !0u32 << (32 - prefix)
    };
    let network = u32::from(ip) & mask;
    Some((network, mask))
}

/// Parse an IPv6 CIDR string (e.g. `"2001:db8::/32"`) into a `(network, mask)` pair.
///
/// Both values are byte arrays in network (big-endian) order.
fn parse_cidr_v6(s: &str) -> Option<([u8; 16], [u8; 16])> {
    let (ip_str, prefix_str) = s.split_once('/')?;
    let ip: std::net::Ipv6Addr = ip_str.parse().ok()?;
    let prefix: u32 = prefix_str.parse().ok()?;
    if prefix > 128 {
        return None;
    }
    let mut mask = [0u8; 16];
    for (i, byte) in mask.iter_mut().enumerate() {
        let bit_start = (i * 8) as u32;
        let bit_end = bit_start + 8;
        if prefix >= bit_end {
            *byte = 0xFF;
        } else if prefix > bit_start {
            let bits = prefix - bit_start;
            *byte = !0u8 << (8 - bits);
        }
    }
    let ip_bytes = ip.octets();
    let mut network = [0u8; 16];
    for i in 0..16 {
        network[i] = ip_bytes[i] & mask[i];
    }
    Some((network, mask))
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
            blocked_asn_v4: Vec::with_capacity(0),
            blocked_asn_v6: Vec::with_capacity(0),
        }
    }

    pub fn build_from_files() -> Self {
        let cfg = CONFIG.load();
        let sources = &cfg.sources;

        let mut fast_map: HashMap<u64, u8> = HashMap::new();
        let mut hierarchical_list: Vec<DomainEntry> = Vec::new();
        let mut regex_pool: Vec<Regex> = Vec::new();
        let mut wildcard_patterns: Vec<String> = Vec::new();
        let mut host_index: HashMap<u64, String> = HashMap::new();

        // Load blacklists
        for path in &sources.blacklists {
            if let Err(e) = load_list_file(
                path,
                DomainEntryFlags::NONE,
                &mut fast_map,
                &mut hierarchical_list,
                &mut wildcard_patterns,
                &mut regex_pool,
                &mut host_index,
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
                &mut host_index,
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
                &mut host_index,
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
            blocked_asn_v4: Vec::new(),
            blocked_asn_v6: Vec::new(),
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
        self.suspicious_tld_hashes = cfg
            .tld
            .suspicious_tlds
            .iter()
            .map(|tld| {
                let tld_clean = tld.strip_prefix('.').unwrap_or(tld).to_ascii_lowercase();
                twox_hash::XxHash64::oneshot(seed, tld_clean.as_bytes())
            })
            .collect();

        self.lexical_strict = lexical.strict_keyword_matching;
    }

    /// Load ASN CIDR-range filters from configuration.
    ///
    /// Parses `cfg.security.asn_filter.blocked_ranges` once at engine build
    /// time and stores the results as pre-computed `(network, mask)` pairs for
    /// zero-allocation hot-path matching. Invalid CIDR strings are skipped with
    /// a warning.
    pub fn load_asn_filters(&mut self) {
        let cfg = CONFIG.load();
        let asn = &cfg.security.asn_filter;

        if !asn.enabled {
            return;
        }

        for range in &asn.blocked_ranges {
            if range.contains(':') {
                match parse_cidr_v6(range) {
                    Some(parsed) => self.blocked_asn_v6.push(parsed),
                    None => eprintln!("Warning: Invalid IPv6 CIDR range in asn_filter: {range}"),
                }
            } else {
                match parse_cidr_v4(range) {
                    Some(parsed) => self.blocked_asn_v4.push(parsed),
                    None => eprintln!("Warning: Invalid IPv4 CIDR range in asn_filter: {range}"),
                }
            }
        }
    }

    /// Return `true` if `ip` falls within any configured blocked ASN IPv4 range.
    #[inline]
    pub fn is_asn_blocked_v4(&self, ip: std::net::Ipv4Addr) -> bool {
        let ip_bits = u32::from(ip);
        self.blocked_asn_v4
            .iter()
            .any(|&(network, mask)| (ip_bits & mask) == network)
    }

    /// Return `true` if `ip` falls within any configured blocked ASN IPv6 range.
    #[inline]
    pub fn is_asn_blocked_v6(&self, ip: std::net::Ipv6Addr) -> bool {
        let ip_bytes = ip.octets();
        self.blocked_asn_v6.iter().any(|(network, mask)| {
            ip_bytes
                .iter()
                .zip(network.iter())
                .zip(mask.iter())
                .all(|((ip_b, net_b), mask_b)| (ip_b & mask_b) == *net_b)
        })
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

    // --- Tests for CIDR parsing ---

    #[test]
    fn test_parse_cidr_v4_valid() {
        let (net, mask) = parse_cidr_v4("203.0.113.0/24").unwrap();
        assert_eq!(mask, 0xFFFF_FF00);
        assert_eq!(net, u32::from(std::net::Ipv4Addr::new(203, 0, 113, 0)));
    }

    #[test]
    fn test_parse_cidr_v4_slash32() {
        let (net, mask) = parse_cidr_v4("1.2.3.4/32").unwrap();
        assert_eq!(mask, 0xFFFF_FFFF);
        assert_eq!(net, u32::from(std::net::Ipv4Addr::new(1, 2, 3, 4)));
    }

    #[test]
    fn test_parse_cidr_v4_slash0() {
        let (net, mask) = parse_cidr_v4("0.0.0.0/0").unwrap();
        assert_eq!(mask, 0);
        assert_eq!(net, 0);
    }

    #[test]
    fn test_parse_cidr_v4_invalid() {
        assert!(parse_cidr_v4("not-a-cidr").is_none());
        assert!(parse_cidr_v4("1.2.3.4/33").is_none());
        assert!(parse_cidr_v4("1.2.3.4").is_none()); // no prefix
    }

    #[test]
    fn test_parse_cidr_v6_valid() {
        let (net, mask) = parse_cidr_v6("2001:db8::/32").unwrap();
        // First 4 bytes should be FF for a /32
        assert_eq!(&mask[..4], &[0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(&mask[4..], &[0u8; 12]);
        // Network bytes should be 2001:0db8::
        let expected_net: std::net::Ipv6Addr = "2001:db8::".parse().unwrap();
        assert_eq!(net, expected_net.octets());
    }

    #[test]
    fn test_parse_cidr_v6_slash128() {
        let (net, mask) = parse_cidr_v6("::1/128").unwrap();
        assert_eq!(mask, [0xFF; 16]);
        let expected: std::net::Ipv6Addr = "::1".parse().unwrap();
        assert_eq!(net, expected.octets());
    }

    #[test]
    fn test_parse_cidr_v6_invalid() {
        assert!(parse_cidr_v6("not-a-cidr").is_none());
        assert!(parse_cidr_v6("2001:db8::/129").is_none());
    }

    // --- Tests for load_asn_filters and range checks ---

    #[test]
    fn test_load_asn_filters_parses_ranges() {
        init_seed();
        let mut engine = FilterEngine::empty();

        let mut cfg = crate::config::Config::default();
        cfg.security.asn_filter.enabled = true;
        cfg.security.asn_filter.blocked_ranges = vec![
            String::from("203.0.113.0/24"),
            String::from("2001:db8::/32"),
        ];
        CONFIG.store(Arc::new(cfg));

        engine.load_asn_filters();

        assert_eq!(engine.blocked_asn_v4.len(), 1);
        assert_eq!(engine.blocked_asn_v6.len(), 1);
    }

    #[test]
    fn test_load_asn_filters_disabled_skips_parsing() {
        init_seed();
        let mut engine = FilterEngine::empty();

        let mut cfg = crate::config::Config::default();
        cfg.security.asn_filter.enabled = false;
        cfg.security.asn_filter.blocked_ranges = vec![String::from("203.0.113.0/24")];
        CONFIG.store(Arc::new(cfg));

        engine.load_asn_filters();

        assert!(engine.blocked_asn_v4.is_empty());
        assert!(engine.blocked_asn_v6.is_empty());
    }

    #[test]
    fn test_is_asn_blocked_v4_in_range() {
        let mut engine = FilterEngine::empty();
        engine.blocked_asn_v4 = vec![parse_cidr_v4("203.0.113.0/24").unwrap()];

        assert!(engine.is_asn_blocked_v4("203.0.113.1".parse().unwrap()));
        assert!(engine.is_asn_blocked_v4("203.0.113.255".parse().unwrap()));
        assert!(!engine.is_asn_blocked_v4("203.0.112.255".parse().unwrap()));
        assert!(!engine.is_asn_blocked_v4("203.0.114.0".parse().unwrap()));
    }

    #[test]
    fn test_is_asn_blocked_v6_in_range() {
        let mut engine = FilterEngine::empty();
        engine.blocked_asn_v6 = vec![parse_cidr_v6("2001:db8::/32").unwrap()];

        assert!(engine.is_asn_blocked_v6("2001:db8::1".parse().unwrap()));
        assert!(engine.is_asn_blocked_v6("2001:db8:ffff::1".parse().unwrap()));
        assert!(!engine.is_asn_blocked_v6("2001:db9::1".parse().unwrap()));
        assert!(!engine.is_asn_blocked_v6("2002:db8::1".parse().unwrap()));
    }

    #[test]
    fn test_is_asn_blocked_empty_ranges() {
        let engine = FilterEngine::empty();
        assert!(!engine.is_asn_blocked_v4("1.2.3.4".parse().unwrap()));
        assert!(!engine.is_asn_blocked_v6("2001:db8::1".parse().unwrap()));
    }
}
