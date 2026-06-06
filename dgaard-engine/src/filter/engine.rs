use aho_corasick::AhoCorasick;
use regex::Regex;
use std::collections::{HashMap, HashSet};

use crate::{
    config::Config,
    filter::io::load_list_file,
    model::{DomainEntry, DomainEntryFlags},
};

pub struct FilterEngine {
    // Exact match (WL & BL without wildcards)
    pub fast_map: HashMap<u64, u8>,

    // For TLD & Wildcards (sorted by depth then hash)
    pub hierarchical_list: Vec<DomainEntry>,

    // Heavy data
    pub regex_pool: Vec<Regex>,
    pub wildcard_patterns: Vec<String>,

    // Lexical analysis (parental control)
    pub keyword_automaton: Option<AhoCorasick>,
    pub keyword_patterns: Vec<String>,
    pub suspicious_tld_hashes: HashSet<u64>,
    pub lexical_strict: bool,

    // ASN IP-range filtering
    pub blocked_asn_v4: Vec<(u32, u32)>,
    pub blocked_asn_v6: Vec<([u8; 16], [u8; 16])>,

    /// Hash seed used for all domain fingerprinting within this engine instance.
    pub seed: u64,
}

/// Parse an IPv4 CIDR string (e.g. `"203.0.113.0/24"`) into a `(network, mask)` pair.
pub(crate) fn parse_cidr_v4(s: &str) -> Option<(u32, u32)> {
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
pub(crate) fn parse_cidr_v6(s: &str) -> Option<([u8; 16], [u8; 16])> {
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
            seed: 0,
        }
    }

    /// Build an engine from file-based sources in the config.
    ///
    /// Does not perform any HTTP downloads — use `load_list_file` directly for
    /// URL-fetched content processed in `dgaard`.
    pub fn build_from_files(config: &Config, seed: u64) -> Self {
        let sources = &config.sources;

        let mut fast_map: HashMap<u64, u8> = HashMap::new();
        let mut hierarchical_list: Vec<DomainEntry> = Vec::new();
        let mut regex_pool: Vec<Regex> = Vec::new();
        let mut wildcard_patterns: Vec<String> = Vec::new();
        let mut host_index: HashMap<u64, String> = HashMap::new();
        let mut browser_rules: Vec<String> = Vec::new();

        // Load blacklists
        for path in &sources.blacklists {
            if let Err(e) = load_list_file(
                path,
                DomainEntryFlags::NONE,
                seed,
                &mut fast_map,
                &mut hierarchical_list,
                &mut wildcard_patterns,
                &mut regex_pool,
                &mut host_index,
                &mut browser_rules,
            ) {
                eprintln!("Warning: Failed to load blacklist {}: {}", path, e);
            }
        }

        // Load whitelists (with WHITELIST flag)
        for path in &sources.whitelists {
            if let Err(e) = load_list_file(
                path,
                DomainEntryFlags::WHITELIST,
                seed,
                &mut fast_map,
                &mut hierarchical_list,
                &mut wildcard_patterns,
                &mut regex_pool,
                &mut host_index,
                &mut browser_rules,
            ) {
                eprintln!("Warning: Failed to load whitelist {}: {}", path, e);
            }
        }

        // Load NRD list if path is set
        if !sources.nrd_list_path.is_empty()
            && let Err(e) = load_list_file(
                &sources.nrd_list_path,
                DomainEntryFlags::NRD,
                seed,
                &mut fast_map,
                &mut hierarchical_list,
                &mut wildcard_patterns,
                &mut regex_pool,
                &mut host_index,
                &mut browser_rules,
            )
        {
            eprintln!(
                "Warning: Failed to load NRD list {}: {}",
                sources.nrd_list_path, e
            );
        }

        // Sort hierarchical list by depth then hash for binary search
        hierarchical_list.sort_by(|a, b| a.depth.cmp(&b.depth).then(a.hash.cmp(&b.hash)));

        let mut engine = Self {
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
            seed,
        };

        engine.load_tld_filters(config);
        engine.load_lexical_filters(config);
        engine.load_asn_filters(config);

        engine
    }

    /// Load TLD exclusion filters from configuration.
    pub fn load_tld_filters(&mut self, config: &Config) {
        for tld in &config.tld.exclude {
            let tld_clean = tld.strip_prefix('.').unwrap_or(tld);
            self.hierarchical_list.push(DomainEntry {
                hash: twox_hash::XxHash64::oneshot(
                    self.seed,
                    tld_clean.to_ascii_lowercase().as_bytes(),
                ),
                depth: 0,
                data_idx: 0,
                flags: DomainEntryFlags::WILDCARD,
            });
        }
    }

    /// Load lexical filters (keyword blocking for parental control).
    pub fn load_lexical_filters(&mut self, config: &Config) {
        let lexical = &config.security.lexical;

        if !lexical.enabled || lexical.banned_keywords.is_empty() {
            return;
        }

        self.keyword_patterns = lexical
            .banned_keywords
            .iter()
            .map(|k| k.to_lowercase())
            .collect();

        self.keyword_automaton = AhoCorasick::new(&self.keyword_patterns).ok();

        self.suspicious_tld_hashes = config
            .tld
            .suspicious_tlds
            .iter()
            .map(|tld| {
                let tld_clean = tld.strip_prefix('.').unwrap_or(tld).to_ascii_lowercase();
                twox_hash::XxHash64::oneshot(self.seed, tld_clean.as_bytes())
            })
            .collect();

        self.lexical_strict = lexical.strict_keyword_matching;
    }

    /// Load ASN CIDR-range filters from configuration.
    pub fn load_asn_filters(&mut self, config: &Config) {
        let asn = &config.security.asn_filter;

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
        let hash = twox_hash::XxHash64::oneshot(self.seed, tld.to_ascii_lowercase().as_bytes());
        self.suspicious_tld_hashes.contains(&hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: u64 = 42;

    fn make_engine() -> FilterEngine {
        let mut e = FilterEngine::empty();
        e.seed = SEED;
        e
    }

    #[test]
    fn test_load_tld_filters_adds_entries() {
        let mut engine = make_engine();
        let mut cfg = Config::default();
        cfg.tld.exclude = vec![String::from(".xyz"), String::from(".top")];

        engine.load_tld_filters(&cfg);

        assert_eq!(engine.hierarchical_list.len(), 2);
        for entry in &engine.hierarchical_list {
            assert_eq!(entry.depth, 0);
            assert!(entry.flags.contains(DomainEntryFlags::WILDCARD));
        }
    }

    #[test]
    fn test_load_tld_filters_strips_leading_dot() {
        let mut engine = make_engine();
        let mut cfg = Config::default();
        cfg.tld.exclude = vec![String::from(".xyz")];
        engine.load_tld_filters(&cfg);

        let expected_hash = twox_hash::XxHash64::oneshot(SEED, "xyz".as_bytes());
        assert_eq!(engine.hierarchical_list[0].hash, expected_hash);
    }

    #[test]
    fn test_load_asn_filters_parses_ranges() {
        let mut engine = make_engine();
        let mut cfg = Config::default();
        cfg.security.asn_filter.enabled = true;
        cfg.security.asn_filter.blocked_ranges = vec![
            String::from("203.0.113.0/24"),
            String::from("2001:db8::/32"),
        ];

        engine.load_asn_filters(&cfg);

        assert_eq!(engine.blocked_asn_v4.len(), 1);
        assert_eq!(engine.blocked_asn_v6.len(), 1);
    }

    #[test]
    fn test_is_asn_blocked_v4_in_range() {
        let mut engine = make_engine();
        engine.blocked_asn_v4 = vec![parse_cidr_v4("203.0.113.0/24").unwrap()];

        assert!(engine.is_asn_blocked_v4("203.0.113.1".parse().unwrap()));
        assert!(!engine.is_asn_blocked_v4("203.0.112.255".parse().unwrap()));
    }

    #[test]
    fn test_is_suspicious_tld_with_empty_set() {
        let engine = make_engine();
        assert!(engine.is_suspicious_tld("com"));
        assert!(engine.is_suspicious_tld("xyz"));
    }

    #[test]
    fn test_parse_cidr_v4_valid() {
        let (net, mask) = parse_cidr_v4("203.0.113.0/24").unwrap();
        assert_eq!(mask, 0xFFFF_FF00);
        assert_eq!(net, u32::from(std::net::Ipv4Addr::new(203, 0, 113, 0)));
    }

    #[test]
    fn test_parse_cidr_v4_invalid() {
        assert!(parse_cidr_v4("not-a-cidr").is_none());
        assert!(parse_cidr_v4("1.2.3.4/33").is_none());
    }

    #[test]
    fn test_parse_cidr_v6_valid() {
        let (net, mask) = parse_cidr_v6("2001:db8::/32").unwrap();
        assert_eq!(&mask[..4], &[0xFF, 0xFF, 0xFF, 0xFF]);
        let expected_net: std::net::Ipv6Addr = "2001:db8::".parse().unwrap();
        assert_eq!(net, expected_net.octets());
    }
}
