use std::net::IpAddr;

use aho_corasick::AhoCorasick;
use regex::Regex;
use std::collections::{HashMap, HashSet};

use crate::{
    config::Config,
    filter::io::load_list_file,
    model::{DomainEntry, DomainEntryFlags},
};

/// Filesystem metadata captured when the GeoIP database was last mmap'd.
///
/// Stored so that the next reload can compare the current file state and warn
/// when an in-place write (truncate + overwrite) was detected.  Rename-based
/// replacement is safe; in-place writes cause SIGBUS → UB.
#[derive(Debug, Clone)]
pub struct GeoipFileMeta {
    /// inode number of the mapped file.
    pub ino: u64,
    /// File size in bytes at open time.
    pub size: u64,
    /// Modification time (seconds since Unix epoch).
    pub mtime: i64,
}

pub struct FilterEngine {
    // Exact match (WL & BL without wildcards)
    pub fast_map: HashMap<u64, (u8, Box<str>)>,

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

    // GeoIP country-based suspicion scoring
    pub geoip_reader: Option<maxminddb::Reader<maxminddb::Mmap>>,
    pub suspicious_country_codes: HashSet<String>,
    pub suspicious_country_score: u8,

    /// Inode snapshot of the GeoIP database file taken at last open.
    /// Used to detect in-place modifications before the next reload.
    pub geoip_file_meta: Option<GeoipFileMeta>,

    /// User-defined custom flag domain lookups.
    /// Each entry is `(bit_index, suspicious_score, domain_hash_set)`.
    /// Bit indices correspond to bits 16–31 of `StatBlockReason`.
    pub custom_flag_maps: Vec<(u8, u8, HashMap<u64, ()>)>,

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
            geoip_reader: None,
            geoip_file_meta: None,
            suspicious_country_codes: HashSet::with_capacity(0),
            suspicious_country_score: 3,
            custom_flag_maps: Vec::with_capacity(0),
            seed: 0,
        }
    }

    /// Build an engine from file-based sources in the config.
    ///
    /// Does not perform any HTTP downloads — use `load_list_file` directly for
    /// URL-fetched content processed in `dgaard`.
    pub fn build_from_files(config: &Config, seed: u64) -> Self {
        let sources = &config.sources;

        let mut fast_map: HashMap<u64, (u8, Box<str>)> = HashMap::new();
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
            geoip_reader: None,
            geoip_file_meta: None,
            suspicious_country_codes: HashSet::new(),
            suspicious_country_score: 3,
            custom_flag_maps: Vec::new(),
            seed,
        };

        engine.load_tld_filters(config);
        engine.load_lexical_filters(config);
        engine.load_asn_filters(config);
        engine.load_geoip_filter(config);
        engine.load_custom_flags(config);

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

    /// Load GeoIP filter from a MaxMind MMDB file.
    ///
    /// Opens the database with mmap — no heap copy of the file contents.
    /// Country codes in `suspicious_countries` are normalised to uppercase.
    pub fn load_geoip_filter(&mut self, config: &Config) {
        let geo = &config.security.geo_ip;

        if !geo.enabled || geo.database_path.is_empty() {
            return;
        }

        let path = &geo.database_path;

        // Compare the current on-disk metadata against the snapshot taken at
        // the last open.  If the inode is unchanged but size or mtime differ,
        // the file was modified in-place while the old mmap was live — SIGBUS
        // is possible on any in-flight read that touches a page past the new
        // EOF.  Emit an early warning so the operator can switch to rename-based
        // updates before the next reload.
        #[cfg(unix)]
        if let (Some(prev), Ok(cur)) = (&self.geoip_file_meta, std::fs::metadata(path)) {
            use std::os::unix::fs::MetadataExt;
            if prev.ino == cur.ino() && (prev.size != cur.len() || prev.mtime != cur.mtime()) {
                eprintln!(
                    "Warning: GeoIP database '{}' was modified in-place (inode \
                     unchanged, size/mtime changed). The previous mmap may be \
                     corrupted — SIGBUS is possible under concurrent reads. \
                     Use atomic rename-based updates: write to a sibling temp \
                     file and `mv` it into place.",
                    path
                );
            }
        }

        // SAFETY: opens the database file read-only via mmap.
        //
        // Rename-based replacement IS safe on Linux: `mv tmp.mmdb geoip.mmdb`
        // is an atomic rename(2).  The mmap holds an open reference to the old
        // inode; the path atomically points to the new file.  In-flight reads
        // continue to see consistent data; the old inode is freed when the last
        // reference drops.
        //
        // In-place writes (truncate then overwrite) are NOT safe: any access to
        // a mmap'd page past the new EOF causes SIGBUS, which is undefined
        // behaviour in Rust.  External updaters (e.g. `geoipupdate`) MUST use
        // rename-based replacement.
        match unsafe { maxminddb::Reader::open_mmap(path) } {
            Ok(reader) => {
                // Snapshot inode + size + mtime so the next reload can detect
                // an in-place write that happened while this reader was live.
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    self.geoip_file_meta = std::fs::metadata(path).ok().map(|m| GeoipFileMeta {
                        ino: m.ino(),
                        size: m.len(),
                        mtime: m.mtime(),
                    });
                }

                self.geoip_reader = Some(reader);
                self.suspicious_country_codes = geo
                    .suspicious_countries
                    .iter()
                    .map(|c| c.to_ascii_uppercase())
                    .collect();
                self.suspicious_country_score = geo.suspicious_country_score;
            }
            Err(e) => eprintln!(
                "Warning: Failed to open GeoIP database {}: {}",
                geo.database_path, e
            ),
        }
    }

    /// Load user-defined custom flag domain lists from configuration.
    ///
    /// For each `[[security.custom_flags]]` entry, reads every `list_path` file
    /// as a plain-text domain list (one domain per line, `#` comments stripped)
    /// and stores the hashed domain set alongside its bit index and score.
    pub fn load_custom_flags(&mut self, config: &Config) {
        for flag in &config.security.custom_flags {
            let mut map: HashMap<u64, ()> = HashMap::new();
            for path in &flag.list_path {
                match Self::load_plain_domain_list(path, self.seed) {
                    Ok(domains) => map.extend(domains),
                    Err(e) => eprintln!(
                        "Warning: Failed to load custom flag list {} (bit {}): {}",
                        path, flag.bit, e
                    ),
                }
            }
            self.custom_flag_maps
                .push((flag.bit, flag.suspicious_score, map));
        }
    }

    /// Read a plain-text domain list file and return a set of XxHash64 digests.
    fn load_plain_domain_list(path: &str, seed: u64) -> std::io::Result<HashMap<u64, ()>> {
        use std::io::BufRead;
        let file = std::fs::File::open(path)?;
        let reader = std::io::BufReader::new(file);
        let mut map = HashMap::new();
        for line in reader.lines() {
            let line = line?;
            let line = line.trim();
            let line = line.find('#').map(|i| &line[..i]).unwrap_or(line).trim();
            if line.is_empty() {
                continue;
            }
            let hash = twox_hash::XxHash64::oneshot(seed, line.to_ascii_lowercase().as_bytes());
            map.insert(hash, ());
        }
        Ok(map)
    }

    /// Return the ISO 3166-1 alpha-2 country code if `ip` is in a suspicious
    /// country, or `None` if the IP is unknown or the country is not suspicious.
    pub fn geoip_country_suspicious_v4(&self, ip: std::net::Ipv4Addr) -> Option<String> {
        self.geoip_country_suspicious(IpAddr::V4(ip))
    }

    /// Return the ISO 3166-1 alpha-2 country code if `ip` is in a suspicious
    /// country, or `None` if the IP is unknown or the country is not suspicious.
    pub fn geoip_country_suspicious_v6(&self, ip: std::net::Ipv6Addr) -> Option<String> {
        self.geoip_country_suspicious(IpAddr::V6(ip))
    }

    fn geoip_country_suspicious(&self, ip: IpAddr) -> Option<String> {
        let reader = self.geoip_reader.as_ref()?;
        let result = reader.lookup(ip).ok()?;
        let record = result.decode::<maxminddb::geoip2::Country>().ok()??;
        let iso_code = record.country.iso_code?;
        if self.suspicious_country_codes.contains(iso_code) {
            Some(iso_code.to_string())
        } else {
            None
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
    fn test_load_geoip_filter_disabled() {
        let mut engine = make_engine();
        let cfg = Config::default(); // geo_ip.enabled = false
        engine.load_geoip_filter(&cfg);
        assert!(engine.geoip_reader.is_none());
        assert!(engine.suspicious_country_codes.is_empty());
    }

    #[test]
    fn test_load_geoip_filter_missing_db() {
        let mut engine = make_engine();
        let mut cfg = Config::default();
        cfg.security.geo_ip.enabled = true;
        cfg.security.geo_ip.database_path = "/nonexistent/GeoLite2-Country.mmdb".to_string();
        cfg.security.geo_ip.suspicious_countries = vec!["RU".to_string()];
        // Should log a warning but not panic; reader stays None
        engine.load_geoip_filter(&cfg);
        assert!(engine.geoip_reader.is_none());
    }

    #[test]
    fn test_geoip_suspicious_with_no_reader() {
        let engine = make_engine();
        // No reader loaded — all IPs are non-suspicious
        assert!(
            engine
                .geoip_country_suspicious_v4("1.2.3.4".parse().unwrap())
                .is_none()
        );
        assert!(
            engine
                .geoip_country_suspicious_v6("2001:db8::1".parse().unwrap())
                .is_none()
        );
    }

    #[test]
    fn test_parse_cidr_v6_valid() {
        let (net, mask) = parse_cidr_v6("2001:db8::/32").unwrap();
        assert_eq!(&mask[..4], &[0xFF, 0xFF, 0xFF, 0xFF]);
        let expected_net: std::net::Ipv6Addr = "2001:db8::".parse().unwrap();
        assert_eq!(net, expected_net.octets());
    }

    // ── custom_flag_maps ─────────────────────────────────────────────────────────

    #[test]
    fn test_load_custom_flags_empty_when_no_config() {
        let mut engine = make_engine();
        let cfg = Config::default();
        engine.load_custom_flags(&cfg);
        assert!(engine.custom_flag_maps.is_empty());
    }

    #[test]
    fn test_load_custom_flags_from_file() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "evil.example.com").unwrap();
        writeln!(f, "# this is a comment").unwrap();
        writeln!(f, "bad.tld").unwrap();
        writeln!(f, "  spaced.domain.net  ").unwrap();
        writeln!(f, "MIXED.Case.COM").unwrap(); // must match as lowercase
        f.flush().unwrap();

        let mut cfg = Config::default();
        cfg.security
            .custom_flags
            .push(crate::config::CustomFlagConfig {
                bit: 16,
                code: "TEST".to_string(),
                name: "Test Flag".to_string(),
                description: String::new(),
                suspicious_score: 5,
                list_path: vec![f.path().to_str().unwrap().to_string()],
            });

        let mut engine = make_engine();
        engine.load_custom_flags(&cfg);

        assert_eq!(engine.custom_flag_maps.len(), 1);
        let (bit, score, ref map) = engine.custom_flag_maps[0];
        assert_eq!(bit, 16);
        assert_eq!(score, 5);

        for domain in &[
            "evil.example.com",
            "bad.tld",
            "spaced.domain.net",
            "mixed.case.com",
        ] {
            let hash = twox_hash::XxHash64::oneshot(SEED, domain.as_bytes());
            assert!(
                map.contains_key(&hash),
                "expected '{}' to be in the map",
                domain
            );
        }
        // Comment line must not appear
        let comment_hash = twox_hash::XxHash64::oneshot(SEED, b"# this is a comment");
        assert!(!map.contains_key(&comment_hash));
    }

    #[test]
    fn test_load_custom_flags_missing_file_logs_warning_not_panic() {
        let mut cfg = Config::default();
        cfg.security
            .custom_flags
            .push(crate::config::CustomFlagConfig {
                bit: 17,
                code: "MISSING".to_string(),
                name: String::new(),
                description: String::new(),
                suspicious_score: 1,
                list_path: vec!["/nonexistent/path/custom.txt".to_string()],
            });

        let mut engine = make_engine();
        // Should not panic — missing file emits a warning and yields an empty map.
        engine.load_custom_flags(&cfg);
        assert_eq!(engine.custom_flag_maps.len(), 1);
        let (_, _, ref map) = engine.custom_flag_maps[0];
        assert!(map.is_empty());
    }

    #[test]
    fn test_load_custom_flags_multiple_list_paths_merged() {
        use std::io::Write;
        let mut f1 = tempfile::NamedTempFile::new().unwrap();
        writeln!(f1, "a.com").unwrap();
        let mut f2 = tempfile::NamedTempFile::new().unwrap();
        writeln!(f2, "b.com").unwrap();

        let mut cfg = Config::default();
        cfg.security
            .custom_flags
            .push(crate::config::CustomFlagConfig {
                bit: 18,
                code: "MERGED".to_string(),
                name: String::new(),
                description: String::new(),
                suspicious_score: 2,
                list_path: vec![
                    f1.path().to_str().unwrap().to_string(),
                    f2.path().to_str().unwrap().to_string(),
                ],
            });

        let mut engine = make_engine();
        engine.load_custom_flags(&cfg);

        let (_, _, ref map) = engine.custom_flag_maps[0];
        assert_eq!(map.len(), 2);
        let h_a = twox_hash::XxHash64::oneshot(SEED, b"a.com");
        let h_b = twox_hash::XxHash64::oneshot(SEED, b"b.com");
        assert!(map.contains_key(&h_a));
        assert!(map.contains_key(&h_b));
    }
}
