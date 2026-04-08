mod abp;
mod bloom;
pub mod engine;
mod fst;
mod io;
mod parser;
pub mod types;

use http_body_util::Empty;
use hyper::body::Bytes;
use hyper_util::client::legacy::Client;
use regex::Regex;
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, atomic::Ordering},
};

use crate::{
    CONFIG, CURRENT_ENGINE, GLOBAL_SEED,
    filter::{
        engine::FilterEngine,
        io::{build_https_client, load_source},
        parser::{detect_format, parse_dnsmasq_line, parse_host_line, parse_plain_domain},
        types::{ListError, ListFormat},
    },
    model::{DomainEntry, DomainEntryFlags, RawDomainEntry},
};

use abp::parse_abp_line;

type HttpsClient = Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    Empty<Bytes>,
>;

/// Checks if a domain is already covered by a broader rule (lower depth).
/// For "some.long.domain.tld", checks if "long.domain.tld", "domain.tld", or "tld" exist.
fn is_redundant(entry: &RawDomainEntry, fast_map: &HashMap<u64, u8>) -> bool {
    let domain = &entry.value;
    let seed = GLOBAL_SEED.load(Ordering::Relaxed);

    if entry.flags.contains(DomainEntryFlags::REGEX) {
        // For regex, split by "\\." and rebuild with "." to match fast_map keys
        let parts: Vec<&str> = domain.split("\\.").collect();
        if parts.len() <= 1 {
            return false;
        }
        // Check parents from TLD upward (excluding full domain)
        for i in (1..parts.len()).rev() {
            let parent = parts[i..].join(".");
            let hash = twox_hash::XxHash64::oneshot(seed, parent.as_bytes());
            if fast_map.contains_key(&hash) {
                return true;
            }
        }
    } else {
        // Zero-allocation: use string slices for parent domains
        let mut pos = 0;
        while let Some(dot_pos) = domain[pos..].find('.') {
            let parent = &domain[pos + dot_pos + 1..];
            let hash = twox_hash::XxHash64::oneshot(seed, parent.as_bytes());
            if fast_map.contains_key(&hash) {
                return true;
            }
            pos += dot_pos + 1;
        }
    }

    false
}

/// Process a single line using the appropriate parser based on detected format.
fn process_line(
    line: &str,
    base_flags: DomainEntryFlags,
    fast_map: &mut HashMap<u64, u8>,
    hierarchical_list: &mut Vec<DomainEntry>,
    wildcard_patterns: &mut Vec<String>,
    regex_pool: &mut Vec<Regex>,
    // stats: &mut LoadStats,
) {
    // Use parse_line wrapper for common logic (trim, skip comments)
    let result: Result<RawDomainEntry, ListError<'_>> =
        parse_line(line, |trimmed| match detect_format(trimmed) {
            ListFormat::Hosts => parse_host_line(trimmed),
            ListFormat::Dnsmasq => parse_dnsmasq_line(trimmed),
            ListFormat::Plain => parse_plain_domain(trimmed),
            ListFormat::Abp => parse_abp_line(trimmed),
            ListFormat::Unknown => Err(ListError::ParseError(
                std::io::Error::new(std::io::ErrorKind::InvalidData, "Unknown format"),
                trimmed,
                "unknown",
            )),
        });

    match result {
        Ok(entry) => {
            // Merge base_flags with entry flags (e.g., WHITELIST from config + WILDCARD from parser)
            let combined_flags = base_flags | entry.flags;
            let is_whitelist = combined_flags.contains(DomainEntryFlags::WHITELIST);

            // --- REDUNDANCY CHECK ---
            // If this is a blacklist entry, check if a parent is already in the fast_map.
            // Example: If 'example.com' (depth 1) is blocked, 'ads.example.com' (depth 2) is redundant.
            if !is_whitelist && is_redundant(&entry, fast_map) {
                // stats.redundant += 1;
                return;
            }

            // // Increment Whitelist/Blacklist counters
            // if is_whitelist {
            //     stats.whitelisted += 1;
            // } else {
            //     stats.blacklisted += 1;
            // }

            // Intelligent dispatch based on flags
            // parse_abp_line already extracts clean domains and hashes them appropriately
            if combined_flags.contains(DomainEntryFlags::REGEX) {
                // Regex rules: only add to hierarchical list (for later regex pool processing)
                regex_pool.push(Regex::new(&entry.value).unwrap());
                hierarchical_list.push(DomainEntry {
                    hash: entry.hash,
                    flags: combined_flags,
                    depth: entry.depth,
                    data_idx: regex_pool.len(),
                });
            } else if combined_flags.contains(DomainEntryFlags::WILDCARD) {
                // Extract clean pattern from ABP syntax (remove || prefix and ^ suffix)
                let clean_pattern = entry.value.trim_start_matches("||").trim_end_matches('^');

                // Check if pattern needs glob matching (has * within a segment, not as standalone)
                // e.g., "ads*.example.com" needs glob, but "*.example.com" is suffix-only
                let needs_glob = clean_pattern
                    .split('.')
                    .any(|seg| seg.contains('*') && seg != "*");

                let data_idx = if needs_glob {
                    wildcard_patterns.push(clean_pattern.to_string());
                    wildcard_patterns.len() // 1-based index
                } else {
                    0 // Suffix-only, no glob pattern stored
                };

                hierarchical_list.push(DomainEntry {
                    hash: entry.hash,
                    flags: combined_flags,
                    depth: entry.depth,
                    data_idx,
                });
            } else {
                // Standard entry: add to fast_map for O(1) lookup and hierarchical list
                fast_map.insert(entry.hash, combined_flags.bits());

                hierarchical_list.push(DomainEntry {
                    hash: entry.hash,
                    flags: combined_flags,
                    depth: entry.depth,
                    data_idx: 0,
                });
            }
        }
        Err(ListError::Skip) => {
            // Empty line or comment, silently skip
        }
        Err(_) => {
            // Parse error, silently skip (could log in debug mode)
        }
    }
}

pub fn parse_line<'a, F>(line: &'a str, parser: F) -> Result<RawDomainEntry, ListError<'a>>
where
    F: Fn(&'a str) -> Result<RawDomainEntry, ListError<'a>>,
{
    // common logic like trimming and ignoring comments
    let trimmed = line.trim();
    // Skip empty lines, hosts/dnsmasq comments (#), and ABP comments (!)
    if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('!') {
        return Err(ListError::Skip);
    }
    // Skip ABP cosmetic rules (contain ##)
    if trimmed.contains("##") {
        return Err(ListError::Skip);
    }

    parser(trimmed)
}

/// Load a list from raw content (e.g., downloaded from URL).
fn load_list_content(
    content: &str,
    base_flags: DomainEntryFlags,
    fast_map: &mut HashMap<u64, u8>,
    hierarchical_list: &mut Vec<DomainEntry>,
    wildcard_patterns: &mut Vec<String>,
    regex_pool: &mut Vec<Regex>,
) {
    for line in content.lines() {
        process_line(
            line,
            base_flags,
            fast_map,
            hierarchical_list,
            wildcard_patterns,
            regex_pool,
        );
    }
}

pub async fn reload_lists() {
    let client = build_https_client();
    let cfg = CONFIG.load();
    let sources = &cfg.sources;

    let mut fast_map: HashMap<u64, u8> = HashMap::new();
    let mut hierarchical_list: Vec<DomainEntry> = Vec::new();
    let mut regex_pool: Vec<Regex> = Vec::new();
    let mut wildcard_patterns: Vec<String> = Vec::new();

    // Load whitelists sequentially (with WHITELIST flag)
    for source in &sources.whitelists {
        load_source(
            source,
            DomainEntryFlags::WHITELIST,
            &client,
            &mut fast_map,
            &mut hierarchical_list,
            &mut wildcard_patterns,
            &mut regex_pool,
        )
        .await;
    }

    // Load NRD list if path is set
    if !sources.nrd_list_path.is_empty() {
        load_source(
            &sources.nrd_list_path,
            DomainEntryFlags::NONE,
            &client,
            &mut fast_map,
            &mut hierarchical_list,
            &mut wildcard_patterns,
            &mut regex_pool,
        )
        .await;
    }

    // Load blacklists sequentially
    for source in &sources.blacklists {
        load_source(
            source,
            DomainEntryFlags::NONE,
            &client,
            &mut fast_map,
            &mut hierarchical_list,
            &mut wildcard_patterns,
            &mut regex_pool,
        )
        .await;

        // println!(
        //     "{} blacklisted,\t{} whitelisted (skipped\t{} redundant rules) for {}",
        //     stats.blacklisted, stats.whitelisted, stats.redundant, source
        // );
    }
    // println!(
    //     "Engine reloaded: {} blacklisted, {} whitelisted (skipped {} redundant rules)",
    //     stats.blacklisted, stats.whitelisted, stats.redundant
    // );

    // Build the new engine
    let mut new_engine = FilterEngine {
        fast_map,
        hierarchical_list,
        regex_pool,
        wildcard_patterns,
        keyword_automaton: None,
        keyword_patterns: Vec::new(),
        suspicious_tld_hashes: HashSet::new(),
        lexical_strict: true,
    };

    new_engine.load_tld_filters();
    new_engine.load_lexical_filters();
    new_engine.hierarchical_list.sort_by_key(|de| de.hash);
    new_engine.wildcard_patterns.sort();
    new_engine.hierarchical_list.dedup();
    new_engine.wildcard_patterns.dedup();
    CURRENT_ENGINE.store(Arc::new(new_engine));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GLOBAL_SEED, filter::types::ListError, model::DomainEntryFlags};

    pub fn init_seed() {
        GLOBAL_SEED.store(42, Ordering::Relaxed);
    }

    // --- Tests for parse_line wrapper ---

    #[test]
    fn test_parse_line_skips_empty() {
        init_seed();
        let result = parse_line("", parse_plain_domain);
        assert!(matches!(result, Err(ListError::Skip)));
    }

    #[test]
    fn test_parse_line_skips_comment() {
        init_seed();
        let result = parse_line("# this is a comment", parse_plain_domain);
        assert!(matches!(result, Err(ListError::Skip)));
    }

    #[test]
    fn test_parse_line_trims_whitespace() {
        init_seed();
        let result = parse_line("  example.com  ", parse_plain_domain).unwrap();
        assert_eq!(result.value, "example.com");
    }

    // --- Tests for process_line ---

    #[test]
    fn test_process_line_hosts_format() {
        init_seed();
        let mut fast_map = HashMap::new();
        let mut hierarchical_list = Vec::new();
        let mut wildcard_patterns = Vec::new();
        let mut regex_pool = Vec::new();

        process_line(
            "0.0.0.0 test.example.com",
            DomainEntryFlags::NONE,
            &mut fast_map,
            &mut hierarchical_list,
            &mut wildcard_patterns,
            &mut regex_pool,
        );

        assert_eq!(fast_map.len(), 1);
        assert_eq!(hierarchical_list.len(), 1);
        assert_eq!(hierarchical_list[0].depth, 2);
    }

    #[test]
    fn test_process_line_dnsmasq_format() {
        init_seed();
        let mut fast_map = HashMap::new();
        let mut hierarchical_list = Vec::new();
        let mut wildcard_patterns = Vec::new();
        let mut regex_pool = Vec::new();

        process_line(
            "server=/doubleclick.net/",
            DomainEntryFlags::NONE,
            &mut fast_map,
            &mut hierarchical_list,
            &mut wildcard_patterns,
            &mut regex_pool,
        );

        assert_eq!(fast_map.len(), 1);
        assert_eq!(hierarchical_list.len(), 1);
        assert_eq!(hierarchical_list[0].depth, 1);
    }

    #[test]
    fn test_process_line_plain_domain() {
        init_seed();
        let mut fast_map = HashMap::new();
        let mut hierarchical_list = Vec::new();
        let mut wildcard_patterns = Vec::new();
        let mut regex_pool = Vec::new();

        process_line(
            "ads.example.org",
            DomainEntryFlags::NONE,
            &mut fast_map,
            &mut hierarchical_list,
            &mut wildcard_patterns,
            &mut regex_pool,
        );

        assert_eq!(fast_map.len(), 1);
        assert_eq!(hierarchical_list.len(), 1);
        assert_eq!(hierarchical_list[0].depth, 2);
    }

    #[test]
    fn test_process_line_comment_ignored() {
        init_seed();
        let mut fast_map = HashMap::new();
        let mut hierarchical_list = Vec::new();
        let mut wildcard_patterns = Vec::new();
        let mut regex_pool = Vec::new();

        process_line(
            "# This is a comment",
            DomainEntryFlags::NONE,
            &mut fast_map,
            &mut hierarchical_list,
            &mut wildcard_patterns,
            &mut regex_pool,
        );

        assert!(fast_map.is_empty());
        assert!(hierarchical_list.is_empty());
    }

    #[test]
    fn test_process_line_empty_ignored() {
        init_seed();
        let mut fast_map = HashMap::new();
        let mut hierarchical_list = Vec::new();
        let mut wildcard_patterns = Vec::new();
        let mut regex_pool = Vec::new();

        process_line(
            "",
            DomainEntryFlags::NONE,
            &mut fast_map,
            &mut hierarchical_list,
            &mut wildcard_patterns,
            &mut regex_pool,
        );
        process_line(
            "   ",
            DomainEntryFlags::NONE,
            &mut fast_map,
            &mut hierarchical_list,
            &mut wildcard_patterns,
            &mut regex_pool,
        );

        assert!(fast_map.is_empty());
        assert!(hierarchical_list.is_empty());
    }

    #[test]
    fn test_process_line_whitelist_flag() {
        init_seed();
        let mut fast_map = HashMap::new();
        let mut hierarchical_list = Vec::new();
        let mut wildcard_patterns = Vec::new();
        let mut regex_pool = Vec::new();

        process_line(
            "allowed.example.com",
            DomainEntryFlags::WHITELIST,
            &mut fast_map,
            &mut hierarchical_list,
            &mut wildcard_patterns,
            &mut regex_pool,
        );

        assert_eq!(fast_map.len(), 1);
        // Check the flags value in fast_map
        let flags_bits = *fast_map.values().next().unwrap();
        assert_eq!(flags_bits, DomainEntryFlags::WHITELIST.bits());

        assert_eq!(hierarchical_list[0].flags, DomainEntryFlags::WHITELIST);
    }

    // --- Tests for process_line with ABP format ---

    #[test]
    fn test_process_line_abp_simple_domain() {
        init_seed();
        let mut fast_map = HashMap::new();
        let mut hierarchical_list = Vec::new();
        let mut wildcard_patterns = Vec::new();
        let mut regex_pool = Vec::new();

        process_line(
            "||ads.example.com^",
            DomainEntryFlags::NONE,
            &mut fast_map,
            &mut hierarchical_list,
            &mut wildcard_patterns,
            &mut regex_pool,
        );

        // Should extract clean domain and add to fast_map
        assert_eq!(fast_map.len(), 1);
        assert_eq!(hierarchical_list.len(), 1);

        // Verify the hash is for "ads.example.com" not "||ads.example.com^"
        let expected_hash = twox_hash::XxHash64::oneshot(42, "ads.example.com".as_bytes());
        assert!(fast_map.contains_key(&expected_hash));
        assert_eq!(hierarchical_list[0].depth, 2);
    }

    #[test]
    fn test_process_line_abp_whitelist() {
        init_seed();
        let mut fast_map = HashMap::new();
        let mut hierarchical_list = Vec::new();
        let mut wildcard_patterns = Vec::new();
        let mut regex_pool = Vec::new();

        process_line(
            "@@||trusted.example.com^",
            DomainEntryFlags::NONE,
            &mut fast_map,
            &mut hierarchical_list,
            &mut wildcard_patterns,
            &mut regex_pool,
        );

        assert_eq!(fast_map.len(), 1);
        let flags_bits = *fast_map.values().next().unwrap();
        assert!(
            DomainEntryFlags::from_bits(flags_bits)
                .unwrap()
                .contains(DomainEntryFlags::WHITELIST)
        );
    }

    #[test]
    fn test_process_line_abp_wildcard_suffix_only() {
        init_seed();
        let mut fast_map = HashMap::new();
        let mut hierarchical_list = Vec::new();
        let mut wildcard_patterns = Vec::new();
        let mut regex_pool = Vec::new();

        // Pattern like *.tracking.com is suffix-only (handled by is_suffix_blocked)
        process_line(
            "||*.tracking.com^",
            DomainEntryFlags::NONE,
            &mut fast_map,
            &mut hierarchical_list,
            &mut wildcard_patterns,
            &mut regex_pool,
        );

        // Suffix wildcard should go to hierarchical_list only, NOT wildcard_patterns
        assert_eq!(fast_map.len(), 0);
        assert_eq!(hierarchical_list.len(), 1);
        assert!(
            hierarchical_list[0]
                .flags
                .contains(DomainEntryFlags::WILDCARD)
        );
        assert_eq!(hierarchical_list[0].data_idx, 0); // No glob pattern stored
        assert_eq!(wildcard_patterns.len(), 0); // Suffix patterns don't need glob matching
    }

    #[test]
    fn test_process_line_wildcard_pattern_stored() {
        init_seed();
        let mut fast_map = HashMap::new();
        let mut hierarchical_list = Vec::new();
        let mut wildcard_patterns = Vec::new();
        let mut regex_pool = Vec::new();

        // Test pattern like ads*.example.com
        process_line(
            "||ads*.example.com^",
            DomainEntryFlags::NONE,
            &mut fast_map,
            &mut hierarchical_list,
            &mut wildcard_patterns,
            &mut regex_pool,
        );

        assert_eq!(wildcard_patterns.len(), 1);
        assert_eq!(wildcard_patterns[0], "ads*.example.com");
        assert_eq!(hierarchical_list[0].data_idx, 1); // 1-based index
    }

    #[test]
    fn test_process_line_multiple_wildcard_patterns() {
        init_seed();
        let mut fast_map = HashMap::new();
        let mut hierarchical_list = Vec::new();
        let mut wildcard_patterns = Vec::new();
        let mut regex_pool = Vec::new();

        // Glob patterns (need wildcard_patterns)
        process_line(
            "||ads*.example.com^",
            DomainEntryFlags::NONE,
            &mut fast_map,
            &mut hierarchical_list,
            &mut wildcard_patterns,
            &mut regex_pool,
        );
        process_line(
            "||*tracker.analytics.com^",
            DomainEntryFlags::NONE,
            &mut fast_map,
            &mut hierarchical_list,
            &mut wildcard_patterns,
            &mut regex_pool,
        );
        process_line(
            "||banner*.ad.net^",
            DomainEntryFlags::NONE,
            &mut fast_map,
            &mut hierarchical_list,
            &mut wildcard_patterns,
            &mut regex_pool,
        );

        assert_eq!(wildcard_patterns.len(), 3);
        assert_eq!(wildcard_patterns[0], "ads*.example.com");
        assert_eq!(wildcard_patterns[1], "*tracker.analytics.com");
        assert_eq!(wildcard_patterns[2], "banner*.ad.net");
    }

    #[test]
    fn test_process_line_mixed_wildcard_types() {
        init_seed();
        let mut fast_map = HashMap::new();
        let mut hierarchical_list = Vec::new();
        let mut wildcard_patterns = Vec::new();
        let mut regex_pool = Vec::new();

        // Suffix-only pattern (standalone * segment)
        process_line(
            "||*.tracking.com^",
            DomainEntryFlags::NONE,
            &mut fast_map,
            &mut hierarchical_list,
            &mut wildcard_patterns,
            &mut regex_pool,
        );
        // Glob pattern (* within segment)
        process_line(
            "||ads*.example.com^",
            DomainEntryFlags::NONE,
            &mut fast_map,
            &mut hierarchical_list,
            &mut wildcard_patterns,
            &mut regex_pool,
        );
        // Another suffix-only
        process_line(
            "||*.ads.net^",
            DomainEntryFlags::NONE,
            &mut fast_map,
            &mut hierarchical_list,
            &mut wildcard_patterns,
            &mut regex_pool,
        );

        // All go to hierarchical_list
        assert_eq!(hierarchical_list.len(), 3);

        // Only glob pattern goes to wildcard_patterns
        assert_eq!(wildcard_patterns.len(), 1);
        assert_eq!(wildcard_patterns[0], "ads*.example.com");

        // Check data_idx: 0 for suffix-only, non-zero for glob
        assert_eq!(hierarchical_list[0].data_idx, 0); // *.tracking.com
        assert_eq!(hierarchical_list[1].data_idx, 1); // ads*.example.com
        assert_eq!(hierarchical_list[2].data_idx, 0); // *.ads.net
    }

    #[test]
    fn test_process_line_abp_regex() {
        init_seed();
        let mut fast_map = HashMap::new();
        let mut hierarchical_list = Vec::new();
        let mut wildcard_patterns = Vec::new();
        let mut regex_pool = Vec::new();

        process_line(
            "/ads[0-9]+\\.example\\.com/",
            DomainEntryFlags::NONE,
            &mut fast_map,
            &mut hierarchical_list,
            &mut wildcard_patterns,
            &mut regex_pool,
        );

        // Regex should only go to hierarchical_list, not fast_map
        assert_eq!(fast_map.len(), 0);
        assert_eq!(hierarchical_list.len(), 1);
        assert!(hierarchical_list[0].flags.contains(DomainEntryFlags::REGEX));
    }

    #[test]
    fn test_process_line_abp_comment_skipped() {
        init_seed();
        let mut fast_map = HashMap::new();
        let mut hierarchical_list = Vec::new();
        let mut wildcard_patterns = Vec::new();
        let mut regex_pool = Vec::new();

        process_line(
            "! This is an ABP comment",
            DomainEntryFlags::NONE,
            &mut fast_map,
            &mut hierarchical_list,
            &mut wildcard_patterns,
            &mut regex_pool,
        );

        assert!(fast_map.is_empty());
        assert!(hierarchical_list.is_empty());
    }

    #[test]
    fn test_process_line_abp_cosmetic_rule_skipped() {
        init_seed();
        let mut fast_map = HashMap::new();
        let mut hierarchical_list = Vec::new();
        let mut wildcard_patterns = Vec::new();
        let mut regex_pool = Vec::new();

        process_line(
            "example.com##.ad-banner",
            DomainEntryFlags::NONE,
            &mut fast_map,
            &mut hierarchical_list,
            &mut wildcard_patterns,
            &mut regex_pool,
        );

        assert!(fast_map.is_empty());
        assert!(hierarchical_list.is_empty());
    }

    // --- Tests for load_list_content ---

    #[test]
    fn test_load_list_content_plain_domains() {
        init_seed();
        let mut fast_map = HashMap::new();
        let mut hierarchical_list = Vec::new();
        let mut wildcard_patterns = Vec::new();
        let mut regex_pool = Vec::new();

        let content = "example.com\ntest.org\nfoo.bar.net";
        load_list_content(
            content,
            DomainEntryFlags::NONE,
            &mut fast_map,
            &mut hierarchical_list,
            &mut wildcard_patterns,
            &mut regex_pool,
        );

        assert_eq!(fast_map.len(), 3);
        assert_eq!(hierarchical_list.len(), 3);
    }

    #[test]
    fn test_load_list_content_hosts_format() {
        init_seed();
        let mut fast_map = HashMap::new();
        let mut hierarchical_list = Vec::new();
        let mut wildcard_patterns = Vec::new();
        let mut regex_pool = Vec::new();

        let content =
            "0.0.0.0 ads.example.com\n127.0.0.1 tracking.site.org\n# comment\n\n:: ipv6.test.com";
        load_list_content(
            content,
            DomainEntryFlags::NONE,
            &mut fast_map,
            &mut hierarchical_list,
            &mut wildcard_patterns,
            &mut regex_pool,
        );

        assert_eq!(fast_map.len(), 3);
        assert_eq!(hierarchical_list.len(), 3);
    }

    #[test]
    fn test_load_list_content_mixed_formats() {
        init_seed();
        let mut fast_map = HashMap::new();
        let mut hierarchical_list = Vec::new();
        let mut wildcard_patterns = Vec::new();
        let mut regex_pool = Vec::new();

        let content = r#"# Comment line
plain.domain.com
0.0.0.0 hosts.format.com
server=/dnsmasq.format.com/
||abp.format.com^
"#;
        load_list_content(
            content,
            DomainEntryFlags::NONE,
            &mut fast_map,
            &mut hierarchical_list,
            &mut wildcard_patterns,
            &mut regex_pool,
        );

        assert_eq!(fast_map.len(), 4);
        assert_eq!(hierarchical_list.len(), 4);
    }

    #[test]
    fn test_load_list_content_with_whitelist_flag() {
        init_seed();
        let mut fast_map = HashMap::new();
        let mut hierarchical_list = Vec::new();
        let mut wildcard_patterns = Vec::new();
        let mut regex_pool = Vec::new();

        let content = "allowed.com\ntrusted.org";
        load_list_content(
            content,
            DomainEntryFlags::WHITELIST,
            &mut fast_map,
            &mut hierarchical_list,
            &mut wildcard_patterns,
            &mut regex_pool,
        );

        assert_eq!(fast_map.len(), 2);
        for entry in &hierarchical_list {
            assert!(
                entry.flags.contains(DomainEntryFlags::WHITELIST),
                "Entries should have WHITELIST flag"
            );
        }
    }

    #[test]
    fn test_load_list_content_empty() {
        init_seed();
        let mut fast_map = HashMap::new();
        let mut hierarchical_list = Vec::new();
        let mut wildcard_patterns = Vec::new();
        let mut regex_pool = Vec::new();

        let content = "";
        load_list_content(
            content,
            DomainEntryFlags::NONE,
            &mut fast_map,
            &mut hierarchical_list,
            &mut wildcard_patterns,
            &mut regex_pool,
        );

        assert!(fast_map.is_empty());
        assert!(hierarchical_list.is_empty());
    }

    #[test]
    fn test_load_list_content_only_comments() {
        init_seed();
        let mut fast_map = HashMap::new();
        let mut hierarchical_list = Vec::new();
        let mut wildcard_patterns = Vec::new();
        let mut regex_pool = Vec::new();

        let content = "# comment 1\n# comment 2\n! ABP comment\n";
        load_list_content(
            content,
            DomainEntryFlags::NONE,
            &mut fast_map,
            &mut hierarchical_list,
            &mut wildcard_patterns,
            &mut regex_pool,
        );

        assert!(fast_map.is_empty());
        assert!(hierarchical_list.is_empty());
    }

    // --- Tests for load_lexical_filters ---

    #[test]
    fn test_load_lexical_filters_builds_automaton() {
        init_seed();
        let mut cfg = crate::config::Config::default();
        cfg.security.lexical.enabled = true;
        cfg.security.lexical.banned_keywords = vec!["casino".into(), "porno".into()];
        cfg.security.lexical.strict_keyword_matching = true;
        CONFIG.store(Arc::new(cfg));

        let mut engine = FilterEngine::empty();
        engine.load_lexical_filters();

        assert!(engine.keyword_automaton.is_some());
        assert_eq!(engine.keyword_patterns.len(), 2);
        assert!(engine.keyword_patterns.contains(&"casino".to_string()));
        assert!(engine.keyword_patterns.contains(&"porno".to_string()));
        assert!(engine.lexical_strict);
    }

    #[test]
    fn test_load_lexical_filters_hashes_suspicious_tlds() {
        init_seed();
        let mut cfg = crate::config::Config::default();
        cfg.security.lexical.enabled = true;
        cfg.security.lexical.banned_keywords = vec!["test".into()];
        cfg.tld.suspicious_tlds = vec![".xyz".into(), ".top".into()];
        CONFIG.store(Arc::new(cfg));

        let mut engine = FilterEngine::empty();
        engine.load_lexical_filters();

        assert_eq!(engine.suspicious_tld_hashes.len(), 2);

        // Verify TLD hashes are stored without leading dot
        let xyz_hash = twox_hash::XxHash64::oneshot(42, "xyz".as_bytes());
        let top_hash = twox_hash::XxHash64::oneshot(42, "top".as_bytes());
        assert!(engine.suspicious_tld_hashes.contains(&xyz_hash));
        assert!(engine.suspicious_tld_hashes.contains(&top_hash));
    }

    #[test]
    fn test_load_lexical_filters_disabled_noop() {
        init_seed();
        let mut cfg = crate::config::Config::default();
        cfg.security.lexical.enabled = false;
        cfg.security.lexical.banned_keywords = vec!["casino".into()];
        CONFIG.store(Arc::new(cfg));

        let mut engine = FilterEngine::empty();
        engine.load_lexical_filters();

        assert!(engine.keyword_automaton.is_none());
        assert!(engine.keyword_patterns.is_empty());
    }

    #[test]
    fn test_load_lexical_filters_empty_keywords_noop() {
        init_seed();
        let mut cfg = crate::config::Config::default();
        cfg.security.lexical.enabled = true;
        cfg.security.lexical.banned_keywords = vec![];
        CONFIG.store(Arc::new(cfg));

        let mut engine = FilterEngine::empty();
        engine.load_lexical_filters();

        assert!(engine.keyword_automaton.is_none());
        assert!(engine.keyword_patterns.is_empty());
    }

    #[test]
    fn test_is_suspicious_tld_with_empty_set() {
        init_seed();
        let engine = FilterEngine::empty();

        // Empty set = all TLDs are suspicious (no restriction)
        assert!(engine.is_suspicious_tld("com"));
        assert!(engine.is_suspicious_tld("xyz"));
    }

    #[test]
    fn test_is_suspicious_tld_with_configured_set() {
        init_seed();
        let mut cfg = crate::config::Config::default();
        cfg.security.lexical.enabled = true;
        cfg.security.lexical.banned_keywords = vec!["test".into()];
        cfg.tld.suspicious_tlds = vec![".xyz".into(), ".top".into()];
        CONFIG.store(Arc::new(cfg));

        let mut engine = FilterEngine::empty();
        engine.load_lexical_filters();

        // Configured TLDs should match
        assert!(engine.is_suspicious_tld("xyz"));
        assert!(engine.is_suspicious_tld("top"));
        assert!(engine.is_suspicious_tld("XYZ")); // Case insensitive

        // Non-configured TLDs should not match
        assert!(!engine.is_suspicious_tld("com"));
        assert!(!engine.is_suspicious_tld("org"));
    }

    #[test]
    fn test_load_lexical_filters_lowercases_keywords() {
        init_seed();
        let mut cfg = crate::config::Config::default();
        cfg.security.lexical.enabled = true;
        cfg.security.lexical.banned_keywords = vec!["CASINO".into(), "Porno".into()];
        CONFIG.store(Arc::new(cfg));

        let mut engine = FilterEngine::empty();
        engine.load_lexical_filters();

        // Keywords should be stored lowercase
        assert!(engine.keyword_patterns.contains(&"casino".to_string()));
        assert!(engine.keyword_patterns.contains(&"porno".to_string()));
        assert!(!engine.keyword_patterns.contains(&"CASINO".to_string()));
    }

    // --- Tests for is_redundant ---

    fn make_entry(value: &str, flags: DomainEntryFlags) -> RawDomainEntry {
        let seed = GLOBAL_SEED.load(Ordering::Relaxed);
        RawDomainEntry {
            value: value.to_string(),
            hash: twox_hash::XxHash64::oneshot(seed, value.as_bytes()),
            flags,
            depth: value.matches('.').count() as u8,
        }
    }

    fn insert_domain(fast_map: &mut HashMap<u64, u8>, domain: &str) {
        let seed = GLOBAL_SEED.load(Ordering::Relaxed);
        let hash = twox_hash::XxHash64::oneshot(seed, domain.as_bytes());
        fast_map.insert(hash, DomainEntryFlags::NONE.bits());
    }

    #[test]
    fn test_is_redundant_parent_blocked() {
        init_seed();
        let mut fast_map = HashMap::new();
        insert_domain(&mut fast_map, "example.com");

        // sub.example.com should be redundant since example.com is blocked
        let entry = make_entry("sub.example.com", DomainEntryFlags::NONE);
        assert!(is_redundant(&entry, &fast_map));
    }

    #[test]
    fn test_is_redundant_grandparent_blocked() {
        init_seed();
        let mut fast_map = HashMap::new();
        insert_domain(&mut fast_map, "example.com");

        // deep.sub.example.com should be redundant
        let entry = make_entry("deep.sub.example.com", DomainEntryFlags::NONE);
        assert!(is_redundant(&entry, &fast_map));
    }

    #[test]
    fn test_is_redundant_tld_blocked() {
        init_seed();
        let mut fast_map = HashMap::new();
        insert_domain(&mut fast_map, "com");

        // example.com should be redundant since TLD "com" is blocked
        let entry = make_entry("example.com", DomainEntryFlags::NONE);
        assert!(is_redundant(&entry, &fast_map));
    }

    #[test]
    fn test_is_redundant_not_redundant() {
        init_seed();
        let mut fast_map = HashMap::new();
        insert_domain(&mut fast_map, "other.com");

        // example.com should NOT be redundant
        let entry = make_entry("example.com", DomainEntryFlags::NONE);
        assert!(!is_redundant(&entry, &fast_map));
    }

    #[test]
    fn test_is_redundant_self_not_redundant() {
        init_seed();
        let mut fast_map = HashMap::new();
        insert_domain(&mut fast_map, "example.com");

        // example.com itself should NOT be redundant (only parents are checked)
        let entry = make_entry("example.com", DomainEntryFlags::NONE);
        assert!(!is_redundant(&entry, &fast_map));
    }

    #[test]
    fn test_is_redundant_tld_only() {
        init_seed();
        let fast_map = HashMap::new();

        // Single-label domain has no parents to check
        let entry = make_entry("com", DomainEntryFlags::NONE);
        assert!(!is_redundant(&entry, &fast_map));
    }

    #[test]
    fn test_is_redundant_sibling_not_redundant() {
        init_seed();
        let mut fast_map = HashMap::new();
        insert_domain(&mut fast_map, "other.example.com");

        // sub.example.com should NOT be redundant (sibling, not parent)
        let entry = make_entry("sub.example.com", DomainEntryFlags::NONE);
        assert!(!is_redundant(&entry, &fast_map));
    }

    #[test]
    fn test_is_redundant_regex_parent_blocked() {
        init_seed();
        let mut fast_map = HashMap::new();
        insert_domain(&mut fast_map, "example.com");

        // Regex entry ads\.example\.com should be redundant if example.com is blocked
        let entry = make_entry(r"ads\.example\.com", DomainEntryFlags::REGEX);
        assert!(is_redundant(&entry, &fast_map));
    }

    #[test]
    fn test_is_redundant_regex_not_redundant() {
        init_seed();
        let mut fast_map = HashMap::new();
        insert_domain(&mut fast_map, "other.com");

        let entry = make_entry(r"ads\.example\.com", DomainEntryFlags::REGEX);
        assert!(!is_redundant(&entry, &fast_map));
    }
}
