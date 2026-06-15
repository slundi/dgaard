mod abp;
mod bloom;
pub mod engine;
mod fst;
pub mod host_index;
mod io;
mod parser;
pub mod types;

pub use io::load_list_file;
pub use types::{ListError, ListFormat};

use regex::Regex;
use std::collections::HashMap;

use abp::parse_abp_line;
use parser::{detect_format, parse_dnsmasq_line, parse_host_line, parse_plain_domain};

use crate::model::{DomainEntry, DomainEntryFlags, RawDomainEntry};

/// Checks if a domain is already covered by a broader rule (lower depth).
fn is_redundant(
    entry: &RawDomainEntry,
    fast_map: &HashMap<u64, (u8, Box<str>)>,
    seed: u64,
) -> bool {
    let domain = &entry.value;

    if entry.flags.contains(DomainEntryFlags::REGEX) {
        let parts: Vec<&str> = domain.split("\\.").collect();
        if parts.len() <= 1 {
            return false;
        }
        for i in (1..parts.len()).rev() {
            let parent = parts[i..].join(".");
            let hash = twox_hash::XxHash64::oneshot(seed, parent.as_bytes());
            if fast_map.contains_key(&hash) {
                return true;
            }
        }
    } else {
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
#[allow(clippy::too_many_arguments)]
pub(crate) fn process_line(
    line: &str,
    base_flags: DomainEntryFlags,
    seed: u64,
    fast_map: &mut HashMap<u64, (u8, Box<str>)>,
    hierarchical_list: &mut Vec<DomainEntry>,
    wildcard_patterns: &mut Vec<String>,
    regex_pool: &mut Vec<Regex>,
    host_index: &mut HashMap<u64, String>,
    browser_rules: &mut Vec<String>,
) {
    let result: Result<RawDomainEntry, ListError<'_>> =
        parse_line(line, |trimmed| match detect_format(trimmed) {
            ListFormat::Hosts => parse_host_line(trimmed, seed),
            ListFormat::Dnsmasq => parse_dnsmasq_line(trimmed, seed),
            ListFormat::Plain => parse_plain_domain(trimmed, seed),
            ListFormat::Abp => parse_abp_line(trimmed, seed),
            ListFormat::Unknown => Err(ListError::ParseError(
                std::io::Error::new(std::io::ErrorKind::InvalidData, "Unknown format"),
                trimmed,
                "unknown",
            )),
        });

    match result {
        Ok(entry) => {
            let combined_flags = base_flags | entry.flags;
            let is_whitelist = combined_flags.contains(DomainEntryFlags::WHITELIST);

            if !is_whitelist && is_redundant(&entry, fast_map, seed) {
                return;
            }

            if combined_flags.contains(DomainEntryFlags::REGEX) {
                regex_pool.push(Regex::new(&entry.value).unwrap());
                hierarchical_list.push(DomainEntry {
                    hash: entry.hash,
                    flags: combined_flags,
                    depth: entry.depth,
                    data_idx: regex_pool.len(),
                });
            } else if combined_flags.contains(DomainEntryFlags::WILDCARD) {
                let clean_pattern = entry.value.trim_start_matches("||").trim_end_matches('^');

                let needs_glob = clean_pattern
                    .split('.')
                    .any(|seg| seg.contains('*') && seg != "*");

                let data_idx = if needs_glob {
                    wildcard_patterns.push(clean_pattern.to_string());
                    wildcard_patterns.len()
                } else {
                    0
                };

                hierarchical_list.push(DomainEntry {
                    hash: entry.hash,
                    flags: combined_flags,
                    depth: entry.depth,
                    data_idx,
                });
            } else {
                match fast_map.entry(entry.hash) {
                    std::collections::hash_map::Entry::Vacant(slot) => {
                        slot.insert((combined_flags.bits(), entry.value.as_str().into()));
                    }
                    std::collections::hash_map::Entry::Occupied(mut slot) => {
                        let (stored_flags, stored_domain) = slot.get_mut();
                        if stored_domain.as_ref() == entry.value.as_str() {
                            *stored_flags |= combined_flags.bits();
                        } else {
                            eprintln!(
                                "Warning: hash collision between '{}' and '{}' (hash {:016x}); \
                                 dropping new entry",
                                stored_domain, entry.value, entry.hash
                            );
                        }
                    }
                }
                host_index.insert(entry.hash, entry.value.clone());

                hierarchical_list.push(DomainEntry {
                    hash: entry.hash,
                    flags: combined_flags,
                    depth: entry.depth,
                    data_idx: 0,
                });
            }
        }
        Err(ListError::Skip) => {}
        Err(ListError::BrowserRule(rule)) => {
            browser_rules.push(rule.to_string());
        }
        Err(_) => {}
    }
}

pub fn parse_line<'a, F>(line: &'a str, parser: F) -> Result<RawDomainEntry, ListError<'a>>
where
    F: Fn(&'a str) -> Result<RawDomainEntry, ListError<'a>>,
{
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('!') {
        return Err(ListError::Skip);
    }
    const BROWSER_MARKERS: &[&str] = &["##", "#@#", "#$#", "#%#", "#^#", "#?#"];
    if BROWSER_MARKERS.iter().any(|m| trimmed.contains(m)) {
        return Err(ListError::BrowserRule(trimmed));
    }

    parser(trimmed)
}

/// Load a list from raw content (e.g., downloaded from URL).
#[allow(clippy::too_many_arguments)]
pub fn load_list_content(
    content: &str,
    base_flags: DomainEntryFlags,
    seed: u64,
    fast_map: &mut HashMap<u64, (u8, Box<str>)>,
    hierarchical_list: &mut Vec<DomainEntry>,
    wildcard_patterns: &mut Vec<String>,
    regex_pool: &mut Vec<Regex>,
    host_index: &mut HashMap<u64, String>,
    browser_rules: &mut Vec<String>,
) {
    for line in content.lines() {
        process_line(
            line,
            base_flags,
            seed,
            fast_map,
            hierarchical_list,
            wildcard_patterns,
            regex_pool,
            host_index,
            browser_rules,
        );
    }
}

/// Write browser-only ABP rules to a plain text file.
pub fn write_browser_rules(path: &str, rules: &[String]) -> std::io::Result<()> {
    use std::io::Write as _;
    if path.is_empty() || rules.is_empty() {
        return Ok(());
    }
    if let Some(parent) = std::path::Path::new(path).parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let file = std::fs::File::create(path)?;
    let mut w = std::io::BufWriter::new(file);
    for rule in rules {
        writeln!(w, "{}", rule)?;
    }
    w.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::types::ListError;

    const SEED: u64 = 42;

    #[allow(clippy::type_complexity)]
    fn make_collections() -> (
        HashMap<u64, (u8, Box<str>)>,
        Vec<DomainEntry>,
        Vec<String>,
        Vec<Regex>,
        HashMap<u64, String>,
        Vec<String>,
    ) {
        (
            HashMap::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            HashMap::new(),
            Vec::new(),
        )
    }

    #[test]
    fn test_parse_line_skips_empty() {
        let result = parse_line("", |_| unreachable!());
        assert!(matches!(result, Err(ListError::Skip)));
    }

    #[test]
    fn test_parse_line_skips_comment() {
        let result = parse_line("# comment", |_| unreachable!());
        assert!(matches!(result, Err(ListError::Skip)));
    }

    #[test]
    fn test_parse_line_returns_browser_rule() {
        let result = parse_line("example.com##.ads", |_| unreachable!());
        assert!(matches!(result, Err(ListError::BrowserRule(_))));
    }

    #[test]
    fn test_process_line_hosts_format() {
        let (mut fm, mut hl, mut wp, mut rp, mut hi, mut br) = make_collections();
        process_line(
            "0.0.0.0 test.example.com",
            DomainEntryFlags::NONE,
            SEED,
            &mut fm,
            &mut hl,
            &mut wp,
            &mut rp,
            &mut hi,
            &mut br,
        );
        assert_eq!(fm.len(), 1);
        assert_eq!(hl[0].depth, 2);
    }

    #[test]
    fn test_process_line_plain_domain() {
        let (mut fm, mut hl, mut wp, mut rp, mut hi, mut br) = make_collections();
        process_line(
            "ads.example.org",
            DomainEntryFlags::NONE,
            SEED,
            &mut fm,
            &mut hl,
            &mut wp,
            &mut rp,
            &mut hi,
            &mut br,
        );
        assert_eq!(fm.len(), 1);
        assert_eq!(hl[0].depth, 2);
    }

    #[test]
    fn test_process_line_comment_ignored() {
        let (mut fm, mut hl, mut wp, mut rp, mut hi, mut br) = make_collections();
        process_line(
            "# comment",
            DomainEntryFlags::NONE,
            SEED,
            &mut fm,
            &mut hl,
            &mut wp,
            &mut rp,
            &mut hi,
            &mut br,
        );
        assert!(fm.is_empty());
    }

    #[test]
    fn test_process_line_whitelist_flag() {
        let (mut fm, mut hl, mut wp, mut rp, mut hi, mut br) = make_collections();
        process_line(
            "allowed.example.com",
            DomainEntryFlags::WHITELIST,
            SEED,
            &mut fm,
            &mut hl,
            &mut wp,
            &mut rp,
            &mut hi,
            &mut br,
        );
        assert_eq!(fm.len(), 1);
        assert_eq!(hl[0].flags, DomainEntryFlags::WHITELIST);
    }

    #[test]
    fn test_process_line_abp_simple_domain() {
        let (mut fm, mut hl, mut wp, mut rp, mut hi, mut br) = make_collections();
        process_line(
            "||ads.example.com^",
            DomainEntryFlags::NONE,
            SEED,
            &mut fm,
            &mut hl,
            &mut wp,
            &mut rp,
            &mut hi,
            &mut br,
        );
        assert_eq!(fm.len(), 1);
        let expected_hash = twox_hash::XxHash64::oneshot(SEED, "ads.example.com".as_bytes());
        assert!(fm.contains_key(&expected_hash));
    }

    #[test]
    fn test_process_line_abp_wildcard_suffix_only() {
        let (mut fm, mut hl, mut wp, mut rp, mut hi, mut br) = make_collections();
        process_line(
            "||*.tracking.com^",
            DomainEntryFlags::NONE,
            SEED,
            &mut fm,
            &mut hl,
            &mut wp,
            &mut rp,
            &mut hi,
            &mut br,
        );
        assert_eq!(fm.len(), 0);
        assert_eq!(hl.len(), 1);
        assert!(hl[0].flags.contains(DomainEntryFlags::WILDCARD));
        assert_eq!(hl[0].data_idx, 0);
        assert_eq!(wp.len(), 0);
    }

    #[test]
    fn test_process_line_wildcard_pattern_stored() {
        let (mut fm, mut hl, mut wp, mut rp, mut hi, mut br) = make_collections();
        process_line(
            "||ads*.example.com^",
            DomainEntryFlags::NONE,
            SEED,
            &mut fm,
            &mut hl,
            &mut wp,
            &mut rp,
            &mut hi,
            &mut br,
        );
        assert_eq!(wp.len(), 1);
        assert_eq!(wp[0], "ads*.example.com");
        assert_eq!(hl[0].data_idx, 1);
    }

    #[test]
    fn test_process_line_abp_cosmetic_rule_collected() {
        let (mut fm, mut hl, mut wp, mut rp, mut hi, mut br) = make_collections();
        process_line(
            "example.com##.ad-banner",
            DomainEntryFlags::NONE,
            SEED,
            &mut fm,
            &mut hl,
            &mut wp,
            &mut rp,
            &mut hi,
            &mut br,
        );
        assert!(fm.is_empty());
        assert!(hl.is_empty());
        assert_eq!(br.len(), 1);
    }

    #[test]
    fn test_load_list_content_plain_domains() {
        let (mut fm, mut hl, mut wp, mut rp, mut hi, mut br) = make_collections();
        load_list_content(
            "example.com\ntest.org\nfoo.bar.net",
            DomainEntryFlags::NONE,
            SEED,
            &mut fm,
            &mut hl,
            &mut wp,
            &mut rp,
            &mut hi,
            &mut br,
        );
        assert_eq!(fm.len(), 3);
        assert_eq!(hl.len(), 3);
    }

    #[test]
    fn test_load_list_content_mixed_formats() {
        let (mut fm, mut hl, mut wp, mut rp, mut hi, mut br) = make_collections();
        let content = "plain.domain.com\n0.0.0.0 hosts.format.com\nserver=/dnsmasq.format.com/\n||abp.format.com^\n";
        load_list_content(
            content,
            DomainEntryFlags::NONE,
            SEED,
            &mut fm,
            &mut hl,
            &mut wp,
            &mut rp,
            &mut hi,
            &mut br,
        );
        assert_eq!(fm.len(), 4);
    }

    #[test]
    fn test_load_list_content_empty() {
        let (mut fm, mut hl, mut wp, mut rp, mut hi, mut br) = make_collections();
        load_list_content(
            "",
            DomainEntryFlags::NONE,
            SEED,
            &mut fm,
            &mut hl,
            &mut wp,
            &mut rp,
            &mut hi,
            &mut br,
        );
        assert!(fm.is_empty());
    }

    #[test]
    fn test_is_redundant_parent_blocked() {
        let mut fast_map: HashMap<u64, (u8, Box<str>)> = HashMap::new();
        let hash = twox_hash::XxHash64::oneshot(SEED, "example.com".as_bytes());
        fast_map.insert(hash, (DomainEntryFlags::NONE.bits(), "example.com".into()));

        let entry = RawDomainEntry {
            value: "sub.example.com".to_string(),
            hash: twox_hash::XxHash64::oneshot(SEED, "sub.example.com".as_bytes()),
            flags: DomainEntryFlags::NONE,
            depth: 2,
        };
        assert!(is_redundant(&entry, &fast_map, SEED));
    }

    #[test]
    fn test_is_redundant_not_redundant() {
        let mut fast_map: HashMap<u64, (u8, Box<str>)> = HashMap::new();
        let hash = twox_hash::XxHash64::oneshot(SEED, "other.com".as_bytes());
        fast_map.insert(hash, (DomainEntryFlags::NONE.bits(), "other.com".into()));

        let entry = RawDomainEntry {
            value: "example.com".to_string(),
            hash: twox_hash::XxHash64::oneshot(SEED, "example.com".as_bytes()),
            flags: DomainEntryFlags::NONE,
            depth: 1,
        };
        assert!(!is_redundant(&entry, &fast_map, SEED));
    }
}
