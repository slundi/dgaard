mod abp;
mod bloom;
mod fst;

use core::sync::atomic::Ordering;
use hickory_resolver::{Name, proto::ProtoError};
use regex::Regex;
use std::{
    collections::HashMap,
    fs::File,
    io::{BufReader, Read as _},
    path::Path,
    str::FromStr,
    sync::Arc,
};
use thiserror::Error;

use crate::{
    CONFIG, CURRENT_ENGINE, GLOBAL_SEED,
    model::{DomainEntry, DomainEntryFlags, RawDomainEntry},
    utils::count_dots,
};

/// 2MB chunk size for reading large list files
const CHUNK_SIZE: usize = 2 * 1024 * 1024;

#[derive(Error, Debug)]
pub enum ListError<'a> {
    #[error("Invalid domain {1}: {0}")]
    InvalidDomain(#[source] ProtoError, &'a str),
    #[error("Failed to parse line: {1}, format: {2}. Internal error: {0}")]
    ParseError(#[source] std::io::Error, &'a str, &'a str),
    #[error("Line skipped (empty or comment)")]
    Skip,
}

pub struct FilterEngine {
    // Exact match (WL & BL without wildcards)
    // u64 is xxh3 of complete domain name
    pub fast_map: HashMap<u64, u8>,

    // For TLD & Wildcards (sorted by depth then hash)
    pub hierarchical_list: Vec<DomainEntry>,

    // Heavy data
    pub regex_pool: Vec<Regex>, // compiled regex so regex.is_match(domain) to check
    pub wildcard_patterns: Vec<String>, // TODO: transform regex into wildcard when possible
}
impl FilterEngine {
    pub fn empty() -> Self {
        Self {
            fast_map: HashMap::with_capacity(0),
            hierarchical_list: Vec::with_capacity(0),
            regex_pool: Vec::with_capacity(0),
            wildcard_patterns: Vec::with_capacity(0),
        }
    }

    pub fn build_from_files() -> Self {
        let cfg = CONFIG.load();
        let sources = &cfg.sources;

        let mut fast_map: HashMap<u64, u8> = HashMap::new();
        let mut hierarchical_list: Vec<DomainEntry> = Vec::new();
        let regex_pool: Vec<Regex> = Vec::new();
        let wildcard_patterns: Vec<String> = Vec::new();

        // Load blacklists
        for path in &sources.blacklists {
            if let Err(e) = load_list_file(
                path,
                DomainEntryFlags::NONE,
                &mut fast_map,
                &mut hierarchical_list,
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
        }
    }
}

/// Load a list file by reading 2MB chunks at a time.
/// Detects format (hosts, dnsmasq, or plain domain) and parses accordingly.
fn load_list_file(
    path: &str,
    base_flags: DomainEntryFlags,
    fast_map: &mut HashMap<u64, u8>,
    hierarchical_list: &mut Vec<DomainEntry>,
) -> std::io::Result<()> {
    let path = Path::new(path);
    if !path.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("File not found: {}", path.display()),
        ));
    }

    let file = File::open(path)?;
    let file_size = file.metadata()?.len();

    // Use BufReader with 2MB buffer
    let mut reader = BufReader::with_capacity(CHUNK_SIZE, file);
    let mut leftover = String::new();
    let mut bytes_read_total: u64 = 0;

    loop {
        let mut chunk = vec![0u8; CHUNK_SIZE];
        let bytes_read = reader.read(&mut chunk)?;

        if bytes_read == 0 {
            // Process any remaining leftover
            if !leftover.is_empty() {
                process_line(&leftover, base_flags, fast_map, hierarchical_list);
            }
            break;
        }

        bytes_read_total += bytes_read as u64;
        chunk.truncate(bytes_read);

        // Convert chunk to string (lossy to handle any invalid UTF-8)
        let chunk_str = String::from_utf8_lossy(&chunk);

        // Combine with leftover from previous chunk
        let combined = format!("{}{}", leftover, chunk_str);

        // Find the last newline to split complete lines from partial
        let last_newline = combined.rfind('\n');

        let (complete, new_leftover) = match last_newline {
            Some(idx) if bytes_read_total < file_size => {
                // More data to come, save incomplete line
                (&combined[..idx + 1], &combined[idx + 1..])
            }
            _ => {
                // Last chunk or no newline found, process everything
                (combined.as_str(), "")
            }
        };

        // Process complete lines
        for line in complete.lines() {
            process_line(line, base_flags, fast_map, hierarchical_list);
        }

        leftover = new_leftover.to_string();
    }

    Ok(())
}

/// Detect format type from a line
fn detect_format(line: &str) -> ListFormat {
    if line.starts_with("server=/") || line.starts_with("address=/") {
        ListFormat::Dnsmasq
    } else if line.starts_with("0.0.0.0 ")
        || line.starts_with("127.0.0.1 ")
        || line.starts_with(":: ")
    {
        ListFormat::Hosts
    } else if !line.contains(' ') && !line.contains('/') {
        ListFormat::Plain
    } else {
        ListFormat::Unknown
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum ListFormat {
    Hosts,
    Dnsmasq,
    Plain,
    Unknown,
}

/// Process a single line using the appropriate parser based on detected format.
fn process_line(
    line: &str,
    base_flags: DomainEntryFlags,
    fast_map: &mut HashMap<u64, u8>,
    hierarchical_list: &mut Vec<DomainEntry>,
) {
    // Use parse_line wrapper for common logic (trim, skip comments)
    let result: Result<RawDomainEntry, ListError<'_>> =
        parse_line(line, |trimmed| match detect_format(trimmed) {
            ListFormat::Hosts => parse_host_line(trimmed),
            ListFormat::Dnsmasq => parse_dnsmasq_line(trimmed),
            ListFormat::Plain => parse_plain_domain(trimmed),
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

            // Add to fast_map for exact matching
            fast_map.insert(entry.hash, combined_flags.bits());

            // Also add to hierarchical list for wildcards/depth-based lookups
            hierarchical_list.push(DomainEntry {
                hash: entry.hash,
                flags: combined_flags,
                depth: entry.depth,
                data_idx: 0,
            });
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
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return Err(ListError::Skip);
    }

    parser(trimmed)
}

/// Parse hosts format line: "0.0.0.0 domain.com" or "127.0.0.1 domain.com" or ":: domain.com"
pub fn parse_host_line(line: &str) -> Result<RawDomainEntry, ListError<'_>> {
    // Split by whitespace and get the domain (second part)
    let domain = line.split_whitespace().nth(1).ok_or_else(|| {
        ListError::ParseError(
            std::io::Error::new(std::io::ErrorKind::InvalidData, "No domain found"),
            line,
            "host",
        )
    })?;

    // Validate domain
    Name::from_str(domain).map_err(|e| ListError::InvalidDomain(e, domain))?;

    let hash = twox_hash::XxHash64::oneshot(GLOBAL_SEED.load(Ordering::Relaxed), domain.as_bytes());

    Ok(RawDomainEntry {
        hash,
        value: domain.to_string(),
        flags: DomainEntryFlags::NONE,
        depth: count_dots(domain),
    })
}

/// Parse dnsmasq format line: "server=/domain.com/" or "address=/domain.com/127.0.0.1"
pub fn parse_dnsmasq_line(line: &str) -> Result<RawDomainEntry, ListError<'_>> {
    let domain = line.split('/').nth(1).ok_or_else(|| {
        ListError::ParseError(
            std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid dnsmasq format"),
            line,
            "dnsmasq",
        )
    })?;

    if domain.is_empty() {
        return Err(ListError::ParseError(
            std::io::Error::new(std::io::ErrorKind::InvalidData, "Empty domain"),
            line,
            "dnsmasq",
        ));
    }

    let hash = twox_hash::XxHash64::oneshot(GLOBAL_SEED.load(Ordering::Relaxed), domain.as_bytes());

    Ok(RawDomainEntry {
        hash,
        value: domain.to_string(),
        flags: DomainEntryFlags::NONE,
        depth: count_dots(domain),
    })
}

/// Parse plain domain format: just the domain name with no IP prefix
pub fn parse_plain_domain(line: &str) -> Result<RawDomainEntry, ListError<'_>> {
    let domain = line.trim();

    if domain.is_empty() {
        return Err(ListError::ParseError(
            std::io::Error::new(std::io::ErrorKind::InvalidData, "Empty domain"),
            line,
            "plain",
        ));
    }

    // Validate domain
    Name::from_str(domain).map_err(|e| ListError::InvalidDomain(e, domain))?;

    let hash = twox_hash::XxHash64::oneshot(GLOBAL_SEED.load(Ordering::Relaxed), domain.as_bytes());

    Ok(RawDomainEntry {
        hash,
        value: domain.to_string(),
        flags: DomainEntryFlags::NONE,
        depth: count_dots(domain),
    })
}

pub fn reload_lists() {
    let new_engine = FilterEngine::build_from_files();
    CURRENT_ENGINE.store(Arc::new(new_engine));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::DomainEntryFlags;

    fn init_seed() {
        GLOBAL_SEED.store(42, Ordering::Relaxed);
    }

    #[test]
    fn test_parse_host_line_simple() {
        init_seed();
        let result = parse_host_line("0.0.0.0 ads.example.com").unwrap();
        assert_eq!(result.value, "ads.example.com");
        assert_eq!(result.flags, DomainEntryFlags::NONE);
        assert_eq!(result.depth, 2);
    }

    #[test]
    fn test_parse_host_line_localhost() {
        init_seed();
        let result = parse_host_line("127.0.0.1 tracking.site.com").unwrap();
        assert_eq!(result.value, "tracking.site.com");
        assert_eq!(result.depth, 2);
    }

    #[test]
    fn test_parse_host_line_ipv6() {
        init_seed();
        let result = parse_host_line(":: malware.net").unwrap();
        assert_eq!(result.value, "malware.net");
        assert_eq!(result.depth, 1);
    }

    #[test]
    fn test_parse_host_line_missing_domain() {
        init_seed();
        let result = parse_host_line("0.0.0.0");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_host_line_from_file() {
        init_seed();
        let content = include_str!("../../tests/list_host.txt");
        let mut parsed = 0;
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            // Pass the full line to parse_host_line
            let result = parse_host_line(trimmed);
            assert!(result.is_ok(), "Failed to parse: {}", trimmed);
            let entry = result.unwrap();
            assert!(!entry.value.is_empty(), "Domain should not be empty");
            parsed += 1;
        }
        assert!(parsed > 0, "Should parse at least one host entry");
    }

    #[test]
    fn test_parse_dnsmasq_line_simple() {
        init_seed();
        let result = parse_dnsmasq_line("server=/doubleclick.net/").unwrap();
        assert_eq!(result.value, "doubleclick.net");
        assert_eq!(result.flags, DomainEntryFlags::NONE);
        assert_eq!(result.depth, 1);
    }

    #[test]
    fn test_parse_dnsmasq_line_address_format() {
        init_seed();
        let result = parse_dnsmasq_line("address=/ads.example.com/127.0.0.1").unwrap();
        assert_eq!(result.value, "ads.example.com");
        assert_eq!(result.depth, 2);
    }

    #[test]
    fn test_parse_dnsmasq_line_from_file() {
        init_seed();
        let content = include_str!("../../tests/list_dnsmasq.txt");
        let mut parsed = 0;
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let result = parse_dnsmasq_line(trimmed);
            assert!(result.is_ok(), "Failed to parse: {}", trimmed);
            let entry = result.unwrap();
            assert!(!entry.value.is_empty(), "Domain should not be empty");
            parsed += 1;
        }
        assert!(parsed > 0, "Should parse at least one dnsmasq entry");
    }

    #[test]
    fn test_parse_dnsmasq_invalid_format() {
        init_seed();
        let result = parse_dnsmasq_line("invalid-no-slashes");
        assert!(result.is_err());
    }

    // --- Tests for parse_plain_domain ---

    #[test]
    fn test_parse_plain_domain_simple() {
        init_seed();
        let result = parse_plain_domain("example.com").unwrap();
        assert_eq!(result.value, "example.com");
        assert_eq!(result.depth, 1);
    }

    #[test]
    fn test_parse_plain_domain_subdomain() {
        init_seed();
        let result = parse_plain_domain("sub.domain.example.org").unwrap();
        assert_eq!(result.value, "sub.domain.example.org");
        assert_eq!(result.depth, 3);
    }

    #[test]
    fn test_parse_plain_domain_empty() {
        init_seed();
        let result = parse_plain_domain("");
        assert!(result.is_err());
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

    // --- Tests for detect_format ---

    #[test]
    fn test_detect_format_hosts() {
        assert_eq!(detect_format("0.0.0.0 example.com"), ListFormat::Hosts);
        assert_eq!(detect_format("127.0.0.1 example.com"), ListFormat::Hosts);
        assert_eq!(detect_format(":: example.com"), ListFormat::Hosts);
    }

    #[test]
    fn test_detect_format_dnsmasq() {
        assert_eq!(detect_format("server=/example.com/"), ListFormat::Dnsmasq);
        assert_eq!(
            detect_format("address=/example.com/127.0.0.1"),
            ListFormat::Dnsmasq
        );
    }

    #[test]
    fn test_detect_format_plain() {
        assert_eq!(detect_format("example.com"), ListFormat::Plain);
        assert_eq!(detect_format("sub.domain.example.org"), ListFormat::Plain);
    }

    #[test]
    fn test_detect_format_unknown() {
        assert_eq!(detect_format("some random text"), ListFormat::Unknown);
    }

    // --- Tests for parse_dnsmasq_line edge cases ---

    #[test]
    fn test_parse_dnsmasq_empty_domain() {
        init_seed();
        let result = parse_dnsmasq_line("server=//");
        assert!(result.is_err());
    }

    // --- Tests for process_line ---

    #[test]
    fn test_process_line_hosts_format() {
        init_seed();
        let mut fast_map = HashMap::new();
        let mut hierarchical_list = Vec::new();

        process_line(
            "0.0.0.0 test.example.com",
            DomainEntryFlags::NONE,
            &mut fast_map,
            &mut hierarchical_list,
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

        process_line(
            "server=/doubleclick.net/",
            DomainEntryFlags::NONE,
            &mut fast_map,
            &mut hierarchical_list,
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

        process_line(
            "ads.example.org",
            DomainEntryFlags::NONE,
            &mut fast_map,
            &mut hierarchical_list,
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

        process_line(
            "# This is a comment",
            DomainEntryFlags::NONE,
            &mut fast_map,
            &mut hierarchical_list,
        );

        assert!(fast_map.is_empty());
        assert!(hierarchical_list.is_empty());
    }

    #[test]
    fn test_process_line_empty_ignored() {
        init_seed();
        let mut fast_map = HashMap::new();
        let mut hierarchical_list = Vec::new();

        process_line(
            "",
            DomainEntryFlags::NONE,
            &mut fast_map,
            &mut hierarchical_list,
        );
        process_line(
            "   ",
            DomainEntryFlags::NONE,
            &mut fast_map,
            &mut hierarchical_list,
        );

        assert!(fast_map.is_empty());
        assert!(hierarchical_list.is_empty());
    }

    #[test]
    fn test_process_line_whitelist_flag() {
        init_seed();
        let mut fast_map = HashMap::new();
        let mut hierarchical_list = Vec::new();

        process_line(
            "allowed.example.com",
            DomainEntryFlags::WHITELIST,
            &mut fast_map,
            &mut hierarchical_list,
        );

        assert_eq!(fast_map.len(), 1);
        // Check the flags value in fast_map
        let flags_bits = *fast_map.values().next().unwrap();
        assert_eq!(flags_bits, DomainEntryFlags::WHITELIST.bits());

        assert_eq!(hierarchical_list[0].flags, DomainEntryFlags::WHITELIST);
    }

    // --- Tests for load_list_file ---

    #[test]
    fn test_load_list_file_hosts() {
        init_seed();
        let mut fast_map = HashMap::new();
        let mut hierarchical_list = Vec::new();

        let result = load_list_file(
            "tests/list_host.txt",
            DomainEntryFlags::NONE,
            &mut fast_map,
            &mut hierarchical_list,
        );

        assert!(result.is_ok(), "Failed to load hosts file: {:?}", result);
        // The test file has 78 entries (excluding comments and empty lines)
        assert!(
            fast_map.len() >= 70,
            "Expected at least 70 entries, got {}",
            fast_map.len()
        );
        assert_eq!(fast_map.len(), hierarchical_list.len());
    }

    #[test]
    fn test_load_list_file_dnsmasq() {
        init_seed();
        let mut fast_map = HashMap::new();
        let mut hierarchical_list = Vec::new();

        let result = load_list_file(
            "tests/list_dnsmasq.txt",
            DomainEntryFlags::NONE,
            &mut fast_map,
            &mut hierarchical_list,
        );

        assert!(result.is_ok(), "Failed to load dnsmasq file: {:?}", result);
        assert!(
            fast_map.len() >= 70,
            "Expected at least 70 entries, got {}",
            fast_map.len()
        );
        assert_eq!(fast_map.len(), hierarchical_list.len());
    }

    #[test]
    fn test_load_list_file_not_found() {
        init_seed();
        let mut fast_map = HashMap::new();
        let mut hierarchical_list = Vec::new();

        let result = load_list_file(
            "nonexistent_file.txt",
            DomainEntryFlags::NONE,
            &mut fast_map,
            &mut hierarchical_list,
        );

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn test_load_list_file_with_whitelist_flag() {
        init_seed();
        let mut fast_map = HashMap::new();
        let mut hierarchical_list = Vec::new();

        let result = load_list_file(
            "tests/list_host.txt",
            DomainEntryFlags::WHITELIST,
            &mut fast_map,
            &mut hierarchical_list,
        );

        assert!(result.is_ok());
        // All entries should have WHITELIST flag
        for entry in &hierarchical_list {
            assert!(
                entry.flags.contains(DomainEntryFlags::WHITELIST),
                "Entry should have WHITELIST flag"
            );
        }
    }
}
