mod abp;
mod bloom;
mod fst;

use core::sync::atomic::Ordering;
use hickory_resolver::{Name, proto::ProtoError};
use regex::Regex;
use std::{collections::HashMap, str::FromStr, sync::Arc};
use thiserror::Error;

use crate::{
    CURRENT_ENGINE, GLOBAL_SEED,
    model::{DomainEntry, DomainEntryFlags, RawDomainEntry},
    utils::count_dots,
};

#[derive(Error, Debug)]
pub enum ListError<'a> {
    #[error("Invalid domain {1}: {0}")]
    InvalidDomain(#[source] ProtoError, &'a str),
    #[error("Failed to parse line: {1}, format: {2}. Internal error: {0}")]
    ParseError(#[source] std::io::Error, &'a str, &'a str),
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
        todo!("does not load list yet")
    }
}

pub fn parse_line<'a, F>(line: &'a str, parser: F) -> Result<RawDomainEntry, ListError<'a>>
where
    F: Fn(&'a str) -> Result<RawDomainEntry, ListError<'a>>,
{
    // common logic like trimming and ignoring comments
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        todo!("ignore the line");
    }

    parser(trimmed)
}

pub fn parse_host_line(line: &str) -> Result<RawDomainEntry, ListError<'_>> {
    let mut s = line.split('.');
    let domain = s.next_back().ok_or_else(|| {
        ListError::ParseError(
            std::io::Error::new(std::io::ErrorKind::InvalidData, "No domain found"),
            line,
            "host",
        )
    })?;

    Name::from_str(domain).map_err(|e| ListError::InvalidDomain(e, domain))?;

    let hash = twox_hash::XxHash64::oneshot(GLOBAL_SEED.load(Ordering::Relaxed), line.as_bytes());

    Ok(RawDomainEntry {
        hash,
        value: domain.to_string(),
        flags: DomainEntryFlags::NONE,
        depth: count_dots(domain),
    })
}

// Example with (ex: dnsmasq format "address=/doubleclick.net/127.0.0.1")
pub fn parse_dnsmasq_line(line: &str) -> Result<RawDomainEntry, ListError<'_>> {
    // Logique simplifiée pour l'exemple
    let domain = line.split('/').nth(1).ok_or_else(|| {
        ListError::ParseError(
            std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid dnsmasq format"),
            line,
            "dnsmasq",
        )
    })?;

    let hash = twox_hash::XxHash64::oneshot(GLOBAL_SEED.load(Ordering::Relaxed), line.as_bytes());

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
        assert_eq!(result.value, "com");
        assert_eq!(result.flags, DomainEntryFlags::NONE);
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
            // Host format: "0.0.0.0 domain.com" - extract domain part
            let domain = trimmed.split_whitespace().nth(1);
            if let Some(domain) = domain {
                let result = parse_host_line(domain);
                assert!(result.is_ok(), "Failed to parse: {}", domain);
                parsed += 1;
            }
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
}
