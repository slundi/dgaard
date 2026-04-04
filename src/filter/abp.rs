//! Adblock rules
//! * `||example.com^`: domain and all its sub domains
//! * `@@||example.com^`: whitelist for this domain
//! * `/regex/`: regular expression
//! * `*`: universal wildcard, can be anywhere in the domain

use std::{collections::HashSet, sync::atomic::Ordering};

use crate::{
    GLOBAL_SEED,
    filter::ListError,
    model::{DomainEntryFlags, RawDomainEntry},
    utils::count_dots,
};

pub fn parse_abp_line(line: &str) -> Result<RawDomainEntry, ListError<'_>> {
    let mut input = line.trim();

    // 1. Check if it is a whitelist (@@) or a blacklist
    let mut flags = if input.starts_with("@@") {
        input = &input[2..];
        DomainEntryFlags::WHITELIST
    } else {
        DomainEntryFlags::NONE
    };

    // 2. Cleanup option (ignore following '$')
    if let Some(pos) = input.find('$') {
        input = &input[..pos];
    }

    // 3. Identify pattern type
    let pattern = if input.starts_with('/') && input.ends_with('/') && input.len() > 2 {
        // this is a regex
        flags |= DomainEntryFlags::REGEX;
        &input[1..input.len() - 1]
    } else {
        // it is a domain or a wildcard (ex: ||example.com^ ou *doubleclick*)
        // keep symbols || and ^ because they can be useful for later matching
        if input.contains('*') {
            // TODO: improve because we may have `*.example.com` so it needs to be treated as wildcard.
            // But for `some.*.thing.com` or `facebook*.com` it will be a dedicated wildcard processing
            flags |= DomainEntryFlags::WILDCARD;
        }
        input
    };

    if pattern.is_empty() {
        return Err(ListError::ParseError(
            std::io::Error::new(std::io::ErrorKind::InvalidData, "Empty ABP pattern"),
            line,
            "abp",
        ));
    }

    let hash = twox_hash::XxHash64::oneshot(GLOBAL_SEED.load(Ordering::Relaxed), line.as_bytes());

    Ok(RawDomainEntry {
        hash,
        value: pattern.to_string(),
        depth: count_dots(pattern),
        flags,
    })
}

pub struct AbpFilter {
    pub blocked_domains: HashSet<String>,
    pub exceptions: HashSet<String>,
}

impl AbpFilter {
    pub fn parse_line(&mut self, line: &str) {
        let line = line.trim();
        if line.is_empty() || line.starts_with('!') || line.contains("##") {
            return; // Skip comments and cosmetic rules
        }

        if line.starts_with("@@||") {
            // Exception rule: @@||example.com^
            if let Some(domain) = line.strip_prefix("@@||").and_then(|s| s.split('^').next()) {
                self.exceptions.insert(domain.to_string());
            }
        } else if line.starts_with("||") {
            // Block rule: ||example.com^
            if let Some(domain) = line.strip_prefix("||").and_then(|s| s.split('^').next()) {
                self.blocked_domains.insert(domain.to_string());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    fn init_seed() {
        GLOBAL_SEED.store(42, Ordering::Relaxed);
    }

    #[test]
    fn test_parse_abp_block_rule() {
        init_seed();
        let result = parse_abp_line("||example.com^").unwrap();
        assert_eq!(result.value, "||example.com^");
        assert_eq!(result.flags, DomainEntryFlags::NONE);
        assert_eq!(result.depth, 1);
    }

    #[test]
    fn test_parse_abp_whitelist_rule() {
        init_seed();
        let result = parse_abp_line("@@||trusted.com^").unwrap();
        assert_eq!(result.value, "||trusted.com^");
        assert!(result.flags.contains(DomainEntryFlags::WHITELIST));
        assert_eq!(result.depth, 1);
    }

    #[test]
    fn test_parse_abp_wildcard_rule() {
        init_seed();
        let result = parse_abp_line("||*.ads.example.com^").unwrap();
        assert!(result.flags.contains(DomainEntryFlags::WILDCARD));
    }

    #[test]
    fn test_parse_abp_regex_rule() {
        init_seed();
        let result = parse_abp_line("/ads[0-9]+\\.example\\.com/").unwrap();
        assert!(result.flags.contains(DomainEntryFlags::REGEX));
        assert_eq!(result.value, "ads[0-9]+\\.example\\.com");
    }

    #[test]
    fn test_parse_abp_with_options() {
        init_seed();
        let result = parse_abp_line("||ads.example.com^$third-party").unwrap();
        assert_eq!(result.value, "||ads.example.com^");
    }

    #[test]
    fn test_parse_abp_whitelist_with_options() {
        init_seed();
        let result = parse_abp_line("@@||safe.com^$document").unwrap();
        assert!(result.flags.contains(DomainEntryFlags::WHITELIST));
        assert_eq!(result.value, "||safe.com^");
    }

    #[test]
    fn test_parse_abp_empty_pattern() {
        init_seed();
        let result = parse_abp_line("");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_abp_from_file() {
        init_seed();
        let content = include_str!("../../tests/list_abp.txt");
        let mut parsed = 0;
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('!') {
                continue;
            }
            let result = parse_abp_line(trimmed);
            assert!(result.is_ok(), "Failed to parse: {}", trimmed);
            let entry = result.unwrap();
            assert!(!entry.value.is_empty(), "Pattern should not be empty");
            parsed += 1;
        }
        assert!(parsed > 0, "Should parse at least one ABP entry");
    }

    #[test]
    fn test_parse_abp_subdomain_depth() {
        init_seed();
        let result = parse_abp_line("||sub.domain.example.com^").unwrap();
        assert_eq!(result.depth, 3);
    }

    #[test]
    fn test_abp_filter_parse_line_block() {
        let mut filter = AbpFilter {
            blocked_domains: HashSet::new(),
            exceptions: HashSet::new(),
        };
        filter.parse_line("||ads.example.com^");
        assert!(filter.blocked_domains.contains("ads.example.com"));
    }

    #[test]
    fn test_abp_filter_parse_line_exception() {
        let mut filter = AbpFilter {
            blocked_domains: HashSet::new(),
            exceptions: HashSet::new(),
        };
        filter.parse_line("@@||trusted.example.com^");
        assert!(filter.exceptions.contains("trusted.example.com"));
    }

    #[test]
    fn test_abp_filter_skips_comments() {
        let mut filter = AbpFilter {
            blocked_domains: HashSet::new(),
            exceptions: HashSet::new(),
        };
        filter.parse_line("! This is a comment");
        assert!(filter.blocked_domains.is_empty());
        assert!(filter.exceptions.is_empty());
    }

    #[test]
    fn test_abp_filter_skips_cosmetic_rules() {
        let mut filter = AbpFilter {
            blocked_domains: HashSet::new(),
            exceptions: HashSet::new(),
        };
        filter.parse_line("example.com##.ad-banner");
        assert!(filter.blocked_domains.is_empty());
    }
}
