//! Adblock rules
//! * `||example.com^`: domain and all its sub domains
//! * `@@||example.com^`: whitelist for this domain
//! * `/regex/`: regular expression
//! * `*`: universal wildcard, can be anywhere in the domain

use std::sync::atomic::Ordering;

use crate::{
    GLOBAL_SEED,
    filter::ListError,
    model::{DomainEntryFlags, RawDomainEntry},
    utils::count_dots,
};

/// Extract clean domain from ABP domain pattern like `||example.com^`
/// Returns the domain without `||` prefix and `^` suffix
fn extract_domain_from_abp(pattern: &str) -> Option<&str> {
    let domain = pattern.strip_prefix("||")?;
    // Split on ^ and take the first part (the domain)
    let domain = domain.split('^').next()?;
    if domain.is_empty() {
        return None;
    }
    Some(domain)
}

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

    // 3. Identify pattern type and extract value
    let (value, hash_source) = if input.starts_with('/') && input.ends_with('/') && input.len() > 2
    {
        // Regex pattern: /pattern/
        flags |= DomainEntryFlags::REGEX;
        let pattern = &input[1..input.len() - 1];
        (pattern, pattern)
    } else if input.contains('*') {
        // Wildcard pattern: contains *
        flags |= DomainEntryFlags::WILDCARD;
        // For wildcards, keep the full pattern for later matching
        (input, input)
    } else if let Some(domain) = extract_domain_from_abp(input) {
        // Simple domain rule: ||domain.com^ -> extract clean domain
        (domain, domain)
    } else {
        // Fallback: use the input as-is
        (input, input)
    };

    if value.is_empty() {
        return Err(ListError::ParseError(
            std::io::Error::new(std::io::ErrorKind::InvalidData, "Empty ABP pattern"),
            line,
            "abp",
        ));
    }

    let hash =
        twox_hash::XxHash64::oneshot(GLOBAL_SEED.load(Ordering::Relaxed), hash_source.as_bytes());

    Ok(RawDomainEntry {
        hash,
        value: value.to_string(),
        depth: count_dots(value),
        flags,
    })
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
        // Clean domain extracted from ||example.com^
        assert_eq!(result.value, "example.com");
        assert_eq!(result.flags, DomainEntryFlags::NONE);
        assert_eq!(result.depth, 1);
    }

    #[test]
    fn test_parse_abp_whitelist_rule() {
        init_seed();
        let result = parse_abp_line("@@||trusted.com^").unwrap();
        // Clean domain extracted from ||trusted.com^
        assert_eq!(result.value, "trusted.com");
        assert!(result.flags.contains(DomainEntryFlags::WHITELIST));
        assert_eq!(result.depth, 1);
    }

    #[test]
    fn test_parse_abp_wildcard_rule() {
        init_seed();
        let result = parse_abp_line("||*.ads.example.com^").unwrap();
        assert!(result.flags.contains(DomainEntryFlags::WILDCARD));
        // Wildcard patterns keep the full pattern
        assert_eq!(result.value, "||*.ads.example.com^");
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
        // Clean domain extracted, options stripped
        assert_eq!(result.value, "ads.example.com");
    }

    #[test]
    fn test_parse_abp_whitelist_with_options() {
        init_seed();
        let result = parse_abp_line("@@||safe.com^$document").unwrap();
        assert!(result.flags.contains(DomainEntryFlags::WHITELIST));
        // Clean domain extracted, options stripped
        assert_eq!(result.value, "safe.com");
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
        assert_eq!(result.value, "sub.domain.example.com");
        assert_eq!(result.depth, 3);
    }
}
