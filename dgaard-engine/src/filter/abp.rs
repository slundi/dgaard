//! Adblock rules
//! * `||example.com^`: domain and all its sub domains
//! * `@@||example.com^`: whitelist for this domain
//! * `/regex/`: regular expression
//! * `*`: universal wildcard, can be anywhere in the domain

use crate::{
    filter::ListError,
    model::{DomainEntryFlags, RawDomainEntry},
    utils::count_dots,
};

/// Extract clean domain from ABP domain pattern like `||example.com^`
fn extract_domain_from_abp(pattern: &str) -> Option<&str> {
    let domain = pattern.strip_prefix("||")?;
    // Split on ^ and take the first part (the domain)
    let domain = domain.split('^').next()?;
    if domain.is_empty() {
        return None;
    }
    Some(domain)
}

pub fn parse_abp_line(line: &str, seed: u64) -> Result<RawDomainEntry, ListError<'_>> {
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

    let hash = twox_hash::XxHash64::oneshot(seed, hash_source.as_bytes());

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

    const SEED: u64 = 42;

    #[test]
    fn test_parse_abp_block_rule() {
        let result = parse_abp_line("||example.com^", SEED).unwrap();
        assert_eq!(result.value, "example.com");
        assert_eq!(result.flags, DomainEntryFlags::NONE);
        assert_eq!(result.depth, 1);
    }

    #[test]
    fn test_parse_abp_whitelist_rule() {
        let result = parse_abp_line("@@||trusted.com^", SEED).unwrap();
        assert_eq!(result.value, "trusted.com");
        assert!(result.flags.contains(DomainEntryFlags::WHITELIST));
        assert_eq!(result.depth, 1);
    }

    #[test]
    fn test_parse_abp_wildcard_rule() {
        let result = parse_abp_line("||*.ads.example.com^", SEED).unwrap();
        assert!(result.flags.contains(DomainEntryFlags::WILDCARD));
        assert_eq!(result.value, "||*.ads.example.com^");
    }

    #[test]
    fn test_parse_abp_regex_rule() {
        let result = parse_abp_line("/ads[0-9]+\\.example\\.com/", SEED).unwrap();
        assert!(result.flags.contains(DomainEntryFlags::REGEX));
        assert_eq!(result.value, "ads[0-9]+\\.example\\.com");
    }

    #[test]
    fn test_parse_abp_with_options() {
        let result = parse_abp_line("||ads.example.com^$third-party", SEED).unwrap();
        assert_eq!(result.value, "ads.example.com");
    }

    #[test]
    fn test_parse_abp_empty_pattern() {
        let result = parse_abp_line("", SEED);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_abp_subdomain_depth() {
        let result = parse_abp_line("||sub.domain.example.com^", SEED).unwrap();
        assert_eq!(result.value, "sub.domain.example.com");
        assert_eq!(result.depth, 3);
    }
}
