use core::sync::atomic::Ordering;
use hickory_resolver::Name;
use std::str::FromStr;

use crate::{
    GLOBAL_SEED,
    filter::{ListError, types::ListFormat},
    model::{DomainEntryFlags, RawDomainEntry},
    utils::count_dots,
};

/// Detect format type from a line
pub(crate) fn detect_format(line: &str) -> ListFormat {
    if line.starts_with("server=/") || line.starts_with("address=/") {
        ListFormat::Dnsmasq
    } else if line.starts_with("0.0.0.0 ")
        || line.starts_with("127.0.0.1 ")
        || line.starts_with(":: ")
    {
        ListFormat::Hosts
    } else if line.starts_with("||") || line.starts_with("@@||") {
        // ABP domain rules: ||example.com^ or @@||example.com^
        ListFormat::Abp
    } else if line.starts_with('/') && line.len() > 2 && line[1..].contains('/') {
        // ABP regex rules: /pattern/
        ListFormat::Abp
    } else if !line.contains(' ') && !line.contains('/') {
        ListFormat::Plain
    } else {
        ListFormat::Unknown
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{filter::tests::init_seed, model::DomainEntryFlags};

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

    #[test]
    fn test_parse_dnsmasq_empty_domain() {
        init_seed();
        let result = parse_dnsmasq_line("server=//");
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

    // --- Tests for ABP format detection ---

    #[test]
    fn test_detect_format_abp_block() {
        assert_eq!(detect_format("||example.com^"), ListFormat::Abp);
        assert_eq!(detect_format("||ads.example.com^"), ListFormat::Abp);
    }

    #[test]
    fn test_detect_format_abp_whitelist() {
        assert_eq!(detect_format("@@||example.com^"), ListFormat::Abp);
        assert_eq!(detect_format("@@||trusted.site.com^"), ListFormat::Abp);
    }

    #[test]
    fn test_detect_format_abp_regex() {
        assert_eq!(
            detect_format("/ads[0-9]+\\.example\\.com/"),
            ListFormat::Abp
        );
    }
}
