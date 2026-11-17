use hickory_resolver::proto::rr::Name;
use std::str::FromStr;

use crate::{
    filter::{ListError, types::ListFormat},
    model::{DomainEntryFlags, RawDomainEntry},
    utils::{count_dots, normalize_domain},
};

/// Sinkhole addresses that introduce a hosts-format line.
const HOSTS_SINKHOLES: &[&str] = &["0.0.0.0", "127.0.0.1", "::"];

/// A hosts line is a sinkhole address followed by any whitespace (space or tab).
fn is_hosts_line(line: &str) -> bool {
    line.split_once(char::is_whitespace)
        .is_some_and(|(address, _)| HOSTS_SINKHOLES.contains(&address))
}

/// Detect format type from a line
pub(crate) fn detect_format(line: &str) -> ListFormat {
    if line.starts_with("server=/") || line.starts_with("address=/") {
        ListFormat::Dnsmasq
    } else if is_hosts_line(line) {
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

/// Build an exact-match entry from an already-extracted domain.
fn exact_entry(domain: &str, seed: u64) -> RawDomainEntry {
    let value = normalize_domain(domain);
    RawDomainEntry {
        hash: twox_hash::XxHash64::oneshot(seed, value.as_bytes()),
        depth: count_dots(&value),
        value,
        flags: DomainEntryFlags::NONE,
    }
}

/// Parse hosts format line: "0.0.0.0 domain.com" or "127.0.0.1 domain.com" or ":: domain.com".
///
/// Fields may be separated by any whitespace, a line may list several names
/// (`0.0.0.0 a.com b.com`), and an inline `#` starts a trailing comment.
/// Invalid names are skipped; the line fails only if no valid name remains.
pub fn parse_host_line(line: &str, seed: u64) -> Result<Vec<RawDomainEntry>, ListError<'_>> {
    let content = line.split_once('#').map_or(line, |(before, _)| before);

    let mut first_error = None;
    let mut entries = Vec::new();
    for domain in content.split_whitespace().skip(1) {
        match Name::from_str(domain) {
            Ok(_) => entries.push(exact_entry(domain, seed)),
            Err(e) => {
                first_error.get_or_insert(ListError::InvalidDomain(e, domain));
            }
        }
    }

    if !entries.is_empty() {
        return Ok(entries);
    }
    Err(first_error.unwrap_or_else(|| {
        ListError::ParseError(
            std::io::Error::new(std::io::ErrorKind::InvalidData, "No domain found"),
            line,
            "host",
        )
    }))
}

/// Parse dnsmasq format line: "server=/domain.com/" or "address=/domain.com/127.0.0.1"
pub fn parse_dnsmasq_line(line: &str, seed: u64) -> Result<RawDomainEntry, ListError<'_>> {
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

    Ok(exact_entry(domain, seed))
}

/// Parse plain domain format: just the domain name with no IP prefix
pub fn parse_plain_domain(line: &str, seed: u64) -> Result<RawDomainEntry, ListError<'_>> {
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

    Ok(exact_entry(domain, seed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::DomainEntryFlags;

    const SEED: u64 = 42;

    fn host_values(line: &str) -> Vec<String> {
        parse_host_line(line, SEED)
            .unwrap()
            .into_iter()
            .map(|entry| entry.value)
            .collect()
    }

    #[test]
    fn test_parse_host_line_simple() {
        let result = parse_host_line("0.0.0.0 ads.example.com", SEED).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].value, "ads.example.com");
        assert_eq!(result[0].flags, DomainEntryFlags::NONE);
        assert_eq!(result[0].depth, 2);
    }

    #[test]
    fn test_parse_host_line_localhost() {
        let result = parse_host_line("127.0.0.1 tracking.site.com", SEED).unwrap();
        assert_eq!(result[0].value, "tracking.site.com");
        assert_eq!(result[0].depth, 2);
    }

    #[test]
    fn test_parse_host_line_ipv6() {
        let result = parse_host_line(":: malware.net", SEED).unwrap();
        assert_eq!(result[0].value, "malware.net");
        assert_eq!(result[0].depth, 1);
    }

    #[test]
    fn test_parse_host_line_missing_domain() {
        let result = parse_host_line("0.0.0.0", SEED);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_host_line_tab_separated() {
        assert_eq!(host_values("0.0.0.0\tads.com"), ["ads.com"]);
        assert_eq!(host_values("0.0.0.0 \t  ads.com"), ["ads.com"]);
    }

    #[test]
    fn test_parse_host_line_multiple_names() {
        assert_eq!(
            host_values("0.0.0.0 a.com b.com\tc.com"),
            ["a.com", "b.com", "c.com"]
        );
    }

    #[test]
    fn test_parse_host_line_inline_comment() {
        assert_eq!(
            host_values("0.0.0.0 ads.com # tracker, see issue 12"),
            ["ads.com"]
        );
        assert_eq!(host_values("0.0.0.0 ads.com#comment"), ["ads.com"]);
    }

    #[test]
    fn test_parse_host_line_only_comment_is_error() {
        assert!(parse_host_line("0.0.0.0 # nothing here", SEED).is_err());
    }

    #[test]
    fn test_parse_host_line_skips_invalid_names() {
        let long_label = "a".repeat(64);
        let line = format!("0.0.0.0 {long_label}.com ok.com");
        assert_eq!(host_values(&line), ["ok.com"]);
        let only_invalid = format!("0.0.0.0 {long_label}.com");
        assert!(matches!(
            parse_host_line(&only_invalid, SEED),
            Err(ListError::InvalidDomain(..))
        ));
    }

    #[test]
    fn test_parse_host_line_normalizes() {
        let result = parse_host_line("0.0.0.0 Tracker.COM.", SEED).unwrap();
        assert_eq!(result[0].value, "tracker.com");
        assert_eq!(result[0].depth, 1);
        assert_eq!(
            result[0].hash,
            twox_hash::XxHash64::oneshot(SEED, b"tracker.com")
        );
    }

    #[test]
    fn test_parse_dnsmasq_line_normalizes() {
        let result = parse_dnsmasq_line("server=/Ads.Example.COM/", SEED).unwrap();
        assert_eq!(result.value, "ads.example.com");
    }

    #[test]
    fn test_parse_plain_domain_normalizes() {
        let result = parse_plain_domain("Example.COM.", SEED).unwrap();
        assert_eq!(result.value, "example.com");
        assert_eq!(result.depth, 1);
    }

    #[test]
    fn test_parse_dnsmasq_line_simple() {
        let result = parse_dnsmasq_line("server=/doubleclick.net/", SEED).unwrap();
        assert_eq!(result.value, "doubleclick.net");
        assert_eq!(result.flags, DomainEntryFlags::NONE);
        assert_eq!(result.depth, 1);
    }

    #[test]
    fn test_parse_dnsmasq_line_address_format() {
        let result = parse_dnsmasq_line("address=/ads.example.com/127.0.0.1", SEED).unwrap();
        assert_eq!(result.value, "ads.example.com");
        assert_eq!(result.depth, 2);
    }

    #[test]
    fn test_parse_dnsmasq_invalid_format() {
        let result = parse_dnsmasq_line("invalid-no-slashes", SEED);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_dnsmasq_empty_domain() {
        let result = parse_dnsmasq_line("server=//", SEED);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_plain_domain_simple() {
        let result = parse_plain_domain("example.com", SEED).unwrap();
        assert_eq!(result.value, "example.com");
        assert_eq!(result.depth, 1);
    }

    #[test]
    fn test_parse_plain_domain_subdomain() {
        let result = parse_plain_domain("sub.domain.example.org", SEED).unwrap();
        assert_eq!(result.value, "sub.domain.example.org");
        assert_eq!(result.depth, 3);
    }

    #[test]
    fn test_parse_plain_domain_empty() {
        let result = parse_plain_domain("", SEED);
        assert!(result.is_err());
    }

    #[test]
    fn test_detect_format_hosts() {
        assert_eq!(detect_format("0.0.0.0 example.com"), ListFormat::Hosts);
        assert_eq!(detect_format("127.0.0.1 example.com"), ListFormat::Hosts);
        assert_eq!(detect_format(":: example.com"), ListFormat::Hosts);
    }

    #[test]
    fn test_detect_format_hosts_tab_separated() {
        assert_eq!(detect_format("0.0.0.0\texample.com"), ListFormat::Hosts);
        assert_eq!(detect_format("127.0.0.1\t\texample.com"), ListFormat::Hosts);
        assert_eq!(detect_format("::\texample.com"), ListFormat::Hosts);
    }

    #[test]
    fn test_detect_format_hosts_requires_sinkhole_address() {
        // A bare address is not a hosts line, nor is an unknown address.
        assert_ne!(detect_format("0.0.0.0"), ListFormat::Hosts);
        assert_ne!(detect_format("10.0.0.1 example.com"), ListFormat::Hosts);
        assert_ne!(detect_format("0.0.0.0.example.com"), ListFormat::Hosts);
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
    fn test_detect_format_abp_block() {
        assert_eq!(detect_format("||example.com^"), ListFormat::Abp);
        assert_eq!(detect_format("@@||example.com^"), ListFormat::Abp);
    }
}
