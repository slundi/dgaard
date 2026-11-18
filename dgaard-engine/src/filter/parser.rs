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
    if line.starts_with("server=/") || line.starts_with("address=/") || line.starts_with("local=/")
    {
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

/// Prefix marking a subdomains-only rule (`*.zone`): it matches every name
/// strictly below `zone`, never `zone` itself.
pub(crate) const SUBDOMAINS_PREFIX: &str = "*.";

/// Return the zone of a `*.zone` pattern, or `None` for any other pattern
/// (no prefix, empty zone, or more wildcards inside the zone).
pub(crate) fn subdomains_zone(pattern: &str) -> Option<&str> {
    pattern
        .strip_prefix(SUBDOMAINS_PREFIX)
        .filter(|zone| !zone.is_empty() && !zone.contains('*'))
}

/// Build a subdomains-only entry for `zone`.
///
/// The value keeps the `*.` prefix so the loader can tell it from `||zone^`,
/// but the hash and depth are those of `zone`: the matcher walks the parents
/// of a query and looks each one up by `(depth, hash)`.
pub(crate) fn subdomains_entry(zone: &str, seed: u64) -> RawDomainEntry {
    let zone = normalize_domain(zone);
    RawDomainEntry {
        hash: twox_hash::XxHash64::oneshot(seed, zone.as_bytes()),
        depth: count_dots(&zone),
        value: format!("{SUBDOMAINS_PREFIX}{zone}"),
        flags: DomainEntryFlags::WILDCARD,
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

/// `address=` targets that make the rule a block rather than a redirect:
/// none (NXDOMAIN), a sinkhole, or `#` (dnsmasq's 0.0.0.0 / ::).
const DNSMASQ_SINKHOLES: &[&str] = &["", "#", "0.0.0.0", "::", "127.0.0.1", "::1"];

/// Parse a dnsmasq rule: `directive=/domain/[domain/...]target`.
///
/// Only the forms that block are kept, the way dnsmasq itself reads them:
/// * `server=/x/` and `local=/x/` (no server): answered locally only, so
///   NXDOMAIN;
/// * `address=/x/` with no address, a sinkhole address or `#`.
///
/// `server=/x/1.2.3.4` (forward to that server), `server=/x/#` (use the
/// default servers) and `address=/x/192.0.2.10` (redirect to a real host)
/// are not blocks and are rejected. A dnsmasq rule covers the domain and
/// all its subdomains, so each entry is a suffix rule like `||x^`; every
/// domain is validated, and `#` ("every domain") is refused.
pub fn parse_dnsmasq_line(line: &str, seed: u64) -> Result<Vec<RawDomainEntry>, ListError<'_>> {
    let invalid = |reason: &str| {
        ListError::ParseError(
            std::io::Error::new(std::io::ErrorKind::InvalidData, reason.to_string()),
            line,
            "dnsmasq",
        )
    };

    let (directive, rest) = line
        .split_once('=')
        .ok_or_else(|| invalid("Invalid dnsmasq format"))?;
    let (domains, target) = rest
        .strip_prefix('/')
        .and_then(|rest| rest.rsplit_once('/'))
        .ok_or_else(|| invalid("Invalid dnsmasq format"))?;

    let blocks = match directive {
        "server" | "local" => target.is_empty(),
        "address" => DNSMASQ_SINKHOLES.contains(&target),
        _ => return Err(invalid("Unsupported dnsmasq directive")),
    };
    if !blocks {
        return Err(invalid("Forwarding or redirect rule, not a block"));
    }

    let mut entries = Vec::new();
    for domain in domains.split('/') {
        if domain.is_empty() {
            return Err(invalid("Empty domain"));
        }
        if domain == "#" {
            return Err(invalid("'#' (every domain) is not a block rule"));
        }
        Name::from_str(domain).map_err(|e| ListError::InvalidDomain(e, domain))?;
        let mut entry = exact_entry(domain, seed);
        entry.flags = DomainEntryFlags::WILDCARD;
        entries.push(entry);
    }
    Ok(entries)
}

/// Parse plain domain format: just the domain name with no IP prefix.
/// A leading `*.` (`*.example.com`) makes it a subdomains-only rule.
pub fn parse_plain_domain(line: &str, seed: u64) -> Result<RawDomainEntry, ListError<'_>> {
    let domain = line.trim();

    if domain.is_empty() {
        return Err(ListError::ParseError(
            std::io::Error::new(std::io::ErrorKind::InvalidData, "Empty domain"),
            line,
            "plain",
        ));
    }

    if let Some(zone) = subdomains_zone(domain) {
        Name::from_str(zone).map_err(|e| ListError::InvalidDomain(e, zone))?;
        return Ok(subdomains_entry(zone, seed));
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
        assert_eq!(result[0].value, "ads.example.com");
    }

    fn dnsmasq_values(line: &str) -> Vec<String> {
        parse_dnsmasq_line(line, SEED)
            .unwrap()
            .into_iter()
            .map(|entry| entry.value)
            .collect()
    }

    #[test]
    fn test_parse_dnsmasq_block_forms() {
        for line in [
            "server=/ads.com/",
            "local=/ads.com/",
            "address=/ads.com/",
            "address=/ads.com/0.0.0.0",
            "address=/ads.com/127.0.0.1",
            "address=/ads.com/::",
            "address=/ads.com/::1",
            "address=/ads.com/#",
        ] {
            assert_eq!(dnsmasq_values(line), ["ads.com"], "{line}");
        }
    }

    #[test]
    fn test_parse_dnsmasq_forwarding_and_redirects_are_not_blocks() {
        // Review F14: these used to be loaded as blocks.
        for line in [
            "server=/corp.example/10.0.0.53",
            "server=/corp.example/10.0.0.53#5353",
            "server=/corp.example/#",
            "address=/printer.lan/192.168.1.20",
            "address=/printer.lan/fd00::20",
        ] {
            assert!(
                matches!(
                    parse_dnsmasq_line(line, SEED),
                    Err(ListError::ParseError(..))
                ),
                "{line}"
            );
        }
    }

    #[test]
    fn test_parse_dnsmasq_rule_covers_subdomains() {
        // dnsmasq rules match the domain and every name below it.
        let entry = &parse_dnsmasq_line("address=/ads.com/0.0.0.0", SEED).unwrap()[0];
        assert_eq!(entry.flags, DomainEntryFlags::WILDCARD);
        assert_eq!(entry.hash, twox_hash::XxHash64::oneshot(SEED, b"ads.com"));
    }

    #[test]
    fn test_parse_dnsmasq_several_domains() {
        assert_eq!(
            dnsmasq_values("address=/a.com/B.com/c.net/0.0.0.0"),
            ["a.com", "b.com", "c.net"]
        );
        assert_eq!(dnsmasq_values("server=/a.com/b.com/"), ["a.com", "b.com"]);
    }

    #[test]
    fn test_parse_dnsmasq_validates_domains() {
        let long_label = "a".repeat(64);
        let line = format!("server=/{long_label}.com/");
        assert!(matches!(
            parse_dnsmasq_line(&line, SEED),
            Err(ListError::InvalidDomain(..))
        ));
        // `#` means every domain in dnsmasq: never a list entry.
        assert!(parse_dnsmasq_line("address=/#/0.0.0.0", SEED).is_err());
        assert!(parse_dnsmasq_line("server=/a.com//", SEED).is_err());
        assert!(parse_dnsmasq_line("server=ads.com", SEED).is_err());
        assert!(parse_dnsmasq_line("cname=/a.com/b.com", SEED).is_err());
    }

    #[test]
    fn test_detect_format_dnsmasq_local() {
        assert_eq!(detect_format("local=/example.com/"), ListFormat::Dnsmasq);
    }

    #[test]
    fn test_parse_plain_domain_subdomains_rule() {
        let result = parse_plain_domain("*.Ads.Example.COM", SEED).unwrap();
        assert_eq!(result.value, "*.ads.example.com");
        assert_eq!(result.flags, DomainEntryFlags::WILDCARD);
        assert_eq!(result.depth, 2);
        assert_eq!(
            result.hash,
            twox_hash::XxHash64::oneshot(SEED, b"ads.example.com")
        );
    }

    #[test]
    fn test_parse_plain_domain_subdomains_rule_invalid_zone() {
        let line = format!("*.{}.com", "a".repeat(64));
        assert!(matches!(
            parse_plain_domain(&line, SEED),
            Err(ListError::InvalidDomain(..))
        ));
    }

    #[test]
    fn test_subdomains_zone() {
        assert_eq!(subdomains_zone("*.example.com"), Some("example.com"));
        assert_eq!(subdomains_zone("example.com"), None);
        assert_eq!(subdomains_zone("*."), None);
        assert_eq!(subdomains_zone("*.*.example.com"), None);
        assert_eq!(subdomains_zone("ads*.example.com"), None);
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
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].value, "doubleclick.net");
        assert_eq!(result[0].flags, DomainEntryFlags::WILDCARD);
        assert_eq!(result[0].depth, 1);
    }

    #[test]
    fn test_parse_dnsmasq_line_address_format() {
        let result = parse_dnsmasq_line("address=/ads.example.com/127.0.0.1", SEED).unwrap();
        assert_eq!(result[0].value, "ads.example.com");
        assert_eq!(result[0].depth, 2);
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
