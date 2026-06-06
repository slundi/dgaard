use std::str::FromStr;

use hickory_resolver::proto::rr::Name;

use crate::{
    error::ListError,
    model::{ListFormat, Rule},
};

/// Detect format type from a line
pub fn detect_format(line: &str) -> ListFormat {
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
pub fn parse_host_line(line: &str) -> Result<Rule, ListError<'_>> {
    let domain = line.split_whitespace().nth(1).ok_or_else(|| {
        ListError::ParseError(
            std::io::Error::new(std::io::ErrorKind::InvalidData, "No domain found"),
            line,
            "host",
        )
    })?;

    Name::from_str(domain).map_err(|e| ListError::InvalidDomain(e, domain))?;

    Ok(Rule::NetworkDomain(domain.to_string()))
}

/// Parse dnsmasq format line: "server=/domain.com/" or "address=/domain.com/127.0.0.1"
pub fn parse_dnsmasq_line(line: &str) -> Result<Rule, ListError<'_>> {
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

    Ok(Rule::NetworkDomain(domain.to_string()))
}

/// Parse plain domain format: just the domain name with no IP prefix
pub fn parse_plain_domain(line: &str) -> Result<Rule, ListError<'_>> {
    let domain = line.trim();

    if domain.is_empty() {
        return Err(ListError::ParseError(
            std::io::Error::new(std::io::ErrorKind::InvalidData, "Empty domain"),
            line,
            "plain",
        ));
    }

    Name::from_str(domain).map_err(|e| ListError::InvalidDomain(e, domain))?;

    Ok(Rule::NetworkDomain(domain.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── detect_format ─────────────────────────────────────────────────────────

    #[test]
    fn detect_hosts_format_zero_prefix() {
        assert_eq!(detect_format("0.0.0.0 example.com"), ListFormat::Hosts);
    }

    #[test]
    fn detect_hosts_format_loopback_prefix() {
        assert_eq!(detect_format("127.0.0.1 example.com"), ListFormat::Hosts);
    }

    #[test]
    fn detect_hosts_format_ipv6_prefix() {
        assert_eq!(detect_format(":: example.com"), ListFormat::Hosts);
    }

    #[test]
    fn detect_dnsmasq_server_format() {
        assert_eq!(detect_format("server=/example.com/"), ListFormat::Dnsmasq);
    }

    #[test]
    fn detect_dnsmasq_address_format() {
        assert_eq!(
            detect_format("address=/example.com/127.0.0.1"),
            ListFormat::Dnsmasq
        );
    }

    #[test]
    fn detect_abp_domain_rule() {
        assert_eq!(detect_format("||example.com^"), ListFormat::Abp);
    }

    #[test]
    fn detect_abp_whitelist_rule() {
        assert_eq!(detect_format("@@||safe.com^"), ListFormat::Abp);
    }

    #[test]
    fn detect_abp_regex_rule() {
        assert_eq!(detect_format("/pattern/"), ListFormat::Abp);
    }

    #[test]
    fn detect_plain_domain() {
        assert_eq!(detect_format("example.com"), ListFormat::Plain);
    }

    #[test]
    fn detect_unknown_format_with_spaces() {
        assert_eq!(detect_format("some random text"), ListFormat::Unknown);
    }

    // ── parse_host_line ───────────────────────────────────────────────────────

    #[test]
    fn parse_host_line_zero_prefix() {
        let rule = parse_host_line("0.0.0.0 example.com").unwrap();
        assert_eq!(rule, Rule::NetworkDomain("example.com".to_string()));
    }

    #[test]
    fn parse_host_line_loopback_prefix() {
        let rule = parse_host_line("127.0.0.1 ads.example.com").unwrap();
        assert_eq!(rule, Rule::NetworkDomain("ads.example.com".to_string()));
    }

    #[test]
    fn parse_host_line_missing_domain_returns_error() {
        let result = parse_host_line("0.0.0.0");
        assert!(result.is_err());
    }

    #[test]
    fn parse_host_line_invalid_domain_returns_error() {
        // Domain with invalid characters
        let result = parse_host_line("0.0.0.0 not_a_valid_domain!!!");
        assert!(result.is_err());
    }

    // ── parse_dnsmasq_line ────────────────────────────────────────────────────

    #[test]
    fn parse_dnsmasq_server_format() {
        let rule = parse_dnsmasq_line("server=/example.com/").unwrap();
        assert_eq!(rule, Rule::NetworkDomain("example.com".to_string()));
    }

    #[test]
    fn parse_dnsmasq_address_format() {
        let rule = parse_dnsmasq_line("address=/example.com/127.0.0.1").unwrap();
        assert_eq!(rule, Rule::NetworkDomain("example.com".to_string()));
    }

    #[test]
    fn parse_dnsmasq_empty_domain_returns_error() {
        let result = parse_dnsmasq_line("server=//");
        assert!(result.is_err());
    }

    // ── parse_plain_domain ────────────────────────────────────────────────────

    #[test]
    fn parse_plain_domain_valid() {
        let rule = parse_plain_domain("example.com").unwrap();
        assert_eq!(rule, Rule::NetworkDomain("example.com".to_string()));
    }

    #[test]
    fn parse_plain_domain_with_subdomain() {
        let rule = parse_plain_domain("sub.example.com").unwrap();
        assert_eq!(rule, Rule::NetworkDomain("sub.example.com".to_string()));
    }

    #[test]
    fn parse_plain_domain_empty_returns_error() {
        assert!(parse_plain_domain("").is_err());
        assert!(parse_plain_domain("   ").is_err());
    }
}
