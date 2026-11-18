use std::str::FromStr;

use hickory_resolver::proto::rr::Name;

use crate::{
    error::ListError,
    model::{ListFormat, Rule},
};

/// Detect format type from a line
pub fn detect_format(line: &str) -> ListFormat {
    if line.starts_with("server=/") || line.starts_with("address=/") || line.starts_with("local=/")
    {
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

/// `address=` targets that make the rule a block rather than a redirect:
/// none (NXDOMAIN), a sinkhole, or `#` (dnsmasq's 0.0.0.0 / ::).
const DNSMASQ_SINKHOLES: &[&str] = &["", "#", "0.0.0.0", "::", "127.0.0.1", "::1"];

/// Parse a dnsmasq rule: `directive=/domain/[domain/...]target`.
///
/// Only blocking forms become rules: `server=/x/` and `local=/x/` (no
/// server, so NXDOMAIN) and `address=/x/` with no address, a sinkhole or
/// `#`. Forwarding (`server=/x/1.2.3.4`, `server=/x/#`) and redirects to a
/// real host (`address=/x/192.0.2.10`) are rejected. Every domain is
/// validated; `#` ("every domain") is refused.
pub fn parse_dnsmasq_line(line: &str) -> Result<Vec<Rule>, ListError<'_>> {
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

    domains
        .split('/')
        .map(|domain| {
            if domain.is_empty() {
                return Err(invalid("Empty domain"));
            }
            if domain == "#" {
                return Err(invalid("'#' (every domain) is not a block rule"));
            }
            Name::from_str(domain).map_err(|e| ListError::InvalidDomain(e, domain))?;
            Ok(Rule::NetworkDomain(domain.to_string()))
        })
        .collect()
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
        let rules = parse_dnsmasq_line("server=/example.com/").unwrap();
        assert_eq!(rules, [Rule::NetworkDomain("example.com".to_string())]);
    }

    #[test]
    fn parse_dnsmasq_address_format() {
        let rules = parse_dnsmasq_line("address=/example.com/127.0.0.1").unwrap();
        assert_eq!(rules, [Rule::NetworkDomain("example.com".to_string())]);
    }

    #[test]
    fn parse_dnsmasq_block_forms() {
        for line in [
            "local=/ads.com/",
            "address=/ads.com/",
            "address=/ads.com/0.0.0.0",
            "address=/ads.com/::",
            "address=/ads.com/::1",
            "address=/ads.com/#",
        ] {
            let rules = parse_dnsmasq_line(line).unwrap();
            assert_eq!(rules, [Rule::NetworkDomain("ads.com".into())], "{line}");
        }
    }

    #[test]
    fn parse_dnsmasq_forwarding_and_redirects_are_not_blocks() {
        // Review F14: these used to become block rules.
        for line in [
            "server=/corp.example/10.0.0.53",
            "server=/corp.example/#",
            "address=/printer.lan/192.168.1.20",
        ] {
            assert!(parse_dnsmasq_line(line).is_err(), "{line}");
        }
    }

    #[test]
    fn parse_dnsmasq_several_domains_and_validation() {
        assert_eq!(
            parse_dnsmasq_line("address=/a.com/b.com/0.0.0.0").unwrap(),
            [
                Rule::NetworkDomain("a.com".into()),
                Rule::NetworkDomain("b.com".into())
            ]
        );
        assert!(parse_dnsmasq_line("address=/#/0.0.0.0").is_err());
        let long_label = "a".repeat(64);
        assert!(parse_dnsmasq_line(&format!("server=/{long_label}.com/")).is_err());
    }

    #[test]
    fn detect_dnsmasq_local_format() {
        assert_eq!(detect_format("local=/example.com/"), ListFormat::Dnsmasq);
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
