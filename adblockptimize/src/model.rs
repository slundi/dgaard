use std::{fmt, path::PathBuf, str::FromStr};

use url::Url;

/// A parsed filter rule, classified by its intended blocking layer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Rule {
    /// DNS-level block: a plain domain (e.g. `example.com`)
    NetworkDomain(String),
    /// DNS-level block: a wildcard pattern (e.g. `*.example.com`)
    NetworkWildcard(String),
    /// DNS-level block: a regex pattern (e.g. `^ads\.`)
    NetworkRegex(String),
    /// Exception/whitelist rule — overrides a block
    Whitelist(String),
    /// Browser-only rule: cosmetic CSS or scriptlet JS (not DNS-filterable)
    Browser(String),
}

impl Rule {
    pub fn is_network(&self) -> bool {
        matches!(
            self,
            Rule::NetworkDomain(_) | Rule::NetworkWildcard(_) | Rule::NetworkRegex(_)
        )
    }

    pub fn is_browser(&self) -> bool {
        matches!(self, Rule::Browser(_))
    }

    pub fn is_whitelist(&self) -> bool {
        matches!(self, Rule::Whitelist(_))
    }

    pub fn value(&self) -> &str {
        match self {
            Rule::NetworkDomain(s)
            | Rule::NetworkWildcard(s)
            | Rule::NetworkRegex(s)
            | Rule::Whitelist(s)
            | Rule::Browser(s) => s,
        }
    }
}

/// The DNS server target that determines the output format for network rules.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DnsTarget {
    /// Plain domain, one per line: `example.com`
    Plain,
    /// Hosts file format: `0.0.0.0 example.com`
    Hosts,
    /// dnsmasq `address` directive: `address=/example.com/#`
    Dnsmasq,
    /// Unbound `local-zone`: `local-zone: "example.com." always_nxdomain`
    Unbound,
    /// Pi-hole gravity list: plain domain (identical to `Plain`)
    PiHole,
    /// AdGuard Home / AdGuard DNS ABP-style: `||example.com^`
    AdGuard,
}

impl fmt::Display for DnsTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsTarget::Plain => write!(f, "plain"),
            DnsTarget::Hosts => write!(f, "hosts"),
            DnsTarget::Dnsmasq => write!(f, "dnsmasq"),
            DnsTarget::Unbound => write!(f, "unbound"),
            DnsTarget::PiHole => write!(f, "pihole"),
            DnsTarget::AdGuard => write!(f, "adguard"),
        }
    }
}

impl FromStr for DnsTarget {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "plain" => Ok(DnsTarget::Plain),
            "hosts" => Ok(DnsTarget::Hosts),
            "dnsmasq" => Ok(DnsTarget::Dnsmasq),
            "unbound" => Ok(DnsTarget::Unbound),
            "pihole" => Ok(DnsTarget::PiHole),
            "adguard" => Ok(DnsTarget::AdGuard),
            _ => Err(format!(
                "unknown target '{s}', expected: plain, hosts, dnsmasq, unbound, pihole, adguard"
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum ListFormat {
    Hosts,
    Dnsmasq,
    Plain,
    Abp,
    Unknown,
}

impl FromStr for ListFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "hosts" => Ok(ListFormat::Hosts),
            "dnsmasq" => Ok(ListFormat::Dnsmasq),
            "plain" => Ok(ListFormat::Plain),
            "abp" => Ok(ListFormat::Abp),
            _ => Err(format!(
                "unknown format '{s}', expected: hosts, dnsmasq, plain, abp"
            )),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum Resource {
    HttpUrl(Url),
    FilePath(PathBuf),
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Rule methods ──────────────────────────────────────────────────────────

    #[test]
    fn rule_is_network_for_network_variants() {
        assert!(Rule::NetworkDomain("example.com".into()).is_network());
        assert!(Rule::NetworkWildcard("*.example.com".into()).is_network());
        assert!(Rule::NetworkRegex("^ads".into()).is_network());
    }

    #[test]
    fn rule_is_network_false_for_other_variants() {
        assert!(!Rule::Whitelist("example.com".into()).is_network());
        assert!(!Rule::Browser("##.banner".into()).is_network());
    }

    #[test]
    fn rule_is_browser() {
        assert!(Rule::Browser("##.banner".into()).is_browser());
        assert!(!Rule::NetworkDomain("example.com".into()).is_browser());
    }

    #[test]
    fn rule_is_whitelist() {
        assert!(Rule::Whitelist("safe.com".into()).is_whitelist());
        assert!(!Rule::NetworkDomain("example.com".into()).is_whitelist());
    }

    #[test]
    fn rule_value_returns_inner_string() {
        assert_eq!(
            Rule::NetworkDomain("example.com".into()).value(),
            "example.com"
        );
        assert_eq!(
            Rule::NetworkWildcard("*.example.com".into()).value(),
            "*.example.com"
        );
        assert_eq!(Rule::NetworkRegex("^ads".into()).value(), "^ads");
        assert_eq!(Rule::Whitelist("safe.com".into()).value(), "safe.com");
        assert_eq!(Rule::Browser("##.banner".into()).value(), "##.banner");
    }

    // ── DnsTarget FromStr / Display ───────────────────────────────────────────

    #[test]
    fn dns_target_from_str_all_variants() {
        assert_eq!("plain".parse::<DnsTarget>().unwrap(), DnsTarget::Plain);
        assert_eq!("hosts".parse::<DnsTarget>().unwrap(), DnsTarget::Hosts);
        assert_eq!("dnsmasq".parse::<DnsTarget>().unwrap(), DnsTarget::Dnsmasq);
        assert_eq!("unbound".parse::<DnsTarget>().unwrap(), DnsTarget::Unbound);
        assert_eq!("pihole".parse::<DnsTarget>().unwrap(), DnsTarget::PiHole);
        assert_eq!("adguard".parse::<DnsTarget>().unwrap(), DnsTarget::AdGuard);
    }

    #[test]
    fn dns_target_from_str_case_insensitive() {
        assert_eq!("PLAIN".parse::<DnsTarget>().unwrap(), DnsTarget::Plain);
        assert_eq!("Hosts".parse::<DnsTarget>().unwrap(), DnsTarget::Hosts);
    }

    #[test]
    fn dns_target_from_str_unknown_returns_error() {
        assert!("unknown".parse::<DnsTarget>().is_err());
        assert!("".parse::<DnsTarget>().is_err());
    }

    #[test]
    fn dns_target_display_round_trips() {
        for (target, expected) in [
            (DnsTarget::Plain, "plain"),
            (DnsTarget::Hosts, "hosts"),
            (DnsTarget::Dnsmasq, "dnsmasq"),
            (DnsTarget::Unbound, "unbound"),
            (DnsTarget::PiHole, "pihole"),
            (DnsTarget::AdGuard, "adguard"),
        ] {
            assert_eq!(target.to_string(), expected);
            // Verify round-trip
            assert_eq!(expected.parse::<DnsTarget>().unwrap().to_string(), expected);
        }
    }

    // ── ListFormat FromStr ────────────────────────────────────────────────────

    #[test]
    fn list_format_from_str_all_variants() {
        assert_eq!("hosts".parse::<ListFormat>().unwrap(), ListFormat::Hosts);
        assert_eq!(
            "dnsmasq".parse::<ListFormat>().unwrap(),
            ListFormat::Dnsmasq
        );
        assert_eq!("plain".parse::<ListFormat>().unwrap(), ListFormat::Plain);
        assert_eq!("abp".parse::<ListFormat>().unwrap(), ListFormat::Abp);
    }

    #[test]
    fn list_format_from_str_unknown_returns_error() {
        assert!("csv".parse::<ListFormat>().is_err());
        assert!("".parse::<ListFormat>().is_err());
    }
}
