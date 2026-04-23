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
