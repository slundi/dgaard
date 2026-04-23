use crate::model::{DnsTarget, Rule};

/// Format a single rule for the given DNS target.
///
/// Returns `None` when the target cannot express the rule type — e.g. a regex
/// rule on a dnsmasq target, or a browser rule in network output.
pub fn format_rule(rule: &Rule, target: DnsTarget) -> Option<String> {
    match rule {
        Rule::NetworkDomain(domain) => Some(format_domain(domain, target)),
        Rule::NetworkWildcard(pattern) => format_wildcard(pattern, target),
        Rule::NetworkRegex(regex) => format_regex(regex, target),
        Rule::Whitelist(value) => format_whitelist(value, target),
        Rule::Browser(_) => None,
    }
}

fn format_domain(domain: &str, target: DnsTarget) -> String {
    match target {
        DnsTarget::Plain | DnsTarget::PiHole => domain.to_string(),
        DnsTarget::Hosts => format!("0.0.0.0 {domain}"),
        DnsTarget::Dnsmasq => format!("address=/{domain}/#"),
        DnsTarget::Unbound => format!("local-zone: \"{domain}.\" always_nxdomain"),
        DnsTarget::AdGuard => format!("||{domain}^"),
    }
}

/// Wildcards like `*.example.com` — strip the leading `*.` to get the base domain,
/// then render in the target-specific syntax that blocks all subdomains.
fn format_wildcard(pattern: &str, target: DnsTarget) -> Option<String> {
    let base = pattern.strip_prefix("*.").unwrap_or(pattern);

    match target {
        // Plain / Pi-hole / Hosts cannot express a wildcard; emit the base domain as a best-effort.
        DnsTarget::Plain | DnsTarget::PiHole => Some(base.to_string()),
        DnsTarget::Hosts => Some(format!("0.0.0.0 {base}")),
        // dnsmasq: leading dot means "match all subdomains"
        DnsTarget::Dnsmasq => Some(format!("address=/.{base}/#")),
        // Unbound: local-zone covers all names within the zone including subdomains
        DnsTarget::Unbound => Some(format!("local-zone: \"{base}.\" always_nxdomain")),
        // AdGuard `||` anchor already matches the domain and all its subdomains
        DnsTarget::AdGuard => Some(format!("||{base}^")),
    }
}

/// Regex rules are only expressible in AdGuard syntax.
fn format_regex(regex: &str, target: DnsTarget) -> Option<String> {
    match target {
        DnsTarget::AdGuard => Some(format!("/{regex}/")),
        _ => None,
    }
}

/// Whitelist (exception) rules are only expressible in AdGuard syntax.
fn format_whitelist(value: &str, target: DnsTarget) -> Option<String> {
    match target {
        DnsTarget::AdGuard => Some(format!("@@||{value}^")),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{DnsTarget, Rule};

    // --- NetworkDomain ---

    #[test]
    fn domain_plain() {
        assert_eq!(
            format_rule(&Rule::NetworkDomain("example.com".into()), DnsTarget::Plain),
            Some("example.com".into())
        );
    }

    #[test]
    fn domain_pihole() {
        assert_eq!(
            format_rule(
                &Rule::NetworkDomain("ads.example.com".into()),
                DnsTarget::PiHole
            ),
            Some("ads.example.com".into())
        );
    }

    #[test]
    fn domain_hosts() {
        assert_eq!(
            format_rule(&Rule::NetworkDomain("example.com".into()), DnsTarget::Hosts),
            Some("0.0.0.0 example.com".into())
        );
    }

    #[test]
    fn domain_dnsmasq() {
        assert_eq!(
            format_rule(
                &Rule::NetworkDomain("example.com".into()),
                DnsTarget::Dnsmasq
            ),
            Some("address=/example.com/#".into())
        );
    }

    #[test]
    fn domain_unbound() {
        assert_eq!(
            format_rule(
                &Rule::NetworkDomain("example.com".into()),
                DnsTarget::Unbound
            ),
            Some("local-zone: \"example.com.\" always_nxdomain".into())
        );
    }

    #[test]
    fn domain_adguard() {
        assert_eq!(
            format_rule(
                &Rule::NetworkDomain("example.com".into()),
                DnsTarget::AdGuard
            ),
            Some("||example.com^".into())
        );
    }

    // --- NetworkWildcard ---

    #[test]
    fn wildcard_dnsmasq_strips_prefix() {
        assert_eq!(
            format_rule(
                &Rule::NetworkWildcard("*.example.com".into()),
                DnsTarget::Dnsmasq
            ),
            Some("address=/.example.com/#".into())
        );
    }

    #[test]
    fn wildcard_unbound_strips_prefix() {
        assert_eq!(
            format_rule(
                &Rule::NetworkWildcard("*.example.com".into()),
                DnsTarget::Unbound
            ),
            Some("local-zone: \"example.com.\" always_nxdomain".into())
        );
    }

    #[test]
    fn wildcard_adguard_strips_prefix() {
        assert_eq!(
            format_rule(
                &Rule::NetworkWildcard("*.example.com".into()),
                DnsTarget::AdGuard
            ),
            Some("||example.com^".into())
        );
    }

    #[test]
    fn wildcard_plain_falls_back_to_base_domain() {
        assert_eq!(
            format_rule(
                &Rule::NetworkWildcard("*.example.com".into()),
                DnsTarget::Plain
            ),
            Some("example.com".into())
        );
    }

    #[test]
    fn wildcard_hosts_falls_back_to_base_domain() {
        assert_eq!(
            format_rule(
                &Rule::NetworkWildcard("*.example.com".into()),
                DnsTarget::Hosts
            ),
            Some("0.0.0.0 example.com".into())
        );
    }

    // --- NetworkRegex ---

    #[test]
    fn regex_adguard() {
        assert_eq!(
            format_rule(&Rule::NetworkRegex("^ads\\.".into()), DnsTarget::AdGuard),
            Some("/^ads\\./".into())
        );
    }

    #[test]
    fn regex_dnsmasq_is_none() {
        assert_eq!(
            format_rule(&Rule::NetworkRegex("^ads\\.".into()), DnsTarget::Dnsmasq),
            None
        );
    }

    #[test]
    fn regex_unbound_is_none() {
        assert_eq!(
            format_rule(&Rule::NetworkRegex("^ads\\.".into()), DnsTarget::Unbound),
            None
        );
    }

    // --- Whitelist ---

    #[test]
    fn whitelist_adguard() {
        assert_eq!(
            format_rule(
                &Rule::Whitelist("safe.example.com".into()),
                DnsTarget::AdGuard
            ),
            Some("@@||safe.example.com^".into())
        );
    }

    #[test]
    fn whitelist_plain_is_none() {
        assert_eq!(
            format_rule(
                &Rule::Whitelist("safe.example.com".into()),
                DnsTarget::Plain
            ),
            None
        );
    }

    // --- Browser ---

    #[test]
    fn browser_rule_always_none() {
        for target in [
            DnsTarget::Plain,
            DnsTarget::Hosts,
            DnsTarget::Dnsmasq,
            DnsTarget::Unbound,
            DnsTarget::PiHole,
            DnsTarget::AdGuard,
        ] {
            assert_eq!(
                format_rule(&Rule::Browser("example.com##.ad".into()), target),
                None,
                "expected None for target {target}"
            );
        }
    }
}
