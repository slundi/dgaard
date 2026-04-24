use std::net::IpAddr;

use crate::protocol::StatAction;

/// Convert internal 16-byte IP to a display string.
///
/// The proxy stores IPv4 addresses in the first 4 bytes with the remaining 12
/// bytes zeroed, so we detect that pattern and format as dotted-decimal.
pub fn ip_to_string(ip: &[u8; 16]) -> String {
    if ip[4..].iter().all(|&b| b == 0) {
        format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
    } else {
        std::net::Ipv6Addr::from(*ip).to_string()
    }
}

/// Parse a user-supplied IP string into the internal 16-byte format.
pub fn parse_filter_ip(s: &str) -> Option<[u8; 16]> {
    let addr: IpAddr = s.parse().ok()?;
    Some(match addr {
        IpAddr::V4(v4) => {
            let [a, b, c, d] = v4.octets();
            [a, b, c, d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        }
        IpAddr::V6(v6) => v6.octets(),
    })
}

pub fn action_name(action: &StatAction) -> &'static str {
    match action {
        StatAction::Allowed => "Allowed",
        StatAction::Proxied => "Proxied",
        StatAction::Blocked(_) => "Blocked",
        StatAction::Suspicious(_) => "Suspicious",
        StatAction::HighlySuspicious(_) => "HighlySuspicious",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4(a: u8, b: u8, c: u8, d: u8) -> [u8; 16] {
        [a, b, c, d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    }

    // ── ip_to_string ─────────────────────────────────────────────────────────

    #[test]
    fn ipv4_displayed_as_dotted_decimal() {
        let ip = ipv4(192, 168, 1, 10);
        assert_eq!(ip_to_string(&ip), "192.168.1.10");
    }

    #[test]
    fn non_ipv4_displayed_as_ipv6() {
        let ip: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let s = ip_to_string(&ip);
        // Should parse back as a valid IPv6 address.
        assert!(s.parse::<std::net::Ipv6Addr>().is_ok(), "got: {s}");
    }

    // ── parse_filter_ip ───────────────────────────────────────────────────────

    #[test]
    fn parse_ipv4_roundtrip() {
        let parsed = parse_filter_ip("10.0.0.1").unwrap();
        assert_eq!(parsed, ipv4(10, 0, 0, 1));
    }

    #[test]
    fn parse_invalid_ip_returns_none() {
        assert!(parse_filter_ip("not-an-ip").is_none());
        assert!(parse_filter_ip("999.0.0.1").is_none());
    }
}
