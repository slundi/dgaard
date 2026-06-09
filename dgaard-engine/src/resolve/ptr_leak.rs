//! PTR leak prevention for private IP ranges (roadmap item 10.3).
//!
//! Reverse-DNS queries for RFC 1918 / loopback / link-local addresses must
//! never be forwarded to a public upstream resolver. Forwarding them exposes
//! the internal host layout of the network to third-party DNS infrastructure.
//!
//! Covered ranges (same as the DNS rebinding shield):
//! `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`,
//! `169.254.0.0/16`, `100.64.0.0/10`, `::1/128`, `fc00::/7`, `fe80::/10`.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::config::Config;
use crate::resolve::scoring::{is_private_ipv4, is_private_ipv6};

/// Return `true` if `domain` is a PTR query for a private or reserved IP that
/// must not be forwarded upstream.
///
/// Handles both IPv4 (`*.in-addr.arpa`) and full 32-nibble IPv6 (`*.ip6.arpa`)
/// reverse-DNS names. Partial PTR names (subnet delegation) are also handled
/// for IPv4 — the unspecified low-order octets are filled with zero.
pub fn is_ptr_leak_domain(domain: &str, config: &Config) -> bool {
    if !config.security.rebinding_shield.enabled || !config.security.rebinding_shield.block_ptr_leak
    {
        return false;
    }

    // Strip optional trailing dot.
    let domain = domain.strip_suffix('.').unwrap_or(domain);
    let lower = domain.to_ascii_lowercase();

    if let Some(ip) = decode_in_addr_arpa(&lower) {
        return is_private_ipv4(ip);
    }
    if let Some(ip) = decode_ip6_arpa(&lower) {
        return is_private_ipv6(ip);
    }

    false
}

/// Decode `<reversed-octets>.in-addr.arpa` into an `Ipv4Addr`.
///
/// Supports partial names (1–4 octets). Missing low-order octets default to 0,
/// so `"1.10.in-addr.arpa"` decodes as `10.1.0.0`.
fn decode_in_addr_arpa(domain: &str) -> Option<Ipv4Addr> {
    let labels = domain.strip_suffix(".in-addr.arpa")?;
    let parts: Vec<&str> = labels.split('.').collect();
    if parts.is_empty() || parts.len() > 4 {
        return None;
    }
    // Parts are in LSB→MSB order (e.g. "4.3.2.1" for 1.2.3.4). Validate and
    // parse each, then reverse to get the canonical dotted-quad order.
    let mut octets = [0u8; 4];
    for (i, p) in parts.iter().rev().enumerate() {
        octets[i] = p.parse::<u8>().ok()?;
    }
    Some(Ipv4Addr::from(octets))
}

/// Decode a full 32-nibble `<nibbles>.ip6.arpa` into an `Ipv6Addr`.
///
/// Only full 32-nibble names are handled (partial PTRs are not decoded).
fn decode_ip6_arpa(domain: &str) -> Option<Ipv6Addr> {
    let nibbles_str = domain.strip_suffix(".ip6.arpa")?;
    let nibbles: Vec<&str> = nibbles_str.split('.').collect();
    if nibbles.len() != 32 {
        return None;
    }
    // Each nibble must be a single hex digit.
    if !nibbles
        .iter()
        .all(|n| n.len() == 1 && n.chars().next().is_some_and(|c| c.is_ascii_hexdigit()))
    {
        return None;
    }
    // Reverse the nibbles (they are stored LSB-first) and reassemble 16 bytes.
    let hex: String = nibbles.iter().rev().flat_map(|n| n.chars()).collect();
    let mut bytes = [0u8; 16];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(Ipv6Addr::from(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn config_enabled() -> Config {
        Config::default()
    }

    fn config_ptr_disabled() -> Config {
        let mut c = Config::default();
        c.security.rebinding_shield.block_ptr_leak = false;
        c
    }

    fn config_shield_disabled() -> Config {
        let mut c = Config::default();
        c.security.rebinding_shield.enabled = false;
        c
    }

    // --- IPv4 private ranges ---

    #[test]
    fn blocks_rfc1918_10_0_0_0() {
        assert!(is_ptr_leak_domain(
            "1.0.0.10.in-addr.arpa",
            &config_enabled()
        ));
    }

    #[test]
    fn blocks_rfc1918_172_16_0_0() {
        assert!(is_ptr_leak_domain(
            "1.0.16.172.in-addr.arpa",
            &config_enabled()
        ));
        assert!(is_ptr_leak_domain(
            "1.0.31.172.in-addr.arpa",
            &config_enabled()
        ));
    }

    #[test]
    fn blocks_rfc1918_192_168_0_0() {
        assert!(is_ptr_leak_domain(
            "100.1.168.192.in-addr.arpa",
            &config_enabled()
        ));
    }

    #[test]
    fn blocks_loopback_127() {
        assert!(is_ptr_leak_domain(
            "1.0.0.127.in-addr.arpa",
            &config_enabled()
        ));
    }

    #[test]
    fn blocks_link_local_169_254() {
        assert!(is_ptr_leak_domain(
            "1.1.254.169.in-addr.arpa",
            &config_enabled()
        ));
    }

    #[test]
    fn blocks_cgnat_100_64() {
        assert!(is_ptr_leak_domain(
            "1.1.64.100.in-addr.arpa",
            &config_enabled()
        ));
    }

    // --- IPv4 public ranges must not be blocked ---

    #[test]
    fn does_not_block_public_ipv4() {
        let c = config_enabled();
        assert!(!is_ptr_leak_domain("1.1.1.1.in-addr.arpa", &c));
        assert!(!is_ptr_leak_domain("8.8.8.8.in-addr.arpa", &c));
        assert!(!is_ptr_leak_domain("4.4.8.8.in-addr.arpa", &c));
    }

    // --- Partial PTR (subnet delegation) ---

    #[test]
    fn blocks_partial_ptr_10_prefix() {
        // "10.in-addr.arpa" → 10.0.0.0 → private
        assert!(is_ptr_leak_domain("10.in-addr.arpa", &config_enabled()));
    }

    #[test]
    fn blocks_partial_ptr_192_168() {
        assert!(is_ptr_leak_domain(
            "168.192.in-addr.arpa",
            &config_enabled()
        ));
    }

    #[test]
    fn does_not_block_partial_ptr_public() {
        // "1.1.in-addr.arpa" → 1.1.0.0 → public
        assert!(!is_ptr_leak_domain("1.1.in-addr.arpa", &config_enabled()));
    }

    // --- IPv6 private ranges ---

    #[test]
    fn blocks_ipv6_loopback() {
        // ::1 → 0000...0001.ip6.arpa
        let ptr = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa";
        assert!(is_ptr_leak_domain(ptr, &config_enabled()));
    }

    #[test]
    fn blocks_ipv6_unique_local_fc() {
        // fc00::1
        let ptr = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.c.f.ip6.arpa";
        assert!(is_ptr_leak_domain(ptr, &config_enabled()));
    }

    #[test]
    fn blocks_ipv6_link_local_fe80() {
        // fe80::1
        let ptr = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa";
        assert!(is_ptr_leak_domain(ptr, &config_enabled()));
    }

    #[test]
    fn does_not_block_public_ipv6() {
        // 2001:db8::1 (documentation range — not private per is_private_ipv6)
        let ptr = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa";
        assert!(!is_ptr_leak_domain(ptr, &config_enabled()));
    }

    // --- Trailing dot ---

    #[test]
    fn strips_trailing_dot() {
        assert!(is_ptr_leak_domain(
            "1.0.0.10.in-addr.arpa.",
            &config_enabled()
        ));
    }

    // --- Case insensitivity ---

    #[test]
    fn case_insensitive() {
        assert!(is_ptr_leak_domain(
            "1.0.0.10.IN-ADDR.ARPA",
            &config_enabled()
        ));
    }

    // --- Disabled config ---

    #[test]
    fn does_nothing_when_ptr_disabled() {
        assert!(!is_ptr_leak_domain(
            "1.0.0.10.in-addr.arpa",
            &config_ptr_disabled()
        ));
    }

    #[test]
    fn does_nothing_when_shield_disabled() {
        assert!(!is_ptr_leak_domain(
            "1.0.0.10.in-addr.arpa",
            &config_shield_disabled()
        ));
    }

    // --- Non-PTR domains must not be blocked ---

    #[test]
    fn does_not_block_regular_domains() {
        let c = config_enabled();
        assert!(!is_ptr_leak_domain("example.com", &c));
        assert!(!is_ptr_leak_domain("google.com", &c));
        assert!(!is_ptr_leak_domain("arpa", &c));
        assert!(!is_ptr_leak_domain("in-addr.arpa", &c));
    }

    // --- Malformed PTR labels ---

    #[test]
    fn ignores_non_numeric_in_addr_arpa() {
        // "abc.in-addr.arpa" can't be decoded as an IP
        assert!(!is_ptr_leak_domain("abc.in-addr.arpa", &config_enabled()));
    }

    #[test]
    fn ignores_too_many_labels_in_addr_arpa() {
        // 5 labels is invalid
        assert!(!is_ptr_leak_domain(
            "1.2.3.4.5.in-addr.arpa",
            &config_enabled()
        ));
    }

    #[test]
    fn ignores_partial_ipv6_ptr() {
        // Less than 32 nibbles — not decoded
        let ptr = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa";
        assert!(!is_ptr_leak_domain(ptr, &config_enabled()));
    }

    // --- decode_in_addr_arpa unit tests ---

    #[test]
    fn decode_ipv4_full() {
        assert_eq!(
            decode_in_addr_arpa("4.3.2.1.in-addr.arpa"),
            Some(Ipv4Addr::new(1, 2, 3, 4))
        );
    }

    #[test]
    fn decode_ipv4_partial_two_octets() {
        assert_eq!(
            decode_in_addr_arpa("168.192.in-addr.arpa"),
            Some(Ipv4Addr::new(192, 168, 0, 0))
        );
    }

    #[test]
    fn decode_ipv4_single_octet() {
        assert_eq!(
            decode_in_addr_arpa("10.in-addr.arpa"),
            Some(Ipv4Addr::new(10, 0, 0, 0))
        );
    }

    // --- decode_ip6_arpa unit tests ---

    #[test]
    fn decode_ipv6_loopback() {
        let ptr = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa";
        assert_eq!(
            decode_ip6_arpa(ptr),
            Some(Ipv6Addr::from([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
            ]))
        );
    }
}
