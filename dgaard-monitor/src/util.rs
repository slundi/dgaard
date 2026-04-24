use std::collections::HashMap;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::protocol::{StatAction, StatBlockReason, StatEvent};

// ── IP helpers ─────────────────────────────────────────────────────────────────

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

// ── Event serialisation ────────────────────────────────────────────────────────

pub fn flags_of(action: &StatAction) -> Option<StatBlockReason> {
    match action {
        StatAction::Blocked(r) | StatAction::Suspicious(r) | StatAction::HighlySuspicious(r) => {
            Some(*r)
        }
        _ => None,
    }
}

pub fn reason_labels(r: StatBlockReason) -> Vec<&'static str> {
    let mut v = Vec::new();
    if r.contains(StatBlockReason::STATIC_BLACKLIST) {
        v.push("STATIC_BLACKLIST");
    }
    if r.contains(StatBlockReason::ABP_RULE) {
        v.push("ABP_RULE");
    }
    if r.contains(StatBlockReason::HIGH_ENTROPY) {
        v.push("HIGH_ENTROPY");
    }
    if r.contains(StatBlockReason::LEXICAL_ANALYSIS) {
        v.push("LEXICAL_ANALYSIS");
    }
    if r.contains(StatBlockReason::BANNED_KEYWORD) {
        v.push("BANNED_KEYWORD");
    }
    if r.contains(StatBlockReason::INVALID_STRUCTURE) {
        v.push("INVALID_STRUCTURE");
    }
    if r.contains(StatBlockReason::SUSPICIOUS_IDN) {
        v.push("SUSPICIOUS_IDN");
    }
    if r.contains(StatBlockReason::NRD_LIST) {
        v.push("NRD_LIST");
    }
    if r.contains(StatBlockReason::TLD_EXCLUDED) {
        v.push("TLD_EXCLUDED");
    }
    if r.contains(StatBlockReason::SUSPICIOUS) {
        v.push("SUSPICIOUS");
    }
    if r.contains(StatBlockReason::CNAME_CLOAKING) {
        v.push("CNAME_CLOAKING");
    }
    if r.contains(StatBlockReason::FORBIDDEN_QTYPE) {
        v.push("FORBIDDEN_QTYPE");
    }
    if r.contains(StatBlockReason::DNS_REBINDING) {
        v.push("DNS_REBINDING");
    }
    if r.contains(StatBlockReason::LOW_TTL) {
        v.push("LOW_TTL");
    }
    if r.contains(StatBlockReason::ASN_BLOCKED) {
        v.push("ASN_BLOCKED");
    }
    v
}

/// Wire format shared by the REST API and WebSocket stream.
#[derive(Serialize, Deserialize)]
pub struct EventRecord {
    pub timestamp: u64,
    /// Resolved domain name, or `null` when the hash is unknown.
    pub domain: Option<String>,
    /// Raw domain hash as a 16-digit hex string.
    pub domain_hash: String,
    pub client_ip: String,
    pub action: String,
    /// Raw block-reason bitmask; `null` for Allowed and Proxied events.
    pub flags: Option<u16>,
    /// Human-readable labels for each set bit in `flags`.
    pub flags_labels: Vec<String>,
}

/// Build an [`EventRecord`] from a raw event and the current domain map snapshot.
pub fn event_to_record(event: &StatEvent, domain_map: &HashMap<u64, String>) -> EventRecord {
    let resolved = domain_map.get(&event.domain_hash).cloned();
    let reason = flags_of(&event.action);
    EventRecord {
        timestamp: event.timestamp,
        domain: resolved,
        domain_hash: format!("{:016x}", event.domain_hash),
        client_ip: ip_to_string(&event.client_ip),
        action: action_name(&event.action).to_string(),
        flags: reason.map(|r| r.bits()),
        flags_labels: reason
            .map_or_else(Vec::new, reason_labels)
            .into_iter()
            .map(str::to_string)
            .collect(),
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::StatAction;

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

    // ── reason_labels ─────────────────────────────────────────────────────────

    #[test]
    fn reason_labels_lists_set_bits() {
        let r = StatBlockReason::STATIC_BLACKLIST | StatBlockReason::HIGH_ENTROPY;
        let labels = reason_labels(r);
        assert!(labels.contains(&"STATIC_BLACKLIST"));
        assert!(labels.contains(&"HIGH_ENTROPY"));
        assert!(!labels.contains(&"ABP_RULE"));
    }

    #[test]
    fn reason_labels_empty_for_empty_flags() {
        assert!(reason_labels(StatBlockReason::empty()).is_empty());
    }

    // ── event_to_record ───────────────────────────────────────────────────────

    #[test]
    fn event_to_record_allowed() {
        let event = StatEvent {
            timestamp: 1000,
            domain_hash: 0xaabbcc,
            client_ip: ipv4(10, 0, 0, 1),
            action: StatAction::Allowed,
        };
        let mut map = HashMap::new();
        map.insert(0xaabbcc_u64, "example.com".to_string());

        let rec = event_to_record(&event, &map);
        assert_eq!(rec.timestamp, 1000);
        assert_eq!(rec.domain.as_deref(), Some("example.com"));
        assert_eq!(rec.client_ip, "10.0.0.1");
        assert_eq!(rec.action, "Allowed");
        assert!(rec.flags.is_none());
        assert!(rec.flags_labels.is_empty());
    }

    #[test]
    fn event_to_record_blocked_with_flags() {
        let event = StatEvent {
            timestamp: 2000,
            domain_hash: 0xdeadbeef,
            client_ip: ipv4(192, 168, 1, 1),
            action: StatAction::Blocked(StatBlockReason::NRD_LIST | StatBlockReason::HIGH_ENTROPY),
        };
        let rec = event_to_record(&event, &HashMap::new());
        assert_eq!(rec.action, "Blocked");
        assert!(rec.flags.is_some());
        assert!(rec.flags_labels.contains(&"NRD_LIST".to_string()));
        assert!(rec.flags_labels.contains(&"HIGH_ENTROPY".to_string()));
        assert!(rec.domain.is_none());
    }

    #[test]
    fn event_to_record_unknown_domain_is_null() {
        let event = StatEvent {
            timestamp: 0,
            domain_hash: 0xffffffff,
            client_ip: ipv4(1, 1, 1, 1),
            action: StatAction::Allowed,
        };
        let rec = event_to_record(&event, &HashMap::new());
        assert!(rec.domain.is_none());
        assert_eq!(rec.domain_hash, format!("{:016x}", 0xffffffff_u64));
    }
}
