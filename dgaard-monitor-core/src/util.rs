use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use crate::protocol::{StatAction, StatBlockReason, StatError, StatEvent};

// ── IP helpers ─────────────────────────────────────────────────────────────────

/// Decode dgaard's 16-byte client address.
///
/// dgaard sends IPv4 clients as IPv4-mapped IPv6 (`::ffff:a.b.c.d`), which
/// becomes `IpAddr::V4`; anything else stays `IpAddr::V6`.
pub fn client_ip_addr(ip: &[u8; 16]) -> IpAddr {
    Ipv6Addr::from(*ip).to_canonical()
}

/// Render dgaard's 16-byte client address for every output (JSON, SQLite,
/// forwarding, TUI, NATS): `a.b.c.d` for IPv4, compressed IPv6 otherwise.
pub fn format_client_ip(ip: &[u8; 16]) -> String {
    client_ip_addr(ip).to_string()
}

/// Parse an IP string into dgaard's 16-byte layout (inverse of
/// [`format_client_ip`]): IPv4 becomes IPv4-mapped IPv6.
pub fn parse_client_ip(s: &str) -> Option<[u8; 16]> {
    let addr: IpAddr = s.parse().ok()?;
    Some(match addr {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    })
}

/// Every name [`action_name`] can return, e.g. for validating a filter.
pub const ACTION_NAMES: [&str; 9] = [
    "Allowed",
    "Proxied",
    "Blocked",
    "Suspicious",
    "HighlySuspicious",
    "Override",
    "Cached",
    "UpstreamError",
    "DnssecBogus",
];

pub fn action_name(action: &StatAction) -> &'static str {
    match action {
        StatAction::Allowed => "Allowed",
        StatAction::Proxied => "Proxied",
        StatAction::Blocked(_) => "Blocked",
        StatAction::Suspicious(_) => "Suspicious",
        StatAction::HighlySuspicious(_) => "HighlySuspicious",
        StatAction::AllowedWithOverride => "Override",
        StatAction::Cached => "Cached",
        StatAction::Error(StatError::Upstream) => "UpstreamError",
        StatAction::Error(StatError::DnssecBogus) => "DnssecBogus",
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

/// Labels of the custom bits 16–31, from the engine's
/// `[[security.custom_flags]]` (`(bit, code)`). Set once at startup.
static CUSTOM_FLAG_LABELS: OnceLock<Vec<(u8, String)>> = OnceLock::new();

/// Register the custom bit labels used by every output. Returns `false` if
/// they were already set (they are process-wide and immutable).
pub fn set_custom_flag_labels(labels: Vec<(u8, String)>) -> bool {
    CUSTOM_FLAG_LABELS.set(labels).is_ok()
}

fn custom_flag_labels() -> &'static [(u8, String)] {
    CUSTOM_FLAG_LABELS.get().map_or(&[], Vec::as_slice)
}

/// Label of one custom bit (16–31): its configured code, or `CUSTOM_BIT_<n>`.
pub fn custom_bit_label(bit: u8) -> String {
    custom_label(bit, custom_flag_labels())
}

fn custom_label(bit: u8, defs: &[(u8, String)]) -> String {
    defs.iter()
        .find(|(b, _)| *b == bit)
        .map(|(_, code)| code.clone())
        .unwrap_or_else(|| format!("CUSTOM_BIT_{bit}"))
}

/// Labels of every bit set in `r`, custom bits resolved through the
/// registered labels (see [`set_custom_flag_labels`]).
pub fn reason_labels(r: StatBlockReason) -> Vec<String> {
    reason_labels_with_defs(r, custom_flag_labels())
}

/// Like `reason_labels` but resolves custom bits 16–31 using the supplied
/// registry. Each entry is `(bit_index, code_string)`. Bits not found in the
/// registry fall back to `"CUSTOM_BIT_<n>"`.
pub fn reason_labels_with_defs(r: StatBlockReason, defs: &[(u8, String)]) -> Vec<String> {
    let mut v = Vec::new();
    if r.contains(StatBlockReason::STATIC_BLACKLIST) {
        v.push("STATIC_BLACKLIST".to_string());
    }
    if r.contains(StatBlockReason::ABP_RULE) {
        v.push("ABP_RULE".to_string());
    }
    if r.contains(StatBlockReason::HIGH_ENTROPY) {
        v.push("HIGH_ENTROPY".to_string());
    }
    if r.contains(StatBlockReason::LEXICAL_ANALYSIS) {
        v.push("LEXICAL_ANALYSIS".to_string());
    }
    if r.contains(StatBlockReason::BANNED_KEYWORD) {
        v.push("BANNED_KEYWORD".to_string());
    }
    if r.contains(StatBlockReason::INVALID_STRUCTURE) {
        v.push("INVALID_STRUCTURE".to_string());
    }
    if r.contains(StatBlockReason::SUSPICIOUS_IDN) {
        v.push("SUSPICIOUS_IDN".to_string());
    }
    if r.contains(StatBlockReason::NRD_LIST) {
        v.push("NRD_LIST".to_string());
    }
    if r.contains(StatBlockReason::TLD_EXCLUDED) {
        v.push("TLD_EXCLUDED".to_string());
    }
    if r.contains(StatBlockReason::SUSPICIOUS) {
        v.push("SUSPICIOUS".to_string());
    }
    if r.contains(StatBlockReason::CNAME_CLOAKING) {
        v.push("CNAME_CLOAKING".to_string());
    }
    if r.contains(StatBlockReason::FORBIDDEN_QTYPE) {
        v.push("FORBIDDEN_QTYPE".to_string());
    }
    if r.contains(StatBlockReason::DNS_REBINDING) {
        v.push("DNS_REBINDING".to_string());
    }
    if r.contains(StatBlockReason::LOW_TTL) {
        v.push("LOW_TTL".to_string());
    }
    if r.contains(StatBlockReason::ASN_BLOCKED) {
        v.push("ASN_BLOCKED".to_string());
    }
    if r.contains(StatBlockReason::SUSPICIOUS_GEO_IP) {
        v.push("SUSPICIOUS_GEO_IP".to_string());
    }
    // Custom bits 16–31
    let bits = r.bits();
    for bit in 16u8..=31 {
        if bits & (1u32 << bit) != 0 {
            v.push(custom_label(bit, defs));
        }
    }
    v
}

/// Wire format shared by the REST API and WebSocket stream.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventRecord {
    pub timestamp: u64,
    /// Resolved domain name, or `null` when the hash is unknown.
    pub domain: Option<String>,
    /// Raw domain hash as a 16-digit hex string.
    pub domain_hash: String,
    pub client_ip: String,
    pub action: String,
    /// Raw block-reason bitmask; `null` for Allowed and Proxied events.
    pub flags: Option<u32>,
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
        client_ip: format_client_ip(&event.client_ip),
        action: action_name(&event.action).to_string(),
        flags: reason.map(|r| r.bits()),
        flags_labels: reason.map_or_else(Vec::new, reason_labels),
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::StatAction;

    /// IPv4 client as dgaard sends it: IPv4-mapped IPv6.
    fn ipv4(a: u8, b: u8, c: u8, d: u8) -> [u8; 16] {
        std::net::Ipv4Addr::new(a, b, c, d)
            .to_ipv6_mapped()
            .octets()
    }

    // ── format_client_ip ─────────────────────────────────────────────────────

    #[test]
    fn ipv4_mapped_displayed_as_dotted_decimal() {
        assert_eq!(format_client_ip(&ipv4(192, 168, 1, 10)), "192.168.1.10");
    }

    #[test]
    fn non_ipv4_displayed_as_compressed_ipv6() {
        let ip: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(format_client_ip(&ip), "2001:db8::1");
    }

    #[test]
    fn client_ip_addr_decodes_mapped_as_v4() {
        assert_eq!(
            client_ip_addr(&ipv4(10, 0, 0, 1)),
            "10.0.0.1".parse::<IpAddr>().unwrap()
        );
        let v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert_eq!(client_ip_addr(&v6.octets()), IpAddr::V6(v6));
    }

    #[test]
    fn ipv6_loopback_and_unspecified_are_not_ipv4() {
        assert_eq!(format_client_ip(&Ipv6Addr::LOCALHOST.octets()), "::1");
        assert_eq!(format_client_ip(&[0; 16]), "::");
    }

    // ── parse_client_ip ──────────────────────────────────────────────────────

    #[test]
    fn parse_ipv4_gives_mapped_layout() {
        assert_eq!(parse_client_ip("10.0.0.1").unwrap(), ipv4(10, 0, 0, 1));
    }

    #[test]
    fn parse_and_format_round_trip() {
        for text in ["10.0.0.1", "192.168.1.254", "2001:db8::1", "fe80::1"] {
            let bytes = parse_client_ip(text).unwrap();
            assert_eq!(format_client_ip(&bytes), text);
        }
    }

    #[test]
    fn parse_invalid_ip_returns_none() {
        assert!(parse_client_ip("not-an-ip").is_none());
        assert!(parse_client_ip("999.0.0.1").is_none());
    }

    // ── ACTION_NAMES ─────────────────────────────────────────────────────────

    #[test]
    fn action_names_cover_every_action() {
        let reason = StatBlockReason::empty();
        let actions = [
            StatAction::Allowed,
            StatAction::Proxied,
            StatAction::Blocked(reason),
            StatAction::Suspicious(reason),
            StatAction::HighlySuspicious(reason),
            StatAction::AllowedWithOverride,
            StatAction::Cached,
            StatAction::Error(StatError::Upstream),
            StatAction::Error(StatError::DnssecBogus),
        ];
        let names: Vec<&str> = actions.iter().map(action_name).collect();
        assert_eq!(names, ACTION_NAMES);
    }

    // ── reason_labels ─────────────────────────────────────────────────────────

    #[test]
    fn reason_labels_lists_set_bits() {
        let r = StatBlockReason::STATIC_BLACKLIST | StatBlockReason::HIGH_ENTROPY;
        let labels = reason_labels(r);
        assert!(labels.iter().any(|l| l.as_str() == "STATIC_BLACKLIST"));
        assert!(labels.iter().any(|l| l.as_str() == "HIGH_ENTROPY"));
        assert!(!labels.iter().any(|l| l.as_str() == "ABP_RULE"));
    }

    #[test]
    fn reason_labels_empty_for_empty_flags() {
        assert!(reason_labels(StatBlockReason::empty()).is_empty());
    }

    /// Every flag `StatBlockReason` defines has its own label, so outputs
    /// built on `reason_labels` lose nothing.
    #[test]
    fn every_defined_flag_has_its_label() {
        for (name, flag) in StatBlockReason::all().iter_names() {
            assert_eq!(reason_labels_with_defs(flag, &[]), [name], "{name}");
        }
    }

    #[test]
    fn custom_bits_use_the_supplied_codes() {
        let r = StatBlockReason::from_bits_retain((1 << 20) | (1 << 21))
            | StatBlockReason::HIGH_ENTROPY;
        let defs = [(20, "AI_GENERATED".to_string())];
        assert_eq!(
            reason_labels_with_defs(r, &defs),
            ["HIGH_ENTROPY", "AI_GENERATED", "CUSTOM_BIT_21"]
        );
    }

    /// Regression: `input.engine_config_path` was parsed but never used, so
    /// custom bits always rendered as `CUSTOM_BIT_<n>`. Bit 29 is used by no
    /// other test, the registry being process-wide.
    #[test]
    fn registered_labels_reach_reason_labels() {
        set_custom_flag_labels(vec![(29, "CORP_FEED".to_string())]);
        let r = StatBlockReason::from_bits_retain(1 << 29);
        assert_eq!(reason_labels(r), ["CORP_FEED"]);
        assert_eq!(custom_bit_label(29), "CORP_FEED");
        assert!(!set_custom_flag_labels(Vec::new()), "labels are set once");
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
