mod action;
mod domain;

use std::net::{IpAddr, SocketAddr};

pub use action::*;
pub use domain::*;

// stats

#[derive(Debug, Clone)]
pub enum BlockReason {
    /// Hit a static blacklist (e.g., OISD, StevenBlack).
    StaticBlacklist(String), // String is the name of the source file

    /// Blocked by an ABP-style pattern or wildcard.
    AbpRule(String),

    /// High Shannon Entropy detected (DGA). Carries the calculated score.
    HighEntropy(f32),

    /// Failed lexical analysis (Consonant ratio or N-Gram probability).
    LexicalAnalysis,

    /// Blocked by parental control keyword filter. Carries the matched keyword.
    BannedKeyword(String),

    /// Failed structural checks (Subdomain depth, TXT length, etc.).
    InvalidStructure,

    /// Suspicious IDN/Punycode homograph attack.
    SuspiciousIdn,

    /// Domain is on a known "Newly Registered Domain" list.
    NrdList,

    /// Suspicious
    Suspicious,

    /// TLD is explicitly excluded in config.
    TldExcluded,

    /// CNAME chain contains a known-blacklisted domain (cloaking attack).
    CnameCloaking,

    /// Query type is explicitly forbidden by the QType Warden policy.
    /// Carries the raw RFC 1035 type code (e.g. 10=NULL, 13=HINFO, 255=ANY).
    ForbiddenQType(u16),

    /// DNS rebinding — upstream response maps a public domain to a private/reserved IP.
    /// Highest-priority signal: an attacker's domain resolving to a LAN address
    /// can bypass same-origin policy and reach internal services from a browser tab.
    DnsRebinding,

    /// Abnormally low DNS response TTL — characteristic of fast-flux malware
    /// infrastructure where IPs rotate rapidly to evade blocklists.
    /// Carries the observed TTL value (in seconds).
    LowTtl(u32),

    /// Upstream response resolves to an IP within a user-configured blocked
    /// ASN (Autonomous System) range — typically a known crypto mining pool,
    /// bulletproof hosting provider, or malware C2 network.
    AsnBlocked,
}

/// Messages sent over the stats channel to the collector.
///
/// The protocol uses two message types:
/// - `DomainMapping`: Sent once per unique domain to establish hash-to-domain mapping
/// - `Event`: Sent for every DNS query with minimal data (uses hash references)
///
/// ## Binary Wire Format (Little Endian)
///
/// Each message is length-prefixed for framing over the Unix socket:
/// ```text
/// [msg_len: u16][message_type: u8][payload...]
/// ```
///
/// ### DomainMapping (type = 0x00)
/// ```text
/// [hash: u64][domain_len: u16][domain: UTF-8 bytes]
/// ```
///
/// ### Event (type = 0x01)
/// ```text
/// [timestamp: u64][domain_hash: u64][client_ip: 16 bytes][action: u8][block_reason?: u8]
/// ```
#[derive(Debug, Clone, PartialEq)]
pub enum StatMessage {
    /// Sent only once per domain per session to "seed" the collector's database.
    /// This allows the Event messages to use compact hashes instead of full strings.
    DomainMapping {
        /// xxh3_64 hash of the domain name
        hash: u64,
        /// The full domain name (e.g., "example.com")
        domain: String,
    },
    /// Sent for every DNS query/block event.
    Event(StatEvent),
}

// Message type discriminants
const MSG_TYPE_DOMAIN_MAPPING: u8 = 0x00;
const MSG_TYPE_EVENT: u8 = 0x01;

impl StatMessage {
    /// Serialize to binary format for Unix socket transmission.
    /// Format: [msg_len: u16][type: u8][payload...]
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);

        // Reserve space for length prefix (filled in at the end)
        buf.extend_from_slice(&[0u8; 2]);

        match self {
            StatMessage::DomainMapping { hash, domain } => {
                buf.push(MSG_TYPE_DOMAIN_MAPPING);
                buf.extend_from_slice(&hash.to_le_bytes());
                let domain_bytes = domain.as_bytes();
                buf.extend_from_slice(&(domain_bytes.len() as u16).to_le_bytes());
                buf.extend_from_slice(domain_bytes);
            }
            StatMessage::Event(event) => {
                buf.push(MSG_TYPE_EVENT);
                buf.extend_from_slice(&event.timestamp.to_le_bytes());
                buf.extend_from_slice(&event.domain_hash.to_le_bytes());
                buf.extend_from_slice(&event.client_ip);
                match event.action {
                    StatAction::Allowed => buf.push(0),
                    StatAction::Proxied => buf.push(1),
                    StatAction::Blocked(reason) => {
                        buf.push(2);
                        buf.push(reason as u8);
                    }
                }
            }
        }

        // Fill in length prefix (excluding the 2-byte prefix itself)
        let len = (buf.len() - 2) as u16;
        buf[0..2].copy_from_slice(&len.to_le_bytes());

        buf
    }

    /// Deserialize from binary format.
    /// Expects: [msg_len: u16][type: u8][payload...]
    #[allow(dead_code)] // For stats client/dashboard integration
    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 3 {
            return None;
        }

        let msg_len = u16::from_le_bytes([bytes[0], bytes[1]]) as usize;
        if bytes.len() < 2 + msg_len {
            return None;
        }

        let msg_type = bytes[2];
        let payload = &bytes[3..2 + msg_len];

        match msg_type {
            MSG_TYPE_DOMAIN_MAPPING => {
                if payload.len() < 10 {
                    return None;
                }
                let hash = u64::from_le_bytes(payload[0..8].try_into().ok()?);
                let domain_len = u16::from_le_bytes(payload[8..10].try_into().ok()?) as usize;
                if payload.len() < 10 + domain_len {
                    return None;
                }
                let domain = String::from_utf8(payload[10..10 + domain_len].to_vec()).ok()?;
                Some(StatMessage::DomainMapping { hash, domain })
            }
            MSG_TYPE_EVENT => {
                // timestamp(8) + domain_hash(8) + client_ip(16) + action(1) = 33 min
                if payload.len() < 33 {
                    return None;
                }
                let timestamp = u64::from_le_bytes(payload[0..8].try_into().ok()?);
                let domain_hash = u64::from_le_bytes(payload[8..16].try_into().ok()?);
                let client_ip: [u8; 16] = payload[16..32].try_into().ok()?;
                let action = match payload[32] {
                    0 => StatAction::Allowed,
                    1 => StatAction::Proxied,
                    2 => {
                        if payload.len() < 34 {
                            return None;
                        }
                        match StatBlockReason::try_from(payload[33]) {
                            Ok(reason) => StatAction::Blocked(reason),
                            Err(e) => {
                                eprintln!("Unknown reason: {:?}", e);
                                return None;
                            }
                        }
                    }
                    _ => return None,
                };

                Some(StatMessage::Event(StatEvent {
                    timestamp,
                    domain_hash,
                    client_ip,
                    action,
                }))
            }
            _ => None,
        }
    }
}

/// A single DNS query event with all relevant telemetry data.
///
/// Designed to be compact for high-throughput scenarios:
/// - Uses u64 hashes instead of strings where possible
/// - Client IP stored as 16 bytes (IPv4 mapped to IPv6 format)
/// - Timestamp as Unix epoch seconds (u64)
#[derive(Debug, Clone, PartialEq)]
pub struct StatEvent {
    /// Unix timestamp (seconds since epoch)
    pub timestamp: u64,
    /// xxh3_64 hash of the queried domain
    pub domain_hash: u64,
    /// Client IP address in IPv6 format (IPv4 mapped as ::ffff:x.x.x.x)
    pub client_ip: [u8; 16],
    /// The action taken for this query
    pub action: StatAction,
}

impl StatEvent {
    /// Create a new StatEvent with the current timestamp.
    pub fn new(domain_hash: u64, client_addr: SocketAddr, action: StatAction) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let client_ip = match client_addr.ip() {
            IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
            IpAddr::V6(v6) => v6.octets(),
        };

        Self {
            timestamp,
            domain_hash,
            client_ip,
            action,
        }
    }
}

/// Suspicion score for a domain.
///
/// Accumulates points from various heuristic checks. The score ranges from 0 to 255,
/// where higher scores indicate more suspicious domains.
///
/// Scoring thresholds (from roadmap):
/// - 0-3: Safe
/// - 4-6: Suspicious (logged)
/// - 7-9: Highly suspicious
/// - 10+: Malicious (blocking threshold)
#[derive(Debug, Clone, Default)]
pub struct SuspicionScore {
    /// Total accumulated score (0-255, saturating)
    pub total: u8,
    /// List of reasons contributing to the score
    pub reasons: Vec<BlockReason>,
}

/// Score points for various heuristic signals.
pub mod score_points {
    /// High Shannon entropy (>4.0) - indicates DGA
    pub const ENTROPY_HIGH: u8 = 4;
    /// Consonant clustering / unpronounceable pattern
    pub const CONSONANT_CLUSTER: u8 = 3;
    /// Deep subdomain structure (>=5 levels)
    pub const DEEP_SUBDOMAIN: u8 = 3;
    /// Very long domain string (>60 chars)
    pub const LONG_DOMAIN: u8 = 3;
    /// Suspicious TLD (.xyz, .top, .biz, etc.)
    pub const SUSPICIOUS_TLD: u8 = 3;
    /// Low TTL in DNS response
    pub const LOW_TTL: u8 = 2;
    /// IDN/Punycode homograph attack
    pub const IDN_HOMOGRAPH: u8 = 6;
    /// TXT record content exceeding `max_txt_record_length` (DNS tunneling indicator).
    pub const TXT_RECORD_TOO_LONG: u8 = 3;
    /// Answer section contains more records than `max_answers_per_query`.
    pub const EXCESSIVE_ANSWERS: u8 = 2;
    /// CNAME chain resolves to a known-blacklisted domain (cloaking attack).
    pub const CNAME_CLOAKING: u8 = 10;
    /// Newly Registered Domain (<24h)
    pub const NRD: u8 = 5;
    /// DNS rebinding attempt - immediate block
    pub const DNS_REBINDING: u8 = 10;
    /// Forbidden keyword + suspicious TLD combo - immediate block
    pub const KEYWORD_SUSPICIOUS_TLD: u8 = 10;
    /// IP resolved into a user-configured blocked ASN range — immediate block
    pub const ASN_BLOCKED: u8 = 10;
}

impl SuspicionScore {
    /// Create a new empty score.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add points for a specific reason.
    pub fn add(&mut self, points: u8, reason: BlockReason) {
        self.total = self.total.saturating_add(points);
        self.reasons.push(reason);
    }

    /// Add points without a specific reason (for sub-threshold signals).
    pub fn add_points(&mut self, points: u8) {
        self.total = self.total.saturating_add(points);
    }

    /// Check if the domain should be considered malicious (score >= 10).
    pub fn is_malicious(&self) -> bool {
        self.total >= 10
    }

    /// Check if the domain is suspicious (score >= 4).
    pub fn is_suspicious(&self) -> bool {
        self.total >= 4
    }

    /// Check if the domain is highly suspicious (score >= 7).
    pub fn is_highly_suspicious(&self) -> bool {
        self.total >= 7
    }

    /// Get the primary block reason (the one with highest individual score contribution).
    pub fn primary_reason(&self) -> Option<&BlockReason> {
        self.reasons.first()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // SuspicionScore tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_suspicion_score_new() {
        let score = SuspicionScore::new();
        assert_eq!(score.total, 0);
        assert!(score.reasons.is_empty());
        assert!(!score.is_suspicious());
        assert!(!score.is_highly_suspicious());
        assert!(!score.is_malicious());
    }

    #[test]
    fn test_suspicion_score_add() {
        let mut score = SuspicionScore::new();
        score.add(4, BlockReason::HighEntropy(4.5));
        assert_eq!(score.total, 4);
        assert_eq!(score.reasons.len(), 1);
        assert!(score.is_suspicious());
        assert!(!score.is_malicious());
    }

    #[test]
    fn test_suspicion_score_add_points() {
        let mut score = SuspicionScore::new();
        score.add_points(3);
        assert_eq!(score.total, 3);
        assert!(score.reasons.is_empty());
    }

    #[test]
    fn test_suspicion_score_thresholds() {
        let mut score = SuspicionScore::new();

        // 0-3: Safe
        score.add_points(3);
        assert!(!score.is_suspicious());
        assert!(!score.is_highly_suspicious());
        assert!(!score.is_malicious());

        // 4-6: Suspicious
        score.add_points(1);
        assert!(score.is_suspicious());
        assert!(!score.is_highly_suspicious());
        assert!(!score.is_malicious());

        // 7-9: Highly suspicious
        score.add_points(3);
        assert!(score.is_suspicious());
        assert!(score.is_highly_suspicious());
        assert!(!score.is_malicious());

        // 10+: Malicious
        score.add_points(3);
        assert!(score.is_suspicious());
        assert!(score.is_highly_suspicious());
        assert!(score.is_malicious());
    }

    #[test]
    fn test_suspicion_score_saturating() {
        let mut score = SuspicionScore::new();
        score.add_points(200);
        score.add_points(100); // Would overflow without saturation
        assert_eq!(score.total, 255);
    }

    #[test]
    fn test_suspicion_score_primary_reason() {
        let mut score = SuspicionScore::new();
        assert!(score.primary_reason().is_none());

        score.add(4, BlockReason::HighEntropy(4.5));
        score.add(3, BlockReason::InvalidStructure);

        // Primary reason is the first one added
        assert!(matches!(
            score.primary_reason(),
            Some(BlockReason::HighEntropy(_))
        ));
    }

    // -----------------------------------------------------------------------
    // StatMessage serialization tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_domain_mapping_roundtrip() {
        let msg = StatMessage::DomainMapping {
            hash: 0x123456789ABCDEF0,
            domain: "example.com".to_string(),
        };

        let bytes = msg.serialize();
        let decoded = StatMessage::deserialize(&bytes).expect("deserialize failed");

        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_event_allowed_roundtrip() {
        let event = StatEvent {
            timestamp: 1704067200,
            domain_hash: 0xDEADBEEF,
            client_ip: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 192, 168, 1, 100],
            action: StatAction::Allowed,
        };
        let msg = StatMessage::Event(event);

        let bytes = msg.serialize();
        let decoded = StatMessage::deserialize(&bytes).expect("deserialize failed");

        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_event_proxied_roundtrip() {
        let event = StatEvent {
            timestamp: 1704067200,
            domain_hash: 0xCAFEBABE,
            client_ip: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 10, 0, 0, 1],
            action: StatAction::Proxied,
        };
        let msg = StatMessage::Event(event);

        let bytes = msg.serialize();
        let decoded = StatMessage::deserialize(&bytes).expect("deserialize failed");

        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_event_blocked_all_reasons() {
        let reasons = [
            StatBlockReason::StaticBlacklist,
            StatBlockReason::AbpRule,
            StatBlockReason::HighEntropy,
            StatBlockReason::LexicalAnalysis,
            StatBlockReason::InvalidStructure,
            StatBlockReason::SuspiciousIdn,
            StatBlockReason::NrdList,
            StatBlockReason::TldExcluded,
            StatBlockReason::CnameCloaking,
            StatBlockReason::ForbiddenQType,
            StatBlockReason::DnsRebinding,
            StatBlockReason::LowTtl,
            StatBlockReason::AsnBlocked,
        ];

        for reason in reasons {
            let event = StatEvent {
                timestamp: 1704067200,
                domain_hash: 0x1234,
                client_ip: [0u8; 16],
                action: StatAction::Blocked(reason),
            };
            let msg = StatMessage::Event(event);

            let bytes = msg.serialize();
            let decoded = StatMessage::deserialize(&bytes).expect("deserialize failed");

            assert_eq!(msg, decoded, "Failed for reason {:?}", reason);
        }
    }

    #[test]
    fn test_stat_event_new_ipv4() {
        let addr: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        let event = StatEvent::new(0x1234, addr, StatAction::Allowed);

        // IPv4 mapped to IPv6: ::ffff:192.168.1.100
        assert_eq!(
            &event.client_ip[0..12],
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF]
        );
        assert_eq!(&event.client_ip[12..16], &[192, 168, 1, 100]);
    }

    #[test]
    fn test_stat_event_new_ipv6() {
        let addr: SocketAddr = "[::1]:12345".parse().unwrap();
        let event = StatEvent::new(0x1234, addr, StatAction::Proxied);

        // Loopback IPv6
        let expected = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(event.client_ip, expected);
    }

    #[test]
    fn test_deserialize_truncated_fails() {
        let msg = StatMessage::DomainMapping {
            hash: 0x1234,
            domain: "test.com".to_string(),
        };
        let bytes = msg.serialize();

        // Truncate the message
        assert!(StatMessage::deserialize(&bytes[..5]).is_none());
        assert!(StatMessage::deserialize(&bytes[..2]).is_none());
        assert!(StatMessage::deserialize(&[]).is_none());
    }

    #[test]
    fn test_deserialize_invalid_action_fails() {
        // Manually craft an event with invalid action byte
        let mut bytes = vec![
            35, 0,    // length prefix (35 bytes)
            0x01, // MSG_TYPE_EVENT
        ];
        bytes.extend_from_slice(&0u64.to_le_bytes()); // timestamp
        bytes.extend_from_slice(&0u64.to_le_bytes()); // domain_hash
        bytes.extend_from_slice(&[0u8; 16]); // client_ip
        bytes.push(99); // invalid action byte

        assert!(StatMessage::deserialize(&bytes).is_none());
    }

    #[test]
    fn test_domain_mapping_binary_format() {
        let msg = StatMessage::DomainMapping {
            hash: 0x0102030405060708,
            domain: "a.b".to_string(),
        };
        let bytes = msg.serialize();

        // [len:2][type:1][hash:8][domain_len:2][domain:3] = 16 bytes total
        assert_eq!(bytes.len(), 16);

        // Length prefix = 14 (total - 2)
        assert_eq!(u16::from_le_bytes([bytes[0], bytes[1]]), 14);

        // Message type = 0 (DomainMapping)
        assert_eq!(bytes[2], 0x00);

        // Hash in LE
        assert_eq!(
            u64::from_le_bytes(bytes[3..11].try_into().unwrap()),
            0x0102030405060708
        );

        // Domain length = 3
        assert_eq!(u16::from_le_bytes([bytes[11], bytes[12]]), 3);

        // Domain bytes
        assert_eq!(&bytes[13..16], b"a.b");
    }

    #[test]
    fn test_event_binary_size() {
        let event = StatEvent {
            timestamp: 0,
            domain_hash: 0,
            client_ip: [0u8; 16],
            action: StatAction::Allowed,
        };
        let msg = StatMessage::Event(event);
        let bytes = msg.serialize();

        // [len:2][type:1][ts:8][hash:8][ip:16][action:1] = 36 bytes for Allowed
        assert_eq!(bytes.len(), 36);

        // For Blocked, add 1 byte for reason
        let event_blocked = StatEvent {
            timestamp: 0,
            domain_hash: 0,
            client_ip: [0u8; 16],
            action: StatAction::Blocked(StatBlockReason::HighEntropy),
        };
        let msg_blocked = StatMessage::Event(event_blocked);
        let bytes_blocked = msg_blocked.serialize();
        assert_eq!(bytes_blocked.len(), 37);
    }
}
