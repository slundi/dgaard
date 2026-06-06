mod action;
pub mod answer;
mod domain;

use std::net::{IpAddr, SocketAddr};

pub use action::*;
pub use answer::InspectedAnswer;
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
    DnsRebinding,

    /// Abnormally low DNS response TTL.
    /// Carries the observed TTL value (in seconds).
    LowTtl(u32),

    /// Upstream response resolves to an IP within a user-configured blocked ASN range.
    AsnBlocked,
}

/// Messages sent over the stats channel to the collector.
#[derive(Debug, Clone, PartialEq)]
pub enum StatMessage {
    /// Sent only once per domain per session to "seed" the collector's database.
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
                        buf.extend_from_slice(&reason.bits().to_le_bytes());
                    }
                    StatAction::Suspicious(reason) => {
                        buf.push(3);
                        buf.extend_from_slice(&reason.bits().to_le_bytes());
                    }
                    StatAction::HighlySuspicious(reason) => {
                        buf.push(4);
                        buf.extend_from_slice(&reason.bits().to_le_bytes());
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
    #[allow(dead_code)]
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
                        if payload.len() < 35 {
                            return None;
                        }
                        let bits = u16::from_le_bytes([payload[33], payload[34]]);
                        match StatBlockReason::from_bits(bits) {
                            Some(reason) => StatAction::Blocked(reason),
                            None => {
                                eprintln!("Unknown reason bits: 0x{:04x}", bits);
                                return None;
                            }
                        }
                    }
                    3 => {
                        if payload.len() < 35 {
                            return None;
                        }
                        let bits = u16::from_le_bytes([payload[33], payload[34]]);
                        match StatBlockReason::from_bits(bits) {
                            Some(reason) => StatAction::Suspicious(reason),
                            None => {
                                eprintln!("Unknown reason bits: 0x{:04x}", bits);
                                return None;
                            }
                        }
                    }
                    4 => {
                        if payload.len() < 35 {
                            return None;
                        }
                        let bits = u16::from_le_bytes([payload[33], payload[34]]);
                        match StatBlockReason::from_bits(bits) {
                            Some(reason) => StatAction::HighlySuspicious(reason),
                            None => {
                                eprintln!("Unknown reason bits: 0x{:04x}", bits);
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

#[derive(Debug, Clone, PartialEq)]
pub struct StatEvent {
    pub timestamp: u64,
    pub domain_hash: u64,
    pub client_ip: [u8; 16],
    pub action: StatAction,
}

impl StatEvent {
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
#[derive(Debug, Clone, Default)]
pub struct SuspicionScore {
    pub total: u8,
    pub reasons: Vec<BlockReason>,
}

/// Score points for various heuristic signals.
pub mod score_points {
    pub const ENTROPY_HIGH: u8 = 4;
    pub const CONSONANT_CLUSTER: u8 = 3;
    pub const DEEP_SUBDOMAIN: u8 = 3;
    pub const LONG_DOMAIN: u8 = 3;
    pub const SUSPICIOUS_TLD: u8 = 3;
    pub const LOW_TTL: u8 = 2;
    pub const IDN_HOMOGRAPH: u8 = 6;
    pub const TXT_RECORD_TOO_LONG: u8 = 3;
    pub const EXCESSIVE_ANSWERS: u8 = 2;
    pub const CNAME_CLOAKING: u8 = 10;
    pub const NRD: u8 = 5;
    pub const DNS_REBINDING: u8 = 10;
    pub const KEYWORD_SUSPICIOUS_TLD: u8 = 10;
    pub const ASN_BLOCKED: u8 = 10;
}

impl SuspicionScore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, points: u8, reason: BlockReason) {
        self.total = self.total.saturating_add(points);
        self.reasons.push(reason);
    }

    pub fn primary_reason(&self) -> Option<&BlockReason> {
        self.reasons.first()
    }
}
