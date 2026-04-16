use bitflags::bitflags;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct StatBlockReason: u16 {
        const STATIC_BLACKLIST  = 1 << 0;
        const ABP_RULE          = 1 << 1;
        const HIGH_ENTROPY      = 1 << 2;
        const LEXICAL_ANALYSIS  = 1 << 3;
        const BANNED_KEYWORD    = 1 << 4;
        const INVALID_STRUCTURE = 1 << 5;
        const SUSPICIOUS_IDN    = 1 << 6;
        const NRD_LIST          = 1 << 7;
        const TLD_EXCLUDED      = 1 << 8;
        const SUSPICIOUS        = 1 << 9;
        const CNAME_CLOAKING    = 1 << 10;
        const FORBIDDEN_QTYPE   = 1 << 11;
        const DNS_REBINDING     = 1 << 12;
        const LOW_TTL           = 1 << 13;
        const ASN_BLOCKED       = 1 << 14;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatAction {
    Allowed,
    Proxied,
    Blocked(StatBlockReason),
    Suspicious(StatBlockReason),
    HighlySuspicious(StatBlockReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatEvent {
    pub timestamp: u64,
    pub domain_hash: u64,
    pub client_ip: [u8; 16],
    pub action: StatAction,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatMessage {
    DomainMapping { hash: u64, domain: String },
    Event(StatEvent),
}

impl StatMessage {
    /// Deserialize from the full frame bytes (including the 2-byte length prefix).
    /// Frame layout: [msg_len: u16 LE][msg_type: u8][payload...]
    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        // Need at least 3 bytes: 2 for length, 1 for type
        if bytes.len() < 3 {
            return None;
        }

        let msg_len = u16::from_le_bytes([bytes[0], bytes[1]]) as usize;
        let msg_type = bytes[2];

        // The payload starts at byte 3; total frame = 2 + msg_len bytes
        // msg_len covers type byte + payload
        if bytes.len() < 2 + msg_len {
            return None;
        }

        let payload = &bytes[3..2 + msg_len];

        match msg_type {
            // DomainMapping: [hash: u64 LE][domain_len: u16 LE][domain: UTF-8]
            0x00 => {
                if payload.len() < 10 {
                    return None;
                }
                let hash = u64::from_le_bytes(payload[0..8].try_into().ok()?);
                let domain_len = u16::from_le_bytes([payload[8], payload[9]]) as usize;
                if payload.len() < 10 + domain_len {
                    return None;
                }
                let domain = String::from_utf8(payload[10..10 + domain_len].to_vec()).ok()?;
                Some(StatMessage::DomainMapping { hash, domain })
            }
            // Event: [timestamp: u64 LE][domain_hash: u64 LE][client_ip: 16 bytes][action: u8][block_reason?: u16 LE]
            0x01 => {
                if payload.len() < 25 {
                    return None;
                }
                let timestamp = u64::from_le_bytes(payload[0..8].try_into().ok()?);
                let domain_hash = u64::from_le_bytes(payload[8..16].try_into().ok()?);
                let client_ip: [u8; 16] = payload[16..32].try_into().ok()?;
                let action_byte = payload[32];

                let action = match action_byte {
                    0 => StatAction::Allowed,
                    1 => StatAction::Proxied,
                    2 => {
                        if payload.len() < 35 {
                            return None;
                        }
                        let reason = u16::from_le_bytes([payload[33], payload[34]]);
                        StatAction::Blocked(StatBlockReason::from_bits_truncate(reason))
                    }
                    3 => {
                        if payload.len() < 35 {
                            return None;
                        }
                        let reason = u16::from_le_bytes([payload[33], payload[34]]);
                        StatAction::Suspicious(StatBlockReason::from_bits_truncate(reason))
                    }
                    4 => {
                        if payload.len() < 35 {
                            return None;
                        }
                        let reason = u16::from_le_bytes([payload[33], payload[34]]);
                        StatAction::HighlySuspicious(StatBlockReason::from_bits_truncate(reason))
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

    /// Serialize to the full frame bytes (including the 2-byte length prefix).
    #[allow(dead_code)]
    pub fn serialize(&self) -> Vec<u8> {
        match self {
            StatMessage::DomainMapping { hash, domain } => {
                let domain_bytes = domain.as_bytes();
                let domain_len = domain_bytes.len() as u16;
                // payload = hash(8) + domain_len(2) + domain(n)
                let payload_len = 8 + 2 + domain_bytes.len();
                // msg_len = type(1) + payload
                let msg_len = (1 + payload_len) as u16;

                let mut buf = Vec::with_capacity(2 + 1 + payload_len);
                buf.extend_from_slice(&msg_len.to_le_bytes());
                buf.push(0x00);
                buf.extend_from_slice(&hash.to_le_bytes());
                buf.extend_from_slice(&domain_len.to_le_bytes());
                buf.extend_from_slice(domain_bytes);
                buf
            }
            StatMessage::Event(event) => {
                let has_reason = matches!(
                    event.action,
                    StatAction::Blocked(_)
                        | StatAction::Suspicious(_)
                        | StatAction::HighlySuspicious(_)
                );
                // payload = timestamp(8) + domain_hash(8) + client_ip(16) + action(1) [+ reason(2)]
                let payload_len = 8 + 8 + 16 + 1 + if has_reason { 2 } else { 0 };
                let msg_len = (1 + payload_len) as u16;

                let mut buf = Vec::with_capacity(2 + 1 + payload_len);
                buf.extend_from_slice(&msg_len.to_le_bytes());
                buf.push(0x01);
                buf.extend_from_slice(&event.timestamp.to_le_bytes());
                buf.extend_from_slice(&event.domain_hash.to_le_bytes());
                buf.extend_from_slice(&event.client_ip);

                match &event.action {
                    StatAction::Allowed => buf.push(0),
                    StatAction::Proxied => buf.push(1),
                    StatAction::Blocked(r) => {
                        buf.push(2);
                        buf.extend_from_slice(&r.bits().to_le_bytes());
                    }
                    StatAction::Suspicious(r) => {
                        buf.push(3);
                        buf.extend_from_slice(&r.bits().to_le_bytes());
                    }
                    StatAction::HighlySuspicious(r) => {
                        buf.push(4);
                        buf.extend_from_slice(&r.bits().to_le_bytes());
                    }
                }

                buf
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(action: StatAction) -> StatEvent {
        StatEvent {
            timestamp: 1_700_000_000,
            domain_hash: 0xdeadbeef_cafebabe,
            client_ip: [192, 168, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            action,
        }
    }

    #[test]
    fn test_domain_mapping_roundtrip() {
        let msg = StatMessage::DomainMapping {
            hash: 0xabcdef1234567890,
            domain: "example.com".to_string(),
        };
        let bytes = msg.serialize();
        let decoded = StatMessage::deserialize(&bytes).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_event_allowed_roundtrip() {
        let msg = StatMessage::Event(make_event(StatAction::Allowed));
        let bytes = msg.serialize();
        let decoded = StatMessage::deserialize(&bytes).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_event_proxied_roundtrip() {
        let msg = StatMessage::Event(make_event(StatAction::Proxied));
        let bytes = msg.serialize();
        let decoded = StatMessage::deserialize(&bytes).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_event_blocked_roundtrip() {
        let reason = StatBlockReason::STATIC_BLACKLIST | StatBlockReason::ABP_RULE;
        let msg = StatMessage::Event(make_event(StatAction::Blocked(reason)));
        let bytes = msg.serialize();
        let decoded = StatMessage::deserialize(&bytes).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_event_suspicious_roundtrip() {
        let reason = StatBlockReason::HIGH_ENTROPY | StatBlockReason::NRD_LIST;
        let msg = StatMessage::Event(make_event(StatAction::Suspicious(reason)));
        let bytes = msg.serialize();
        let decoded = StatMessage::deserialize(&bytes).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_event_highly_suspicious_roundtrip() {
        let reason = StatBlockReason::CNAME_CLOAKING | StatBlockReason::DNS_REBINDING;
        let msg = StatMessage::Event(make_event(StatAction::HighlySuspicious(reason)));
        let bytes = msg.serialize();
        let decoded = StatMessage::deserialize(&bytes).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_combined_block_reasons_roundtrip() {
        let reason = StatBlockReason::STATIC_BLACKLIST
            | StatBlockReason::ABP_RULE
            | StatBlockReason::HIGH_ENTROPY
            | StatBlockReason::LEXICAL_ANALYSIS
            | StatBlockReason::BANNED_KEYWORD
            | StatBlockReason::INVALID_STRUCTURE
            | StatBlockReason::SUSPICIOUS_IDN
            | StatBlockReason::NRD_LIST
            | StatBlockReason::TLD_EXCLUDED
            | StatBlockReason::SUSPICIOUS
            | StatBlockReason::CNAME_CLOAKING
            | StatBlockReason::FORBIDDEN_QTYPE
            | StatBlockReason::DNS_REBINDING
            | StatBlockReason::LOW_TTL
            | StatBlockReason::ASN_BLOCKED;
        let msg = StatMessage::Event(make_event(StatAction::Blocked(reason)));
        let bytes = msg.serialize();
        let decoded = StatMessage::deserialize(&bytes).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_truncated_bytes_returns_none() {
        let msg = StatMessage::DomainMapping {
            hash: 0x1234,
            domain: "test.com".to_string(),
        };
        let bytes = msg.serialize();
        // truncate to only 2 bytes (not enough for type byte)
        assert!(StatMessage::deserialize(&bytes[..2]).is_none());
    }

    #[test]
    fn test_too_short_returns_none() {
        assert!(StatMessage::deserialize(&[]).is_none());
        assert!(StatMessage::deserialize(&[0x05]).is_none());
        assert!(StatMessage::deserialize(&[0x05, 0x00]).is_none());
    }

    #[test]
    fn test_invalid_action_byte_returns_none() {
        let event = make_event(StatAction::Allowed);
        let mut bytes = StatMessage::Event(event).serialize();
        // action byte is at offset 2(len) + 1(type) + 8(ts) + 8(hash) + 16(ip) = 35
        bytes[35] = 0xFF;
        assert!(StatMessage::deserialize(&bytes).is_none());
    }

    #[test]
    fn test_binary_layout_sizes() {
        // DomainMapping with 11-byte domain: 2(len) + 1(type) + 8(hash) + 2(domain_len) + 11 = 24
        let msg = StatMessage::DomainMapping {
            hash: 0,
            domain: "example.com".to_string(),
        };
        assert_eq!(msg.serialize().len(), 24);

        // Allowed event: 2(len) + 1(type) + 8(ts) + 8(hash) + 16(ip) + 1(action) = 36
        let msg = StatMessage::Event(make_event(StatAction::Allowed));
        assert_eq!(msg.serialize().len(), 36);

        // Blocked event: 36 + 2(reason) = 38
        let msg = StatMessage::Event(make_event(StatAction::Blocked(StatBlockReason::empty())));
        assert_eq!(msg.serialize().len(), 38);
    }
}
