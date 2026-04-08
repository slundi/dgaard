use std::net::{Ipv4Addr, Ipv6Addr};

use hickory_resolver::proto::op::{Message, MessageType, ResponseCode};
use hickory_resolver::proto::rr::RData;

pub struct DnsPacket {
    pub message: Message,
    pub domain: String,
}

impl DnsPacket {
    /// Parses raw UDP bytes into a DNS Message and extracts the query domain
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let message = Message::from_vec(bytes).ok()?;

        // DNS packets usually have 1 question. We take the first one.
        let query = message.queries().first()?;
        let domain = query.name().to_string().to_lowercase();

        // Remove trailing dot if present (e.g., "example.com." -> "example.com")
        let clean_domain = domain.trim_end_matches('.').to_string();

        Some(DnsPacket {
            message,
            domain: clean_domain,
        })
    }

    /// Generates a standard NXDOMAIN (Non-Existent Domain) response
    /// to effectively "block" the request.
    pub fn build_nxdomain_response(query_msg: &Message) -> Vec<u8> {
        let mut response = query_msg.clone();

        response.set_message_type(MessageType::Response);
        response.set_response_code(ResponseCode::NXDomain);
        response.set_recursion_available(true);
        response.set_authoritative(true);

        response.to_vec().unwrap_or_default()
    }

    /// Generates a SERVFAIL response for upstream errors.
    pub fn build_servfail_response(query_msg: &Message) -> Vec<u8> {
        let mut response = query_msg.clone();

        response.set_message_type(MessageType::Response);
        response.set_response_code(ResponseCode::ServFail);
        response.set_recursion_available(true);

        response.to_vec().unwrap_or_default()
    }
}

/// Records extracted from the answer section of an upstream DNS response.
///
/// Foundation for DPI Lite (Phase 8):
/// - 8.2: entropy check on `txt_records`
/// - 8.3: `cname_targets` chain-following for cloaking detection
/// - 8.4: DNS rebinding — check `a_records`/`aaaa_records` against private ranges
/// - 8.6: `min_ttl` for low-TTL suspicion scoring
#[derive(Debug, Default)]
pub struct InspectedAnswer {
    /// IPv4 addresses from A records.
    pub a_records: Vec<Ipv4Addr>,
    /// IPv6 addresses from AAAA records.
    pub aaaa_records: Vec<Ipv6Addr>,
    /// Raw byte segments from TXT records (one entry per TXT string segment).
    /// Kept as bytes so phase 8.2 can run entropy directly on them.
    pub txt_records: Vec<Vec<u8>>,
    /// CNAME targets (trailing dot stripped), for phase 8.3 chain resolution.
    pub cname_targets: Vec<String>,
    /// Minimum TTL across all answer records; `None` if there are no answers.
    pub min_ttl: Option<u32>,
}

impl InspectedAnswer {
    /// Parse the answer section from raw upstream DNS response bytes.
    ///
    /// Returns `None` if `bytes` cannot be decoded as a valid DNS message.
    pub fn from_response(bytes: &[u8]) -> Option<Self> {
        let message = Message::from_vec(bytes).ok()?;
        let mut result = Self::default();

        for record in message.answers() {
            let ttl = record.ttl();
            result.min_ttl = Some(match result.min_ttl {
                Some(current) => current.min(ttl),
                None => ttl,
            });

            match record.data() {
                RData::A(a) => result.a_records.push(a.0),
                RData::AAAA(aaaa) => result.aaaa_records.push(aaaa.0),
                RData::CNAME(cname) => {
                    // Strip trailing dot to stay consistent with DnsPacket::from_bytes.
                    result
                        .cname_targets
                        .push(cname.0.to_string().trim_end_matches('.').to_string());
                }
                RData::TXT(txt) => {
                    for segment in txt.txt_data() {
                        result.txt_records.push(segment.to_vec());
                    }
                }
                _ => {}
            }
        }

        Some(result)
    }

    /// Returns `true` if no recognized answer records were found.
    pub fn is_empty(&self) -> bool {
        self.a_records.is_empty()
            && self.aaaa_records.is_empty()
            && self.txt_records.is_empty()
            && self.cname_targets.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_packet_from_bytes_valid() {
        // Valid DNS query for "example.com" (type A)
        // This is a minimal valid DNS query packet
        let packet = [
            0x00, 0x01, // Transaction ID
            0x01, 0x00, // Flags: Standard query
            0x00, 0x01, // Questions: 1
            0x00, 0x00, // Answers: 0
            0x00, 0x00, // Authority: 0
            0x00, 0x00, // Additional: 0
            // Question: example.com, type A
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', // "example"
            0x03, b'c', b'o', b'm', // "com"
            0x00, // null terminator
            0x00, 0x01, // Type: A
            0x00, 0x01, // Class: IN
        ];

        let result = DnsPacket::from_bytes(&packet);
        assert!(result.is_some());
        let dns_packet = result.unwrap();
        assert_eq!(dns_packet.domain, "example.com");
    }

    #[test]
    fn test_dns_packet_from_bytes_invalid() {
        // Invalid packet (too short)
        let packet = [0x00, 0x01];
        let result = DnsPacket::from_bytes(&packet);
        assert!(result.is_none());
    }

    #[test]
    fn test_dns_packet_removes_trailing_dot() {
        // DNS query with trailing dot in FQDN is handled by hickory
        // The from_bytes function removes trailing dots
        let packet = [
            0x00, 0x01, // Transaction ID
            0x01, 0x00, // Flags
            0x00, 0x01, // Questions: 1
            0x00, 0x00, // Answers: 0
            0x00, 0x00, // Authority: 0
            0x00, 0x00, // Additional: 0
            0x04, b't', b'e', b's', b't', // "test"
            0x03, b'c', b'o', b'm', // "com"
            0x00, // null terminator
            0x00, 0x01, // Type: A
            0x00, 0x01, // Class: IN
        ];

        let result = DnsPacket::from_bytes(&packet);
        assert!(result.is_some());
        let dns_packet = result.unwrap();
        assert!(!dns_packet.domain.ends_with('.'));
    }

    #[test]
    fn test_build_nxdomain_response() {
        // First create a valid query message
        let packet = [
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ];

        let dns_packet = DnsPacket::from_bytes(&packet).unwrap();
        let response = DnsPacket::build_nxdomain_response(&dns_packet.message);

        // Response should not be empty
        assert!(!response.is_empty());

        // Parse response to verify it's NXDOMAIN
        let response_msg = Message::from_vec(&response).unwrap();
        assert_eq!(response_msg.message_type(), MessageType::Response);
        assert_eq!(response_msg.response_code(), ResponseCode::NXDomain);
    }

    #[test]
    fn test_build_servfail_response() {
        let packet = [
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ];

        let dns_packet = DnsPacket::from_bytes(&packet).unwrap();
        let response = DnsPacket::build_servfail_response(&dns_packet.message);

        let response_msg = Message::from_vec(&response).unwrap();
        assert_eq!(response_msg.message_type(), MessageType::Response);
        assert_eq!(response_msg.response_code(), ResponseCode::ServFail);
    }
}

#[cfg(test)]
mod tests_inspector {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    use hickory_resolver::proto::rr::rdata::{A, AAAA, CNAME, TXT};
    use hickory_resolver::proto::rr::{Name, RData, Record};

    use super::*;

    // --- helpers ---

    fn build_response(answers: Vec<Record>) -> Vec<u8> {
        let mut msg = Message::new();
        msg.set_message_type(MessageType::Response);
        msg.set_response_code(ResponseCode::NoError);
        for record in answers {
            msg.add_answer(record);
        }
        msg.to_vec().unwrap()
    }

    fn a_record(domain: &str, ip: Ipv4Addr, ttl: u32) -> Record {
        Record::from_rdata(
            Name::from_str(&format!("{domain}.")).unwrap(),
            ttl,
            RData::A(A(ip)),
        )
    }

    fn aaaa_record(domain: &str, ip: Ipv6Addr, ttl: u32) -> Record {
        Record::from_rdata(
            Name::from_str(&format!("{domain}.")).unwrap(),
            ttl,
            RData::AAAA(AAAA(ip)),
        )
    }

    fn txt_record(domain: &str, data: &[u8], ttl: u32) -> Record {
        let txt = TXT::new(vec![String::from_utf8_lossy(data).into_owned()]);
        Record::from_rdata(
            Name::from_str(&format!("{domain}.")).unwrap(),
            ttl,
            RData::TXT(txt),
        )
    }

    fn cname_record(domain: &str, target: &str, ttl: u32) -> Record {
        let target_name = Name::from_str(&format!("{target}.")).unwrap();
        Record::from_rdata(
            Name::from_str(&format!("{domain}.")).unwrap(),
            ttl,
            RData::CNAME(CNAME(target_name)),
        )
    }

    // --- tests ---

    #[test]
    fn test_inspect_invalid_bytes() {
        // Too short to be a valid DNS message.
        assert!(InspectedAnswer::from_response(&[0x00, 0x01]).is_none());
    }

    #[test]
    fn test_inspect_empty_response() {
        let bytes = build_response(vec![]);
        let answer = InspectedAnswer::from_response(&bytes).unwrap();
        assert!(answer.is_empty());
        assert!(answer.min_ttl.is_none());
    }

    #[test]
    fn test_inspect_a_record() {
        let ip = Ipv4Addr::new(1, 2, 3, 4);
        let bytes = build_response(vec![a_record("example.com", ip, 300)]);
        let answer = InspectedAnswer::from_response(&bytes).unwrap();

        assert_eq!(answer.a_records, vec![ip]);
        assert!(answer.aaaa_records.is_empty());
        assert!(answer.txt_records.is_empty());
        assert!(answer.cname_targets.is_empty());
        assert_eq!(answer.min_ttl, Some(300));
        assert!(!answer.is_empty());
    }

    #[test]
    fn test_inspect_aaaa_record() {
        let ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let bytes = build_response(vec![aaaa_record("example.com", ip, 600)]);
        let answer = InspectedAnswer::from_response(&bytes).unwrap();

        assert_eq!(answer.aaaa_records, vec![ip]);
        assert!(answer.a_records.is_empty());
        assert_eq!(answer.min_ttl, Some(600));
    }

    #[test]
    fn test_inspect_txt_record() {
        let data = b"v=spf1 include:example.com ~all";
        let bytes = build_response(vec![txt_record("example.com", data, 3600)]);
        let answer = InspectedAnswer::from_response(&bytes).unwrap();

        assert_eq!(answer.txt_records.len(), 1);
        assert_eq!(answer.txt_records[0], data.as_slice());
        assert_eq!(answer.min_ttl, Some(3600));
    }

    #[test]
    fn test_inspect_cname_target() {
        let bytes = build_response(vec![cname_record("www.example.com", "example.com", 300)]);
        let answer = InspectedAnswer::from_response(&bytes).unwrap();

        assert_eq!(answer.cname_targets.len(), 1);
        assert_eq!(answer.cname_targets[0], "example.com");
    }

    #[test]
    fn test_inspect_min_ttl_picks_lowest() {
        let bytes = build_response(vec![
            a_record("example.com", Ipv4Addr::new(1, 1, 1, 1), 100),
            a_record("example.com", Ipv4Addr::new(2, 2, 2, 2), 50),
            a_record("example.com", Ipv4Addr::new(3, 3, 3, 3), 200),
        ]);
        let answer = InspectedAnswer::from_response(&bytes).unwrap();

        assert_eq!(answer.a_records.len(), 3);
        assert_eq!(answer.min_ttl, Some(50));
    }

    #[test]
    fn test_inspect_multiple_record_types() {
        let ip = Ipv4Addr::new(93, 184, 216, 34);
        let bytes = build_response(vec![
            a_record("example.com", ip, 300),
            txt_record("example.com", b"v=spf1 ~all", 3600),
            cname_record("www.example.com", "example.com", 300),
        ]);
        let answer = InspectedAnswer::from_response(&bytes).unwrap();

        assert_eq!(answer.a_records, vec![ip]);
        assert_eq!(answer.txt_records.len(), 1);
        assert_eq!(answer.cname_targets, vec!["example.com"]);
        // min TTL across A (300), TXT (3600), CNAME (300) = 300
        assert_eq!(answer.min_ttl, Some(300));
        assert!(!answer.is_empty());
    }
}
