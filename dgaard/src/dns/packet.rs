use std::net::IpAddr;

use hickory_resolver::proto::op::{Message, MessageType, ResponseCode};
use hickory_resolver::proto::rr::rdata::{A, AAAA};
use hickory_resolver::proto::rr::{RData, Record};

pub struct DnsPacket {
    pub message: Message,
    pub domain: String,
    /// Raw DNS record type code from the query section (RFC 1035, §3.2.2).
    /// Used by the QType Warden to block forbidden query types before domain
    /// resolution. Common suspicious values: NULL=10, HINFO=13, ANY=255.
    pub qtype: u16,
    /// Raw DNS query class code from the query section (RFC 1035, §3.2.4).
    /// Class IN=1 is normal Internet queries. Class CH=3 (CHAOS) is blocked
    /// by default to prevent upstream reconnaissance.
    pub qclass: u16,
}

impl DnsPacket {
    /// Parses raw UDP bytes into a DNS Message and extracts the query domain
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let message = Message::from_vec(bytes).ok()?;

        // DNS packets usually have 1 question. We take the first one.
        let query = message.queries.first()?;
        let domain = query.name().to_string().to_lowercase();

        // Remove trailing dot if present (e.g., "example.com." -> "example.com")
        let clean_domain = domain.trim_end_matches('.').to_string();
        let qtype = u16::from(query.query_type());
        let qclass = u16::from(query.query_class());

        Some(DnsPacket {
            message,
            domain: clean_domain,
            qtype,
            qclass,
        })
    }

    /// Generates a standard NXDOMAIN (Non-Existent Domain) response
    /// to effectively "block" the request.
    pub fn build_nxdomain_response(query_msg: &Message) -> Vec<u8> {
        let mut response = query_msg.clone();

        response.metadata.message_type = MessageType::Response;
        response.metadata.response_code = ResponseCode::NXDomain;
        response.metadata.recursion_available = true;
        response.metadata.authoritative = true;

        response.to_vec().unwrap_or_default()
    }

    /// Generates a REFUSED response for queries the server is configured to reject.
    ///
    /// Used for CHAOS class blocking: the server is refusing to process the
    /// request, not asserting that a domain is non-existent.
    pub fn build_refused_response(query_msg: &Message) -> Vec<u8> {
        let mut response = query_msg.clone();
        response.metadata.message_type = MessageType::Response;
        response.metadata.response_code = ResponseCode::Refused;
        response.metadata.recursion_available = true;
        response.to_vec().unwrap_or_default()
    }

    /// Build a NOERROR response containing a synthetic A or AAAA answer for `ip`.
    ///
    /// The record type is chosen to match the IP address family. When the query
    /// asked for a type that doesn't match (e.g. AAAA for an IPv4 address), the
    /// answer section is left empty — correct DNS behaviour for "name exists,
    /// record type absent".
    pub fn build_ip_response(query_msg: &Message, ip: IpAddr) -> Vec<u8> {
        const SYNTHETIC_TTL: u32 = 300;
        const QTYPE_A: u16 = 1;
        const QTYPE_AAAA: u16 = 28;

        let mut response = query_msg.clone();
        response.metadata.message_type = MessageType::Response;
        response.metadata.response_code = ResponseCode::NoError;
        response.metadata.recursion_available = true;
        response.metadata.authoritative = true;

        if let Some(q) = query_msg.queries.first() {
            let qtype = u16::from(q.query_type());
            let rdata = match ip {
                IpAddr::V4(v4) if qtype == QTYPE_A => Some(RData::A(A(v4))),
                IpAddr::V6(v6) if qtype == QTYPE_AAAA => Some(RData::AAAA(AAAA(v6))),
                _ => None,
            };
            if let Some(rdata) = rdata {
                response.add_answer(Record::from_rdata(q.name().clone(), SYNTHETIC_TTL, rdata));
            }
        }

        response.to_vec().unwrap_or_default()
    }

    /// Generates a SERVFAIL response for upstream errors.
    pub fn build_servfail_response(query_msg: &Message) -> Vec<u8> {
        let mut response = query_msg.clone();

        response.metadata.message_type = MessageType::Response;
        response.metadata.response_code = ResponseCode::ServFail;
        response.metadata.recursion_available = true;

        response.to_vec().unwrap_or_default()
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

    fn make_query(qtype_a_or_aaaa: &str) -> Vec<u8> {
        // Builds a minimal query for "example.com" with the given record type.
        let qtype: &[u8] = match qtype_a_or_aaaa {
            "A" => &[0x00, 0x01],
            "AAAA" => &[0x00, 0x1C],
            _ => panic!("unsupported qtype"),
        };
        let mut pkt = vec![
            0x00, 0x01, // ID
            0x01, 0x00, // Flags: standard query
            0x00, 0x01, // QDCOUNT: 1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // AN/NS/AR: 0
            // QNAME: example.com
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
        ];
        pkt.extend_from_slice(qtype);
        pkt.extend_from_slice(&[0x00, 0x01]); // QCLASS IN
        pkt
    }

    #[test]
    fn build_ip_response_ipv4_a_query_returns_a_record() {
        use std::net::Ipv4Addr;
        let query = DnsPacket::from_bytes(&make_query("A")).unwrap();
        let ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        let resp_bytes = DnsPacket::build_ip_response(&query.message, ip);
        let resp = Message::from_vec(&resp_bytes).unwrap();
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert_eq!(resp.answers.len(), 1);
        match &resp.answers[0].data {
            RData::A(a) => assert_eq!(a.0, Ipv4Addr::new(93, 184, 216, 34)),
            other => panic!("expected A record, got {:?}", other),
        }
    }

    #[test]
    fn build_ip_response_ipv6_aaaa_query_returns_aaaa_record() {
        use std::net::Ipv6Addr;
        let query = DnsPacket::from_bytes(&make_query("AAAA")).unwrap();
        let ip = IpAddr::V6(Ipv6Addr::new(
            0x2606, 0x2800, 0x21f, 0xcb07, 0x6820, 0, 0, 0x1,
        ));
        let resp_bytes = DnsPacket::build_ip_response(&query.message, ip);
        let resp = Message::from_vec(&resp_bytes).unwrap();
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert_eq!(resp.answers.len(), 1);
        match &resp.answers[0].data {
            RData::AAAA(aaaa) => assert_eq!(
                aaaa.0,
                Ipv6Addr::new(0x2606, 0x2800, 0x21f, 0xcb07, 0x6820, 0, 0, 0x1)
            ),
            other => panic!("expected AAAA record, got {:?}", other),
        }
    }

    #[test]
    fn build_ip_response_ipv4_aaaa_query_returns_noerror_no_answers() {
        use std::net::Ipv4Addr;
        let query = DnsPacket::from_bytes(&make_query("AAAA")).unwrap();
        let ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        let resp_bytes = DnsPacket::build_ip_response(&query.message, ip);
        let resp = Message::from_vec(&resp_bytes).unwrap();
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert!(
            resp.answers.is_empty(),
            "no AAAA record should be synthesised for an IPv4 address"
        );
    }

    #[test]
    fn build_ip_response_ipv6_a_query_returns_noerror_no_answers() {
        use std::net::Ipv6Addr;
        let query = DnsPacket::from_bytes(&make_query("A")).unwrap();
        let ip = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let resp_bytes = DnsPacket::build_ip_response(&query.message, ip);
        let resp = Message::from_vec(&resp_bytes).unwrap();
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert!(
            resp.answers.is_empty(),
            "no A record should be synthesised for an IPv6 address"
        );
    }

    #[test]
    fn build_ip_response_sets_correct_flags() {
        use std::net::Ipv4Addr;
        let query = DnsPacket::from_bytes(&make_query("A")).unwrap();
        let resp_bytes =
            DnsPacket::build_ip_response(&query.message, IpAddr::V4(Ipv4Addr::LOCALHOST));
        let resp = Message::from_vec(&resp_bytes).unwrap();
        assert_eq!(resp.metadata.message_type, MessageType::Response);
        assert!(resp.metadata.recursion_available);
        assert!(resp.metadata.authoritative);
    }

    #[test]
    fn build_nxdomain_response() {
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
        assert_eq!(response_msg.metadata.message_type, MessageType::Response);
        assert_eq!(response_msg.metadata.response_code, ResponseCode::NXDomain);
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
        assert_eq!(response_msg.metadata.message_type, MessageType::Response);
        assert_eq!(response_msg.metadata.response_code, ResponseCode::ServFail);
    }

    #[test]
    fn test_build_ip_response_ipv4() {
        use std::net::{IpAddr, Ipv4Addr};

        let packet = [
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ];

        let dns_packet = DnsPacket::from_bytes(&packet).unwrap();
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let response = DnsPacket::build_ip_response(&dns_packet.message, ip);

        let response_msg = Message::from_vec(&response).unwrap();
        assert_eq!(response_msg.metadata.message_type, MessageType::Response);
        assert_eq!(response_msg.metadata.response_code, ResponseCode::NoError);
        assert_eq!(response_msg.answers.len(), 1);
    }

    #[test]
    fn test_build_ip_response_ipv6() {
        use std::net::{IpAddr, Ipv6Addr};

        let packet = [
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x1c, 0x00,
            0x01,
        ];

        let dns_packet = DnsPacket::from_bytes(&packet).unwrap();
        let ip = IpAddr::V6(Ipv6Addr::new(0x20, 0x01, 0, 0, 0, 0, 0, 1));
        let response = DnsPacket::build_ip_response(&dns_packet.message, ip);

        let response_msg = Message::from_vec(&response).unwrap();
        assert_eq!(response_msg.metadata.message_type, MessageType::Response);
        assert_eq!(response_msg.metadata.response_code, ResponseCode::NoError);
        assert_eq!(response_msg.answers.len(), 1);
    }
}
