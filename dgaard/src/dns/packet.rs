use std::net::IpAddr;

use hickory_resolver::proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_resolver::proto::rr::rdata::{A, AAAA};
use hickory_resolver::proto::rr::{DNSClass, Name, RData, Record, RecordType};

/// What to do with a datagram received on the listening socket.
pub enum Incoming {
    /// A standard query with exactly one question: run the pipeline.
    Query(DnsPacket),
    /// Malformed bytes or a response: never answered.
    Drop,
    /// A request dgaard does not serve: send this error response once.
    Reject(Vec<u8>),
}

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

/// Encode a DNS `Message` to wire bytes.
///
/// If `to_vec()` fails (extremely rare — only possible if hickory cannot
/// encode its own in-memory representation), returns a hand-built 12-byte
/// SERVFAIL header carrying the original transaction ID. This guarantees
/// callers always send a parseable DNS response instead of a 0-byte datagram,
/// which clients cannot interpret and will retry aggressively.
fn encode_response(msg: Message) -> Vec<u8> {
    let id = msg.metadata.id;
    msg.to_vec().unwrap_or_else(|_| {
        // Minimal valid DNS response header (RFC 1035 §4.1.1):
        //   Flags: QR=1 Opcode=0 AA=0 TC=0 RD=1 RA=1 Z=0 RCODE=SERVFAIL(2)
        //          → 0x81 0x82
        //   All section counts = 0
        let [hi, lo] = id.to_be_bytes();
        vec![hi, lo, 0x81, 0x82, 0, 0, 0, 0, 0, 0, 0, 0]
    })
}

impl DnsPacket {
    /// Build a synthetic client-style query for `domain` and `qtype`.
    ///
    /// Used by the Phase 5 prefetch worker, which needs to feed an
    /// [`UpstreamResolver`] but has no incoming wire packet to parse —
    /// only the cache key (`(domain, qtype)`). The resulting `DnsPacket`
    /// matches what a stub resolver would send: a single standard query
    /// in class IN with RD=1 (forwarder mode uses RD when it forwards;
    /// recursive mode ignores RD and walks the chain itself).
    ///
    /// Returns `None` if `domain` cannot be parsed as a DNS name. The
    /// prefetch worker drops such requests silently — they can only
    /// happen if a cache entry was inserted with a malformed key, which
    /// today is impossible (cache keys are derived from validated
    /// incoming packets).
    pub fn new_query(domain: &str, qtype: u16) -> Option<Self> {
        let name = Name::parse(domain, Some(&Name::root())).ok()?;
        let mut message = Message::query();
        message.metadata.op_code = OpCode::Query;
        message.metadata.recursion_desired = true;

        let q = Query::query(name, RecordType::from(qtype))
            .set_query_class(DNSClass::IN)
            .clone();
        message.add_query(q);

        Some(DnsPacket {
            message,
            domain: domain.to_ascii_lowercase(),
            qtype,
            qclass: u16::from(DNSClass::IN),
        })
    }

    /// Screen a datagram received on the listening socket before any
    /// filtering (RFC 1035 §4.1.1).
    ///
    /// Only standard queries (QR=0, opcode QUERY) with exactly one question
    /// reach the pipeline. A response (QR=1) is never answered: answering
    /// it would let a forged packet whose source is another resolver, or
    /// dgaard itself, bounce between the two forever. Other opcodes
    /// (NOTIFY, UPDATE…) get a single NOTIMP and other question counts a
    /// single FORMERR; both are responses, which the peer drops in turn.
    pub fn screen(bytes: &[u8]) -> Incoming {
        let Ok(message) = Message::from_vec(bytes) else {
            return Incoming::Drop;
        };
        if message.metadata.message_type == MessageType::Response {
            return Incoming::Drop;
        }
        if message.metadata.op_code != OpCode::Query {
            return Incoming::Reject(Self::build_error_response(&message, ResponseCode::NotImp));
        }
        if message.queries.len() != 1 {
            return Incoming::Reject(Self::build_error_response(&message, ResponseCode::FormErr));
        }

        let query = &message.queries[0];
        // Remove trailing dot (e.g., "example.com." -> "example.com")
        let domain = query
            .name()
            .to_string()
            .to_lowercase()
            .trim_end_matches('.')
            .to_string();
        let qtype = u16::from(query.query_type());
        let qclass = u16::from(query.query_class());

        Incoming::Query(DnsPacket {
            message,
            domain,
            qtype,
            qclass,
        })
    }

    /// Parse raw bytes into a standard query; `None` for anything
    /// [`Self::screen`] would not send through the pipeline.
    #[cfg(test)]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        match Self::screen(bytes) {
            Incoming::Query(packet) => Some(packet),
            Incoming::Drop | Incoming::Reject(_) => None,
        }
    }

    /// Error response to a request dgaard does not serve: same ID, opcode
    /// and question section, `rcode`, and none of the request's records.
    fn build_error_response(request: &Message, rcode: ResponseCode) -> Vec<u8> {
        let mut response = request.clone();
        response.metadata.message_type = MessageType::Response;
        response.metadata.response_code = rcode;
        response.metadata.authoritative = false;
        response.metadata.recursion_available = true;
        response.answers.clear();
        response.authorities.clear();
        response.additionals.clear();
        encode_response(response)
    }

    /// Generates a standard NXDOMAIN (Non-Existent Domain) response
    /// to effectively "block" the request.
    pub fn build_nxdomain_response(query_msg: &Message) -> Vec<u8> {
        let mut response = query_msg.clone();

        response.metadata.message_type = MessageType::Response;
        response.metadata.response_code = ResponseCode::NXDomain;
        response.metadata.recursion_available = true;
        response.metadata.authoritative = true;

        encode_response(response)
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
        encode_response(response)
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

        encode_response(response)
    }

    /// Generates a SERVFAIL response for upstream errors.
    pub fn build_servfail_response(query_msg: &Message) -> Vec<u8> {
        let mut response = query_msg.clone();

        response.metadata.message_type = MessageType::Response;
        response.metadata.response_code = ResponseCode::ServFail;
        response.metadata.recursion_available = true;

        encode_response(response)
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

    // --- encode_response fallback ---

    #[test]
    fn encode_response_fallback_bytes_are_parseable_servfail() {
        // Directly verify the 12-byte fallback is a valid DNS SERVFAIL with the
        // correct transaction ID, so we know clients can parse it.
        let id = 0xAB_CDu16;
        let [hi, lo] = id.to_be_bytes();
        let bytes = vec![hi, lo, 0x81, 0x82, 0, 0, 0, 0, 0, 0, 0, 0];
        let msg = Message::from_vec(&bytes).unwrap();
        assert_eq!(msg.metadata.id, id);
        assert_eq!(msg.metadata.message_type, MessageType::Response);
        assert_eq!(msg.metadata.response_code, ResponseCode::ServFail);
        assert!(msg.answers.is_empty());
    }

    #[test]
    fn encode_response_returns_serialized_bytes_on_success() {
        let pkt = [
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ];
        let query = DnsPacket::from_bytes(&pkt).unwrap();
        let bytes = DnsPacket::build_nxdomain_response(&query.message);
        assert!(!bytes.is_empty());
        // Must parse cleanly — encode_response must not have fallen back.
        let msg = Message::from_vec(&bytes).unwrap();
        assert_eq!(msg.metadata.response_code, ResponseCode::NXDomain);
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

    // --- screen: only standard queries reach the pipeline (review E3) ---

    fn message_bytes(configure: impl FnOnce(&mut Message)) -> Vec<u8> {
        let mut msg = Message::query();
        msg.metadata.id = 0x4242;
        msg.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
        ));
        configure(&mut msg);
        msg.to_vec().unwrap()
    }

    fn rejection(bytes: &[u8]) -> Message {
        match DnsPacket::screen(bytes) {
            Incoming::Reject(response) => Message::from_vec(&response).unwrap(),
            Incoming::Query(_) => panic!("expected a rejection, got a query"),
            Incoming::Drop => panic!("expected a rejection, got a drop"),
        }
    }

    fn a_record() -> Record {
        Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            60,
            RData::A(A(std::net::Ipv4Addr::new(192, 0, 2, 1))),
        )
    }

    #[test]
    fn screen_accepts_a_standard_query() {
        match DnsPacket::screen(&message_bytes(|_| {})) {
            Incoming::Query(packet) => assert_eq!(packet.domain, "example.com"),
            _ => panic!("a standard query must reach the pipeline"),
        }
    }

    #[test]
    fn screen_drops_responses() {
        // Whatever they carry, responses are never answered.
        let responses = [
            message_bytes(|msg| {
                msg.metadata.message_type = MessageType::Response;
                msg.add_answer(a_record());
            }),
            message_bytes(|msg| {
                msg.metadata.message_type = MessageType::Response;
                msg.metadata.response_code = ResponseCode::NXDomain;
            }),
            message_bytes(|msg| {
                msg.metadata.message_type = MessageType::Response;
                msg.metadata.op_code = OpCode::Notify;
            }),
            message_bytes(|msg| {
                msg.metadata.message_type = MessageType::Response;
                msg.queries.clear();
            }),
        ];
        for bytes in responses {
            assert!(matches!(DnsPacket::screen(&bytes), Incoming::Drop));
            assert!(DnsPacket::from_bytes(&bytes).is_none());
        }
    }

    #[test]
    fn screen_drops_malformed_bytes() {
        assert!(matches!(DnsPacket::screen(&[0x00, 0x01]), Incoming::Drop));
        assert!(matches!(DnsPacket::screen(&[]), Incoming::Drop));
    }

    #[test]
    fn screen_rejects_other_opcodes_with_notimp() {
        for op_code in [OpCode::Notify, OpCode::Update, OpCode::Status] {
            let request = message_bytes(|msg| {
                msg.metadata.op_code = op_code;
                // UPDATE carries records; none may be echoed back.
                msg.add_authority(a_record());
            });
            let response = rejection(&request);
            assert_eq!(response.metadata.id, 0x4242);
            assert_eq!(response.metadata.message_type, MessageType::Response);
            assert_eq!(response.metadata.response_code, ResponseCode::NotImp);
            assert_eq!(response.metadata.op_code, op_code);
            assert!(response.answers.is_empty());
            assert!(response.authorities.is_empty());
            assert!(response.additionals.is_empty());
            assert!(DnsPacket::from_bytes(&request).is_none());
        }
    }

    #[test]
    fn screen_rejects_question_counts_other_than_one_with_formerr() {
        let no_question = message_bytes(|msg| msg.queries.clear());
        let two_questions = message_bytes(|msg| {
            msg.add_query(Query::query(
                Name::from_ascii("other.example.").unwrap(),
                RecordType::AAAA,
            ));
        });
        for request in [no_question, two_questions] {
            let response = rejection(&request);
            assert_eq!(response.metadata.id, 0x4242);
            assert_eq!(response.metadata.message_type, MessageType::Response);
            assert_eq!(response.metadata.response_code, ResponseCode::FormErr);
        }
    }

    #[test]
    fn rejections_are_dropped_if_they_come_back() {
        // Two servers applying the same rule exchange at most one packet.
        for request in [
            message_bytes(|msg| msg.metadata.op_code = OpCode::Notify),
            message_bytes(|msg| msg.queries.clear()),
        ] {
            let Incoming::Reject(response) = DnsPacket::screen(&request) else {
                panic!("expected a rejection");
            };
            assert!(matches!(DnsPacket::screen(&response), Incoming::Drop));
        }
    }
}
