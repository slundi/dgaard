use std::net::IpAddr;
use std::sync::LazyLock;

use hickory_resolver::proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_resolver::proto::rr::rdata::{A, AAAA, SOA};
use hickory_resolver::proto::rr::{DNSClass, Name, RData, Record, RecordType};

/// Payload size every DNS server must handle without EDNS (RFC 1035 §4.2.1).
pub(crate) const CLASSIC_UDP_PAYLOAD: usize = 512;

/// Largest UDP response the client of `query` accepts: the EDNS payload size
/// it advertises (RFC 6891 §6.2.3), or 512 bytes without EDNS.
pub(crate) fn client_udp_payload(query: &[u8]) -> usize {
    Message::from_vec(query)
        .map(|msg| usize::from(msg.max_payload()))
        .unwrap_or(CLASSIC_UDP_PAYLOAD)
        .max(CLASSIC_UDP_PAYLOAD)
}

/// Fit `response` in the UDP payload the client of `query` accepts. A bigger
/// response is replaced by the same header with TC=1, the question and the
/// EDNS OPT record but no other records (RFC 2181 §9, RFC 6891 §7), so the
/// client retries over TCP instead of reading a cut datagram.
pub(crate) fn fit_udp_response(query: &[u8], response: Vec<u8>) -> Vec<u8> {
    if response.len() <= client_udp_payload(query) {
        return response;
    }
    Message::from_vec(&response)
        .ok()
        .and_then(|mut msg| {
            msg.answers.clear();
            msg.authorities.clear();
            msg.additionals.clear();
            msg.metadata.truncation = true;
            msg.to_vec().ok()
        })
        .unwrap_or_else(|| truncated_header(&response))
}

/// Last resort when `response` does not parse: its 12-byte header with TC=1
/// and every section count zeroed.
fn truncated_header(response: &[u8]) -> Vec<u8> {
    let mut header = [0u8; 12];
    let len = response.len().min(4);
    header[..len].copy_from_slice(&response[..len]);
    header[2] |= 0x80 | 0x02; // QR, TC
    header.to_vec()
}

/// Transport a client query arrived on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Transport {
    #[default]
    Udp,
    /// RFC 7766 TCP: no size limit, so a truncated upstream answer is
    /// retried over TCP instead of being relayed.
    Tcp,
}

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
    /// Transport the client used.
    pub transport: Transport,
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
    /// only the cache key (name, type, class, DO/CD). The resulting
    /// `DnsPacket` matches what a stub resolver would send: a single
    /// standard query with RD=1 (forwarder mode uses RD when it forwards;
    /// recursive mode ignores RD and walks the chain itself), EDNS with DO
    /// when the cached entry was for a DNSSEC-aware client, and CD when the
    /// client disabled validation.
    ///
    /// Returns `None` if `domain` cannot be parsed as a DNS name. The
    /// prefetch worker drops such requests silently — they can only
    /// happen if a cache entry was inserted with a malformed key, which
    /// today is impossible (cache keys are derived from validated
    /// incoming packets).
    pub fn new_query(
        domain: &str,
        qtype: u16,
        qclass: u16,
        flags: crate::cache::QueryFlags,
    ) -> Option<Self> {
        let name = Name::parse(domain, Some(&Name::root())).ok()?;
        let mut message = Message::query();
        message.metadata.op_code = OpCode::Query;
        message.metadata.recursion_desired = true;
        message.metadata.checking_disabled = flags.checking_disabled;
        if flags.dnssec_ok {
            let mut edns = Edns::new();
            edns.set_max_payload(EDNS_PAYLOAD);
            edns.set_dnssec_ok(true);
            message.set_edns(edns);
        }

        let q = Query::query(name, RecordType::from(qtype))
            .set_query_class(DNSClass::from(qclass))
            .clone();
        message.add_query(q);

        Some(DnsPacket {
            message,
            domain: domain.to_ascii_lowercase(),
            qtype,
            qclass,
            transport: Transport::Udp,
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
            transport: Transport::Udp,
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
        encode_response(response_to(request, rcode))
    }

    /// Generates a standard NXDOMAIN (Non-Existent Domain) response
    /// to effectively "block" the request.
    ///
    /// The authority section carries a SOA so clients and downstream
    /// resolvers can cache the negative answer (RFC 2308 §3); without it
    /// many of them re-ask on every lookup.
    pub fn build_nxdomain_response(query_msg: &Message) -> Vec<u8> {
        let mut response = response_to(query_msg, ResponseCode::NXDomain);
        response.metadata.authoritative = true;
        add_negative_soa(&mut response);
        encode_response(response)
    }

    /// Generates a REFUSED response for queries the server is configured to reject.
    ///
    /// Used for CHAOS class blocking: the server is refusing to process the
    /// request, not asserting that a domain is non-existent.
    pub fn build_refused_response(query_msg: &Message) -> Vec<u8> {
        encode_response(response_to(query_msg, ResponseCode::Refused))
    }

    /// Build a NOERROR response containing a synthetic A or AAAA answer for `ip`.
    ///
    /// The record type is chosen to match the IP address family. When the query
    /// asked for a type that doesn't match (e.g. AAAA for an IPv4 address), the
    /// answer section is left empty — correct DNS behaviour for "name exists,
    /// record type absent" — and a SOA is added so that NODATA answer can be
    /// cached (RFC 2308 §2.2).
    pub fn build_ip_response(query_msg: &Message, ip: IpAddr) -> Vec<u8> {
        const QTYPE_A: u16 = 1;
        const QTYPE_AAAA: u16 = 28;

        let mut response = response_to(query_msg, ResponseCode::NoError);
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
        if response.answers.is_empty() {
            add_negative_soa(&mut response);
        }

        encode_response(response)
    }

    /// Generates a SERVFAIL response for upstream errors.
    pub fn build_servfail_response(query_msg: &Message) -> Vec<u8> {
        encode_response(response_to(query_msg, ResponseCode::ServFail))
    }
}

/// TTL of the records dgaard synthesises, and the negative-caching TTL
/// (SOA MINIMUM, RFC 2308 §5) of its synthetic NXDOMAIN and NODATA answers.
const SYNTHETIC_TTL: u32 = 300;

/// UDP payload size dgaard advertises in its own EDNS OPT records: the
/// DNS Flag Day 2020 value, which avoids IP fragmentation.
const EDNS_PAYLOAD: u16 = 1232;

/// SOA RDATA of every synthetic negative answer. `dgaard.invalid.` can
/// never collide with a real zone (RFC 6761 §6.4).
static NEGATIVE_SOA: LazyLock<SOA> = LazyLock::new(|| {
    SOA::new(
        Name::from_ascii("dgaard.invalid.").expect("static name"),
        Name::from_ascii("hostmaster.dgaard.invalid.").expect("static name"),
        1,
        1800,
        900,
        604_800,
        SYNTHETIC_TTL,
    )
});

/// Header and question of the response to `query_msg`, with no records.
///
/// Nothing from the query's answer, authority or additional sections (nor
/// its TSIG) is echoed back, and AD is cleared since synthetic data is
/// never DNSSEC-validated. A query with EDNS gets an OPT record of our own
/// (RFC 6891 §7) that copies only the DO bit (RFC 3225 §3), not the
/// client's options.
fn response_to(query_msg: &Message, rcode: ResponseCode) -> Message {
    let mut response = Message::new(
        query_msg.metadata.id,
        MessageType::Response,
        query_msg.metadata.op_code,
    );
    response.metadata.response_code = rcode;
    response.metadata.recursion_desired = query_msg.metadata.recursion_desired;
    response.metadata.checking_disabled = query_msg.metadata.checking_disabled;
    response.metadata.recursion_available = true;
    response.queries = query_msg.queries.clone();
    response.edns = query_msg.edns.as_ref().map(|query_edns| {
        let mut edns = Edns::new();
        edns.set_max_payload(EDNS_PAYLOAD);
        edns.set_dnssec_ok(query_edns.flags().dnssec_ok);
        edns
    });
    response
}

/// Add the SOA of a synthetic negative answer to the authority section.
/// It is owned by the queried name, which is always in bailiwick, and
/// its TTL equals MINIMUM, so the answer is cached for `SYNTHETIC_TTL`.
fn add_negative_soa(response: &mut Message) {
    let Some(query) = response.queries.first() else {
        return;
    };
    let mut soa = Record::from_rdata(
        query.name().clone(),
        SYNTHETIC_TTL,
        RData::SOA(NEGATIVE_SOA.clone()),
    );
    soa.dns_class = query.query_class();
    response.add_authority(soa);
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::proto::rr::rdata::opt::EdnsOption;

    // ---- new_query carries the whole cache key ----

    #[test]
    fn new_query_sets_class_and_dnssec_bits() {
        let flags = crate::cache::QueryFlags {
            dnssec_ok: true,
            checking_disabled: true,
        };
        let packet = DnsPacket::new_query("Example.com", 28, 3, flags).unwrap();
        assert_eq!(packet.domain, "example.com");
        assert_eq!((packet.qtype, packet.qclass), (28, 3));
        let question = &packet.message.queries[0];
        assert_eq!(question.query_class(), DNSClass::CH);
        assert_eq!(question.query_type(), RecordType::AAAA);
        assert!(packet.message.metadata.checking_disabled);
        assert!(packet.message.edns.as_ref().unwrap().flags().dnssec_ok);
        assert_eq!(crate::cache::CacheQuery::of(&packet).flags, flags);
    }

    #[test]
    fn new_query_without_flags_has_no_edns() {
        let packet =
            DnsPacket::new_query("example.com", 1, 1, crate::cache::QueryFlags::default()).unwrap();
        assert!(packet.message.edns.is_none());
        assert!(!packet.message.metadata.checking_disabled);
        assert_eq!(packet.message.queries[0].query_class(), DNSClass::IN);
    }

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

    // --- synthetic responses: negative-caching SOA, no echoed records ---

    fn parsed(bytes: &[u8]) -> Message {
        Message::from_vec(bytes).unwrap()
    }

    fn assert_negative_soa(resp: &Message) {
        assert_eq!(resp.authorities.len(), 1, "exactly one SOA expected");
        let soa_record = &resp.authorities[0];
        assert_eq!(soa_record.name, Name::from_ascii("example.com.").unwrap());
        assert_eq!(soa_record.ttl, SYNTHETIC_TTL);
        assert_eq!(soa_record.dns_class, DNSClass::IN);
        match &soa_record.data {
            RData::SOA(soa) => {
                assert_eq!(soa.minimum, SYNTHETIC_TTL);
                assert_eq!(soa.mname, Name::from_ascii("dgaard.invalid.").unwrap());
            }
            other => panic!("expected SOA, got {other:?}"),
        }
    }

    #[test]
    fn nxdomain_carries_soa_for_negative_caching() {
        let query = DnsPacket::from_bytes(&make_query("A")).unwrap();
        let resp = parsed(&DnsPacket::build_nxdomain_response(&query.message));
        assert!(resp.metadata.authoritative);
        assert!(resp.answers.is_empty());
        assert_negative_soa(&resp);
    }

    #[test]
    fn nodata_ip_response_carries_soa() {
        use std::net::Ipv4Addr;
        let query = DnsPacket::from_bytes(&make_query("AAAA")).unwrap();
        let resp = parsed(&DnsPacket::build_ip_response(
            &query.message,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        ));
        assert!(resp.answers.is_empty());
        assert_negative_soa(&resp);
    }

    #[test]
    fn positive_ip_response_has_no_soa() {
        use std::net::Ipv4Addr;
        let query = DnsPacket::from_bytes(&make_query("A")).unwrap();
        let resp = parsed(&DnsPacket::build_ip_response(
            &query.message,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        ));
        assert_eq!(resp.answers.len(), 1);
        assert_eq!(resp.answers[0].ttl, SYNTHETIC_TTL);
        assert!(resp.authorities.is_empty());
    }

    /// Every synthetic builder, as `(label, response bytes)`.
    fn all_synthetic_responses(query: &Message) -> Vec<(&'static str, Vec<u8>)> {
        use std::net::Ipv4Addr;
        vec![
            ("nxdomain", DnsPacket::build_nxdomain_response(query)),
            ("refused", DnsPacket::build_refused_response(query)),
            ("servfail", DnsPacket::build_servfail_response(query)),
            (
                "ip",
                DnsPacket::build_ip_response(query, IpAddr::V4(Ipv4Addr::LOCALHOST)),
            ),
        ]
    }

    #[test]
    fn synthetic_responses_do_not_echo_query_records() {
        let query = parsed(&message_bytes(|msg| {
            msg.add_answer(a_record());
            msg.add_authority(a_record());
            msg.add_additional(a_record());
        }));
        for (label, bytes) in all_synthetic_responses(&query) {
            let resp = parsed(&bytes);
            assert!(resp.additionals.is_empty(), "{label}: additional echoed");
            assert!(
                resp.authorities
                    .iter()
                    .all(|record| matches!(record.data, RData::SOA(_))),
                "{label}: authority echoed"
            );
            assert!(
                resp.answers
                    .iter()
                    .all(|record| record.ttl == SYNTHETIC_TTL),
                "{label}: answer echoed"
            );
        }
    }

    #[test]
    fn synthetic_responses_answer_edns_with_own_opt() {
        let query = parsed(&message_bytes(|msg| {
            let mut edns = Edns::new();
            edns.set_max_payload(4096);
            edns.set_dnssec_ok(true);
            edns.options_mut()
                .insert(EdnsOption::Unknown(65001, vec![1, 2, 3]));
            msg.set_edns(edns);
        }));
        for (label, bytes) in all_synthetic_responses(&query) {
            let edns = parsed(&bytes).edns.expect("OPT record missing");
            assert_eq!(edns.max_payload(), EDNS_PAYLOAD, "{label}");
            assert!(edns.flags().dnssec_ok, "{label}: DO bit not copied");
            assert!(
                edns.options().options.is_empty(),
                "{label}: client options reflected"
            );
        }
    }

    #[test]
    fn synthetic_responses_omit_opt_without_client_edns() {
        let query = parsed(&message_bytes(|_| {}));
        for (label, bytes) in all_synthetic_responses(&query) {
            assert!(parsed(&bytes).edns.is_none(), "{label}");
        }
    }

    #[test]
    fn synthetic_responses_copy_header_bits_and_clear_ad() {
        let query = parsed(&message_bytes(|msg| {
            msg.metadata.recursion_desired = true;
            msg.metadata.checking_disabled = true;
            msg.metadata.authentic_data = true;
        }));
        for (label, bytes) in all_synthetic_responses(&query) {
            let resp = parsed(&bytes);
            assert_eq!(resp.metadata.id, 0x4242, "{label}");
            assert_eq!(resp.metadata.message_type, MessageType::Response, "{label}");
            assert!(resp.metadata.recursion_desired, "{label}: RD");
            assert!(resp.metadata.recursion_available, "{label}: RA");
            assert!(resp.metadata.checking_disabled, "{label}: CD");
            assert!(!resp.metadata.authentic_data, "{label}: AD must be clear");
            assert_eq!(resp.queries, query.queries, "{label}: question");
        }
    }

    // --- screen: only standard queries reach the pipeline ---

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

    // --- fit_udp_response ---

    /// A query for example.com, with an EDNS OPT advertising `payload`.
    fn query_with_payload(payload: Option<u16>) -> Vec<u8> {
        message_bytes(|msg| {
            if let Some(size) = payload {
                let mut edns = hickory_resolver::proto::op::Edns::new();
                edns.set_max_payload(size);
                msg.set_edns(edns);
            }
        })
    }

    /// The response to `query` carrying `count` A records.
    fn response_with_answers(query: &[u8], count: usize) -> Vec<u8> {
        let mut msg = Message::from_vec(query).unwrap();
        msg.metadata.message_type = MessageType::Response;
        for idx in 0..count {
            msg.add_answer(Record::from_rdata(
                Name::from_ascii("example.com.").unwrap(),
                60,
                RData::A(A(std::net::Ipv4Addr::new(192, 0, 2, (idx % 250) as u8))),
            ));
        }
        msg.to_vec().unwrap()
    }

    #[test]
    fn client_udp_payload_follows_edns() {
        assert_eq!(client_udp_payload(&query_with_payload(None)), 512);
        assert_eq!(client_udp_payload(&query_with_payload(Some(1232))), 1232);
        assert_eq!(client_udp_payload(&query_with_payload(Some(100))), 512);
        assert_eq!(client_udp_payload(&[0x00]), 512);
    }

    #[test]
    fn fit_udp_response_keeps_responses_that_fit() {
        let query = query_with_payload(None);
        let small = response_with_answers(&query, 3);
        assert_eq!(fit_udp_response(&query, small.clone()), small);
        // 60 records do not fit 512 bytes but fit 4096.
        let query = query_with_payload(Some(4096));
        let big = response_with_answers(&query, 60);
        assert!(big.len() > 512);
        assert_eq!(fit_udp_response(&query, big.clone()), big);
    }

    #[test]
    fn fit_udp_response_truncates_with_tc_and_keeps_question_and_edns() {
        for payload in [None, Some(600)] {
            let query = query_with_payload(payload);
            let big = response_with_answers(&query, 60);
            let fitted = fit_udp_response(&query, big);
            assert!(fitted.len() <= client_udp_payload(&query));
            let msg = Message::from_vec(&fitted).unwrap();
            assert!(
                msg.metadata.truncation,
                "TC=1 so the client retries over TCP"
            );
            assert_eq!(msg.metadata.id, 0x4242);
            assert!(msg.answers.is_empty());
            assert_eq!(msg.queries.len(), 1);
            assert_eq!(
                msg.edns.is_some(),
                payload.is_some(),
                "OPT echoed iff asked"
            );
        }
    }

    #[test]
    fn fit_udp_response_unparsable_falls_back_to_a_tc_header() {
        let query = query_with_payload(None);
        let mut garbage = vec![0x42, 0x42, 0x81, 0x80];
        garbage.extend(std::iter::repeat_n(0xFF, 600));
        let fitted = fit_udp_response(&query, garbage);
        assert_eq!(fitted.len(), 12);
        let msg = Message::from_vec(&fitted).unwrap();
        assert!(msg.metadata.truncation);
        assert_eq!(msg.metadata.message_type, MessageType::Response);
    }
}
