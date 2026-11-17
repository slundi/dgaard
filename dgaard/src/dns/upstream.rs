use std::net::SocketAddr;
use std::time::Duration;

use hickory_resolver::proto::op::Message;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::CONFIG;

/// Payload size every DNS server must handle without EDNS (RFC 1035 §4.2.1).
const CLASSIC_UDP_PAYLOAD: usize = 512;

/// DNS header length; the question section starts right after it.
const HEADER_LEN: usize = 12;

/// Largest response the client can accept: the EDNS payload size its query
/// advertises (RFC 6891 §6.2.3), or 512 bytes without EDNS. A server must
/// truncate (TC=1) anything larger, so a bigger datagram is a protocol
/// violation and is never relayed.
fn advertised_payload(query: &[u8]) -> usize {
    Message::from_vec(query)
        .map(|msg| usize::from(msg.max_payload()))
        .unwrap_or(CLASSIC_UDP_PAYLOAD)
        .max(CLASSIC_UDP_PAYLOAD)
}

/// A fresh UDP socket on a kernel-chosen random port, connected to `addr`.
///
/// One socket per upstream attempt: an off-path attacker must guess the
/// source port (~16 bits) on top of the TXID (16 bits) and the 0x20 case
/// pattern, and connecting makes the kernel drop datagrams from any other
/// source. File descriptors stay bounded by the global query semaphore.
async fn connected_socket(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    let bind_addr = if addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = UdpSocket::bind(bind_addr).await?;
    socket.connect(addr).await?;
    Ok(socket)
}

/// What to do with a datagram received from the upstream server.
#[derive(Debug, PartialEq, Eq)]
enum ResponseCheck {
    /// The answer to our query: relay it.
    Accept,
    /// Not the answer (stray, forged, our own query echoed): keep waiting
    /// for the real one within the timeout.
    Ignore,
    /// This server cannot give a usable answer: try the next one.
    Reject,
}

/// Classify `response` against the query we `sent` with `txid`.
///
/// `buffer_len` is the receive buffer size: a datagram filling it was cut
/// by `recv` and cannot be relayed. With `case_sensitive` (0x20 applied),
/// a question echoed with another case means a non-compliant or forged
/// server — waiting would never yield a match.
fn check_response(
    sent: &[u8],
    response: &[u8],
    buffer_len: usize,
    txid: [u8; 2],
    case_sensitive: bool,
) -> ResponseCheck {
    if response.len() >= buffer_len {
        return ResponseCheck::Reject;
    }
    if response.len() < HEADER_LEN || response[..2] != txid {
        return ResponseCheck::Ignore;
    }
    // QR bit (RFC 1035 §4.1.1): only responses answer a query.
    if response[2] & 0x80 == 0 {
        return ResponseCheck::Ignore;
    }
    match compare_questions(sent, response) {
        QuestionMatch::Same => ResponseCheck::Accept,
        QuestionMatch::CaseDiffers if !case_sensitive => ResponseCheck::Accept,
        QuestionMatch::CaseDiffers => ResponseCheck::Reject,
        QuestionMatch::Different => ResponseCheck::Ignore,
    }
}

/// Forward a DNS query to an upstream server and return the response.
pub(crate) async fn forward_to_upstream(packet: &[u8]) -> std::io::Result<Vec<u8>> {
    if packet.len() < 2 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "DNS packet too short to contain a TXID",
        ));
    }

    let config = CONFIG.load();
    let timeout_duration = Duration::from_millis(config.forwarder.timeout_ms);
    let use_0x20 = config.forwarder.use_0x20_randomization;

    // Save the client's original TXID so we can echo it back in the response.
    let original_txid = [packet[0], packet[1]];

    // Always copy: we need to rewrite the TXID and optionally apply 0x20.
    let mut outgoing = packet.to_vec();
    let random_txid = randomize_txid(&mut outgoing);
    // Only compare case-sensitively when we actually mutated the QNAME.
    let applied_0x20 = use_0x20 && apply_0x20(&mut outgoing);
    // One extra byte detects a datagram larger than the client accepts.
    let mut buf = vec![0u8; advertised_payload(packet) + 1];

    // Try each upstream server in order, each within its own timeout.
    for server_addr in &config.forwarder.servers {
        let addr: SocketAddr = match server_addr.parse() {
            Ok(a) => a,
            Err(_) => continue,
        };
        let Ok(socket) = connected_socket(addr).await else {
            continue;
        };
        if socket.send(&outgoing).await.is_err() {
            continue;
        }

        let deadline = tokio::time::Instant::now() + timeout_duration;
        'recv: loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break 'recv;
            }
            // A connected socket also reports ICMP port-unreachable as an
            // error, which moves on to the next server without waiting.
            match timeout(remaining, socket.recv(&mut buf)).await {
                Ok(Ok(len)) => {
                    match check_response(
                        &outgoing,
                        &buf[..len],
                        buf.len(),
                        random_txid,
                        applied_0x20,
                    ) {
                        ResponseCheck::Accept => {
                            let mut response = buf[..len].to_vec();
                            // Restore the original client TXID before returning.
                            response[0] = original_txid[0];
                            response[1] = original_txid[1];
                            return Ok(response);
                        }
                        ResponseCheck::Ignore => continue 'recv,
                        ResponseCheck::Reject => break 'recv,
                    }
                }
                Ok(Err(_)) | Err(_) => break 'recv,
            }
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "All upstream servers failed",
    ))
}

/// Replace the 2-byte Transaction ID in a DNS packet with OS-provided random
/// bytes and return the new TXID.
///
/// If the entropy source fails or `packet` is shorter than 2 bytes the field
/// is left unchanged and the existing value is returned, preserving liveness.
fn randomize_txid(packet: &mut [u8]) -> [u8; 2] {
    if packet.len() >= 2 {
        let mut rnd = [0u8; 2];
        if getrandom::fill(&mut rnd).is_ok() {
            packet[0] = rnd[0];
            packet[1] = rnd[1];
        }
        [packet[0], packet[1]]
    } else {
        [0, 0]
    }
}

/// Randomize the ASCII case of alphabetic bytes in the QNAME of a DNS query
/// packet (DNS0x20, Dagon et al. 2008).
///
/// Modifies `packet` in place and returns `true` on success. Returns `false`
/// if the packet is too short, malformed, or entropy is unavailable — the
/// caller should fall back to sending the unmodified original.
///
/// The QNAME starts at byte 12 (immediately after the fixed-size DNS header).
/// For each label byte that is an ASCII letter, bit 5 is randomly set or
/// cleared, toggling between upper- and lower-case. All other bytes (digits,
/// hyphens, length prefix, null terminator) are left untouched.
fn apply_0x20(packet: &mut [u8]) -> bool {
    const QNAME_OFFSET: usize = 12;
    if packet.len() <= QNAME_OFFSET {
        return false;
    }

    // Fill a scratch buffer with OS-provided entropy.
    let mut rnd = [0u8; 256];
    if getrandom::fill(&mut rnd).is_err() {
        return false;
    }
    let mut rnd_idx = 0usize;

    let mut pos = QNAME_OFFSET;
    loop {
        if pos >= packet.len() {
            return false;
        }
        let label_len = packet[pos] as usize;
        if label_len == 0 {
            return true; // null terminator — done
        }
        // Compression pointers should not appear in an outgoing query.
        if label_len & 0xC0 == 0xC0 {
            return false;
        }
        let label_end = pos + 1 + label_len;
        if label_end > packet.len() {
            return false;
        }
        for byte in &mut packet[pos + 1..label_end] {
            if byte.is_ascii_alphabetic() {
                // Replace bit 5 with a random bit to toggle case.
                *byte = (*byte & !0x20u8) | (rnd[rnd_idx & 0xFF] & 0x20);
                rnd_idx = rnd_idx.wrapping_add(1);
            }
        }
        pos = label_end;
    }
}

/// Extract the raw label bytes of a QNAME from a DNS wire-format packet,
/// starting at `offset`, following compression pointers if present.
///
/// Returns the labels (raw bytes, without length prefixes) and the offset
/// right after the name *where it starts* (after the pointer when the name
/// is compressed). Returns `None` if the packet is malformed.
fn extract_qname_labels(packet: &[u8], mut pos: usize) -> Option<(Vec<Vec<u8>>, usize)> {
    let mut labels: Vec<Vec<u8>> = Vec::new();
    let mut hops = 0u8; // guard against pointer loops (max 5 hops)
    let mut end: Option<usize> = None;

    loop {
        if pos >= packet.len() {
            return None;
        }
        let b = packet[pos];
        if b == 0 {
            return Some((labels, end.unwrap_or(pos + 1))); // null terminator
        }
        if b & 0xC0 == 0xC0 {
            // Compression pointer: 14-bit offset into the packet.
            if pos + 1 >= packet.len() || hops >= 5 {
                return None;
            }
            let ptr = (((b & 0x3F) as usize) << 8) | (packet[pos + 1] as usize);
            if ptr >= packet.len() {
                return None;
            }
            end.get_or_insert(pos + 2);
            pos = ptr;
            hops += 1;
            continue;
        }
        let label_len = b as usize;
        let label_start = pos + 1;
        let label_end = label_start + label_len;
        if label_end > packet.len() {
            return None;
        }
        labels.push(packet[label_start..label_end].to_vec());
        pos = label_end;
    }
}

/// The single question of a DNS message: QNAME labels, QTYPE, QCLASS.
/// `None` unless QDCOUNT is 1 and the question parses.
fn parse_question(packet: &[u8]) -> Option<(Vec<Vec<u8>>, [u8; 4])> {
    if packet.len() < HEADER_LEN || packet[4..6] != [0, 1] {
        return None;
    }
    let (labels, end) = extract_qname_labels(packet, HEADER_LEN)?;
    let type_and_class: [u8; 4] = packet.get(end..end + 4)?.try_into().ok()?;
    Some((labels, type_and_class))
}

/// How the question echoed in a response compares to the one we sent.
#[derive(Debug, PartialEq, Eq)]
enum QuestionMatch {
    /// Same name (byte for byte), type and class.
    Same,
    /// Same name ignoring ASCII case, same type and class.
    CaseDiffers,
    /// Another question, or none that parses: fails closed.
    Different,
}

/// Compare the question of `response` with the one we `sent`. There is no
/// downstream question check after the upstream call, so anything that
/// does not parse counts as [`QuestionMatch::Different`].
fn compare_questions(sent: &[u8], response: &[u8]) -> QuestionMatch {
    let (Some((sent_labels, sent_tc)), Some((resp_labels, resp_tc))) =
        (parse_question(sent), parse_question(response))
    else {
        return QuestionMatch::Different;
    };
    if sent_tc != resp_tc || sent_labels.len() != resp_labels.len() {
        return QuestionMatch::Different;
    }
    if sent_labels == resp_labels {
        return QuestionMatch::Same;
    }
    let same_ignoring_case = sent_labels
        .iter()
        .zip(&resp_labels)
        .all(|(s, r)| s.eq_ignore_ascii_case(r));
    if same_ignoring_case {
        QuestionMatch::CaseDiffers
    } else {
        QuestionMatch::Different
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    use hickory_resolver::proto::op::{Edns, MessageType, Query, ResponseCode};
    use hickory_resolver::proto::rr::{Name, RecordType};

    use crate::config::Config;
    use crate::dns::packet::DnsPacket;
    use crate::resolve::tests::run_with_globals;

    use super::*;

    // Minimal DNS query for "example.com" type A, class IN.
    // Header (12 bytes) + QNAME + QTYPE + QCLASS
    const EXAMPLE_COM_QUERY: &[u8] = &[
        0x00, 0x01, // Transaction ID
        0x01, 0x00, // Flags: Standard query
        0x00, 0x01, // Questions: 1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Answers/Authority/Additional: 0
        // QNAME: "example.com"
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', // "example"
        0x03, b'c', b'o', b'm', // "com"
        0x00, // null terminator
        0x00, 0x01, // QTYPE: A
        0x00, 0x01, // QCLASS: IN
    ];

    /// Build a minimal response packet whose question section QNAME is given by
    /// `qname_bytes` (raw wire format labels, including length prefixes and the
    /// null terminator).
    fn build_response_with_qname(qname_bytes: &[u8]) -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[
            0x00, 0x01, // ID (matches query)
            0x81, 0x80, // Flags: response, no error
            0x00, 0x01, // QDCOUNT: 1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        pkt.extend_from_slice(qname_bytes);
        pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE + QCLASS
        pkt
    }

    /// `query` turned into a (NOERROR, no answer) response echoing its
    /// question byte for byte.
    fn echo_response(query: &[u8]) -> Vec<u8> {
        let mut response = query.to_vec();
        response[2] |= 0x80;
        response
    }

    // --- randomize_txid ---

    #[test]
    fn randomize_txid_rewrites_header_bytes() {
        let mut pkt = EXAMPLE_COM_QUERY.to_vec();
        let returned = randomize_txid(&mut pkt);
        // Returned value must reflect what is now in the packet.
        assert_eq!(returned, [pkt[0], pkt[1]]);
        // Bytes beyond the header must be unchanged.
        assert_eq!(&pkt[2..], &EXAMPLE_COM_QUERY[2..]);
    }

    #[test]
    fn randomize_txid_produces_random_values() {
        // P(false negative) = (1/65536)^100 ≈ 0 — any collision is a collision
        let original = [EXAMPLE_COM_QUERY[0], EXAMPLE_COM_QUERY[1]];
        let mut any_different = false;
        for _ in 0..100 {
            let mut pkt = EXAMPLE_COM_QUERY.to_vec();
            let returned = randomize_txid(&mut pkt);
            if returned != original {
                any_different = true;
                break;
            }
        }
        assert!(
            any_different,
            "TXID was never randomized over 100 iterations"
        );
    }

    #[test]
    fn randomize_txid_short_packet_returns_zeros() {
        let mut pkt = vec![0x01u8]; // shorter than 2 bytes
        assert_eq!(randomize_txid(&mut pkt), [0, 0]);
    }

    #[test]
    fn randomize_txid_original_txid_restored_in_response() {
        // Simulate the full round-trip: save original, randomize, restore.
        let original_txid = [EXAMPLE_COM_QUERY[0], EXAMPLE_COM_QUERY[1]];
        let mut outgoing = EXAMPLE_COM_QUERY.to_vec();
        let random_txid = randomize_txid(&mut outgoing);

        // Simulate an upstream response that echoes our random TXID.
        let mut response = EXAMPLE_COM_QUERY.to_vec();
        response[0] = random_txid[0];
        response[1] = random_txid[1];

        // Restore original TXID.
        response[0] = original_txid[0];
        response[1] = original_txid[1];

        assert_eq!([response[0], response[1]], original_txid);
    }

    // --- apply_0x20 ---

    #[test]
    fn apply_0x20_preserves_length_bytes_and_null_terminator() {
        let mut pkt = EXAMPLE_COM_QUERY.to_vec();
        let original = pkt.clone();
        let ok = apply_0x20(&mut pkt);
        assert!(ok);

        // Header must be unchanged
        assert_eq!(&pkt[..12], &original[..12]);

        // QNAME length bytes and null terminator must be unchanged.
        // Offsets: 12=len(7), 20=len(3), 24=null
        assert_eq!(pkt[12], 0x07); // "example" label length
        assert_eq!(pkt[20], 0x03); // "com" label length
        assert_eq!(pkt[24], 0x00); // null terminator

        // Non-alpha byte in QNAME must be unchanged (digits/hyphens — none here,
        // but QTYPE/QCLASS bytes must be unchanged)
        assert_eq!(&pkt[25..], &original[25..]); // QTYPE + QCLASS
    }

    #[test]
    fn apply_0x20_only_flips_alpha_bytes() {
        let mut pkt = EXAMPLE_COM_QUERY.to_vec();
        let ok = apply_0x20(&mut pkt);
        assert!(ok);

        // Every byte that was alphabetic must still be alphabetic (case may differ).
        for (orig, modified) in EXAMPLE_COM_QUERY[13..20] // "example" bytes
            .iter()
            .zip(pkt[13..20].iter())
        {
            assert!(modified.is_ascii_alphabetic());
            // Case may or may not have flipped; letter identity preserved.
            assert_eq!(orig.to_ascii_lowercase(), modified.to_ascii_lowercase());
        }
        for (orig, modified) in EXAMPLE_COM_QUERY[21..24] // "com" bytes
            .iter()
            .zip(pkt[21..24].iter())
        {
            assert!(modified.is_ascii_alphabetic());
            assert_eq!(orig.to_ascii_lowercase(), modified.to_ascii_lowercase());
        }
    }

    #[test]
    fn apply_0x20_returns_false_for_short_packet() {
        let mut pkt = vec![0u8; 11]; // shorter than 12-byte header
        assert!(!apply_0x20(&mut pkt));
    }

    #[test]
    fn apply_0x20_returns_false_for_truncated_label() {
        // Header + length byte claiming 200 bytes but packet ends right away
        let mut pkt = vec![0u8; 13];
        pkt[12] = 200; // label length 200 but packet only has 1 more byte
        assert!(!apply_0x20(&mut pkt));
    }

    // --- extract_qname_labels / parse_question ---

    #[test]
    fn extract_qname_labels_example_com() {
        let (labels, end) = extract_qname_labels(EXAMPLE_COM_QUERY, 12).unwrap();
        assert_eq!(labels, [b"example".to_vec(), b"com".to_vec()]);
        assert_eq!(end, 25, "right after the null terminator");
    }

    #[test]
    fn extract_qname_labels_handles_compression_pointer() {
        // QNAME at offset 12 is a pointer to "com\0" at offset 20.
        let mut pkt = vec![0u8; 30];
        pkt[12] = 0xC0;
        pkt[13] = 0x14;
        pkt[20..25].copy_from_slice(b"\x03com\x00");
        let (labels, end) = extract_qname_labels(&pkt, 12).unwrap();
        assert_eq!(labels, [b"com".to_vec()]);
        assert_eq!(end, 14, "the name ends after the pointer where it starts");
    }

    #[test]
    fn extract_qname_labels_returns_none_for_truncated_packet() {
        let pkt = [0x07, b'e', b'x', b'a'];
        assert!(extract_qname_labels(&pkt, 0).is_none());
    }

    #[test]
    fn parse_question_requires_exactly_one_question() {
        assert!(parse_question(EXAMPLE_COM_QUERY).is_some());
        let mut none = EXAMPLE_COM_QUERY.to_vec();
        none[5] = 0;
        assert!(parse_question(&none).is_none());
        let mut two = EXAMPLE_COM_QUERY.to_vec();
        two[5] = 2;
        assert!(parse_question(&two).is_none());
        // Type and class missing.
        assert!(parse_question(&EXAMPLE_COM_QUERY[..26]).is_none());
    }

    // --- compare_questions ---

    #[test]
    fn compare_questions_same_and_case() {
        let query = build_response_with_qname(b"\x07eXaMpLe\x03CoM\x00");
        assert_eq!(compare_questions(&query, &query), QuestionMatch::Same);
        let lower = build_response_with_qname(b"\x07example\x03com\x00");
        assert_eq!(
            compare_questions(&query, &lower),
            QuestionMatch::CaseDiffers
        );
    }

    #[test]
    fn compare_questions_different_name_type_or_malformed() {
        let query = build_response_with_qname(b"\x07example\x03com\x00");
        let other = build_response_with_qname(b"\x06google\x03com\x00");
        assert_eq!(compare_questions(&query, &other), QuestionMatch::Different);
        let mut aaaa = query.clone();
        let qtype_at = aaaa.len() - 3;
        aaaa[qtype_at] = 28;
        assert_eq!(compare_questions(&query, &aaaa), QuestionMatch::Different);
        // Fail closed on anything that does not parse, on either side.
        assert_eq!(
            compare_questions(&query, &[0x00, 0x01]),
            QuestionMatch::Different
        );
        assert_eq!(
            compare_questions(&[0x00, 0x01], &query),
            QuestionMatch::Different
        );
    }

    // --- check_response ---

    const TXID: [u8; 2] = [0x00, 0x01];

    fn check(response: &[u8], case_sensitive: bool) -> ResponseCheck {
        check_response(EXAMPLE_COM_QUERY, response, 513, TXID, case_sensitive)
    }

    #[test]
    fn check_response_accepts_the_answer() {
        assert_eq!(
            check(&echo_response(EXAMPLE_COM_QUERY), true),
            ResponseCheck::Accept
        );
    }

    #[test]
    fn check_response_ignores_strays_and_forgeries() {
        let mut wrong_txid = echo_response(EXAMPLE_COM_QUERY);
        wrong_txid[1] = 0x02;
        assert_eq!(check(&wrong_txid, true), ResponseCheck::Ignore);
        // Our own query reflected back (QR=0).
        assert_eq!(check(EXAMPLE_COM_QUERY, true), ResponseCheck::Ignore);
        let other = build_response_with_qname(b"\x06google\x03com\x00");
        assert_eq!(check(&other, false), ResponseCheck::Ignore);
        assert_eq!(check(&[0x00, 0x01, 0x81], false), ResponseCheck::Ignore);
    }

    #[test]
    fn check_response_case_mismatch_depends_on_0x20() {
        let mut sent = EXAMPLE_COM_QUERY.to_vec();
        sent[13] = b'E';
        let response = echo_response(EXAMPLE_COM_QUERY);
        assert_eq!(
            check_response(&sent, &response, 513, TXID, true),
            ResponseCheck::Reject
        );
        assert_eq!(
            check_response(&sent, &response, 513, TXID, false),
            ResponseCheck::Accept
        );
    }

    #[test]
    fn check_response_rejects_a_datagram_filling_the_buffer() {
        let mut big = echo_response(EXAMPLE_COM_QUERY);
        big.resize(513, 0);
        assert_eq!(check(&big, false), ResponseCheck::Reject);
    }

    // --- advertised_payload ---

    fn query_with_edns(payload: Option<u16>) -> Vec<u8> {
        let mut msg = Message::query();
        msg.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
        ));
        if let Some(size) = payload {
            let mut edns = Edns::new();
            edns.set_max_payload(size);
            msg.set_edns(edns);
        }
        msg.to_vec().unwrap()
    }

    #[test]
    fn advertised_payload_follows_edns() {
        assert_eq!(advertised_payload(&query_with_edns(None)), 512);
        assert_eq!(advertised_payload(&query_with_edns(Some(1232))), 1232);
        assert_eq!(advertised_payload(&query_with_edns(Some(4096))), 4096);
        // Below the classic minimum, and garbage, fall back to 512.
        assert_eq!(advertised_payload(&query_with_edns(Some(100))), 512);
        assert_eq!(advertised_payload(&[0x00]), 512);
    }

    // --- forward_to_upstream against mock upstream servers (review E5) ---

    /// Datagrams a mock upstream sends back for one query, in order.
    type Behaviour = Arc<dyn Fn(&[u8]) -> Vec<Vec<u8>> + Send + Sync>;

    /// Mock upstream on 127.0.0.1: for every query, after `delay`, send what
    /// `behaviour` returns. Records each query's source port.
    async fn spawn_upstream(
        behaviour: Behaviour,
        delay: Duration,
    ) -> (String, Arc<Mutex<Vec<u16>>>) {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = socket.local_addr().unwrap().to_string();
        let ports = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&ports);
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            while let Ok((len, peer)) = socket.recv_from(&mut buf).await {
                seen.lock().unwrap().push(peer.port());
                let replies = behaviour(&buf[..len]);
                let socket = Arc::clone(&socket);
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    for reply in replies {
                        let _ = socket.send_to(&reply, peer).await;
                    }
                });
            }
        });
        (addr, ports)
    }

    fn answering() -> Behaviour {
        Arc::new(|query| vec![echo_response(query)])
    }

    fn silent() -> Behaviour {
        Arc::new(|_| Vec::new())
    }

    fn set_forwarder(servers: &[&str], timeout_ms: u64, use_0x20: bool) {
        let mut config = Config::default();
        config.forwarder.servers = servers.iter().map(|s| s.to_string()).collect();
        config.forwarder.timeout_ms = timeout_ms;
        config.forwarder.use_0x20_randomization = use_0x20;
        CONFIG.store(Arc::new(config));
    }

    fn client_query(id: u16) -> Vec<u8> {
        let mut msg = Message::query();
        msg.metadata.id = id;
        msg.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
        ));
        msg.to_vec().unwrap()
    }

    /// Run `count` forwards concurrently; return how many succeeded and
    /// the wall time.
    async fn forward_concurrently(count: u16) -> (usize, Duration) {
        let started = Instant::now();
        let mut tasks = tokio::task::JoinSet::new();
        for id in 0..count {
            tasks.spawn(async move { forward_to_upstream(&client_query(id)).await });
        }
        let mut ok = 0;
        while let Some(result) = tasks.join_next().await {
            ok += usize::from(result.unwrap().is_ok());
        }
        (ok, started.elapsed())
    }

    #[test]
    fn concurrent_queries_are_not_capped_by_a_socket_pool() {
        // 64 queries to a 200 ms upstream: a pool of 8 serialised them into
        // 8 waves (>= 1.6 s); per-query sockets run them side by side.
        run_with_globals(async {
            let (addr, _) = spawn_upstream(answering(), Duration::from_millis(200)).await;
            set_forwarder(&[&addr], 2000, true);
            let (ok, elapsed) = forward_concurrently(64).await;
            assert_eq!(ok, 64);
            assert!(elapsed < Duration::from_secs(1), "took {elapsed:?}");
        });
    }

    #[test]
    fn silent_upstream_fails_within_the_timeout_under_load() {
        // Waiting for a socket no longer adds to the timeout.
        run_with_globals(async {
            let (addr, _) = spawn_upstream(silent(), Duration::ZERO).await;
            set_forwarder(&[&addr], 150, true);
            let (ok, elapsed) = forward_concurrently(64).await;
            assert_eq!(ok, 0);
            assert!(elapsed < Duration::from_millis(600), "took {elapsed:?}");
        });
    }

    #[test]
    fn each_query_uses_a_fresh_source_port() {
        run_with_globals(async {
            let (addr, ports) = spawn_upstream(answering(), Duration::ZERO).await;
            set_forwarder(&[&addr], 1000, true);
            for id in 0..20 {
                forward_to_upstream(&client_query(id)).await.unwrap();
            }
            let mut seen = ports.lock().unwrap().clone();
            seen.sort_unstable();
            seen.dedup();
            // Kernel-random ports: a collision among 20 is rare, two are not
            // plausible. A fixed pool of 8 would show at most 8.
            assert!(seen.len() >= 19, "only {} distinct ports", seen.len());
        });
    }

    #[test]
    fn strays_with_the_right_txid_are_ignored_until_the_answer() {
        run_with_globals(async {
            let behaviour: Behaviour = Arc::new(|query| {
                let mut wrong_question = Message::from_vec(query).unwrap();
                wrong_question.metadata.message_type = MessageType::Response;
                wrong_question.queries.clear();
                wrong_question.add_query(Query::query(
                    Name::from_ascii("forged.example.").unwrap(),
                    RecordType::A,
                ));
                vec![
                    query.to_vec(), // our query reflected (QR=0)
                    wrong_question.to_vec().unwrap(),
                    echo_response(query),
                ]
            });
            let (addr, _) = spawn_upstream(behaviour, Duration::ZERO).await;
            set_forwarder(&[&addr], 1000, true);
            let response = forward_to_upstream(&client_query(0x1234)).await.unwrap();
            let parsed = Message::from_vec(&response).unwrap();
            assert_eq!(parsed.metadata.id, 0x1234, "client TXID restored");
            assert_eq!(parsed.metadata.message_type, MessageType::Response);
            assert_eq!(
                parsed.queries[0].name().to_ascii().to_ascii_lowercase(),
                "example.com."
            );
        });
    }

    #[test]
    fn datagram_from_another_source_is_dropped() {
        // An impostor that knows our port and TXID still is not the server
        // our socket is connected to.
        run_with_globals(async {
            let impostor = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let addr = socket.local_addr().unwrap().to_string();
            let server = Arc::clone(&socket);
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let (len, peer) = server.recv_from(&mut buf).await.unwrap();
                let mut forged = echo_response(&buf[..len]);
                forged[3] = (forged[3] & 0xF0) | 3; // NXDOMAIN
                impostor.send_to(&forged, peer).await.unwrap();
                tokio::time::sleep(Duration::from_millis(50)).await;
                server
                    .send_to(&echo_response(&buf[..len]), peer)
                    .await
                    .unwrap();
            });
            set_forwarder(&[&addr], 1000, true);
            let response = forward_to_upstream(&client_query(7)).await.unwrap();
            let parsed = Message::from_vec(&response).unwrap();
            assert_eq!(parsed.metadata.response_code, ResponseCode::NoError);
        });
    }

    #[test]
    fn oversized_response_is_never_relayed() {
        // Larger than the 512 bytes a non-EDNS client accepts: truncated by
        // recv, so the next server is asked instead.
        run_with_globals(async {
            let oversized: Behaviour = Arc::new(|query| {
                let mut big = echo_response(query);
                big.resize(700, 0);
                vec![big]
            });
            let (first, _) = spawn_upstream(oversized, Duration::ZERO).await;
            let (second, second_ports) = spawn_upstream(answering(), Duration::ZERO).await;
            set_forwarder(&[&first, &second], 500, true);
            let response = forward_to_upstream(&client_query(9)).await.unwrap();
            assert!(response.len() < 512);
            assert_eq!(second_ports.lock().unwrap().len(), 1);
        });
    }

    #[test]
    fn case_normalizing_server_is_skipped_only_with_0x20() {
        run_with_globals(async {
            let lowercasing: Behaviour = Arc::new(|query| {
                let mut response = echo_response(query);
                let (_, end) = extract_qname_labels(query, HEADER_LEN).unwrap();
                response[HEADER_LEN..end].make_ascii_lowercase();
                vec![response]
            });
            let (first, _) = spawn_upstream(lowercasing, Duration::ZERO).await;
            let (second, second_ports) = spawn_upstream(answering(), Duration::ZERO).await;

            set_forwarder(&[&first, &second], 500, true);
            forward_to_upstream(&client_query(1)).await.unwrap();
            assert_eq!(
                second_ports.lock().unwrap().len(),
                1,
                "0x20 on: next server"
            );

            set_forwarder(&[&first, &second], 500, false);
            forward_to_upstream(&client_query(2)).await.unwrap();
            assert_eq!(
                second_ports.lock().unwrap().len(),
                1,
                "0x20 off: first answer kept"
            );
        });
    }

    #[test]
    fn test_dns_packet_aaaa_query() {
        let packet = [
            0x00, 0x02, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x1C, 0x00,
            0x01,
        ];
        let result = DnsPacket::from_bytes(&packet);
        assert!(result.is_some());
        let dns_packet = result.unwrap();
        assert_eq!(dns_packet.domain, "example.com");
        let query = dns_packet.message.queries.first().unwrap();
        assert_eq!(
            query.query_type(),
            hickory_resolver::proto::rr::RecordType::AAAA
        );
    }
}
