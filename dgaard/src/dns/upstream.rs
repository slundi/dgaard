use std::borrow::Cow;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::CONFIG;

/// Forward a DNS query to an upstream server and return the response.
pub(crate) async fn forward_to_upstream(packet: &[u8]) -> std::io::Result<Vec<u8>> {
    let config = CONFIG.load();
    let timeout_duration = Duration::from_millis(config.upstream.timeout_ms);
    let use_0x20 = config.upstream.use_0x20_randomization;

    // Optionally apply 0x20 case randomization to the outgoing query.
    let outgoing: Cow<[u8]> = if use_0x20 {
        let mut modified = packet.to_vec();
        if apply_0x20(&mut modified) {
            Cow::Owned(modified)
        } else {
            Cow::Borrowed(packet)
        }
    } else {
        Cow::Borrowed(packet)
    };

    // Try each upstream server in order
    for server_addr in &config.upstream.servers {
        let addr: SocketAddr = match server_addr.parse() {
            Ok(a) => a,
            Err(_) => continue,
        };

        // Bind to appropriate address family based on upstream server type
        let bind_addr = if addr.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };

        // Create a new socket for upstream communication
        let upstream_socket = match UdpSocket::bind(bind_addr).await {
            Ok(s) => s,
            Err(_) => continue,
        };

        // Send the query to upstream
        if upstream_socket.send_to(&outgoing, addr).await.is_err() {
            continue;
        }

        // Wait for a response from the expected upstream address within the
        // timeout window. Datagrams arriving from any other source are silently
        // discarded and we keep waiting — a spoofed packet must not win the
        // race against the legitimate resolver.
        let mut buf = [0u8; 4096];
        let deadline = tokio::time::Instant::now() + timeout_duration;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            match timeout(remaining, upstream_socket.recv_from(&mut buf)).await {
                Ok(Ok((len, src))) => {
                    if src != addr {
                        continue;
                    }
                    let response = buf[..len].to_vec();
                    // Verify 0x20 echo: reject forged / case-normalizing responses.
                    if use_0x20 && !verify_0x20(&outgoing, &response) {
                        continue;
                    }
                    return Ok(response);
                }
                Ok(Err(_)) | Err(_) => break,
            }
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "All upstream servers failed",
    ))
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
/// Each element of the returned `Vec` is one label's raw bytes (excluding
/// the length prefix). Returns `None` if the packet is malformed.
fn extract_qname_labels(packet: &[u8], mut pos: usize) -> Option<Vec<Vec<u8>>> {
    let mut labels: Vec<Vec<u8>> = Vec::new();
    let mut hops = 0u8; // guard against pointer loops (max 5 hops)

    loop {
        if pos >= packet.len() {
            return None;
        }
        let b = packet[pos];
        if b == 0 {
            return Some(labels); // null terminator
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

/// Verify that the QNAME echoed in the response question section matches the
/// QNAME we sent, byte-for-byte (case-sensitive).
///
/// Returns `true` if the labels match or if either packet is too malformed to
/// extract a QNAME (we let other validation layers handle those). Returns
/// `false` only when both QNAMEs are parseable and differ — the response is
/// forged or from a non-RFC-compliant resolver.
fn verify_0x20(sent: &[u8], response: &[u8]) -> bool {
    const QNAME_OFFSET: usize = 12;

    let sent_labels = match extract_qname_labels(sent, QNAME_OFFSET) {
        Some(l) => l,
        None => return true, // can't parse our own QNAME — don't reject
    };
    let resp_labels = match extract_qname_labels(response, QNAME_OFFSET) {
        Some(l) => l,
        None => return true, // malformed response — let other checks handle it
    };

    sent_labels.len() == resp_labels.len()
        && sent_labels
            .iter()
            .zip(resp_labels.iter())
            .all(|(s, r)| s == r)
}

#[cfg(test)]
mod tests {
    use crate::dns::packet::DnsPacket;

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
        // Header
        pkt.extend_from_slice(&[
            0x00, 0x01, // ID (matches query)
            0x81, 0x80, // Flags: response, no error
            0x00, 0x01, // QDCOUNT: 1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        // QNAME
        pkt.extend_from_slice(qname_bytes);
        // QTYPE + QCLASS
        pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        pkt
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

    // --- extract_qname_labels ---

    #[test]
    fn extract_qname_labels_example_com() {
        let labels = extract_qname_labels(EXAMPLE_COM_QUERY, 12).unwrap();
        assert_eq!(labels.len(), 2);
        assert_eq!(labels[0], b"example");
        assert_eq!(labels[1], b"com");
    }

    #[test]
    fn extract_qname_labels_handles_compression_pointer() {
        // Packet where QNAME at offset 12 is a pointer to offset 20,
        // and at offset 20 there is "com\0".
        let mut pkt = vec![0u8; 30];
        // At offset 12: compression pointer to offset 20
        pkt[12] = 0xC0;
        pkt[13] = 0x14; // 0x14 = 20
        // At offset 20: label "com"
        pkt[20] = 0x03;
        pkt[21] = b'c';
        pkt[22] = b'o';
        pkt[23] = b'm';
        pkt[24] = 0x00;

        let labels = extract_qname_labels(&pkt, 12).unwrap();
        assert_eq!(labels.len(), 1);
        assert_eq!(labels[0], b"com");
    }

    #[test]
    fn extract_qname_labels_returns_none_for_truncated_packet() {
        // Length byte exceeds packet length
        let pkt = [0x07, b'e', b'x', b'a']; // too short
        assert!(extract_qname_labels(&pkt, 0).is_none());
    }

    // --- verify_0x20 ---

    #[test]
    fn verify_0x20_accepts_matching_qname() {
        let qname = b"\x07eXaMpLe\x03CoM\x00";
        let query = build_response_with_qname(qname); // reuse builder
        let response = build_response_with_qname(qname);
        assert!(verify_0x20(&query, &response));
    }

    #[test]
    fn verify_0x20_rejects_case_changed_qname() {
        // Query: "eXaMpLe.CoM", response: "example.com" (case normalised)
        let sent_qname = b"\x07eXaMpLe\x03CoM\x00";
        let resp_qname = b"\x07example\x03com\x00";
        let query = build_response_with_qname(sent_qname);
        let response = build_response_with_qname(resp_qname);
        assert!(!verify_0x20(&query, &response));
    }

    #[test]
    fn verify_0x20_accepts_when_response_malformed() {
        // Malformed response → don't reject (other checks will catch it)
        assert!(verify_0x20(EXAMPLE_COM_QUERY, &[0x00, 0x01]));
    }

    #[test]
    fn verify_0x20_rejects_different_domain() {
        let q_qname = b"\x07example\x03com\x00";
        let r_qname = b"\x06google\x03com\x00";
        let query = build_response_with_qname(q_qname);
        let response = build_response_with_qname(r_qname);
        assert!(!verify_0x20(&query, &response));
    }

    // --- Source address validation ---

    /// Regression test: a datagram arriving from an address other than the
    /// upstream server must be discarded and must not be returned as a valid
    /// response.  We simulate this by binding two sockets: a "spoofed" sender
    /// that replies immediately from a different port, and a "real" upstream
    /// that replies slightly later but from the expected address.
    #[tokio::test]
    async fn recv_from_ignores_unexpected_source() {
        use tokio::net::UdpSocket;

        // Bind the fake "upstream" server and an attacker socket on localhost.
        let real_upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let attacker = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let real_addr: SocketAddr = real_upstream.local_addr().unwrap();

        // Bind a client socket that will play the role of the proxy.
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();

        // The attacker fires a forged response before the real upstream does.
        let forged = b"FORGED_RESPONSE";
        attacker.send_to(forged, client_addr).await.unwrap();

        // The real upstream sends the legitimate response.
        let legit = b"LEGIT_RESPONSE__";
        real_upstream.send_to(legit, client_addr).await.unwrap();

        // The client must reject the forged datagram and return the legitimate one.
        let mut buf = [0u8; 64];
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        let mut received: Option<Vec<u8>> = None;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            match tokio::time::timeout(remaining, client.recv_from(&mut buf)).await {
                Ok(Ok((len, src))) => {
                    if src != real_addr {
                        continue;
                    }
                    received = Some(buf[..len].to_vec());
                    break;
                }
                _ => break,
            }
        }

        assert_eq!(received.as_deref(), Some(legit.as_slice()));
    }

    // --- IPv6 upstream support tests (unchanged) ---

    #[test]
    fn test_ipv4_upstream_address_parsing() {
        let addr: SocketAddr = "1.1.1.1:53".parse().unwrap();
        assert!(!addr.is_ipv6());
        assert!(addr.is_ipv4());
    }

    #[test]
    fn test_ipv6_upstream_address_parsing() {
        let addr: SocketAddr = "[2606:4700:4700::1111]:53".parse().unwrap();
        assert!(addr.is_ipv6());
        assert!(!addr.is_ipv4());

        let addr: SocketAddr = "[2001:4860:4860::8888]:53".parse().unwrap();
        assert!(addr.is_ipv6());
    }

    #[test]
    fn test_bind_address_selection_ipv4() {
        let addr: SocketAddr = "9.9.9.9:53".parse().unwrap();
        let bind_addr = if addr.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        assert_eq!(bind_addr, "0.0.0.0:0");
    }

    #[test]
    fn test_bind_address_selection_ipv6() {
        let addr: SocketAddr = "[2606:4700:4700::1111]:53".parse().unwrap();
        let bind_addr = if addr.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        assert_eq!(bind_addr, "[::]:0");
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
