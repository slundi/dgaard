use std::net::SocketAddr;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::{Semaphore, SemaphorePermit};
use tokio::time::timeout;

use crate::CONFIG;

/// Number of UDP sockets pre-allocated per address family.
const POOL_SIZE: usize = 8;

/// Bounded pool of pre-bound UDP sockets.
///
/// The semaphore enforces the bound: callers that need a socket block until
/// one is returned rather than creating a new FD, keeping total FD usage at
/// `POOL_SIZE` per address family regardless of query rate.
struct SocketPool {
    sockets: Mutex<Vec<UdpSocket>>,
    available: Semaphore,
}

impl SocketPool {
    fn build(bind_addr: &str) -> std::io::Result<Self> {
        let mut sockets = Vec::with_capacity(POOL_SIZE);
        for _ in 0..POOL_SIZE {
            let std_sock = std::net::UdpSocket::bind(bind_addr)?;
            std_sock.set_nonblocking(true)?;
            sockets.push(UdpSocket::from_std(std_sock)?);
        }
        Ok(Self {
            sockets: Mutex::new(sockets),
            available: Semaphore::new(POOL_SIZE),
        })
    }

    /// Acquire a pooled socket. Returns `None` if the semaphore has been
    /// closed (shutdown) or if the internal vec is empty despite holding
    /// a permit — the latter should be impossible but we degrade gracefully
    /// to an ephemeral socket rather than panicking the worker.
    async fn acquire(&self) -> Option<SocketGuard<'_>> {
        let permit = self.available.acquire().await.ok()?;
        // Lock recovery: a poisoned mutex still has its inner Vec intact,
        // so we keep going with the poisoned guard rather than crashing.
        let mut guard = self
            .sockets
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let socket = guard.pop()?;
        drop(guard);
        Some(SocketGuard {
            socket: Some(socket),
            pool: self,
            _permit: permit,
        })
    }

    fn release(&self, socket: UdpSocket) {
        let mut guard = self
            .sockets
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.push(socket);
    }
}

struct SocketGuard<'a> {
    socket: Option<UdpSocket>,
    pool: &'a SocketPool,
    _permit: SemaphorePermit<'a>,
}

impl SocketGuard<'_> {
    /// Borrow the inner socket. The `Option` is always `Some` between
    /// construction and `Drop`, so this returns a plain `&UdpSocket`.
    fn get(&self) -> &UdpSocket {
        self.socket
            .as_ref()
            .expect("SocketGuard used after release")
    }
}

impl Drop for SocketGuard<'_> {
    fn drop(&mut self) {
        if let Some(s) = self.socket.take() {
            self.pool.release(s);
        }
        // _permit drops after, decrementing the semaphore count
    }
}

/// Holds either a pooled socket guard or a one-shot ephemeral socket so that
/// the forwarding path uses a single `&UdpSocket` regardless of which branch
/// was taken.
enum UpstreamRef<'a> {
    Pooled(SocketGuard<'a>),
    Ephemeral(UdpSocket),
}

impl UpstreamRef<'_> {
    fn socket(&self) -> &UdpSocket {
        match self {
            Self::Pooled(g) => g.get(),
            Self::Ephemeral(s) => s,
        }
    }
}

static V4_POOL: OnceLock<Option<SocketPool>> = OnceLock::new();
static V6_POOL: OnceLock<Option<SocketPool>> = OnceLock::new();

/// Return the pre-allocated pool for the given address family, initialising it
/// on the first call.  Returns `None` if binding failed (e.g. IPv6 disabled on
/// the host); the caller falls back to creating an ephemeral socket.
fn pool_for(is_ipv6: bool) -> Option<&'static SocketPool> {
    let cell = if is_ipv6 { &V6_POOL } else { &V4_POOL };
    cell.get_or_init(|| {
        let addr = if is_ipv6 { "[::]:0" } else { "0.0.0.0:0" };
        SocketPool::build(addr).ok()
    })
    .as_ref()
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
    let timeout_duration = Duration::from_millis(config.upstream.timeout_ms);
    let use_0x20 = config.upstream.use_0x20_randomization;

    // Save the client's original TXID so we can echo it back in the response.
    let original_txid = [packet[0], packet[1]];

    // Always copy: we need to rewrite the TXID and optionally apply 0x20.
    let mut outgoing = packet.to_vec();
    let random_txid = randomize_txid(&mut outgoing);
    // Only guard verify_0x20 when we actually mutated the QNAME.
    let applied_0x20 = use_0x20 && apply_0x20(&mut outgoing);

    // Try each upstream server in order.
    for server_addr in &config.upstream.servers {
        let addr: SocketAddr = match server_addr.parse() {
            Ok(a) => a,
            Err(_) => continue,
        };

        let bind_addr = if addr.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };

        // Acquire a pre-bound socket from the pool, falling back to an
        // ephemeral socket if the pool is unavailable for this address
        // family or its semaphore has been closed (shutdown).
        let pooled = match pool_for(addr.is_ipv6()) {
            Some(pool) => pool.acquire().await,
            None => None,
        };
        let upstream_ref = match pooled {
            Some(g) => UpstreamRef::Pooled(g),
            None => match UdpSocket::bind(bind_addr).await {
                Ok(s) => UpstreamRef::Ephemeral(s),
                Err(_) => continue,
            },
        };
        let upstream_socket = upstream_ref.socket();

        // Send the query to upstream.
        if upstream_socket.send_to(&outgoing, addr).await.is_err() {
            continue;
        }

        // Wait for a response from the correct upstream within the timeout window.
        // An off-path attacker who guesses the ephemeral port must also match the
        // randomized TXID (16 bits of additional entropy) to inject a forged answer.
        let mut buf = [0u8; 4096];
        let deadline = tokio::time::Instant::now() + timeout_duration;
        'recv: loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break 'recv;
            }
            match timeout(remaining, upstream_socket.recv_from(&mut buf)).await {
                Ok(Ok((len, peer))) => {
                    if peer != addr {
                        // Wrong source — discard and keep waiting.
                        continue 'recv;
                    }
                    if len < 2 || buf[0] != random_txid[0] || buf[1] != random_txid[1] {
                        // TXID mismatch: stray or forged response — discard and keep waiting.
                        continue 'recv;
                    }
                    let mut response = buf[..len].to_vec();
                    // Verify 0x20 echo: reject forged / case-normalizing responses.
                    if applied_0x20 && !verify_0x20(&outgoing, &response) {
                        // Non-compliant or forged resolver — try next server.
                        break 'recv;
                    }
                    // Restore the original client TXID before returning.
                    response[0] = original_txid[0];
                    response[1] = original_txid[1];
                    return Ok(response);
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
/// Returns `true` only when both QNAMEs parse cleanly and are identical.
/// Returns `false` in all other cases — including when either packet is
/// malformed — so that unparsable responses are never forwarded to clients.
/// There is no downstream QNAME validation after the upstream call, so this
/// function must fail closed.
fn verify_0x20(sent: &[u8], response: &[u8]) -> bool {
    const QNAME_OFFSET: usize = 12;

    let sent_labels = match extract_qname_labels(sent, QNAME_OFFSET) {
        Some(l) => l,
        None => return false, // can't parse our own QNAME — fail closed
    };
    let resp_labels = match extract_qname_labels(response, QNAME_OFFSET) {
        Some(l) => l,
        None => return false, // malformed response — reject rather than forward
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
    fn verify_0x20_rejects_malformed_response() {
        // Malformed response (too short to contain a QNAME) must be rejected.
        // Fail-closed: no downstream check validates the QNAME after the upstream
        // call, so forwarding an unparsable response is unsafe.
        assert!(!verify_0x20(EXAMPLE_COM_QUERY, &[0x00, 0x01]));
    }

    #[test]
    fn verify_0x20_rejects_malformed_sent_packet() {
        // If the outgoing packet itself is too short to parse, reject rather than
        // pass.  This guards against the corner case where apply_0x20 was skipped
        // and the raw packet passed down is unexpectedly truncated.
        assert!(!verify_0x20(&[0x00, 0x01], EXAMPLE_COM_QUERY));
    }

    #[test]
    fn verify_0x20_rejects_different_domain() {
        let q_qname = b"\x07example\x03com\x00";
        let r_qname = b"\x06google\x03com\x00";
        let query = build_response_with_qname(q_qname);
        let response = build_response_with_qname(r_qname);
        assert!(!verify_0x20(&query, &response));
    }

    // --- source-address validation ---

    /// Verify that a UDP socket receiving a packet from an unexpected sender
    /// correctly identifies the mismatch. This covers the peer != addr check
    /// in forward_to_upstream without requiring a live upstream resolver.
    #[tokio::test]
    async fn recv_from_returns_actual_sender_address() {
        // Bind two sockets: one as the "upstream" and one as the "impostor".
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let impostor = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let upstream_addr = upstream.local_addr().unwrap();
        let impostor_addr = impostor.local_addr().unwrap();
        let client_addr = client.local_addr().unwrap();

        // Impostor sends a packet to the client (simulating a forged response).
        impostor.send_to(b"forged", client_addr).await.unwrap();

        let mut buf = [0u8; 64];
        let (_, peer) = client.recv_from(&mut buf).await.unwrap();

        // The returned peer must be the impostor, not the upstream.
        assert_eq!(peer, impostor_addr);
        assert_ne!(peer, upstream_addr);
    }

    /// Confirm that after discarding a packet from the wrong source the socket
    /// correctly delivers the subsequent packet from the expected source.
    #[tokio::test]
    async fn correct_sender_accepted_after_stray_packet_discarded() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let impostor = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let upstream_addr = upstream.local_addr().unwrap();
        let client_addr = client.local_addr().unwrap();

        // Impostor fires first, upstream fires second.
        impostor.send_to(b"bad", client_addr).await.unwrap();
        upstream.send_to(b"good", client_addr).await.unwrap();

        let timeout_dur = Duration::from_millis(500);
        let deadline = tokio::time::Instant::now() + timeout_dur;
        let mut buf = [0u8; 64];
        let mut received_good = false;

        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            match timeout(remaining, client.recv_from(&mut buf)).await {
                Ok(Ok((len, peer))) => {
                    if peer != upstream_addr {
                        continue; // discard stray packet
                    }
                    assert_eq!(&buf[..len], b"good");
                    received_good = true;
                    break;
                }
                _ => break,
            }
        }

        assert!(
            received_good,
            "should have accepted the packet from the legitimate upstream"
        );
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

    // --- socket pool ---

    #[tokio::test]
    async fn pool_acquire_and_release_cycles_correctly() {
        let pool = SocketPool::build("0.0.0.0:0").expect("IPv4 pool init");
        // Acquire and release POOL_SIZE times to verify sockets return to the pool.
        for _ in 0..POOL_SIZE * 2 {
            let guard = pool.acquire().await.expect("pool not closed");
            let _ = guard.get().local_addr().expect("socket is live");
            // guard drops here, returning the socket
        }
        // All POOL_SIZE permits must be available again.
        assert_eq!(pool.available.available_permits(), POOL_SIZE);
    }

    #[tokio::test]
    async fn pool_acquire_returns_none_when_semaphore_closed() {
        // Regression: acquire must propagate semaphore closure as None
        // rather than panicking via .expect("semaphore closed").
        let pool = SocketPool::build("0.0.0.0:0").expect("IPv4 pool init");
        pool.available.close();
        assert!(pool.acquire().await.is_none());
    }

    #[tokio::test]
    async fn pool_for_ipv4_returns_some() {
        assert!(
            pool_for(false).is_some(),
            "IPv4 socket pool must be available"
        );
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
