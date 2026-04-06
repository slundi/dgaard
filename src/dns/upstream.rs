use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::CONFIG;

/// Forward a DNS query to an upstream server and return the response.
pub(crate) async fn forward_to_upstream(packet: &[u8]) -> std::io::Result<Vec<u8>> {
    let config = CONFIG.load();
    let timeout_duration = Duration::from_millis(config.upstream.timeout_ms);

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
        if upstream_socket.send_to(packet, addr).await.is_err() {
            continue;
        }

        // Wait for response with timeout
        let mut buf = [0u8; 4096];
        match timeout(timeout_duration, upstream_socket.recv_from(&mut buf)).await {
            Ok(Ok((len, _))) => {
                return Ok(buf[..len].to_vec());
            }
            Ok(Err(_)) | Err(_) => {
                // Timeout or error, try next server
                continue;
            }
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "All upstream servers failed",
    ))
}

#[cfg(test)]
mod tests {
    use crate::dns::packet::DnsPacket;

    use super::*;

    // --- IPv6 upstream support tests ---

    #[test]
    fn test_ipv4_upstream_address_parsing() {
        let addr: SocketAddr = "1.1.1.1:53".parse().unwrap();
        assert!(!addr.is_ipv6());
        assert!(addr.is_ipv4());
    }

    #[test]
    fn test_ipv6_upstream_address_parsing() {
        // Cloudflare IPv6 DNS
        let addr: SocketAddr = "[2606:4700:4700::1111]:53".parse().unwrap();
        assert!(addr.is_ipv6());
        assert!(!addr.is_ipv4());

        // Google IPv6 DNS
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
        // Valid DNS query for "example.com" (type AAAA = 0x001C)
        let packet = [
            0x00, 0x02, // Transaction ID
            0x01, 0x00, // Flags: Standard query
            0x00, 0x01, // Questions: 1
            0x00, 0x00, // Answers: 0
            0x00, 0x00, // Authority: 0
            0x00, 0x00, // Additional: 0
            // Question: example.com, type AAAA
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', // "example"
            0x03, b'c', b'o', b'm', // "com"
            0x00, // null terminator
            0x00, 0x1C, // Type: AAAA (28)
            0x00, 0x01, // Class: IN
        ];

        let result = DnsPacket::from_bytes(&packet);
        assert!(result.is_some());
        let dns_packet = result.unwrap();
        assert_eq!(dns_packet.domain, "example.com");

        // Verify the query type is preserved
        let query = dns_packet.message.queries().first().unwrap();
        assert_eq!(
            query.query_type(),
            hickory_resolver::proto::rr::RecordType::AAAA
        );
    }
}
