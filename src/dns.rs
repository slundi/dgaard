use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use dgaard::{Action, StatAction, StatBlockReason};
use hickory_resolver::proto::op::{Message, MessageType, ResponseCode};
use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::resolve::resolve;
use crate::{CONFIG, STATS_COUNTERS, STATS_SENDER};

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

/// Forward a DNS query to an upstream server and return the response.
async fn forward_to_upstream(packet: &[u8]) -> std::io::Result<Vec<u8>> {
    let config = CONFIG.load();
    let timeout_duration = Duration::from_millis(config.upstream.timeout_ms);

    // Try each upstream server in order
    for server_addr in &config.upstream.servers {
        let addr: SocketAddr = match server_addr.parse() {
            Ok(a) => a,
            Err(_) => continue,
        };

        // Create a new socket for upstream communication
        let upstream_socket = UdpSocket::bind("0.0.0.0:0").await?;

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

/// Handle an incoming DNS query by running it through the filter pipeline.
///
/// This function:
/// 1. Parses the DNS packet
/// 2. Runs the domain through the resolve pipeline
/// 3. Either blocks the query (NXDOMAIN) or forwards to upstream
/// 4. Sends the response back to the client
/// 5. Emits stats events for telemetry
pub(crate) async fn handle_query(
    socket: Arc<UdpSocket>,
    packet: Vec<u8>,
    peer: std::net::SocketAddr,
) -> std::io::Result<()> {
    // 1. Parse DNS packet
    let dns_packet = match DnsPacket::from_bytes(&packet) {
        Some(p) => p,
        None => {
            // Malformed packet - silently drop
            return Ok(());
        }
    };

    // Increment total query counter
    STATS_COUNTERS.increment_total();

    // 2. Run domain through the filter pipeline
    let action = resolve(&dns_packet.domain);

    // 3. Process the action and determine stat action
    let (response, stat_action) = match &action {
        Action::Allow => {
            STATS_COUNTERS.increment_allowed();
            // Forward to upstream DNS server
            let resp = match forward_to_upstream(&packet).await {
                Ok(upstream_response) => upstream_response,
                Err(_) => DnsPacket::build_servfail_response(&dns_packet.message),
            };
            (resp, Some(StatAction::Allowed))
        }
        Action::ProxyToUpstream => {
            STATS_COUNTERS.increment_proxied();
            let resp = match forward_to_upstream(&packet).await {
                Ok(upstream_response) => upstream_response,
                Err(_) => DnsPacket::build_servfail_response(&dns_packet.message),
            };
            (resp, Some(StatAction::Proxied))
        }
        Action::Block(reason) => {
            STATS_COUNTERS.increment_blocked();
            let stat_reason = StatBlockReason::from(reason);
            (
                DnsPacket::build_nxdomain_response(&dns_packet.message),
                Some(StatAction::Blocked(stat_reason)),
            )
        }
        Action::Drop => {
            STATS_COUNTERS.increment_blocked();
            (
                DnsPacket::build_nxdomain_response(&dns_packet.message),
                None, // Don't log drops
            )
        }
        Action::LocalResolve(_ip) | Action::Respond(_ip) | Action::Redirect(_ip) => {
            STATS_COUNTERS.increment_proxied();
            // TODO: Build response with the provided IP address
            // For now, proxy to upstream as fallback
            let resp = match forward_to_upstream(&packet).await {
                Ok(upstream_response) => upstream_response,
                Err(_) => DnsPacket::build_servfail_response(&dns_packet.message),
            };
            (resp, Some(StatAction::Proxied))
        }
        Action::InternalRedirect(_) => {
            STATS_COUNTERS.increment_blocked();
            // TODO: Implement internal redirect logic
            (
                DnsPacket::build_nxdomain_response(&dns_packet.message),
                None,
            )
        }
    };

    // 4. Send response back to client
    socket.send_to(&response, peer).await?;

    // 5. Emit stat event (non-blocking)
    if let Some(stat_action) = stat_action
        && let Some(sender) = STATS_SENDER.get()
    {
        sender.send_event(&dns_packet.domain, peer, stat_action);
    }

    Ok(())
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
