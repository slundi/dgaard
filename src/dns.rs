use std::sync::Arc;

use hickory_resolver::proto::op::{Message, MessageType, ResponseCode};
use tokio::net::UdpSocket;

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

        // // Clear any existing answers/records just in case
        // response.clear_answers();
        // response.clear_additionals();
        // response.clear_name_servers();

        response.to_vec().unwrap_or_default()
    }
}

pub(crate) async fn handle_query(
    socket: Arc<UdpSocket>,
    packet: Vec<u8>,
    peer: std::net::SocketAddr,
) -> std::io::Result<()> {
    // TODO:
    // 1. Parse DNS packet
    // 2. Check against CURRENT_ENGINE (FilterEngine)
    // 3. Forward to upstream or return blocked response
    // 4. socket.send_to(&response, peer).await?;
    Ok(())
}
