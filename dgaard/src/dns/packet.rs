use hickory_resolver::proto::op::{Message, MessageType, ResponseCode};

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
}
