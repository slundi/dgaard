pub mod https;
pub mod tcp;
pub mod tls;
pub mod udp;

use crate::error::Result;
use hickory_proto::op::Message;

/// Wire-level transport kinds supported by digaard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    Udp,
    Tcp,
    /// DNS over TLS (RFC 7858)
    Tls,
    /// DNS over HTTPS (RFC 8484)
    Https,
}

impl TransportKind {
    /// Default port for this transport when none is specified.
    pub fn default_port(self) -> u16 {
        match self {
            Self::Udp | Self::Tcp => 53,
            Self::Tls => 853,
            Self::Https => 443,
        }
    }
}

/// Configuration shared by every transport.
#[derive(Debug, Clone)]
pub struct TransportConfig {
    pub server: String,
    pub port: u16,
    pub timeout_ms: u64,
    /// Preferred address family: None = system default, Some(true) = IPv4 only, Some(false) = IPv6 only.
    pub ipv4_only: bool,
    pub ipv6_only: bool,
}

/// Send a single DNS query and return the decoded response.
///
/// Selects the concrete transport based on `kind` and routes through it.
pub async fn send(kind: TransportKind, cfg: &TransportConfig, query: &Message) -> Result<Message> {
    match kind {
        TransportKind::Udp => udp::send(cfg, query).await,
        TransportKind::Tcp => tcp::send(cfg, query).await,
        TransportKind::Tls => tls::send(cfg, query).await,
        TransportKind::Https => https::send(cfg, query).await,
    }
}
