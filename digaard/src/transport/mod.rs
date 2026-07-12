pub mod doq;
pub mod https;
pub mod tcp;
pub mod tls;
pub mod tls_config;
pub mod udp;

use crate::error::Result;
use hickory_proto::op::Message;
use hickory_proto::serialize::binary::BinDecodable;

/// Wire-level transport kinds supported by digaard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    Udp,
    Tcp,
    /// DNS over TLS (RFC 7858)
    Tls,
    /// DNS over HTTPS (RFC 8484)
    Https,
    /// DNS over QUIC (RFC 9250)
    Quic,
}

impl TransportKind {
    /// Default port for this transport when none is specified.
    pub fn default_port(self) -> u16 {
        match self {
            Self::Udp | Self::Tcp => 53,
            Self::Tls | Self::Quic => 853,
            Self::Https => 443,
        }
    }
}

/// How to pick among multiple `-s` servers when batching queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerStrategy {
    /// Always use the first server; other servers are ignored.
    First,
    /// Fire every query at every server in parallel; take the first response.
    Race,
    /// Round-robin queries across the server list.
    RoundRobin,
}

/// TLS/PKI knobs shared by DoT and DoH.
#[derive(Debug, Clone, Default)]
pub struct TlsSettings {
    /// SNI + expected certificate name. `None` = derive from server host.
    pub servername: Option<String>,
    /// Skip certificate verification (debugging only).
    pub insecure: bool,
    /// PEM-formatted trust roots on top of the webpki bundle.
    pub extra_ca_pem: Vec<Vec<u8>>,
}

/// DoH-only settings.
#[derive(Debug, Clone)]
pub struct DohSettings {
    pub method: DohMethod,
    pub path: String,
}

impl Default for DohSettings {
    fn default() -> Self {
        Self {
            method: DohMethod::Post,
            path: "/dns-query".to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DohMethod {
    Get,
    Post,
}

/// Configuration shared by every transport.
#[derive(Debug, Clone)]
pub struct TransportConfig {
    pub server: String,
    pub port: u16,
    pub timeout_ms: u64,
    /// Number of retries on UDP timeout (UDP only; ignored by other transports).
    pub retry: u32,
    /// Force IPv4-only outbound socket.
    pub ipv4_only: bool,
    /// Force IPv6-only outbound socket.
    pub ipv6_only: bool,
    /// Shared TLS knobs. Ignored by UDP / TCP.
    pub tls: TlsSettings,
    /// DoH knobs. Ignored by UDP / TCP / DoT.
    pub doh: DohSettings,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            server: String::new(),
            port: 53,
            timeout_ms: 5000,
            retry: 0,
            ipv4_only: false,
            ipv6_only: false,
            tls: TlsSettings::default(),
            doh: DohSettings::default(),
        }
    }
}

/// Send a single DNS query and return the decoded response.
///
/// Selects the concrete transport based on `kind` and routes through it.
pub async fn send(kind: TransportKind, cfg: &TransportConfig, query: &Message) -> Result<Message> {
    send_with_wire(kind, cfg, query).await.map(|(m, _)| m)
}

/// Send a single DNS query and return both the decoded response and the raw
/// wire bytes (for `--hex` output).
pub async fn send_with_wire(
    kind: TransportKind,
    cfg: &TransportConfig,
    query: &Message,
) -> Result<(Message, Vec<u8>)> {
    let wire = match kind {
        TransportKind::Udp => udp::send_raw(cfg, query).await?,
        TransportKind::Tcp => tcp::send_raw(cfg, query).await?,
        TransportKind::Tls => tls::send_raw(cfg, query).await?,
        TransportKind::Https => https::send_raw(cfg, query).await?,
        TransportKind::Quic => doq::send_raw(cfg, query).await?,
    };
    let msg = Message::from_bytes(&wire)?;
    if kind == TransportKind::Udp && msg.metadata.truncation {
        return Err(crate::error::Error::Truncated);
    }
    Ok((msg, wire))
}

/// Parse a `-s`/`@` server specification into `(host, optional_port)`.
///
/// Accepts:
/// - IPv4 or hostname:               `"1.1.1.1"`, `"dns.example.com"`
/// - IPv4 or hostname with port:     `"1.1.1.1:5353"`, `"dns.example.com:5353"`
/// - Bare IPv6 (no port):            `"::1"`, `"2001:db8::1"`
/// - Bracketed IPv6:                 `"[::1]"`, `"[2001:db8::1]"`
/// - Bracketed IPv6 with port:       `"[::1]:5353"`
///
/// Bare IPv6 with a port is ambiguous (`::1:5353`) and is therefore rejected in
/// favor of the bracketed form.
pub fn parse_server_spec(spec: &str) -> std::result::Result<(String, Option<u16>), String> {
    if spec.is_empty() {
        return Err("empty server spec".to_string());
    }

    if let Some(rest) = spec.strip_prefix('[') {
        let close = rest
            .find(']')
            .ok_or_else(|| format!("missing ']' in server '{spec}'"))?;
        let host = &rest[..close];
        if host.is_empty() {
            return Err(format!("empty host in server '{spec}'"));
        }
        let after = &rest[close + 1..];
        if after.is_empty() {
            return Ok((host.to_string(), None));
        }
        let port_str = after.strip_prefix(':').ok_or_else(|| {
            format!("unexpected characters after ']' in server '{spec}': '{after}'")
        })?;
        let port: u16 = port_str
            .parse()
            .map_err(|e| format!("invalid port '{port_str}' in server '{spec}': {e}"))?;
        return Ok((host.to_string(), Some(port)));
    }

    // Bare IPv6 (two or more colons) — no port allowed without brackets.
    if spec.matches(':').count() > 1 {
        return Ok((spec.to_string(), None));
    }

    if let Some((host, port_str)) = spec.rsplit_once(':') {
        if host.is_empty() {
            return Err(format!("empty host in server '{spec}'"));
        }
        let port: u16 = port_str
            .parse()
            .map_err(|e| format!("invalid port '{port_str}' in server '{spec}': {e}"))?;
        return Ok((host.to_string(), Some(port)));
    }
    Ok((spec.to_string(), None))
}

/// Picks one of many pre-built `TransportConfig`s per query.
///
/// - `First`: always returns index 0.
/// - `RoundRobin`: cycles across the list.
/// - `Race`: caller races all configs concurrently; not handled here.
#[derive(Debug)]
pub struct ServerPicker {
    configs: Vec<std::sync::Arc<TransportConfig>>,
    strategy: ServerStrategy,
    counter: std::sync::atomic::AtomicUsize,
}

impl ServerPicker {
    pub fn new(configs: Vec<std::sync::Arc<TransportConfig>>, strategy: ServerStrategy) -> Self {
        assert!(!configs.is_empty(), "at least one server required");
        Self {
            configs,
            strategy,
            counter: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    pub fn strategy(&self) -> ServerStrategy {
        self.strategy
    }

    /// Return the config to use for the next query.
    ///
    /// For `Race`, callers should use `all()` instead and race the futures.
    pub fn next(&self) -> std::sync::Arc<TransportConfig> {
        match self.strategy {
            ServerStrategy::First => self.configs[0].clone(),
            ServerStrategy::Race => self.configs[0].clone(),
            ServerStrategy::RoundRobin => {
                let idx = self
                    .counter
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.configs[idx % self.configs.len()].clone()
            }
        }
    }

    pub fn all(&self) -> &[std::sync::Arc<TransportConfig>] {
        &self.configs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn cfg(s: &str) -> Arc<TransportConfig> {
        Arc::new(TransportConfig {
            server: s.to_string(),
            ..TransportConfig::default()
        })
    }

    #[test]
    fn first_strategy_pins_to_index_zero() {
        let picker = ServerPicker::new(vec![cfg("a"), cfg("b"), cfg("c")], ServerStrategy::First);
        assert_eq!(picker.next().server, "a");
        assert_eq!(picker.next().server, "a");
    }

    #[test]
    fn round_robin_cycles() {
        let picker = ServerPicker::new(
            vec![cfg("a"), cfg("b"), cfg("c")],
            ServerStrategy::RoundRobin,
        );
        assert_eq!(picker.next().server, "a");
        assert_eq!(picker.next().server, "b");
        assert_eq!(picker.next().server, "c");
        assert_eq!(picker.next().server, "a");
    }

    #[test]
    fn race_exposes_all_configs() {
        let picker = ServerPicker::new(vec![cfg("a"), cfg("b")], ServerStrategy::Race);
        assert_eq!(picker.all().len(), 2);
    }

    #[test]
    fn parse_spec_bare_ipv4() {
        assert_eq!(
            parse_server_spec("1.1.1.1").unwrap(),
            ("1.1.1.1".to_string(), None)
        );
    }

    #[test]
    fn parse_spec_ipv4_with_port() {
        assert_eq!(
            parse_server_spec("192.168.1.1:5353").unwrap(),
            ("192.168.1.1".to_string(), Some(5353))
        );
    }

    #[test]
    fn parse_spec_hostname_with_port() {
        assert_eq!(
            parse_server_spec("dns.example.com:8053").unwrap(),
            ("dns.example.com".to_string(), Some(8053))
        );
    }

    #[test]
    fn parse_spec_hostname_without_port() {
        assert_eq!(
            parse_server_spec("dns.example.com").unwrap(),
            ("dns.example.com".to_string(), None)
        );
    }

    #[test]
    fn parse_spec_bare_ipv6_no_port() {
        assert_eq!(
            parse_server_spec("2001:db8::1").unwrap(),
            ("2001:db8::1".to_string(), None)
        );
        assert_eq!(parse_server_spec("::1").unwrap(), ("::1".to_string(), None));
    }

    #[test]
    fn parse_spec_bracketed_ipv6_no_port() {
        assert_eq!(
            parse_server_spec("[2001:db8::1]").unwrap(),
            ("2001:db8::1".to_string(), None)
        );
    }

    #[test]
    fn parse_spec_bracketed_ipv6_with_port() {
        assert_eq!(
            parse_server_spec("[2001:db8::1]:5353").unwrap(),
            ("2001:db8::1".to_string(), Some(5353))
        );
        assert_eq!(
            parse_server_spec("[::1]:53").unwrap(),
            ("::1".to_string(), Some(53))
        );
    }

    #[test]
    fn parse_spec_rejects_bad_port() {
        assert!(parse_server_spec("1.1.1.1:notaport").is_err());
        assert!(parse_server_spec("1.1.1.1:99999").is_err());
        assert!(parse_server_spec("[::1]:notaport").is_err());
    }

    #[test]
    fn parse_spec_rejects_empty_host() {
        assert!(parse_server_spec("").is_err());
        assert!(parse_server_spec(":53").is_err());
        assert!(parse_server_spec("[]").is_err());
        assert!(parse_server_spec("[]:53").is_err());
    }

    #[test]
    fn parse_spec_rejects_unterminated_bracket() {
        assert!(parse_server_spec("[::1").is_err());
    }

    #[test]
    fn parse_spec_rejects_trailing_garbage_after_bracket() {
        assert!(parse_server_spec("[::1]garbage").is_err());
    }
}
