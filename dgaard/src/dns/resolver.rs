//! Resolver abstraction.
//!
//! `handle_query` does not care whether a "clean" query is satisfied by an
//! upstream forwarder or by an in-process iterative resolver. The
//! [`UpstreamResolver`] trait isolates the choice behind a single async
//! method so the hot path keeps a single call site regardless of
//! `[server] mode`.
//!
//! Phase 1 ships exactly one implementation, [`ForwardingResolver`], which
//! delegates to the existing UDP forwarder. Phase 2 will add
//! `RecursiveResolver` alongside without touching the dispatch path.
//!
//! See `docs/Roadmap-recursive-DNS.md` for the design.
//!
//! # Trait dispatch
//!
//! ```ignore
//! use std::sync::Arc;
//!
//! use crate::dns::resolver::{ForwardingResolver, UpstreamResolver};
//!
//! // The trait object is what `handle_query` holds — concrete type is hidden.
//! let resolver: Arc<dyn UpstreamResolver> = Arc::new(ForwardingResolver::new());
//! // The Arc is `Send + Sync`, so we can share it across worker tasks.
//! let _shared: Arc<dyn UpstreamResolver> = Arc::clone(&resolver);
//! ```

use std::sync::{Arc, OnceLock};

use async_trait::async_trait;

use crate::dns::packet::DnsPacket;
use crate::dns::upstream::forward_to_upstream;

/// Abstraction over "how do we resolve a clean query?".
///
/// Implementors return the **wire-format** DNS response bytes ready to send
/// back to the client. The post-resolution filter pipeline (DPI, DNSSEC,
/// rebinding shield, response scoring) is then applied identically by
/// `handle_query` regardless of which implementor produced the bytes.
///
/// The trait accepts a parsed [`DnsPacket`] rather than raw bytes: `handle_query`
/// already parses the incoming packet, and forcing implementors to re-parse
/// would be wasteful (especially the prefetch worker in Phase 5, which
/// builds the `DnsPacket` directly and would otherwise need to synthesise
/// wire-format bytes only to have them parsed again on the other side).
#[async_trait]
pub trait UpstreamResolver: Send + Sync {
    /// Resolve a parsed DNS query and return the raw wire-format response.
    async fn resolve(&self, query: &DnsPacket) -> std::io::Result<Vec<u8>>;
}

/// `[forwarder]`-mode resolver: delegates to one of the configured upstream
/// servers via UDP, with TXID randomisation and optional DNS0x20 case
/// randomisation. Identical wire behaviour to the pre-Phase-1 inline forward.
#[derive(Debug, Default)]
pub struct ForwardingResolver;

impl ForwardingResolver {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl UpstreamResolver for ForwardingResolver {
    async fn resolve(&self, query: &DnsPacket) -> std::io::Result<Vec<u8>> {
        // The existing forwarder works in wire format because that is what
        // it sends upstream verbatim (preserving the client's question
        // section bit-for-bit). Re-encode from the parsed message so the
        // public API stays packet-oriented.
        let bytes = encode_query(query)?;
        forward_to_upstream(&bytes).await
    }
}

/// Re-encode a parsed DNS query to wire format. The forwarder will rewrite
/// the TXID and optionally apply 0x20 before sending, so we do not need to
/// preserve those bits — we just need a syntactically valid query that
/// echoes the original question section.
fn encode_query(packet: &DnsPacket) -> std::io::Result<Vec<u8>> {
    packet
        .message
        .to_vec()
        .map_err(|e| std::io::Error::other(format!("failed to encode DNS query: {e}")))
}

/// Process-wide active resolver. Set exactly once during startup by `main`
/// (or by a test harness) from the configured `[server] mode`.
pub static UPSTREAM_RESOLVER: OnceLock<Arc<dyn UpstreamResolver>> = OnceLock::new();

/// Install the global resolver. Returns `Err` if the slot was already set —
/// re-initialising the resolver at runtime is not supported because the
/// `OnceLock` semantics guarantee `handle_query` always sees the same
/// instance for the lifetime of the process.
pub fn install(resolver: Arc<dyn UpstreamResolver>) -> Result<(), &'static str> {
    UPSTREAM_RESOLVER
        .set(resolver)
        .map_err(|_| "UPSTREAM_RESOLVER already initialised")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Minimal recorder that proves `handle_query` only needs the trait —
    /// no real network. Used by tests that want to inject a deterministic
    /// response without touching the live forwarder.
    struct MockResolver {
        canned: Vec<u8>,
        seen: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl UpstreamResolver for MockResolver {
        async fn resolve(&self, query: &DnsPacket) -> std::io::Result<Vec<u8>> {
            self.seen.lock().unwrap().push(query.domain.clone());
            Ok(self.canned.clone())
        }
    }

    fn sample_query_bytes() -> &'static [u8] {
        &[
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ]
    }

    #[tokio::test]
    async fn mock_resolver_returns_canned_bytes_and_records_qname() {
        let resolver = MockResolver {
            canned: vec![0x01, 0x02, 0x03],
            seen: Mutex::new(Vec::new()),
        };
        let packet = DnsPacket::from_bytes(sample_query_bytes()).expect("parse query");
        let response = resolver.resolve(&packet).await.unwrap();
        assert_eq!(response, vec![0x01, 0x02, 0x03]);
        assert_eq!(*resolver.seen.lock().unwrap(), vec!["example.com"]);
    }

    #[tokio::test]
    async fn trait_object_is_send_sync_and_shareable_across_tasks() {
        // The Arc<dyn UpstreamResolver> the runtime stores must survive
        // being cloned into spawned tasks. Compile-time check via Send+Sync
        // bounds, runtime check via tokio::spawn returning a value.
        let resolver: Arc<dyn UpstreamResolver> = Arc::new(MockResolver {
            canned: vec![0xAB],
            seen: Mutex::new(Vec::new()),
        });
        let clone = Arc::clone(&resolver);
        let bytes = sample_query_bytes().to_vec();
        let handle = tokio::spawn(async move {
            let packet = DnsPacket::from_bytes(&bytes).unwrap();
            clone.resolve(&packet).await.unwrap()
        });
        assert_eq!(handle.await.unwrap(), vec![0xAB]);
    }

    #[test]
    fn encode_query_round_trips_through_parse() {
        let packet = DnsPacket::from_bytes(sample_query_bytes()).unwrap();
        let bytes = encode_query(&packet).expect("encode");
        let reparsed = DnsPacket::from_bytes(&bytes).expect("parse re-encoded");
        assert_eq!(reparsed.domain, packet.domain);
        assert_eq!(reparsed.qtype, packet.qtype);
        assert_eq!(reparsed.qclass, packet.qclass);
    }

    #[test]
    fn forwarding_resolver_can_be_boxed_into_trait_object() {
        let _r: Arc<dyn UpstreamResolver> = Arc::new(ForwardingResolver::new());
    }
}
