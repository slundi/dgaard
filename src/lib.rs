pub mod blocklist;
pub mod config;
pub mod domain;

use std::net::Ipv4Addr;

use postcard::{from_bytes, to_stdvec};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub enum ProxyMessage {
    /// Sent only once per domain per session to "seed" the collector's database
    DomainMapping { hash: u64, domain: String },
    /// Sent for every DNS query/block
    Event {
        timestamp: u64,
        rule_id: u64,
        domain_hash: u64,
        client_ip: [u8; 16],
    },
}

// impl StatEvent {
//     pub fn serialize(&self) -> Vec<u8> {
//         // Postcard uses Varint encoding automatically
//         to_stdvec(self).unwrap_or_default()
//     }

//     pub fn deserialize(bytes: &[u8]) -> Option<Self> {
//         from_bytes(bytes).ok()
//     }
// }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Action {
    /// The domain is safe and was found in the local cache or whitelist.
    /// Returns the cached IP address.
    LocalResolve(Ipv4Addr),

    /// The domain passed all filters and must be sent to the upstream provider.
    ProxyToUpstream,

    /// The query was intentionally blocked.
    /// Carries the reason for the dashboard/TUI logs.
    /// We should return an NXDOMAIN or a 0.0.0.0 response.
    Block(BlockReason),

    /// A specialized internal response (e.g., redirecting to a local landing page).
    InternalRedirect(Ipv4Addr),

    /// The query was ignored or dropped (e.g., malformed or from unauthorized ACL).
    Drop,

    /// The domain is safe. Forward the original query to the upstream DNS.
    Allow,

    /// The domain is in our "Hot Cache" or "Favorites".
    /// We can return this IP immediately without asking an upstream server.
    Respond(Ipv4Addr),

    /// Optional: The query is redirected to a local landing page (e.g., for a "Blocked" UI).
    Redirect(Ipv4Addr),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BlockReason {
    /// Hit a static blacklist (e.g., OISD, StevenBlack).
    StaticBlacklist(String), // String is the name of the source file

    /// Blocked by an ABP-style pattern or wildcard.
    AbpRule(String),

    /// High Shannon Entropy detected (DGA). Carries the calculated score.
    HighEntropy(f32),

    /// Failed lexical analysis (Consonant ratio or N-Gram probability).
    LexicalAnalysis,

    /// Failed structural checks (Subdomain depth, TXT length, etc.).
    InvalidStructure,

    /// Suspicious IDN/Punycode homograph attack.
    SuspiciousIdn,

    /// Domain is on a known "Newly Registered Domain" list.
    NrdList,

    /// TLD is explicitly excluded in config.
    TldExcluded,
}
