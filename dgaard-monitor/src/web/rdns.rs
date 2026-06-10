use std::net::IpAddr;

use hickory_resolver::TokioResolver;
use hickory_resolver::proto::rr::{Name, RData};

/// Perform a reverse-DNS (PTR) lookup for `ip`.
///
/// Uses the system resolver so RFC-1918 PTR records are resolved by the LAN
/// nameserver instead of a public resolver.  Falls back to the default
/// `ResolverConfig` when the system config cannot be read.
///
/// Returns `None` on any error or when no PTR record exists.
pub async fn resolve(ip: IpAddr) -> Option<String> {
    let resolver = TokioResolver::builder_tokio().ok()?.build().ok()?;
    let ptr_name = Name::from(ip);
    let lookup = resolver.reverse_lookup(ptr_name).await.ok()?;
    lookup.answers().iter().find_map(|r| match &r.data {
        RData::PTR(n) => Some(n.to_string().trim_end_matches('.').to_string()),
        _ => None,
    })
}
