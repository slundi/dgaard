use std::{net::SocketAddr, sync::OnceLock};

use hickory_resolver::{
    TokioResolver,
    config::{NameServerConfig, ResolverConfig},
    net::runtime::TokioRuntimeProvider,
    net::{DnsError, NetError},
    proto::{dnssec::Proof, rr::RecordType},
};

static VALIDATOR: OnceLock<TokioResolver> = OnceLock::new();

/// Result of a DNSSEC side-channel validation.
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum DnssecStatus {
    /// The lookup succeeded or the zone is unsigned (Insecure/Indeterminate).
    Ok,
    /// DNSSEC validation explicitly failed (BOGUS proof).
    Bogus,
}

/// Build and store the DNSSEC-validating resolver from the configured upstream servers.
///
/// Parses each entry in `servers` as `ip:port`. Logs a warning and skips
/// initialization if no valid server addresses are found. Call this once at
/// startup when `security.dnssec.enabled = true`.
pub fn init(servers: &[String]) {
    let mut resolver_config = ResolverConfig::default();
    for addr_str in servers {
        if let Ok(sock_addr) = addr_str.parse::<SocketAddr>() {
            let mut ns = NameServerConfig::udp_and_tcp(sock_addr.ip());
            for conn in &mut ns.connections {
                conn.port = sock_addr.port();
            }
            resolver_config.add_name_server(ns);
        }
    }
    if resolver_config.name_servers().is_empty() {
        eprintln!("dnssec: no valid upstream addresses found — DNSSEC validation disabled");
        return;
    }

    let mut builder =
        TokioResolver::builder_with_config(resolver_config, TokioRuntimeProvider::default());
    builder.options_mut().validate = true;

    match builder.build() {
        Ok(resolver) => {
            let _ = VALIDATOR.set(resolver);
            println!("DNSSEC validation enabled");
        }
        Err(e) => {
            eprintln!("dnssec: failed to build DNSSEC validator: {e}");
        }
    }
}

/// Validate a domain/qtype pair using the side-channel DNSSEC resolver.
///
/// Returns [`DnssecStatus::Bogus`] only when the resolver explicitly returns a
/// DNSSEC-BOGUS failure. All other errors (NXDOMAIN, timeout, SERVFAIL, unsigned
/// zone) are treated as fail-open to avoid false positives.
///
/// Returns [`DnssecStatus::Ok`] immediately when DNSSEC is disabled (validator
/// not initialized).
pub async fn validate(domain: &str, qtype: u16) -> DnssecStatus {
    let Some(resolver) = VALIDATOR.get() else {
        return DnssecStatus::Ok;
    };

    let record_type = RecordType::from(qtype);
    match resolver.lookup(domain, record_type).await {
        Ok(_) => DnssecStatus::Ok,
        Err(e) => {
            if is_bogus(&e) {
                DnssecStatus::Bogus
            } else {
                DnssecStatus::Ok
            }
        }
    }
}

fn is_bogus(e: &NetError) -> bool {
    matches!(
        e,
        NetError::Dns(DnsError::Nsec {
            proof: Proof::Bogus,
            ..
        })
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dnssec_status_ok_is_not_bogus() {
        assert_ne!(DnssecStatus::Ok, DnssecStatus::Bogus);
    }

    #[test]
    fn validate_returns_ok_when_not_initialized() {
        // VALIDATOR is not set in unit tests — must fail open
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let status = rt.block_on(validate("example.com", 1 /* A */));
        assert_eq!(status, DnssecStatus::Ok);
    }
}
