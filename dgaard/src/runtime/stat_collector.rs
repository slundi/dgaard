use crate::CONFIG;
use crate::model::StatBlockReason;
use crate::stats::StatsReceiver;
use lru::LruCache;
use std::num::NonZeroUsize;
use tokio::sync::watch;

const DOMAIN_MAP_CAP: usize = 100_000;

/// Maximum number of simultaneously connected stats clients. A flapping
/// dashboard would otherwise grow `clients: Vec<UnixStream>` without
/// bound, since drops only happen on actual write errors.
const MAX_CLIENTS: usize = 8;

/// Stats collector task that receives events and handles logging/streaming.
///
/// This task:
/// 1. Receives StatMessage events from DNS handlers via MPSC channel
/// 2. Logs block events to stdout (basic CLI logger)
/// 3. Streams events to connected Unix socket clients
pub(crate) async fn stats_collector_task(
    mut receiver: StatsReceiver,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    use tokio::net::UnixStream;

    // Track domain mappings for logging; capped to avoid unbounded growth.
    let mut domain_map: LruCache<u64, String> =
        LruCache::new(NonZeroUsize::new(DOMAIN_MAP_CAP).unwrap());

    // Connected socket clients. Capped to MAX_CLIENTS so a misbehaving
    // dashboard that reconnects in a tight loop cannot grow this vec
    // (and the per-event broadcast cost) without bound.
    let mut clients: Vec<UnixStream> = Vec::new();

    // Try to bind the Unix socket
    let socket_path = CONFIG.load().server.stats_socket_path.clone();
    let listener = match setup_unix_socket(&socket_path).await {
        Ok(l) => {
            println!("Stats socket listening on {}", socket_path);
            Some(l)
        }
        Err(e) => {
            eprintln!(
                "Warning: Failed to create stats socket at {}: {}",
                socket_path, e
            );
            None
        }
    };

    loop {
        tokio::select! {
            biased;

            // Check for shutdown
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    // Drain remaining messages before exit
                    while let Ok(msg) = receiver.try_recv() {
                        process_stat_message(&msg, &mut domain_map, &mut clients).await;
                    }
                    // Clean up socket file in the blocking pool to avoid
                    // stalling the runtime on slow filesystems.
                    if !socket_path.is_empty() {
                        let cleanup_path = socket_path.clone();
                        let _ = tokio::task::spawn_blocking(move || {
                            let _ = std::fs::remove_file(&cleanup_path);
                        })
                        .await;
                    }
                    break;
                }
            }

            // Accept new Unix socket connections
            result = async {
                match &listener {
                    Some(l) => l.accept().await,
                    None => std::future::pending().await,
                }
            } => {
                match result {
                    Ok((stream, _addr)) => {
                        if clients.len() >= MAX_CLIENTS {
                            eprintln!(
                                "stats: refusing new client, MAX_CLIENTS ({MAX_CLIENTS}) reached"
                            );
                            // Dropping `stream` closes the connection immediately.
                            drop(stream);
                            continue;
                        }
                        println!("Stats client connected ({} total)", clients.len() + 1);
                        // Send all current domain mappings to the new client
                        send_domain_mappings_to_client(&mut clients, &domain_map, stream).await;
                    }
                    Err(e) => {
                        eprintln!("Error accepting stats connection: {}", e);
                    }
                }
            }

            // Process stat messages
            msg = receiver.recv() => {
                match msg {
                    Some(msg) => process_stat_message(&msg, &mut domain_map, &mut clients).await,
                    None => break, // All senders dropped
                }
            }
        }
    }
}

/// Set up the Unix domain socket for stats streaming.
///
/// Filesystem prep (mkdir parent, unlink stale socket) runs in a blocking
/// pool so the tokio executor isn't stalled on slow flash or NFS during
/// startup.
pub(crate) async fn setup_unix_socket(path: &str) -> std::io::Result<tokio::net::UnixListener> {
    use tokio::net::UnixListener;

    if path.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Stats socket path is empty",
        ));
    }

    let path_owned = path.to_string();
    tokio::task::spawn_blocking(move || {
        let _ = std::fs::remove_file(&path_owned);
        if let Some(parent) = std::path::Path::new(&path_owned).parent()
            && !parent.as_os_str().is_empty()
        {
            let _ = std::fs::create_dir_all(parent);
        }
    })
    .await
    .map_err(|e| std::io::Error::other(format!("setup_unix_socket join: {e}")))?;

    UnixListener::bind(path)
}

/// Send all current domain mappings to a newly connected client.
pub(crate) async fn send_domain_mappings_to_client(
    clients: &mut Vec<tokio::net::UnixStream>,
    domain_map: &LruCache<u64, String>,
    mut new_client: tokio::net::UnixStream,
) {
    use crate::model::StatMessage;
    use tokio::io::AsyncWriteExt;

    // Send all known domain mappings to the new client
    for (&hash, domain) in domain_map.iter() {
        let msg = StatMessage::DomainMapping {
            hash,
            domain: domain.clone(),
        };
        let bytes = msg.serialize();
        if new_client.write_all(&bytes).await.is_err() {
            // Client disconnected during handshake, don't add it
            return;
        }
    }

    clients.push(new_client);
}

/// Process a single stat message: log to stdout and stream to connected clients.
pub(crate) async fn process_stat_message(
    msg: &crate::model::StatMessage,
    domain_map: &mut LruCache<u64, String>,
    clients: &mut Vec<tokio::net::UnixStream>,
) {
    use crate::model::{StatAction, StatMessage};
    use tokio::io::AsyncWriteExt;

    match msg {
        StatMessage::DomainMapping { hash, domain } => {
            domain_map.put(*hash, domain.clone());
        }
        StatMessage::Event(event) => {
            // Get domain name from mapping (or use hash as fallback)
            let domain = domain_map
                .get(&event.domain_hash)
                .map(|s| s.as_str())
                .unwrap_or("<unknown>");

            // Format client IP
            let client_ip = format_client_ip(&event.client_ip);

            // Log based on action
            match &event.action {
                StatAction::Blocked(reason) => {
                    println!(
                        "[BLOCK] {} -> {} ({})",
                        client_ip,
                        domain,
                        stat_block_reason_str(reason)
                    );
                }
                StatAction::HighlySuspicious(reason) => {
                    let reason_str = stat_block_reason_str(reason);
                    println!(
                        "[SUSPICIOUS:HIGH] {} -> {} ({})",
                        client_ip, domain, reason_str
                    );
                }
                StatAction::Suspicious(reason) => {
                    let reason_str = stat_block_reason_str(reason);
                    println!("[SUSPICIOUS] {} -> {} ({})", client_ip, domain, reason_str);
                }
                StatAction::Allowed => {
                    // Only log in verbose/debug mode (currently silent)
                }
                StatAction::Proxied => {
                    // Only log in verbose/debug mode (currently silent)
                }
            }
        }
    }

    // Stream to connected Unix socket clients
    if !clients.is_empty() {
        let bytes = msg.serialize();
        let mut i = 0;
        while i < clients.len() {
            if clients[i].write_all(&bytes).await.is_err() {
                // Client disconnected, remove it
                let _ = clients.swap_remove(i);
                println!("Stats client disconnected ({} remaining)", clients.len());
            } else {
                i += 1;
            }
        }
    }
}

/// Map a `StatBlockReason` bitflag set to a human-readable label for log output.
/// Multiple active flags are joined with `+`.
fn stat_block_reason_str(reason: &StatBlockReason) -> String {
    let mut parts = Vec::new();
    if reason.contains(StatBlockReason::STATIC_BLACKLIST) {
        parts.push("blocklist");
    }
    if reason.contains(StatBlockReason::ABP_RULE) {
        parts.push("abp-rule");
    }
    if reason.contains(StatBlockReason::HIGH_ENTROPY) {
        parts.push("dga");
    }
    if reason.contains(StatBlockReason::LEXICAL_ANALYSIS) {
        parts.push("lexical");
    }
    if reason.contains(StatBlockReason::BANNED_KEYWORD) {
        parts.push("keyword");
    }
    if reason.contains(StatBlockReason::INVALID_STRUCTURE) {
        parts.push("structure");
    }
    if reason.contains(StatBlockReason::SUSPICIOUS_IDN) {
        parts.push("idn");
    }
    if reason.contains(StatBlockReason::NRD_LIST) {
        parts.push("nrd");
    }
    if reason.contains(StatBlockReason::TLD_EXCLUDED) {
        parts.push("tld");
    }
    if reason.contains(StatBlockReason::SUSPICIOUS) {
        parts.push("suspicious");
    }
    if reason.contains(StatBlockReason::CNAME_CLOAKING) {
        parts.push("cname-cloaking");
    }
    if reason.contains(StatBlockReason::FORBIDDEN_QTYPE) {
        parts.push("forbidden-qtype");
    }
    if reason.contains(StatBlockReason::DNS_REBINDING) {
        parts.push("dns-rebinding");
    }
    if reason.contains(StatBlockReason::LOW_TTL) {
        parts.push("low-ttl");
    }
    if reason.contains(StatBlockReason::ASN_BLOCKED) {
        parts.push("asn-blocked");
    }
    if parts.is_empty() {
        "unknown".to_string()
    } else {
        parts.join("+")
    }
}

/// Format a 16-byte IPv6 address (or IPv4-mapped) for display.
pub(crate) fn format_client_ip(ip_bytes: &[u8; 16]) -> String {
    let v6 = std::net::Ipv6Addr::from(*ip_bytes);
    match v6.to_ipv4_mapped() {
        Some(v4) => v4.to_string(),
        None => v6.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{StatAction, StatBlockReason, StatEvent, StatMessage};

    // ── format_client_ip ─────────────────────────────────────────────────────

    #[test]
    fn format_ipv4_mapped_address() {
        // 127.0.0.1 mapped to IPv6
        let ip: std::net::Ipv4Addr = "127.0.0.1".parse().unwrap();
        let v6 = ip.to_ipv6_mapped();
        let bytes = v6.octets();
        assert_eq!(format_client_ip(&bytes), "127.0.0.1");
    }

    #[test]
    fn format_ipv4_address_192() {
        let ip: std::net::Ipv4Addr = "192.168.1.1".parse().unwrap();
        let bytes = ip.to_ipv6_mapped().octets();
        assert_eq!(format_client_ip(&bytes), "192.168.1.1");
    }

    #[test]
    fn format_pure_ipv6_address() {
        // Pure IPv6 address (not IPv4-mapped)
        let ip: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        let bytes = ip.octets();
        assert_eq!(format_client_ip(&bytes), "2001:db8::1");
    }

    #[test]
    fn format_loopback_ipv6() {
        let ip: std::net::Ipv6Addr = "::1".parse().unwrap();
        let bytes = ip.octets();
        assert_eq!(format_client_ip(&bytes), "::1");
    }

    // ── stat_block_reason_str ────────────────────────────────────────────────

    #[test]
    fn reason_str_single_flag() {
        assert_eq!(
            stat_block_reason_str(&StatBlockReason::STATIC_BLACKLIST),
            "blocklist"
        );
        assert_eq!(
            stat_block_reason_str(&StatBlockReason::ABP_RULE),
            "abp-rule"
        );
        assert_eq!(stat_block_reason_str(&StatBlockReason::HIGH_ENTROPY), "dga");
        assert_eq!(
            stat_block_reason_str(&StatBlockReason::LEXICAL_ANALYSIS),
            "lexical"
        );
        assert_eq!(
            stat_block_reason_str(&StatBlockReason::BANNED_KEYWORD),
            "keyword"
        );
        assert_eq!(
            stat_block_reason_str(&StatBlockReason::INVALID_STRUCTURE),
            "structure"
        );
        assert_eq!(
            stat_block_reason_str(&StatBlockReason::SUSPICIOUS_IDN),
            "idn"
        );
        assert_eq!(stat_block_reason_str(&StatBlockReason::NRD_LIST), "nrd");
        assert_eq!(stat_block_reason_str(&StatBlockReason::TLD_EXCLUDED), "tld");
        assert_eq!(
            stat_block_reason_str(&StatBlockReason::SUSPICIOUS),
            "suspicious"
        );
        assert_eq!(
            stat_block_reason_str(&StatBlockReason::CNAME_CLOAKING),
            "cname-cloaking"
        );
        assert_eq!(
            stat_block_reason_str(&StatBlockReason::FORBIDDEN_QTYPE),
            "forbidden-qtype"
        );
        assert_eq!(
            stat_block_reason_str(&StatBlockReason::DNS_REBINDING),
            "dns-rebinding"
        );
        assert_eq!(stat_block_reason_str(&StatBlockReason::LOW_TTL), "low-ttl");
        assert_eq!(
            stat_block_reason_str(&StatBlockReason::ASN_BLOCKED),
            "asn-blocked"
        );
    }

    #[test]
    fn reason_str_empty_flags_returns_unknown() {
        let empty = StatBlockReason::empty();
        assert_eq!(stat_block_reason_str(&empty), "unknown");
    }

    #[test]
    fn reason_str_multiple_flags_joined_with_plus() {
        let combined = StatBlockReason::HIGH_ENTROPY | StatBlockReason::NRD_LIST;
        let s = stat_block_reason_str(&combined);
        assert!(s.contains("dga"), "expected 'dga' in '{s}'");
        assert!(s.contains("nrd"), "expected 'nrd' in '{s}'");
        assert!(s.contains('+'), "expected '+' separator in '{s}'");
    }

    // ── process_stat_message ─────────────────────────────────────────────────

    fn test_map() -> LruCache<u64, String> {
        LruCache::new(NonZeroUsize::new(1_000).unwrap())
    }

    #[tokio::test]
    async fn process_domain_mapping_populates_map() {
        let mut domain_map = test_map();
        let mut clients = Vec::new();

        let msg = StatMessage::DomainMapping {
            hash: 42,
            domain: "example.com".to_string(),
        };
        process_stat_message(&msg, &mut domain_map, &mut clients).await;

        assert_eq!(domain_map.get(&42), Some(&"example.com".to_string()));
        assert!(clients.is_empty());
    }

    #[tokio::test]
    async fn process_event_uses_domain_map_for_lookup() {
        let mut domain_map = test_map();
        domain_map.put(99u64, "blocked.example".to_string());
        let mut clients = Vec::new();

        let event = StatEvent {
            timestamp: 0,
            domain_hash: 99,
            client_ip: std::net::Ipv4Addr::new(10, 0, 0, 1)
                .to_ipv6_mapped()
                .octets(),
            action: StatAction::Blocked(StatBlockReason::STATIC_BLACKLIST),
        };
        let msg = StatMessage::Event(event);
        // Should not panic even though there are no socket clients
        process_stat_message(&msg, &mut domain_map, &mut clients).await;
    }

    #[tokio::test]
    async fn process_event_unknown_domain_does_not_panic() {
        let mut domain_map = test_map();
        let mut clients = Vec::new();

        let event = StatEvent {
            timestamp: 0,
            domain_hash: 9999, // not in domain_map
            client_ip: [0u8; 16],
            action: StatAction::Allowed,
        };
        process_stat_message(&StatMessage::Event(event), &mut domain_map, &mut clients).await;
    }

    #[tokio::test]
    async fn domain_map_evicts_oldest_when_full() {
        let cap = 4usize;
        let mut domain_map: LruCache<u64, String> = LruCache::new(NonZeroUsize::new(cap).unwrap());
        let mut clients = Vec::new();

        for i in 0..=(cap as u64) {
            let msg = StatMessage::DomainMapping {
                hash: i,
                domain: format!("d{i}.example"),
            };
            process_stat_message(&msg, &mut domain_map, &mut clients).await;
        }

        assert_eq!(domain_map.len(), cap, "map must not exceed capacity");
        // hash 0 was inserted first and never accessed — must have been evicted
        assert!(
            domain_map.peek(&0).is_none(),
            "oldest entry should be evicted"
        );
        // most-recently inserted entry must still be present
        assert!(domain_map.peek(&(cap as u64)).is_some());
    }

    // ── setup_unix_socket ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn setup_unix_socket_empty_path_returns_error() {
        let result = setup_unix_socket("").await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn setup_unix_socket_valid_path_creates_listener() {
        let path = format!("/tmp/dgaard_test_sock_{}", std::process::id());
        let result = setup_unix_socket(&path).await;
        assert!(result.is_ok(), "Should create listener: {:?}", result.err());
        // Cleanup
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn setup_unix_socket_removes_stale_file() {
        let path = format!("/tmp/dgaard_test_stale_{}", std::process::id());
        // Create a stale file
        std::fs::write(&path, b"stale").unwrap();
        let result = setup_unix_socket(&path).await;
        assert!(
            result.is_ok(),
            "Should succeed after removing stale file: {:?}",
            result.err()
        );
        let _ = std::fs::remove_file(&path);
    }
}
