use crate::CONFIG;
use crate::stats::StatsReceiver;
use tokio::sync::watch;

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

    // Track domain mappings for logging
    let mut domain_map: std::collections::HashMap<u64, String> = std::collections::HashMap::new();

    // Connected socket clients
    let mut clients: Vec<UnixStream> = Vec::new();

    // Try to bind the Unix socket
    let socket_path = CONFIG.load().server.stats_socket_path.clone();
    let listener = match setup_unix_socket(&socket_path) {
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
                    // Clean up socket file
                    if !socket_path.is_empty() {
                        let _ = std::fs::remove_file(&socket_path);
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
pub(crate) fn setup_unix_socket(path: &str) -> std::io::Result<tokio::net::UnixListener> {
    use tokio::net::UnixListener;

    if path.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Stats socket path is empty",
        ));
    }

    // Remove existing socket file if it exists
    let _ = std::fs::remove_file(path);

    // Create parent directory if needed
    if let Some(parent) = std::path::Path::new(path).parent()
        && !parent.as_os_str().is_empty()
    {
        let _ = std::fs::create_dir_all(parent);
    }

    UnixListener::bind(path)
}

/// Send all current domain mappings to a newly connected client.
pub(crate) async fn send_domain_mappings_to_client(
    clients: &mut Vec<tokio::net::UnixStream>,
    domain_map: &std::collections::HashMap<u64, String>,
    mut new_client: tokio::net::UnixStream,
) {
    use crate::model::StatMessage;
    use tokio::io::AsyncWriteExt;

    // Send all known domain mappings to the new client
    for (&hash, domain) in domain_map {
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
    domain_map: &mut std::collections::HashMap<u64, String>,
    clients: &mut Vec<tokio::net::UnixStream>,
) {
    use crate::model::{StatAction, StatBlockReason, StatMessage};
    use tokio::io::AsyncWriteExt;

    match msg {
        StatMessage::DomainMapping { hash, domain } => {
            domain_map.insert(*hash, domain.clone());
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
                    let reason_str = match reason {
                        StatBlockReason::StaticBlacklist => "blocklist",
                        StatBlockReason::AbpRule => "abp-rule",
                        StatBlockReason::HighEntropy => "dga",
                        StatBlockReason::LexicalAnalysis => "lexical",
                        StatBlockReason::BannedKeyword => "keyword",
                        StatBlockReason::InvalidStructure => "structure",
                        StatBlockReason::SuspiciousIdn => "idn",
                        StatBlockReason::NrdList => "nrd",
                        StatBlockReason::TldExcluded => "tld",
                        StatBlockReason::Suspicious => "suspicious",
                    };
                    println!("[BLOCK] {} -> {} ({})", client_ip, domain, reason_str);
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

/// Format a 16-byte IPv6 address (or IPv4-mapped) for display.
pub(crate) fn format_client_ip(ip_bytes: &[u8; 16]) -> String {
    let v6 = std::net::Ipv6Addr::from(*ip_bytes);
    match v6.to_ipv4_mapped() {
        Some(v4) => v4.to_string(),
        None => v6.to_string(),
    }
}
