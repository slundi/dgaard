mod cli;
mod config;
mod dga;
mod dns;
mod proxy;
mod resolver;
// mod stats;
// mod updater;

use crate::config::Config;
use crate::resolver::Resolver;
use crate::stats::ProxyState;
use arc_swap::ArcSwap;
use config::Config;
use std::env;
use std::sync::Arc;
use tokio::net::UdpSocket;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Load Configuration
    let args: Vec<String> = std::env::args().collect();
    let config_path = args
        .get(1)
        .map(|s| s.as_str())
        .unwrap_or("/etc/dgaard/dgaard.toml");
    let cfg = Arc::new(Config::load(config_path)?);

    // 2. Initialize Shared State (Atomic Swappable Rules)
    // We start with empty sets or load initial ones from disk
    let initial_resolver = Arc::new(Resolver::new(&cfg).await);
    let shared_resolver = Arc::new(ArcSwap::from_pointee(initial_resolver));

    // 3. Setup Stats & Control Socket
    let state = Arc::new(ProxyState::new(&cfg).await?);

    // 4. Spawn Background Rule Updater
    // This task runs every X hours to download and 'swap' the resolver
    let updater_cfg = Arc::clone(&cfg);
    let updater_resolver = Arc::clone(&shared_resolver);
    tokio::spawn(async move {
        crate::updater::run_periodic_update(updater_cfg, updater_resolver).await;
    });

    // 5. Setup UDP Socket (Standard DNS Port 53 or 5353)
    let socket = UdpSocket::bind(&cfg.server.listen_addr).await?;
    println!("Dgaard 🛡️  is live on {}", cfg.server.listen_addr);

    let mut buf = [0u8; 512]; // Standard DNS max UDP packet size

    // 6. Main Event Loop
    loop {
        tokio::select! {
            // Handle Incoming DNS Queries
            Ok((len, addr)) = socket.recv_from(&mut buf) => {
                let query_data = buf[..len].to_vec();
                let current_resolver = shared_resolver.load();
                let socket_clone = socket.try_clone()?; // Or use Arc<UdpSocket>
                let state_clone = Arc::clone(&state);

                // Spawn a task per query to keep the loop responsive
                tokio::spawn(async move {
                    if let Ok(response) = current_resolver.handle_packet(&query_data, addr, state_clone).await {
                        let _ = socket.send_to(&response, addr).await;
                    }
// // Inside your main loop
// if let Some(packet) = DnsPacket::from_bytes(&buf[..len]) {
//     let domain = &packet.domain;
//     let client_ip = addr.ip();

//     // 1. Run the filter
//     let action = current_resolver.check(domain, client_ip).await;

//     match action {
//         Action::Block => {
//             let response = DnsPacket::build_nxdomain_response(&packet.message);
//             let _ = socket.send_to(&response, addr).await;
//             // Log to your Unix Socket via the ProxyState
//             state.log_block(domain, addr).await;
//         }
//         Action::Allow => {
//             // 2. Forward to Upstream (1.1.1.1, etc)
//             let response = forwarder.proxy_query(&buf[..len]).await;
//             let _ = socket.send_to(&response, addr).await;
//         }
//     }
// }
                });
            }

            // Optional: Handle Shutdown signals (SIGINT/SIGTERM)
            _ = tokio::signal::ctrl_c() => {
                println!("\nShutting down Dgaard...");
                break;
            }
        }
    }

    Ok(())
}

// use bloom::{BloomFilter, ASMS};

// // For 1,000,000 items with 0.01 false positive rate
// let expected_num_items = 1_000_000;
// let false_positive_rate = 0.01;
// let mut filter = BloomFilter::with_rate(false_positive_rate, expected_num_items);

// // During lookup
// if filter.contains(&xxh64_hash_of_domain) {
//     // This domain was registered recently!
//     // Trigger extra checks or log to your Unix Socket
// }
