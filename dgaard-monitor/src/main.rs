mod cli;
mod error;
mod io;
mod protocol;
mod state;

use state::AppState;
use std::time::Duration;

#[tokio::main]
async fn main() {
    let opts = cli::parse();

    // Warm-up: load host index
    let domain_map = match io::index::read_host_index(opts.index_path()) {
        Ok(map) => {
            println!("Loaded {} domains from index", map.len());
            map
        }
        Err(e) => {
            eprintln!("Warning: could not load host index: {e}");
            std::collections::HashMap::new()
        }
    };

    let state = AppState::new(Duration::from_secs(3600));

    // Pre-populate domain map from index
    for (hash, domain) in domain_map {
        state.insert_domain(hash, domain).await;
    }

    // Connect to Unix socket and stream events
    loop {
        match io::socket::connect(opts.socket_path()) {
            Ok(mut stream) => {
                println!("Connected to {}", opts.socket_path());
                loop {
                    match io::socket::read_frame(&mut stream).await {
                        Ok(protocol::StatMessage::DomainMapping { hash, domain }) => {
                            state.insert_domain(hash, domain).await;
                        }
                        Ok(protocol::StatMessage::Event(event)) => {
                            state.record_event(event).await;
                        }
                        Err(e) => {
                            eprintln!("Stream error: {e}");
                            break;
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("Connection failed: {e}, retrying in 5s...");
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    }
}
