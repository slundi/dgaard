use dashmap::DashSet;
use dgaard::{StatAction, StatEvent, StatMessage};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;

pub struct ProxyState {
    /// Stores hashes we have already sent the domain mapping for
    pub announced_hashes: DashSet<u64>,
    /// The active connection to the stats collector
    pub stats_tx: Option<Arc<tokio::sync::Mutex<UnixStream>>>,
}

impl ProxyState {
    /// Log a DNS query event to the stats collector.
    ///
    /// Sends a DomainMapping message for new domains (first time seen),
    /// then sends the StatEvent with the query details.
    pub async fn log_event(&self, domain: &str, hash: u64, client_addr: SocketAddr, action: StatAction) {
        let Some(stream_lock) = &self.stats_tx else {
            return;
        };
        let mut stream = stream_lock.lock().await;

        // 1. If we haven't told the collector what this hash means yet, send Mapping
        if !self.announced_hashes.contains(&hash) {
            let msg = StatMessage::DomainMapping {
                hash,
                domain: domain.to_string(),
            };
            let buf = msg.serialize();
            let _ = stream.write_all(&buf).await;
            self.announced_hashes.insert(hash);
        }

        // 2. Send the actual Event
        let event = StatEvent::new(hash, client_addr, action);
        let msg = StatMessage::Event(event);
        let buf = msg.serialize();
        let _ = stream.write_all(&buf).await;
    }
}
