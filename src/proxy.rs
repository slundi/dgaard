use dgaard::ProxyMessage;
use dashmap::DashSet;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;

pub struct ProxyState {
    // Stores hashes we have already sent the String mapping for
    pub announced_hashes: DashSet<u64>,
    // The active connection to your stats collector tool
    pub stats_tx: Option<Arc<tokio::sync::Mutex<UnixStream>>>,
}

impl ProxyState {
    pub async fn log_event(&self, domain: &str, hash: u64, rule_id: u64, ip: [u8; 16]) {
        let Some(stream_lock) = &self.stats_tx else {
            return;
        };
        let mut stream = stream_lock.lock().await;

        // 1. If we haven't told the collector what this hash means yet, send Mapping
        if !self.announced_hashes.contains(&hash) {
            let msg = ProxyMessage::DomainMapping {
                hash,
                domain: domain.to_string(),
            };

            if let Ok(buf) = postcard::to_stdvec(&msg) {
                let _ = stream.write_all(&buf).await;
            }
            self.announced_hashes.insert(hash);
        }

        // 2. Send the actual Event
        let event = ProxyMessage::Event {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            rule_id,
            domain_hash: hash,
            client_ip: ip,
        };

        if let Ok(buf) = postcard::to_stdvec(&event) {
            let _ = stream.write_all(&buf).await;
        }
    }
}
