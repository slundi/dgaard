pub mod blocklist;
pub mod config;
pub mod domain;

use postcard::{from_bytes, to_stdvec};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub enum ProxyMessage {
    /// Sent only once per domain per session to "seed" the collector's database
    DomainMapping { 
        hash: u64, 
        domain: String 
    },
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
