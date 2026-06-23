//! Optional NATS publisher for scoring decisions.
//!
//! When the `[nats]` section in `dgaard-daemon.toml` sets `enabled = true`,
//! the daemon connects to the configured NATS server at startup and publishes
//! one JSON document per scored domain on the configured subject. The
//! publisher is loosely coupled: scoring continues even if NATS is
//! unreachable, only emitting log warnings.
//!
//! Wire format (UTF-8 JSON):
//! ```json
//! {
//!   "ts": 1731000000,
//!   "domain": "example.com",
//!   "score": 42,
//!   "blocked": false,
//!   "action": "ProxyToUpstream",
//!   "reasons": ["HighEntropy(4.50)"]
//! }
//! ```
//!
//! The schema mirrors `DomainResponse` (the on-socket JSON reply) with an
//! added `ts` field (UNIX seconds when the event was emitted) so consumers
//! can correlate decisions across daemons.
use serde::{Deserialize, Serialize};

use crate::handler::DomainResponse;

/// JSON event published on the NATS bus.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScoreEvent {
    pub ts: u64,
    pub domain: String,
    pub score: u8,
    pub blocked: bool,
    pub action: String,
    pub reasons: Vec<String>,
}

impl ScoreEvent {
    /// Build a `ScoreEvent` for `domain` from the JSON reply that was just
    /// written to the calling socket client.
    pub fn from_response(domain: &str, response: &DomainResponse) -> Self {
        Self {
            ts: now_unix_seconds(),
            domain: domain.to_string(),
            score: response.score,
            blocked: response.blocked,
            action: response.action.clone(),
            reasons: response.reasons.clone(),
        }
    }
}

fn now_unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Thin handle around an `async_nats::Client` that publishes `ScoreEvent`s.
///
/// Cloning is cheap (the underlying client is internally an `Arc`). The
/// handle is detached from connection state: if the broker goes away the
/// client reconnects in the background and publishes that fail in the
/// meantime are surfaced as `Err`.
#[derive(Clone)]
pub struct NatsPublisher {
    client: async_nats::Client,
    subject: async_nats::Subject,
}

impl NatsPublisher {
    /// Connect to `url` and return a publisher bound to `subject`.
    pub async fn connect(url: &str, subject: &str) -> Result<Self, async_nats::ConnectError> {
        let client = async_nats::connect(url).await?;
        Ok(Self {
            client,
            subject: async_nats::Subject::from(subject.to_string()),
        })
    }

    /// Build a publisher from an already-connected client. Used in tests.
    pub fn from_client(client: async_nats::Client, subject: &str) -> Self {
        Self {
            client,
            subject: async_nats::Subject::from(subject.to_string()),
        }
    }

    /// Publish `event` as a JSON document. Errors are logged by the caller
    /// so a transient broker outage doesn't abort the scoring path.
    pub async fn publish(&self, event: &ScoreEvent) -> Result<(), PublishError> {
        let payload = serde_json::to_vec(event).map_err(PublishError::Serialize)?;
        self.client
            .publish(self.subject.clone(), payload.into())
            .await
            .map_err(PublishError::Publish)?;
        Ok(())
    }
}

#[derive(Debug)]
pub enum PublishError {
    Serialize(serde_json::Error),
    Publish(async_nats::PublishError),
}

impl std::fmt::Display for PublishError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PublishError::Serialize(e) => write!(f, "serialize event: {e}"),
            PublishError::Publish(e) => write!(f, "nats publish: {e}"),
        }
    }
}

impl std::error::Error for PublishError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PublishError::Serialize(e) => Some(e),
            PublishError::Publish(e) => Some(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_response() -> DomainResponse {
        DomainResponse {
            score: 42,
            blocked: false,
            action: "ProxyToUpstream".to_string(),
            reasons: vec!["HighEntropy(4.50)".to_string()],
        }
    }

    #[test]
    fn event_from_response_copies_fields() {
        let resp = sample_response();
        let ev = ScoreEvent::from_response("example.com", &resp);
        assert_eq!(ev.domain, "example.com");
        assert_eq!(ev.score, 42);
        assert!(!ev.blocked);
        assert_eq!(ev.action, "ProxyToUpstream");
        assert_eq!(ev.reasons, vec!["HighEntropy(4.50)".to_string()]);
        // ts must be a plausible unix timestamp (after 2020).
        assert!(ev.ts > 1_577_836_800, "ts looks unset: {}", ev.ts);
    }

    #[test]
    fn event_round_trips_through_json() {
        let resp = sample_response();
        let ev = ScoreEvent::from_response("example.com", &resp);
        let bytes = serde_json::to_vec(&ev).unwrap();
        let decoded: ScoreEvent = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(ev, decoded);
    }

    #[test]
    fn event_json_has_stable_field_names() {
        let resp = sample_response();
        let ev = ScoreEvent::from_response("example.com", &resp);
        let s = serde_json::to_string(&ev).unwrap();
        // Field names form part of the public NATS wire format; pin them.
        for key in [
            "\"ts\"",
            "\"domain\"",
            "\"score\"",
            "\"blocked\"",
            "\"action\"",
            "\"reasons\"",
        ] {
            assert!(s.contains(key), "missing field {key} in {s}");
        }
    }
}
