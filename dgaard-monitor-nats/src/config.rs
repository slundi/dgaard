/// Optional NATS publisher + subscriber configuration. Disabled by default.
///
/// When `enabled`, the monitor publishes every enriched event on
/// `publish_subject` and (if `subscribe_subject` is non-empty) subscribes to
/// that subject and feeds incoming events into the local stats/broadcast.
/// This lets monitors federate or relay events from another dgaard daemon
/// without sharing a Unix socket.
#[derive(Debug, Clone, PartialEq)]
pub struct NatsConfig {
    pub enabled: bool,
    pub url: String,
    /// Subject the monitor publishes enriched events on.
    /// Empty string disables publishing.
    pub publish_subject: String,
    /// Subject the monitor subscribes to (e.g. `dgaard.events` or `dgaard.scores`).
    /// Empty string disables subscription.
    pub subscribe_subject: String,
}

fn default_nats_url() -> String {
    "nats://127.0.0.1:4222".to_string()
}

fn default_nats_publish_subject() -> String {
    "dgaard.events".to_string()
}

impl Default for NatsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: default_nats_url(),
            publish_subject: default_nats_publish_subject(),
            subscribe_subject: String::new(),
        }
    }
}
