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

/// Check a subject to publish on: dot-separated, non-empty tokens, without
/// whitespace, control characters or wildcards. An empty subject (leg
/// disabled) is valid.
pub fn validate_publish_subject(subject: &str) -> Result<(), String> {
    check_subject(subject, false)
}

/// Check a subject to subscribe to: like a publish subject, except that
/// wildcards are allowed as whole tokens, `*` anywhere and `>` last.
pub fn validate_subscribe_subject(subject: &str) -> Result<(), String> {
    check_subject(subject, true)
}

fn check_subject(subject: &str, wildcards: bool) -> Result<(), String> {
    if subject.is_empty() {
        return Ok(());
    }
    if subject
        .chars()
        .any(|ch| ch.is_whitespace() || ch.is_control())
    {
        return Err("must not contain whitespace or control characters".to_string());
    }
    let tokens: Vec<&str> = subject.split('.').collect();
    for (position, token) in tokens.iter().enumerate() {
        if token.is_empty() {
            return Err(
                "must not contain empty tokens (leading, trailing or double dot)".to_string(),
            );
        }
        if !token.contains(['*', '>']) {
            continue;
        }
        if !wildcards {
            return Err("wildcards `*` and `>` are only valid in subscriptions".to_string());
        }
        match *token {
            "*" => {}
            ">" if position == tokens.len() - 1 => {}
            ">" => return Err("`>` is only valid as the last token".to_string()),
            _ => {
                return Err(format!(
                    "wildcard inside token `{token}`; use it as a whole token"
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publish_subjects() {
        for valid in ["", "dgaard.events", "site42.dns-events", "a"] {
            assert!(validate_publish_subject(valid).is_ok(), "{valid:?}");
        }
        for invalid in [
            "dgaard.*",
            "dgaard.>",
            "dgaard events",
            "dgaard.events\n",
            "dgaard..events",
            ".dgaard",
            "dgaard.",
            "dg*ard",
        ] {
            assert!(validate_publish_subject(invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn subscribe_subjects() {
        for valid in ["", "dgaard.events", "dgaard.*", "*.events", "dgaard.>", ">"] {
            assert!(validate_subscribe_subject(valid).is_ok(), "{valid:?}");
        }
        for invalid in [
            "dgaard.>.events",
            "dg*ard",
            "dgaard.e>",
            "a b",
            "a..b",
            "\ta",
        ] {
            assert!(validate_subscribe_subject(invalid).is_err(), "{invalid:?}");
        }
    }
}
