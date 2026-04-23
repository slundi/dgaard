use std::collections::HashSet;
use std::sync::Arc;

use tokio::io::AsyncWriteExt;
use tokio::sync::watch;

use crate::config::ForwardingConfig;
use crate::protocol::{StatAction, StatEvent};
use crate::state::AppState;

/// Forward enriched events to external sinks (file or stdout).
///
/// Applies the `filter` list from `config` and formats each event using the
/// configured `template` before writing it.  `forward_url` (HTTP sink) is not
/// yet implemented.
///
/// Returns when `shutdown` is signalled.
pub async fn run(
    config: ForwardingConfig,
    state: Arc<AppState>,
    mut shutdown: watch::Receiver<bool>,
) {
    let ForwardingConfig {
        file,
        template,
        forward_url: _,
        filter,
    } = config;
    let filter: HashSet<String> = filter.into_iter().collect();

    let mut output = match open_output(file.as_deref()).await {
        Ok(o) => o,
        Err(e) => {
            eprintln!("forwarding: failed to open output: {e}");
            return;
        }
    };

    let mut rx = state.subscribe();

    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            result = rx.recv() => {
                match result {
                    Ok(event) => {
                        if !passes_filter(&filter, &event.action) {
                            continue;
                        }
                        let line = format_event(&template, &event, &state).await;
                        if let Err(e) = output.write_line(&line).await {
                            eprintln!("forwarding: write error: {e}");
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        eprintln!("forwarding: lagged, dropped {n} events");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }
}

// --- Output sink ---

enum Output {
    File(tokio::fs::File),
    Stdout,
}

impl Output {
    async fn write_line(&mut self, line: &str) -> std::io::Result<()> {
        let bytes = format!("{line}\n");
        match self {
            Output::File(f) => f.write_all(bytes.as_bytes()).await,
            Output::Stdout => tokio::io::stdout().write_all(bytes.as_bytes()).await,
        }
    }
}

async fn open_output(path: Option<&str>) -> std::io::Result<Output> {
    match path {
        Some(p) => {
            let f = tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(p)
                .await?;
            Ok(Output::File(f))
        }
        None => Ok(Output::Stdout),
    }
}

// --- Helpers ---

fn action_name(action: &StatAction) -> &'static str {
    match action {
        StatAction::Allowed => "Allowed",
        StatAction::Proxied => "Proxied",
        StatAction::Blocked(_) => "Blocked",
        StatAction::Suspicious(_) => "Suspicious",
        StatAction::HighlySuspicious(_) => "HighlySuspicious",
    }
}

/// Returns `true` if `action` should be forwarded given the filter set.
/// An empty filter means forward all.
fn passes_filter(filter: &HashSet<String>, action: &StatAction) -> bool {
    filter.is_empty() || filter.contains(action_name(action))
}

/// Format `event` using `template`, resolving the domain hash via `state`.
async fn format_event(template: &str, event: &StatEvent, state: &AppState) -> String {
    let domain = {
        let map = state.domain_map.read().await;
        map.get(&event.domain_hash)
            .cloned()
            .unwrap_or_else(|| format!("#{:016x}", event.domain_hash))
    };

    template
        .replace("{timestamp}", &event.timestamp.to_string())
        .replace("{client_ip}", &format_ip(&event.client_ip))
        .replace("{action}", action_name(&event.action))
        .replace("{domain}", &domain)
}

/// Format a 16-byte IP array.
/// If the last 12 bytes are zero, treat the first 4 as IPv4.
fn format_ip(ip: &[u8; 16]) -> String {
    if ip[4..].iter().all(|&b| b == 0) {
        format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
    } else {
        std::net::Ipv6Addr::from(*ip).to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{StatBlockReason, StatEvent};
    use std::time::Duration;

    fn make_event(action: StatAction) -> StatEvent {
        StatEvent {
            timestamp: 1_700_000_000,
            domain_hash: 0xdeadbeef,
            client_ip: [192, 168, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            action,
        }
    }

    fn make_state() -> Arc<AppState> {
        Arc::new(AppState::new(Duration::from_secs(3600)))
    }

    #[test]
    fn test_action_name_variants() {
        assert_eq!(action_name(&StatAction::Allowed), "Allowed");
        assert_eq!(action_name(&StatAction::Proxied), "Proxied");
        assert_eq!(
            action_name(&StatAction::Blocked(StatBlockReason::empty())),
            "Blocked"
        );
        assert_eq!(
            action_name(&StatAction::Suspicious(StatBlockReason::empty())),
            "Suspicious"
        );
        assert_eq!(
            action_name(&StatAction::HighlySuspicious(StatBlockReason::empty())),
            "HighlySuspicious"
        );
    }

    #[test]
    fn test_format_ip_v4() {
        assert_eq!(
            format_ip(&[192, 168, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            "192.168.1.1"
        );
        assert_eq!(
            format_ip(&[10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            "10.0.0.1"
        );
    }

    #[test]
    fn test_format_ip_v6() {
        let ip = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(format_ip(&ip), "2001:db8::1");
    }

    #[test]
    fn test_passes_filter_empty_allows_all() {
        let filter = HashSet::new();
        assert!(passes_filter(&filter, &StatAction::Allowed));
        assert!(passes_filter(&filter, &StatAction::Proxied));
        assert!(passes_filter(&filter, &StatAction::Blocked(StatBlockReason::empty())));
        assert!(passes_filter(&filter, &StatAction::Suspicious(StatBlockReason::empty())));
        assert!(passes_filter(
            &filter,
            &StatAction::HighlySuspicious(StatBlockReason::empty())
        ));
    }

    #[test]
    fn test_passes_filter_matches_variant() {
        let filter: HashSet<String> =
            ["Blocked".to_string(), "HighlySuspicious".to_string()]
                .into_iter()
                .collect();
        assert!(!passes_filter(&filter, &StatAction::Allowed));
        assert!(!passes_filter(&filter, &StatAction::Proxied));
        assert!(passes_filter(&filter, &StatAction::Blocked(StatBlockReason::empty())));
        assert!(!passes_filter(&filter, &StatAction::Suspicious(StatBlockReason::empty())));
        assert!(passes_filter(
            &filter,
            &StatAction::HighlySuspicious(StatBlockReason::empty())
        ));
    }

    #[tokio::test]
    async fn test_format_event_default_template() {
        let state = make_state();
        state
            .insert_domain(0xdeadbeef, "example.com".to_string())
            .await;
        let event = make_event(StatAction::Allowed);
        let line =
            format_event("{timestamp} {client_ip} {action} {domain}", &event, &state).await;
        assert_eq!(line, "1700000000 192.168.1.1 Allowed example.com");
    }

    #[tokio::test]
    async fn test_format_event_unknown_domain_falls_back_to_hash() {
        let state = make_state();
        let event = make_event(StatAction::Allowed);
        let line =
            format_event("{timestamp} {client_ip} {action} {domain}", &event, &state).await;
        assert!(
            line.ends_with("#00000000deadbeef"),
            "expected hex hash fallback, got: {line}"
        );
    }

    #[tokio::test]
    async fn test_format_event_custom_template() {
        let state = make_state();
        state
            .insert_domain(0xdeadbeef, "evil.com".to_string())
            .await;
        let event = make_event(StatAction::Blocked(StatBlockReason::STATIC_BLACKLIST));
        let line = format_event("[{action}] {domain} from {client_ip}", &event, &state).await;
        assert_eq!(line, "[Blocked] evil.com from 192.168.1.1");
    }

    #[tokio::test]
    async fn test_write_to_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fwd.log");
        let path_str = path.to_str().unwrap().to_string();

        let state = make_state();
        state
            .insert_domain(0xdeadbeef, "example.com".to_string())
            .await;

        let mut output = open_output(Some(&path_str)).await.unwrap();
        let event = make_event(StatAction::Allowed);
        let line =
            format_event("{timestamp} {client_ip} {action} {domain}", &event, &state).await;
        output.write_line(&line).await.unwrap();

        let content = tokio::fs::read_to_string(&path_str).await.unwrap();
        assert_eq!(content, "1700000000 192.168.1.1 Allowed example.com\n");
    }

    #[tokio::test]
    async fn test_write_appends_to_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fwd.log");
        let path_str = path.to_str().unwrap().to_string();

        let state = make_state();
        state
            .insert_domain(0xdeadbeef, "example.com".to_string())
            .await;

        let event = make_event(StatAction::Allowed);
        let line = format_event("{action} {domain}", &event, &state).await;

        let mut output = open_output(Some(&path_str)).await.unwrap();
        output.write_line(&line).await.unwrap();
        drop(output);

        let mut output2 = open_output(Some(&path_str)).await.unwrap();
        output2.write_line(&line).await.unwrap();
        drop(output2);

        let content = tokio::fs::read_to_string(&path_str).await.unwrap();
        assert_eq!(content, "Allowed example.com\nAllowed example.com\n");
    }
}
