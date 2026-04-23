use std::collections::HashSet;
use std::sync::Arc;

use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper::body::Bytes;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tokio::io::AsyncWriteExt;
use tokio::sync::watch;

use crate::config::ForwardingConfig;
use crate::protocol::StatAction;
use crate::state::AppState;

// --- HTTP client ---

type HttpsClient = Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    Full<Bytes>,
>;

fn build_https_client() -> HttpsClient {
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .build();
    Client::builder(TokioExecutor::new()).build(https)
}

// --- Entry point ---

/// Forward enriched events to configured sinks (file/stdout and/or HTTP POST).
///
/// Applies the `filter` list and formats each event via `template` before
/// writing or posting it.  Returns when `shutdown` is signalled.
pub async fn run(
    config: ForwardingConfig,
    state: Arc<AppState>,
    mut shutdown: watch::Receiver<bool>,
) {
    let ForwardingConfig {
        file,
        template,
        forward_url,
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

    // Only build the HTTP client when a URL is actually configured.
    let http_client = forward_url.as_ref().map(|_| build_https_client());

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

                        // Resolve once; reuse for both sinks.
                        let domain = resolve_domain(&state, event.domain_hash).await;
                        let ip = format_ip(&event.client_ip);
                        let act = action_name(&event.action);

                        let line = apply_template(&template, event.timestamp, &ip, act, &domain);
                        if let Err(e) = output.write_line(&line).await {
                            eprintln!("forwarding: write error: {e}");
                        }

                        if let (Some(client), Some(url)) = (&http_client, &forward_url) {
                            let json = format_json(event.timestamp, &ip, act, &domain);
                            post_event(client, url, &json).await;
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

// --- HTTP sink ---

/// POST `json` to `url`, logging any transport or non-2xx errors.
async fn post_event(client: &HttpsClient, url: &str, json: &str) {
    let body = Full::new(Bytes::from(json.to_owned()));
    let req = match Request::builder()
        .method("POST")
        .uri(url)
        .header("content-type", "application/json")
        .body(body)
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("forwarding: failed to build HTTP request: {e}");
            return;
        }
    };

    match client.request(req).await {
        Ok(resp) => {
            let status = resp.status();
            if !status.is_success() {
                eprintln!("forwarding: HTTP POST returned {status}");
            }
            // Drain body so the connection can be reused.
            let _ = resp.into_body().collect().await;
        }
        Err(e) => eprintln!("forwarding: HTTP POST failed: {e}"),
    }
}

/// Serialize event fields to a compact JSON object.
fn format_json(timestamp: u64, client_ip: &str, action: &str, domain: &str) -> String {
    format!(
        r#"{{"timestamp":{timestamp},"client_ip":"{ci}","action":"{act}","domain":"{dom}"}}"#,
        timestamp = timestamp,
        ci = json_escape(client_ip),
        act = json_escape(action),
        dom = json_escape(domain),
    )
}

/// Minimal JSON string escaper (handles control chars, `"` and `\`).
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
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

/// Look up `hash` in the domain map; fall back to `#<hex>` if not found.
async fn resolve_domain(state: &AppState, hash: u64) -> String {
    state
        .domain_map
        .read()
        .await
        .get(&hash)
        .cloned()
        .unwrap_or_else(|| format!("#{:016x}", hash))
}

/// Replace template placeholders with event field values.
fn apply_template(
    template: &str,
    timestamp: u64,
    client_ip: &str,
    action: &str,
    domain: &str,
) -> String {
    template
        .replace("{timestamp}", &timestamp.to_string())
        .replace("{client_ip}", client_ip)
        .replace("{action}", action)
        .replace("{domain}", domain)
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

    // --- action_name ---

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

    // --- format_ip ---

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

    // --- passes_filter ---

    #[test]
    fn test_passes_filter_empty_allows_all() {
        let filter = HashSet::new();
        assert!(passes_filter(&filter, &StatAction::Allowed));
        assert!(passes_filter(&filter, &StatAction::Proxied));
        assert!(passes_filter(
            &filter,
            &StatAction::Blocked(StatBlockReason::empty())
        ));
        assert!(passes_filter(
            &filter,
            &StatAction::Suspicious(StatBlockReason::empty())
        ));
        assert!(passes_filter(
            &filter,
            &StatAction::HighlySuspicious(StatBlockReason::empty())
        ));
    }

    #[test]
    fn test_passes_filter_matches_variant() {
        let filter: HashSet<String> = ["Blocked".to_string(), "HighlySuspicious".to_string()]
            .into_iter()
            .collect();
        assert!(!passes_filter(&filter, &StatAction::Allowed));
        assert!(!passes_filter(&filter, &StatAction::Proxied));
        assert!(passes_filter(
            &filter,
            &StatAction::Blocked(StatBlockReason::empty())
        ));
        assert!(!passes_filter(
            &filter,
            &StatAction::Suspicious(StatBlockReason::empty())
        ));
        assert!(passes_filter(
            &filter,
            &StatAction::HighlySuspicious(StatBlockReason::empty())
        ));
    }

    // --- apply_template ---

    #[test]
    fn test_apply_template_default() {
        let line = apply_template(
            "{timestamp} {client_ip} {action} {domain}",
            1_700_000_000,
            "192.168.1.1",
            "Allowed",
            "example.com",
        );
        assert_eq!(line, "1700000000 192.168.1.1 Allowed example.com");
    }

    #[test]
    fn test_apply_template_custom() {
        let line = apply_template(
            "[{action}] {domain} from {client_ip}",
            0,
            "10.0.0.1",
            "Blocked",
            "evil.com",
        );
        assert_eq!(line, "[Blocked] evil.com from 10.0.0.1");
    }

    // --- resolve_domain ---

    #[tokio::test]
    async fn test_resolve_domain_known() {
        let state = make_state();
        state
            .insert_domain(0xdeadbeef, "example.com".to_string())
            .await;
        assert_eq!(resolve_domain(&state, 0xdeadbeef).await, "example.com");
    }

    #[tokio::test]
    async fn test_resolve_domain_unknown_falls_back_to_hash() {
        let state = make_state();
        let result = resolve_domain(&state, 0xdeadbeef).await;
        assert_eq!(result, "#00000000deadbeef");
    }

    // --- format_json ---

    #[test]
    fn test_format_json_allowed() {
        let json = format_json(1_700_000_000, "192.168.1.1", "Allowed", "example.com");
        assert_eq!(
            json,
            r#"{"timestamp":1700000000,"client_ip":"192.168.1.1","action":"Allowed","domain":"example.com"}"#
        );
    }

    #[test]
    fn test_format_json_blocked() {
        let json = format_json(0, "10.0.0.1", "Blocked", "malware.example");
        assert_eq!(
            json,
            r#"{"timestamp":0,"client_ip":"10.0.0.1","action":"Blocked","domain":"malware.example"}"#
        );
    }

    #[test]
    fn test_format_json_escapes_quotes_in_domain() {
        // Defensive: a domain shouldn't have quotes, but the escaper must handle them.
        let json = format_json(1, "1.2.3.4", "Allowed", r#"bad"domain"#);
        assert!(
            json.contains(r#"bad\"domain"#),
            "quote should be escaped: {json}"
        );
    }

    #[test]
    fn test_json_escape_control_chars() {
        assert_eq!(json_escape("\x01\x1f"), "\\u0001\\u001f");
        assert_eq!(json_escape("\n\r\t"), "\\n\\r\\t");
        assert_eq!(json_escape("normal"), "normal");
    }

    // --- file output ---

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
        let domain = resolve_domain(&state, event.domain_hash).await;
        let ip = format_ip(&event.client_ip);
        let line = apply_template(
            "{timestamp} {client_ip} {action} {domain}",
            event.timestamp,
            &ip,
            action_name(&event.action),
            &domain,
        );
        output.write_line(&line).await.unwrap();

        let content = tokio::fs::read_to_string(&path_str).await.unwrap();
        assert_eq!(content, "1700000000 192.168.1.1 Allowed example.com\n");
    }

    #[tokio::test]
    async fn test_write_appends_to_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fwd.log");
        let path_str = path.to_str().unwrap().to_string();

        let line = "Allowed example.com";

        let mut output = open_output(Some(&path_str)).await.unwrap();
        output.write_line(line).await.unwrap();
        drop(output);

        let mut output2 = open_output(Some(&path_str)).await.unwrap();
        output2.write_line(line).await.unwrap();
        drop(output2);

        let content = tokio::fs::read_to_string(&path_str).await.unwrap();
        assert_eq!(content, "Allowed example.com\nAllowed example.com\n");
    }

    // --- HTTP sink ---

    #[tokio::test]
    async fn test_post_event_sends_correct_json() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt as _};
        use tokio::net::TcpListener;

        // Minimal HTTP/1.1 echo server — reads one request, returns 200, captures body.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = stream.read(&mut buf).await.unwrap();
            let raw = String::from_utf8_lossy(&buf[..n]).to_string();
            let resp = "HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";
            stream.write_all(resp.as_bytes()).await.unwrap();
            raw
        });

        let client = build_https_client();
        let url = format!("http://127.0.0.1:{port}/events");
        let json = format_json(1_700_000_000, "192.168.1.1", "Blocked", "evil.com");
        post_event(&client, &url, &json).await;

        let raw_request = server.await.unwrap();
        assert!(
            raw_request.contains("POST /events HTTP/1.1"),
            "wrong method/path"
        );
        assert!(
            raw_request
                .to_lowercase()
                .contains("content-type: application/json"),
            "missing content-type header"
        );
        assert!(
            raw_request.contains(r#""action":"Blocked""#),
            "body missing action field"
        );
        assert!(
            raw_request.contains(r#""domain":"evil.com""#),
            "body missing domain field"
        );
        assert!(
            raw_request.contains(r#""client_ip":"192.168.1.1""#),
            "body missing client_ip field"
        );
    }

    #[tokio::test]
    async fn test_post_event_handles_non_2xx_gracefully() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt as _};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let _ = stream.read(&mut buf).await;
            let resp = "HTTP/1.1 500 Internal Server Error\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";
            stream.write_all(resp.as_bytes()).await.unwrap();
        });

        let client = build_https_client();
        let url = format!("http://127.0.0.1:{port}/events");
        // Should not panic — just logs the error.
        post_event(&client, &url, "{}").await;
    }
}
