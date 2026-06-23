use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper::body::Bytes;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tokio::io::AsyncWriteExt;
use tokio::sync::watch;
use tokio::time::timeout;

use crate::config::{ForwardFormat, ForwardingConfig};
use crate::protocol::{StatAction, StatBlockReason};
use crate::state::AppState;

// --- HTTP client ---

type HttpsClient = Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    Full<Bytes>,
>;

fn build_https_client() -> HttpsClient {
    let _ = rustls::crypto::ring::default_provider().install_default();
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
        format,
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

                        let domain = resolve_domain(&state, event.domain_hash).await;
                        let ip = format_ip(&event.client_ip);

                        let body = format_event(
                            &format,
                            &template,
                            event.timestamp,
                            &ip,
                            &event.action,
                            &domain,
                        );
                        if let Err(e) = output.write_line(&body).await {
                            eprintln!("forwarding: write error: {e}");
                        }

                        if let (Some(client), Some(url)) = (&http_client, &forward_url) {
                            let ct = format.content_type();
                            // ES bulk API requires a trailing newline after the last document.
                            // write_line already handles the file case; add it here for HTTP.
                            if ct == "application/x-ndjson" {
                                post_event(client, url, &format!("{body}\n"), ct).await;
                            } else {
                                post_event(client, url, &body, ct).await;
                            }
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

/// Cap on a single outbound POST to a SOAR/webhook endpoint, including
/// the response body drain. A hung sink that never replies must not be
/// allowed to back-pressure the forwarding task and stall every event.
const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// POST `body` to `url` with the given `content_type`, logging any errors.
async fn post_event(client: &HttpsClient, url: &str, body: &str, content_type: &str) {
    let body = Full::new(Bytes::from(body.to_owned()));
    let req = match Request::builder()
        .method("POST")
        .uri(url)
        .header("content-type", content_type)
        .body(body)
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("forwarding: failed to build HTTP request: {e}");
            return;
        }
    };

    let send = async {
        match client.request(req).await {
            Ok(resp) => {
                let status = resp.status();
                if !status.is_success() {
                    eprintln!("forwarding: HTTP POST returned {status}");
                }
                let _ = resp.into_body().collect().await;
            }
            Err(e) => eprintln!("forwarding: HTTP POST failed: {e}"),
        }
    };

    if timeout(HTTP_REQUEST_TIMEOUT, send).await.is_err() {
        eprintln!(
            "forwarding: HTTP POST to {url} timed out after {}s",
            HTTP_REQUEST_TIMEOUT.as_secs(),
        );
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

// --- RFC 3339 timestamp ---

/// Convert Unix epoch seconds to an RFC 3339 UTC string without external crates.
///
/// Uses Howard Hinnant's `civil_from_days` algorithm for the date portion.
fn unix_to_rfc3339(secs: u64) -> String {
    let days = secs / 86400;
    let rem = secs % 86400;
    let hh = rem / 3600;
    let mm = (rem % 3600) / 60;
    let ss = rem % 60;

    let z = days as i64 + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let yr = if mo <= 2 { y + 1 } else { y };

    format!("{yr:04}-{mo:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

// --- Reason labels ---

/// Return a `|`-joined list of set flag names from the action's reason, or `"-"`.
fn reason_labels(action: &StatAction) -> String {
    let reason = match action {
        StatAction::Blocked(r) | StatAction::Suspicious(r) | StatAction::HighlySuspicious(r) => *r,
        _ => return "-".to_string(),
    };
    if reason.is_empty() {
        return "-".to_string();
    }
    let named: Vec<&str> = reason.iter_names().map(|(n, _)| n).collect();
    let unknown = reason.bits() & !StatBlockReason::all().bits();
    if unknown != 0 {
        return if named.is_empty() {
            format!("CUSTOM_0x{unknown:08x}")
        } else {
            format!("{}|CUSTOM_0x{unknown:08x}", named.join("|"))
        };
    }
    named.join("|")
}

// --- RFC 5424 syslog ---

/// Escape `"`, `\`, and `]` for RFC 5424 structured-data param-values.
fn syslog_sd_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            ']' => out.push_str("\\]"),
            c => out.push(c),
        }
    }
    out
}

fn syslog_severity(action: &StatAction) -> u8 {
    match action {
        StatAction::Allowed | StatAction::Proxied => 6,
        StatAction::Suspicious(_) => 5,
        StatAction::HighlySuspicious(_) | StatAction::Blocked(_) => 4,
    }
}

fn format_syslog(timestamp: u64, ip: &str, action: &StatAction, domain: &str) -> String {
    let severity = syslog_severity(action);
    let pri = 4u8 * 8 + severity; // facility 4 = security/authorization messages
    let ts = unix_to_rfc3339(timestamp);
    let act = action_name(action);
    let reason = reason_labels(action);
    format!(
        "<{pri}>1 {ts} - dgaard - DNS-QUERY \
         [dgaard@32473 domain=\"{dom_esc}\" client_ip=\"{ip_esc}\" \
         action=\"{act}\" reason=\"{reason_esc}\"] \
         DNS query {act}: {domain}",
        dom_esc = syslog_sd_escape(domain),
        ip_esc = syslog_sd_escape(ip),
        reason_esc = syslog_sd_escape(&reason),
    )
}

// --- CEF ---

/// Escape `\`, `=`, and newlines for CEF extension field values.
fn cef_ext_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '=' => out.push_str("\\="),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c => out.push(c),
        }
    }
    out
}

fn cef_severity(action: &StatAction) -> u8 {
    match action {
        StatAction::Allowed | StatAction::Proxied => 1,
        StatAction::Suspicious(_) => 5,
        StatAction::HighlySuspicious(_) => 7,
        StatAction::Blocked(_) => 8,
    }
}

fn format_cef(timestamp: u64, ip: &str, action: &StatAction, domain: &str) -> String {
    let (sig_id, event_name) = match action {
        StatAction::Allowed => ("DNS-ALLOWED", "DNS Query Allowed"),
        StatAction::Proxied => ("DNS-PROXIED", "DNS Query Proxied"),
        StatAction::Suspicious(_) => ("DNS-SUSPICIOUS", "DNS Query Suspicious"),
        StatAction::HighlySuspicious(_) => ("DNS-HIGHLY-SUSPICIOUS", "DNS Query Highly Suspicious"),
        StatAction::Blocked(_) => ("DNS-BLOCKED", "DNS Query Blocked"),
    };
    let act = action_name(action);
    let reason = reason_labels(action);
    let rt_ms = timestamp.saturating_mul(1000);
    format!(
        "CEF:0|Stamus Networks|dgaard|1.0|{sig_id}|{event_name}|{sev}|\
         src={ip} dhost={domain} act={act} reason={reason} rt={rt_ms}",
        sev = cef_severity(action),
        ip = cef_ext_escape(ip),
        domain = cef_ext_escape(domain),
        act = cef_ext_escape(act),
        reason = cef_ext_escape(&reason),
    )
}

// --- Elasticsearch bulk ---

fn format_elasticsearch(timestamp: u64, ip: &str, action: &StatAction, domain: &str) -> String {
    let ts = unix_to_rfc3339(timestamp);
    let act = action_name(action);
    let reason = reason_labels(action);
    let (kind, category, ev_type) = match action {
        StatAction::Allowed | StatAction::Proxied => ("event", "network", "allowed"),
        StatAction::Blocked(_) => ("alert", "network", "denied"),
        StatAction::Suspicious(_) | StatAction::HighlySuspicious(_) => {
            ("alert", "intrusion_detection", "info")
        }
    };
    let ip = json_escape(ip);
    let act = json_escape(act);
    let domain = json_escape(domain);
    let reason = json_escape(&reason);
    format!(
        r#"{{"index":{{}}}}
{{"@timestamp":"{ts}","client_ip":"{ip}","action":"{act}","domain":"{domain}","reason":"{reason}","event":{{"kind":"{kind}","category":["{category}"],"type":["{ev_type}"],"dataset":"dgaard.dns"}}}}"#,
    )
}

// --- Format dispatcher ---

fn format_event(
    format: &ForwardFormat,
    template: &str,
    timestamp: u64,
    ip: &str,
    action: &StatAction,
    domain: &str,
) -> String {
    match format {
        ForwardFormat::Template => {
            apply_template(template, timestamp, ip, action_name(action), domain)
        }
        ForwardFormat::Json => format_json(timestamp, ip, action_name(action), domain),
        ForwardFormat::Syslog => format_syslog(timestamp, ip, action, domain),
        ForwardFormat::Cef => format_cef(timestamp, ip, action, domain),
        ForwardFormat::Elasticsearch => format_elasticsearch(timestamp, ip, action, domain),
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

use crate::util::action_name;

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
        post_event(&client, &url, &json, "application/json").await;

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
        post_event(&client, &url, "{}", "application/json").await;
    }

    // --- unix_to_rfc3339 ---

    #[test]
    fn test_unix_to_rfc3339_known_timestamp() {
        // python3: datetime.utcfromtimestamp(1700000000) == 2023-11-14 22:13:20
        assert_eq!(unix_to_rfc3339(1_700_000_000), "2023-11-14T22:13:20Z");
    }

    #[test]
    fn test_unix_to_rfc3339_epoch() {
        assert_eq!(unix_to_rfc3339(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn test_unix_to_rfc3339_leap_day() {
        // 2000-02-29T00:00:00Z = 951782400
        assert_eq!(unix_to_rfc3339(951_782_400), "2000-02-29T00:00:00Z");
    }

    // --- reason_labels ---

    #[test]
    fn test_reason_labels_allowed_proxied_returns_dash() {
        assert_eq!(reason_labels(&StatAction::Allowed), "-");
        assert_eq!(reason_labels(&StatAction::Proxied), "-");
    }

    #[test]
    fn test_reason_labels_empty_reason_returns_dash() {
        assert_eq!(
            reason_labels(&StatAction::Blocked(StatBlockReason::empty())),
            "-"
        );
    }

    #[test]
    fn test_reason_labels_single_flag() {
        let r = StatBlockReason::HIGH_ENTROPY;
        assert_eq!(reason_labels(&StatAction::Blocked(r)), "HIGH_ENTROPY");
    }

    #[test]
    fn test_reason_labels_multiple_flags_pipe_joined() {
        let r = StatBlockReason::STATIC_BLACKLIST | StatBlockReason::NRD_LIST;
        let labels = reason_labels(&StatAction::Blocked(r));
        assert!(labels.contains("STATIC_BLACKLIST"), "got: {labels}");
        assert!(labels.contains("NRD_LIST"), "got: {labels}");
        assert!(labels.contains('|'), "expected pipe separator: {labels}");
    }

    #[test]
    fn test_reason_labels_suspicious_and_highly_suspicious() {
        let r = StatBlockReason::CNAME_CLOAKING;
        assert_eq!(reason_labels(&StatAction::Suspicious(r)), "CNAME_CLOAKING");
        assert_eq!(
            reason_labels(&StatAction::HighlySuspicious(r)),
            "CNAME_CLOAKING"
        );
    }

    // --- format_syslog ---

    #[test]
    fn test_format_syslog_blocked_pri_36() {
        let action = StatAction::Blocked(StatBlockReason::STATIC_BLACKLIST);
        let line = format_syslog(1_700_000_000, "192.168.1.1", &action, "evil.com");
        // facility=4, severity=4 (Warning) → PRI = 36
        assert!(line.starts_with("<36>1 "), "wrong PRI: {line}");
        assert!(line.contains("2023-11-14T22:13:20Z"), "missing ts: {line}");
        assert!(line.contains("dgaard"), "missing app-name: {line}");
        assert!(
            line.contains(r#"domain="evil.com""#),
            "missing domain SD: {line}"
        );
        assert!(
            line.contains(r#"client_ip="192.168.1.1""#),
            "missing ip SD: {line}"
        );
        assert!(
            line.contains(r#"action="Blocked""#),
            "missing action SD: {line}"
        );
        assert!(
            line.contains(r#"reason="STATIC_BLACKLIST""#),
            "missing reason SD: {line}"
        );
        assert!(line.contains("[dgaard@32473 "), "missing SD-ID: {line}");
    }

    #[test]
    fn test_format_syslog_allowed_pri_38() {
        // facility=4, severity=6 (Informational) → PRI = 38
        let line = format_syslog(0, "1.2.3.4", &StatAction::Allowed, "example.com");
        assert!(line.starts_with("<38>1 "), "expected PRI 38: {line}");
    }

    #[test]
    fn test_format_syslog_suspicious_pri_37() {
        // facility=4, severity=5 (Notice) → PRI = 37
        let action = StatAction::Suspicious(StatBlockReason::empty());
        let line = format_syslog(0, "1.2.3.4", &action, "x.com");
        assert!(line.starts_with("<37>1 "), "expected PRI 37: {line}");
    }

    #[test]
    fn test_format_syslog_escapes_double_quote_in_domain() {
        let action = StatAction::Allowed;
        let line = format_syslog(0, "1.2.3.4", &action, r#"bad"domain.com"#);
        assert!(
            line.contains(r#"domain=\"bad\"domain.com\""#) || line.contains(r#"bad\"domain"#),
            "quote not escaped: {line}"
        );
    }

    // --- format_cef ---

    #[test]
    fn test_format_cef_blocked_structure() {
        let action = StatAction::Blocked(StatBlockReason::STATIC_BLACKLIST);
        let line = format_cef(1_700_000_000, "192.168.1.1", &action, "evil.com");
        assert!(
            line.starts_with("CEF:0|Stamus Networks|dgaard|1.0|DNS-BLOCKED|DNS Query Blocked|8|"),
            "wrong header: {line}"
        );
        assert!(line.contains("src=192.168.1.1"), "missing src: {line}");
        assert!(line.contains("dhost=evil.com"), "missing dhost: {line}");
        assert!(line.contains("act=Blocked"), "missing act: {line}");
        assert!(
            line.contains("reason=STATIC_BLACKLIST"),
            "missing reason: {line}"
        );
        assert!(line.contains("rt=1700000000000"), "wrong rt: {line}");
    }

    #[test]
    fn test_format_cef_severity_mapping() {
        let cases: &[(&StatAction, u8)] = &[
            (&StatAction::Allowed, 1),
            (&StatAction::Proxied, 1),
            (&StatAction::Suspicious(StatBlockReason::empty()), 5),
            (&StatAction::HighlySuspicious(StatBlockReason::empty()), 7),
            (&StatAction::Blocked(StatBlockReason::empty()), 8),
        ];
        for (action, expected_sev) in cases {
            let line = format_cef(0, "1.2.3.4", action, "x.com");
            let sev_marker = format!("|{expected_sev}|");
            assert!(
                line.contains(&sev_marker),
                "action {:?} → expected severity {expected_sev}: {line}",
                action
            );
        }
    }

    #[test]
    fn test_format_cef_escapes_equals_in_ext_values() {
        let line = format_cef(0, "1.2.3.4", &StatAction::Allowed, "a=b.com");
        assert!(line.contains(r"dhost=a\=b.com"), "= not escaped: {line}");
    }

    // --- format_elasticsearch ---

    #[test]
    fn test_format_elasticsearch_two_lines() {
        let action = StatAction::Blocked(StatBlockReason::HIGH_ENTROPY);
        let body = format_elasticsearch(1_700_000_000, "192.168.1.1", &action, "evil.com");
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 2, "expected 2 lines");
        assert_eq!(lines[0], r#"{"index":{}}"#);
    }

    #[test]
    fn test_format_elasticsearch_document_fields() {
        let action = StatAction::Blocked(StatBlockReason::HIGH_ENTROPY);
        let body = format_elasticsearch(1_700_000_000, "192.168.1.1", &action, "evil.com");
        let doc = body.lines().nth(1).unwrap();
        assert!(
            doc.contains(r#""@timestamp":"2023-11-14T22:13:20Z""#),
            "missing @timestamp: {doc}"
        );
        assert!(
            doc.contains(r#""client_ip":"192.168.1.1""#),
            "missing client_ip: {doc}"
        );
        assert!(
            doc.contains(r#""action":"Blocked""#),
            "missing action: {doc}"
        );
        assert!(
            doc.contains(r#""domain":"evil.com""#),
            "missing domain: {doc}"
        );
        assert!(
            doc.contains(r#""reason":"HIGH_ENTROPY""#),
            "missing reason: {doc}"
        );
        assert!(
            doc.contains(r#""dataset":"dgaard.dns""#),
            "missing dataset: {doc}"
        );
    }

    #[test]
    fn test_format_elasticsearch_event_classification() {
        let cases: &[(&StatAction, &str, &str)] = &[
            (&StatAction::Allowed, "event", "allowed"),
            (&StatAction::Proxied, "event", "allowed"),
            (
                &StatAction::Blocked(StatBlockReason::empty()),
                "alert",
                "denied",
            ),
            (
                &StatAction::Suspicious(StatBlockReason::empty()),
                "alert",
                "info",
            ),
            (
                &StatAction::HighlySuspicious(StatBlockReason::empty()),
                "alert",
                "info",
            ),
        ];
        for (action, kind, ev_type) in cases {
            let body = format_elasticsearch(0, "1.2.3.4", action, "x.com");
            assert!(
                body.contains(&format!(r#""kind":"{kind}""#)),
                "action {:?} expected kind={kind}: {body}",
                action
            );
            assert!(
                body.contains(&format!(r#""type":["{ev_type}"]"#)),
                "action {:?} expected type={ev_type}: {body}",
                action
            );
        }
    }

    // --- format_event dispatcher ---

    #[test]
    fn test_format_event_template_dispatch() {
        use crate::config::ForwardFormat;
        let body = format_event(
            &ForwardFormat::Template,
            "{timestamp} {domain}",
            100,
            "1.2.3.4",
            &StatAction::Allowed,
            "example.com",
        );
        assert_eq!(body, "100 example.com");
    }

    #[test]
    fn test_format_event_json_dispatch() {
        use crate::config::ForwardFormat;
        let body = format_event(
            &ForwardFormat::Json,
            "",
            0,
            "1.2.3.4",
            &StatAction::Allowed,
            "example.com",
        );
        assert!(body.starts_with('{'), "expected JSON object: {body}");
        assert!(body.contains(r#""action":"Allowed""#));
    }

    #[test]
    fn test_format_event_syslog_dispatch() {
        use crate::config::ForwardFormat;
        let body = format_event(
            &ForwardFormat::Syslog,
            "",
            0,
            "1.2.3.4",
            &StatAction::Allowed,
            "example.com",
        );
        assert!(body.starts_with("<38>1 "), "expected syslog PRI: {body}");
    }

    #[test]
    fn test_format_event_cef_dispatch() {
        use crate::config::ForwardFormat;
        let body = format_event(
            &ForwardFormat::Cef,
            "",
            0,
            "1.2.3.4",
            &StatAction::Allowed,
            "example.com",
        );
        assert!(body.starts_with("CEF:0|"), "expected CEF header: {body}");
    }

    #[test]
    fn test_format_event_elasticsearch_dispatch() {
        use crate::config::ForwardFormat;
        let body = format_event(
            &ForwardFormat::Elasticsearch,
            "",
            0,
            "1.2.3.4",
            &StatAction::Allowed,
            "example.com",
        );
        assert!(
            body.starts_with(r#"{"index":{}}"#),
            "expected ES index action: {body}"
        );
    }
}
