use std::{net::IpAddr, sync::Arc, time::Duration};

use async_trait::async_trait;
use rust_mcp_sdk::{
    macros::{JsonSchema, mcp_tool},
    mcp_server::{HyperServerOptions, ServerHandler, ToMcpServerHandler, hyper_server},
    schema::{
        CallToolRequestParams, CallToolResult, ContentBlock, Implementation, InitializeResult,
        ListToolsResult, PaginatedRequestParams, ProtocolVersion, RpcError, ServerCapabilities,
        ServerCapabilitiesTools, TextContent, schema_utils::CallToolError,
    },
};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;

use crate::{
    config::ConnectivityConfig,
    connectivity::mcp_token_auth_provider::ConfigTokenAuthProvider,
    protocol::{StatAction, StatBlockReason},
    state::AppState,
};

// ── Tool definition ────────────────────────────────────────────────────────────

#[mcp_tool(
    name = "events",
    description = "Query DNS events from the rolling window. Returns events matching ALL supplied \
                   filters, sorted newest-first. All filter fields are optional; omitting a field \
                   applies no restriction for that dimension.",
    read_only_hint = true,
    idempotent_hint = true,
    destructive_hint = false,
    open_world_hint = false
)]
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct EventsTool {
    /// Start of time range, inclusive (UTC unix timestamp in seconds).
    pub from_ts: Option<u64>,
    /// End of time range, inclusive (UTC unix timestamp in seconds).
    pub to_ts: Option<u64>,
    /// Filter by client IP address (IPv4 or IPv6 string, exact match).
    pub client_ip: Option<String>,
    /// Filter by domain name substring (case-insensitive). Matched against the resolved name;
    /// falls back to matching against the hex-encoded hash when the domain is unknown.
    pub domain: Option<String>,
    /// Filter by action variant.
    /// Valid values: "Allowed", "Proxied", "Blocked", "Suspicious", "HighlySuspicious".
    pub action: Option<String>,
    /// Filter by block-reason bitmask (u16). Only events whose reason bits contain ALL supplied
    /// bits are returned. Has no effect when used without a matching action.
    pub flags: Option<u16>,
    /// Maximum number of results to return. Defaults to 200; capped at 1 000.
    pub limit: Option<u64>,
}

rust_mcp_sdk::tool_box!(DgaardTools, [EventsTool]);

// ── IP helpers ─────────────────────────────────────────────────────────────────

/// Convert internal 16-byte IP to a display string.
///
/// The proxy stores IPv4 addresses in the first 4 bytes with the remaining 12
/// bytes zeroed, so we detect that pattern and format as dotted-decimal.
fn ip_to_string(ip: &[u8; 16]) -> String {
    if ip[4..].iter().all(|&b| b == 0) {
        format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
    } else {
        std::net::Ipv6Addr::from(*ip).to_string()
    }
}

/// Parse a user-supplied IP string into the internal 16-byte format.
fn parse_filter_ip(s: &str) -> Option<[u8; 16]> {
    let addr: IpAddr = s.parse().ok()?;
    Some(match addr {
        IpAddr::V4(v4) => {
            let [a, b, c, d] = v4.octets();
            [a, b, c, d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        }
        IpAddr::V6(v6) => v6.octets(),
    })
}

// ── Response types ─────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct EventRecord {
    timestamp: u64,
    /// Resolved domain name, or `null` when the hash is unknown.
    domain: Option<String>,
    /// Raw domain hash as a 16-digit hex string.
    domain_hash: String,
    client_ip: String,
    /// Action variant name.
    action: String,
    /// Raw block-reason bitmask; `null` for Allowed and Proxied events.
    flags: Option<u16>,
    /// Human-readable labels for each set bit in `flags`.
    flags_labels: Vec<String>,
}

fn action_name(action: &StatAction) -> &'static str {
    match action {
        StatAction::Allowed => "Allowed",
        StatAction::Proxied => "Proxied",
        StatAction::Blocked(_) => "Blocked",
        StatAction::Suspicious(_) => "Suspicious",
        StatAction::HighlySuspicious(_) => "HighlySuspicious",
    }
}

fn flags_of(action: &StatAction) -> Option<StatBlockReason> {
    match action {
        StatAction::Blocked(r) | StatAction::Suspicious(r) | StatAction::HighlySuspicious(r) => {
            Some(*r)
        }
        _ => None,
    }
}

fn reason_labels(r: StatBlockReason) -> Vec<&'static str> {
    let mut v = Vec::new();
    if r.contains(StatBlockReason::STATIC_BLACKLIST) {
        v.push("STATIC_BLACKLIST");
    }
    if r.contains(StatBlockReason::ABP_RULE) {
        v.push("ABP_RULE");
    }
    if r.contains(StatBlockReason::HIGH_ENTROPY) {
        v.push("HIGH_ENTROPY");
    }
    if r.contains(StatBlockReason::LEXICAL_ANALYSIS) {
        v.push("LEXICAL_ANALYSIS");
    }
    if r.contains(StatBlockReason::BANNED_KEYWORD) {
        v.push("BANNED_KEYWORD");
    }
    if r.contains(StatBlockReason::INVALID_STRUCTURE) {
        v.push("INVALID_STRUCTURE");
    }
    if r.contains(StatBlockReason::SUSPICIOUS_IDN) {
        v.push("SUSPICIOUS_IDN");
    }
    if r.contains(StatBlockReason::NRD_LIST) {
        v.push("NRD_LIST");
    }
    if r.contains(StatBlockReason::TLD_EXCLUDED) {
        v.push("TLD_EXCLUDED");
    }
    if r.contains(StatBlockReason::SUSPICIOUS) {
        v.push("SUSPICIOUS");
    }
    if r.contains(StatBlockReason::CNAME_CLOAKING) {
        v.push("CNAME_CLOAKING");
    }
    if r.contains(StatBlockReason::FORBIDDEN_QTYPE) {
        v.push("FORBIDDEN_QTYPE");
    }
    if r.contains(StatBlockReason::DNS_REBINDING) {
        v.push("DNS_REBINDING");
    }
    if r.contains(StatBlockReason::LOW_TTL) {
        v.push("LOW_TTL");
    }
    if r.contains(StatBlockReason::ASN_BLOCKED) {
        v.push("ASN_BLOCKED");
    }
    v
}

// ── Handler ────────────────────────────────────────────────────────────────────

struct DgaardMcpHandler {
    state: Arc<AppState>,
}

#[async_trait]
impl ServerHandler for DgaardMcpHandler {
    async fn handle_list_tools_request(
        &self,
        _params: Option<PaginatedRequestParams>,
        _runtime: Arc<dyn rust_mcp_sdk::McpServer>,
    ) -> Result<ListToolsResult, RpcError> {
        Ok(ListToolsResult {
            tools: DgaardTools::tools(),
            next_cursor: None,
            meta: None,
        })
    }

    async fn handle_call_tool_request(
        &self,
        params: CallToolRequestParams,
        _runtime: Arc<dyn rust_mcp_sdk::McpServer>,
    ) -> Result<CallToolResult, CallToolError> {
        let tool = DgaardTools::try_from(params)?;
        match tool {
            DgaardTools::EventsTool(t) => handle_events(t, &self.state).await,
        }
    }
}

async fn handle_events(
    tool: EventsTool,
    state: &AppState,
) -> Result<CallToolResult, CallToolError> {
    let limit = tool.limit.unwrap_or(200).min(1_000) as usize;

    let ip_filter: Option<[u8; 16]> = tool
        .client_ip
        .as_deref()
        .map(|s| {
            parse_filter_ip(s)
                .ok_or_else(|| CallToolError::from_message(format!("invalid IP address: {s}")))
        })
        .transpose()?;

    let required_flags: Option<StatBlockReason> =
        tool.flags.map(StatBlockReason::from_bits_truncate);

    // Snapshot events while holding the lock as briefly as possible.
    let events_snapshot: Vec<_> = {
        let stats = state.stats.read().await;
        stats
            .window_events()
            .iter()
            .map(|(_, ev)| ev.clone())
            .collect()
    };
    let domain_map = state.domain_map.read().await;

    let mut records: Vec<EventRecord> = events_snapshot
        .into_iter()
        .filter(|ev| {
            if let Some(from) = tool.from_ts
                && ev.timestamp < from
            {
                return false;
            }
            if let Some(to) = tool.to_ts
                && ev.timestamp > to
            {
                return false;
            }
            if let Some(ref filter) = ip_filter
                && &ev.client_ip != filter
            {
                return false;
            }
            if let Some(ref action_filter) = tool.action
                && action_name(&ev.action) != action_filter.as_str()
            {
                return false;
            }
            if let Some(required) = required_flags {
                match flags_of(&ev.action) {
                    Some(r) => {
                        if !r.contains(required) {
                            return false;
                        }
                    }
                    None => return false,
                }
            }
            true
        })
        .filter_map(|ev| {
            let resolved = domain_map.get(&ev.domain_hash).cloned();
            if let Some(ref needle) = tool.domain {
                let needle_lc = needle.to_ascii_lowercase();
                let name_match = resolved
                    .as_deref()
                    .map(|n| n.to_ascii_lowercase().contains(&needle_lc))
                    .unwrap_or(false);
                let hash_match = format!("{:016x}", ev.domain_hash).contains(&needle_lc);
                if !name_match && !hash_match {
                    return None;
                }
            }
            let reason = flags_of(&ev.action);
            Some(EventRecord {
                timestamp: ev.timestamp,
                domain: resolved,
                domain_hash: format!("{:016x}", ev.domain_hash),
                client_ip: ip_to_string(&ev.client_ip),
                action: action_name(&ev.action).to_string(),
                flags: reason.map(|r| r.bits()),
                flags_labels: reason
                    .map_or_else(Vec::new, reason_labels)
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
            })
        })
        .collect();

    // Newest first, then truncate.
    records.sort_unstable_by(|a, b| b.timestamp.cmp(&a.timestamp));
    records.truncate(limit);

    let json = serde_json::to_string_pretty(&records)
        .map_err(|e| CallToolError::from_message(e.to_string()))?;

    Ok(CallToolResult {
        content: vec![ContentBlock::TextContent(TextContent::new(
            json, None, None,
        ))],
        is_error: None,
        meta: None,
        structured_content: None,
    })
}

// ── Server entry-point ─────────────────────────────────────────────────────────

/// Serve the MCP (Model Context Protocol) endpoint.
///
/// Only called when `config.enabled` is true.
/// Returns when `shutdown` is signalled or the server stops.
pub async fn run(
    config: ConnectivityConfig,
    state: Arc<AppState>,
    mut shutdown: watch::Receiver<bool>,
) {
    let server_details = InitializeResult {
        server_info: Implementation {
            name: "dgaard-monitor".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            title: Some("Dgaard Monitor MCP Server".into()),
            description: Some("Browse DNS events recorded by dgaard.".into()),
            icons: vec![],
            website_url: None,
        },
        capabilities: ServerCapabilities {
            tools: Some(ServerCapabilitiesTools { list_changed: None }),
            ..Default::default()
        },
        meta: None,
        instructions: Some(
            "Call `events` to query the rolling DNS-event window. \
             All filter parameters are optional; combine them to narrow results."
                .into(),
        ),
        protocol_version: ProtocolVersion::V2025_11_25.into(),
    };

    let handler = DgaardMcpHandler { state };

    // Normalise root_path: treat "/" and "" as "use SDK default" (/mcp).
    let root_path: Option<String> = {
        let p = config.root_path.trim_end_matches('/');
        if p.is_empty() {
            None
        } else {
            Some(p.to_string())
        }
    };

    let server = hyper_server::create_server(
        server_details,
        handler.to_mcp_server_handler(),
        HyperServerOptions {
            host: config.listen,
            port: config.port,
            custom_streamable_http_endpoint: root_path,
            auth: (!config.token.is_empty())
                .then(|| Arc::new(ConfigTokenAuthProvider::new(&config.token)) as Arc<_>),
            health_endpoint: Some("/health".into()),
            ..Default::default()
        },
    );

    // Forward our app-level shutdown signal to the SDK's server handle.
    let handle = server.server_handle();
    tokio::spawn(async move {
        let _ = shutdown.changed().await;
        if *shutdown.borrow() {
            handle.graceful_shutdown(Some(Duration::from_secs(5)));
        }
    });

    if let Err(e) = server.start().await {
        eprintln!("MCP server error: {e}");
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        protocol::{StatAction, StatBlockReason, StatEvent},
        state::AppState,
    };
    use std::time::Duration;

    fn make_state() -> Arc<AppState> {
        Arc::new(AppState::new(Duration::from_secs(3600)))
    }

    fn ipv4(a: u8, b: u8, c: u8, d: u8) -> [u8; 16] {
        [a, b, c, d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    }

    fn blocked_event(ts: u64, hash: u64, ip: [u8; 16], r: StatBlockReason) -> StatEvent {
        StatEvent {
            timestamp: ts,
            domain_hash: hash,
            client_ip: ip,
            action: StatAction::Blocked(r),
        }
    }

    fn allowed_event(ts: u64, hash: u64, ip: [u8; 16]) -> StatEvent {
        StatEvent {
            timestamp: ts,
            domain_hash: hash,
            client_ip: ip,
            action: StatAction::Allowed,
        }
    }

    // ── ip_to_string ─────────────────────────────────────────────────────────

    #[test]
    fn ipv4_displayed_as_dotted_decimal() {
        let ip = ipv4(192, 168, 1, 10);
        assert_eq!(ip_to_string(&ip), "192.168.1.10");
    }

    #[test]
    fn non_ipv4_displayed_as_ipv6() {
        let ip: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let s = ip_to_string(&ip);
        // Should parse back as a valid IPv6 address.
        assert!(s.parse::<std::net::Ipv6Addr>().is_ok(), "got: {s}");
    }

    // ── parse_filter_ip ───────────────────────────────────────────────────────

    #[test]
    fn parse_ipv4_roundtrip() {
        let parsed = parse_filter_ip("10.0.0.1").unwrap();
        assert_eq!(parsed, ipv4(10, 0, 0, 1));
    }

    #[test]
    fn parse_invalid_ip_returns_none() {
        assert!(parse_filter_ip("not-an-ip").is_none());
        assert!(parse_filter_ip("999.0.0.1").is_none());
    }

    // ── reason_labels ─────────────────────────────────────────────────────────

    #[test]
    fn reason_labels_lists_set_bits() {
        let r = StatBlockReason::STATIC_BLACKLIST | StatBlockReason::HIGH_ENTROPY;
        let labels = reason_labels(r);
        assert!(labels.contains(&"STATIC_BLACKLIST"));
        assert!(labels.contains(&"HIGH_ENTROPY"));
        assert!(!labels.contains(&"ABP_RULE"));
    }

    #[test]
    fn reason_labels_empty_for_empty_flags() {
        assert!(reason_labels(StatBlockReason::empty()).is_empty());
    }

    // ── handle_events ─────────────────────────────────────────────────────────

    async fn query(state: &Arc<AppState>, tool: EventsTool) -> Vec<EventRecord> {
        let result = handle_events(tool, state).await.unwrap();
        let text = match &result.content[0] {
            ContentBlock::TextContent(t) => t.text.clone(),
            _ => panic!("expected TextContent"),
        };
        serde_json::from_str(&text).unwrap()
    }

    #[tokio::test]
    async fn returns_all_events_with_no_filters() {
        let state = make_state();
        state
            .record_event(allowed_event(1000, 1, ipv4(1, 0, 0, 0)))
            .await;
        state
            .record_event(blocked_event(
                2000,
                2,
                ipv4(2, 0, 0, 0),
                StatBlockReason::STATIC_BLACKLIST,
            ))
            .await;

        let records = query(
            &state,
            EventsTool {
                from_ts: None,
                to_ts: None,
                client_ip: None,
                domain: None,
                action: None,
                flags: None,
                limit: None,
            },
        )
        .await;
        assert_eq!(records.len(), 2);
    }

    #[tokio::test]
    async fn filters_by_from_ts() {
        let state = make_state();
        state
            .record_event(allowed_event(500, 1, ipv4(1, 0, 0, 0)))
            .await;
        state
            .record_event(allowed_event(1500, 2, ipv4(2, 0, 0, 0)))
            .await;

        let records = query(
            &state,
            EventsTool {
                from_ts: Some(1000),
                to_ts: None,
                client_ip: None,
                domain: None,
                action: None,
                flags: None,
                limit: None,
            },
        )
        .await;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].timestamp, 1500);
    }

    #[tokio::test]
    async fn filters_by_to_ts() {
        let state = make_state();
        state
            .record_event(allowed_event(500, 1, ipv4(1, 0, 0, 0)))
            .await;
        state
            .record_event(allowed_event(1500, 2, ipv4(2, 0, 0, 0)))
            .await;

        let records = query(
            &state,
            EventsTool {
                from_ts: None,
                to_ts: Some(1000),
                client_ip: None,
                domain: None,
                action: None,
                flags: None,
                limit: None,
            },
        )
        .await;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].timestamp, 500);
    }

    #[tokio::test]
    async fn filters_by_client_ip() {
        let state = make_state();
        state
            .record_event(allowed_event(1000, 1, ipv4(10, 0, 0, 1)))
            .await;
        state
            .record_event(allowed_event(1001, 2, ipv4(10, 0, 0, 2)))
            .await;

        let records = query(
            &state,
            EventsTool {
                from_ts: None,
                to_ts: None,
                client_ip: Some("10.0.0.1".into()),
                domain: None,
                action: None,
                flags: None,
                limit: None,
            },
        )
        .await;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].client_ip, "10.0.0.1");
    }

    #[tokio::test]
    async fn filters_by_action() {
        let state = make_state();
        state
            .record_event(allowed_event(1000, 1, ipv4(1, 0, 0, 0)))
            .await;
        state
            .record_event(blocked_event(
                1001,
                2,
                ipv4(2, 0, 0, 0),
                StatBlockReason::ABP_RULE,
            ))
            .await;

        let records = query(
            &state,
            EventsTool {
                from_ts: None,
                to_ts: None,
                client_ip: None,
                domain: None,
                action: Some("Blocked".into()),
                flags: None,
                limit: None,
            },
        )
        .await;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].action, "Blocked");
    }

    #[tokio::test]
    async fn filters_by_flags_bitmask() {
        let state = make_state();
        // event with only STATIC_BLACKLIST
        state
            .record_event(blocked_event(
                1000,
                1,
                ipv4(1, 0, 0, 0),
                StatBlockReason::STATIC_BLACKLIST,
            ))
            .await;
        // event with STATIC_BLACKLIST | HIGH_ENTROPY
        state
            .record_event(blocked_event(
                1001,
                2,
                ipv4(2, 0, 0, 0),
                StatBlockReason::STATIC_BLACKLIST | StatBlockReason::HIGH_ENTROPY,
            ))
            .await;

        // Filter: must have both bits set
        let required = (StatBlockReason::STATIC_BLACKLIST | StatBlockReason::HIGH_ENTROPY).bits();
        let records = query(
            &state,
            EventsTool {
                from_ts: None,
                to_ts: None,
                client_ip: None,
                domain: None,
                action: None,
                flags: Some(required),
                limit: None,
            },
        )
        .await;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].timestamp, 1001);
    }

    #[tokio::test]
    async fn filters_by_domain_name() {
        let state = make_state();
        state
            .insert_domain(0xaabbcc, "evil.example.com".into())
            .await;
        state.insert_domain(0xddeeff, "safe.net".into()).await;
        state
            .record_event(allowed_event(1000, 0xaabbcc, ipv4(1, 0, 0, 0)))
            .await;
        state
            .record_event(allowed_event(1001, 0xddeeff, ipv4(2, 0, 0, 0)))
            .await;

        let records = query(
            &state,
            EventsTool {
                from_ts: None,
                to_ts: None,
                client_ip: None,
                domain: Some("evil".into()),
                action: None,
                flags: None,
                limit: None,
            },
        )
        .await;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].domain.as_deref(), Some("evil.example.com"));
    }

    #[tokio::test]
    async fn results_are_sorted_newest_first() {
        let state = make_state();
        state
            .record_event(allowed_event(300, 1, ipv4(1, 0, 0, 0)))
            .await;
        state
            .record_event(allowed_event(100, 2, ipv4(2, 0, 0, 0)))
            .await;
        state
            .record_event(allowed_event(200, 3, ipv4(3, 0, 0, 0)))
            .await;

        let records = query(
            &state,
            EventsTool {
                from_ts: None,
                to_ts: None,
                client_ip: None,
                domain: None,
                action: None,
                flags: None,
                limit: None,
            },
        )
        .await;
        assert_eq!(records[0].timestamp, 300);
        assert_eq!(records[1].timestamp, 200);
        assert_eq!(records[2].timestamp, 100);
    }

    #[tokio::test]
    async fn limit_is_respected() {
        let state = make_state();
        for i in 0..10 {
            state
                .record_event(allowed_event(i, i, ipv4(1, 0, 0, 0)))
                .await;
        }

        let records = query(
            &state,
            EventsTool {
                from_ts: None,
                to_ts: None,
                client_ip: None,
                domain: None,
                action: None,
                flags: None,
                limit: Some(3),
            },
        )
        .await;
        assert_eq!(records.len(), 3);
    }

    #[tokio::test]
    async fn limit_is_capped_at_1000() {
        let state = make_state();
        for i in 0..5 {
            state
                .record_event(allowed_event(i, i, ipv4(1, 0, 0, 0)))
                .await;
        }

        let records = query(
            &state,
            EventsTool {
                from_ts: None,
                to_ts: None,
                client_ip: None,
                domain: None,
                action: None,
                flags: None,
                limit: Some(99_999),
            },
        )
        .await;
        // Only 5 events exist, all returned; cap doesn't truncate when count < cap.
        assert_eq!(records.len(), 5);
    }

    #[tokio::test]
    async fn invalid_ip_filter_returns_error() {
        let state = make_state();
        let err = handle_events(
            EventsTool {
                from_ts: None,
                to_ts: None,
                client_ip: Some("not-an-ip".into()),
                domain: None,
                action: None,
                flags: None,
                limit: None,
            },
            &state,
        )
        .await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn event_record_includes_flags_labels() {
        let state = make_state();
        state
            .record_event(blocked_event(
                1000,
                1,
                ipv4(1, 0, 0, 0),
                StatBlockReason::NRD_LIST | StatBlockReason::HIGH_ENTROPY,
            ))
            .await;

        let records = query(
            &state,
            EventsTool {
                from_ts: None,
                to_ts: None,
                client_ip: None,
                domain: None,
                action: None,
                flags: None,
                limit: None,
            },
        )
        .await;
        assert_eq!(records.len(), 1);
        assert!(records[0].flags_labels.iter().any(|s| s == "NRD_LIST"));
        assert!(records[0].flags_labels.iter().any(|s| s == "HIGH_ENTROPY"));
    }

    #[tokio::test]
    async fn allowed_event_has_null_flags() {
        let state = make_state();
        state
            .record_event(allowed_event(1000, 1, ipv4(1, 0, 0, 0)))
            .await;

        let records = query(
            &state,
            EventsTool {
                from_ts: None,
                to_ts: None,
                client_ip: None,
                domain: None,
                action: None,
                flags: None,
                limit: None,
            },
        )
        .await;
        assert_eq!(records.len(), 1);
        assert!(records[0].flags.is_none());
        assert!(records[0].flags_labels.is_empty());
    }
}
