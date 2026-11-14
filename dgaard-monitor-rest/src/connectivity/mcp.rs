use std::{sync::Arc, time::Duration};

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

use crate::config::{McpConfig, ServerConfig};
use crate::connectivity::mcp_token_auth_provider::ConfigTokenAuthProvider;
use dgaard_monitor_core::service::events::{EventFilter, query_window};
use dgaard_monitor_core::state::AppState;

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
    /// Filter by action variant (case-insensitive).
    /// Valid values: "Allowed", "Proxied", "Blocked", "Suspicious", "HighlySuspicious".
    pub action: Option<String>,
    /// Filter by block-reason bitmask (u32). Only events whose reason bits contain ALL supplied
    /// bits are returned. Has no effect when used without a matching action.
    pub flags: Option<u32>,
    /// Maximum number of results to return. Defaults to 200; capped at 1 000.
    pub limit: Option<u64>,
}

impl From<EventsTool> for EventFilter {
    fn from(tool: EventsTool) -> Self {
        Self {
            from_ts: tool.from_ts,
            to_ts: tool.to_ts,
            client_ip: tool.client_ip,
            domain: tool.domain,
            action: tool.action,
            flags: tool.flags,
            limit: tool.limit,
        }
    }
}

rust_mcp_sdk::tool_box!(DgaardTools, [EventsTool]);

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
    let records = query_window(state, &tool.into())
        .await
        .map_err(|err| CallToolError::from_message(err.to_string()))?;

    let json = serde_json::to_string_pretty(&records)
        .map_err(|err| CallToolError::from_message(err.to_string()))?;

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
    server: ServerConfig,
    config: McpConfig,
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
            host: server.listen,
            port: config.port,
            custom_streamable_http_endpoint: root_path,
            auth: (!server.token.is_empty())
                .then(|| Arc::new(ConfigTokenAuthProvider::new(&server.token)) as Arc<_>),
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
//
// Filter semantics are covered by `dgaard_monitor_core::service::events`;
// these tests only check the MCP adapter (tool → filter, result → JSON text).

#[cfg(test)]
mod tests {
    use super::*;
    use dgaard_monitor_core::protocol::{StatAction, StatBlockReason, StatEvent};
    use dgaard_monitor_core::util::EventRecord;

    fn make_state() -> Arc<AppState> {
        Arc::new(AppState::new(Duration::from_secs(3600)))
    }

    fn ipv4(a: u8, b: u8, c: u8, d: u8) -> [u8; 16] {
        [a, b, c, d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    }

    fn event(ts: u64, hash: u64, action: StatAction) -> StatEvent {
        StatEvent {
            timestamp: ts,
            domain_hash: hash,
            client_ip: ipv4(10, 0, 0, 1),
            action,
        }
    }

    fn empty_tool() -> EventsTool {
        EventsTool {
            from_ts: None,
            to_ts: None,
            client_ip: None,
            domain: None,
            action: None,
            flags: None,
            limit: None,
        }
    }

    async fn query(state: &Arc<AppState>, tool: EventsTool) -> Vec<EventRecord> {
        let result = handle_events(tool, state).await.unwrap();
        let text = match &result.content[0] {
            ContentBlock::TextContent(t) => t.text.clone(),
            _ => panic!("expected TextContent"),
        };
        serde_json::from_str(&text).unwrap()
    }

    #[test]
    fn tool_converts_into_filter_field_by_field() {
        let filter: EventFilter = EventsTool {
            from_ts: Some(1),
            to_ts: Some(2),
            client_ip: Some("10.0.0.1".into()),
            domain: Some("evil".into()),
            action: Some("Blocked".into()),
            flags: Some(4),
            limit: Some(5),
        }
        .into();
        assert_eq!(filter.from_ts, Some(1));
        assert_eq!(filter.to_ts, Some(2));
        assert_eq!(filter.client_ip.as_deref(), Some("10.0.0.1"));
        assert_eq!(filter.domain.as_deref(), Some("evil"));
        assert_eq!(filter.action.as_deref(), Some("Blocked"));
        assert_eq!(filter.flags, Some(4));
        assert_eq!(filter.limit, Some(5));
    }

    #[tokio::test]
    async fn returns_records_as_json_text() {
        let state = make_state();
        state.insert_domain(1, "example.com".into()).await;
        state
            .record_event(event(1000, 1, StatAction::Allowed))
            .await;
        state
            .record_event(event(
                2000,
                2,
                StatAction::Blocked(StatBlockReason::NRD_LIST | StatBlockReason::HIGH_ENTROPY),
            ))
            .await;

        let records = query(&state, empty_tool()).await;
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].timestamp, 2000);
        assert!(records[0].flags_labels.iter().any(|s| s == "NRD_LIST"));
        assert_eq!(records[1].domain.as_deref(), Some("example.com"));
        assert!(records[1].flags.is_none());
    }

    #[tokio::test]
    async fn action_filter_is_case_insensitive() {
        let state = make_state();
        state
            .record_event(event(1000, 1, StatAction::Allowed))
            .await;
        state
            .record_event(event(
                1001,
                2,
                StatAction::Blocked(StatBlockReason::ABP_RULE),
            ))
            .await;

        let records = query(
            &state,
            EventsTool {
                action: Some("blocked".into()),
                ..empty_tool()
            },
        )
        .await;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].action, "Blocked");
    }

    #[tokio::test]
    async fn invalid_ip_filter_returns_error() {
        let state = make_state();
        let result = handle_events(
            EventsTool {
                client_ip: Some("not-an-ip".into()),
                ..empty_tool()
            },
            &state,
        )
        .await;
        assert!(result.is_err());
    }
}
