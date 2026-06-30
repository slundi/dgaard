// Fields are declared for future use by service implementations.
#![allow(dead_code)]

use toml_span::{Span, value::ValueInner};

use thiserror::Error;

pub use dgaard_monitor_core::config::{ForwardFormat, ForwardingConfig};

#[cfg(feature = "tui")]
pub use dgaard_monitor_tui::config::TuiConfig;
#[cfg(not(feature = "tui"))]
#[derive(Debug, Default)]
pub struct TuiConfig;

#[cfg(feature = "rest")]
pub use dgaard_monitor_rest::config::{
    ApiConfig, McpConfig, ServerConfig, WebConfig, WebSocketConfig,
};
#[cfg(not(feature = "rest"))]
#[derive(Debug, Default)]
pub struct ServerConfig;
#[cfg(not(feature = "rest"))]
#[derive(Debug, Default)]
pub struct ApiConfig;
#[cfg(not(feature = "rest"))]
#[derive(Debug, Default)]
pub struct WebSocketConfig;
#[cfg(not(feature = "rest"))]
#[derive(Debug, Default)]
pub struct McpConfig;
#[cfg(not(feature = "rest"))]
#[derive(Debug, Default)]
pub struct WebConfig;

#[cfg(feature = "nats")]
pub use dgaard_monitor_nats::config::NatsConfig;
#[cfg(not(feature = "nats"))]
#[derive(Debug, Default)]
pub struct NatsConfig;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file: {0}")]
    Io(#[from] std::io::Error),
    #[error("TOML syntax error: {0}")]
    Parse(String),
    #[error("invalid type for key '{key}': expected {expected} at {span:?}")]
    InvalidType {
        key: String,
        expected: &'static str,
        span: Span,
    },
}

#[derive(Debug, Default)]
pub struct Config {
    pub input: InputConfig,
    pub persistence: PersistenceConfig,
    pub tui: TuiConfig,
    pub forwarding: ForwardingConfig,
    pub server: ServerConfig,
    pub api: ApiConfig,
    pub websocket: WebSocketConfig,
    pub mcp: McpConfig,
    pub web: WebConfig,
    pub nats: NatsConfig,
}

#[derive(Debug)]
pub struct InputConfig {
    pub socket: String,
    pub index: String,
    /// Optional path to the dgaard engine config file (`dgaard.toml`).
    /// When set, the monitor parses `[[security.custom_flags]]` from this file
    /// to resolve custom bit indices (16–31) to their configured `code` labels.
    /// Bits with no matching entry render as `CUSTOM_BIT_<n>`.
    pub engine_config_path: Option<String>,
}

fn default_socket() -> String {
    "/tmp/dgaard_stats.sock".to_string()
}

fn default_index() -> String {
    "/var/lib/dns/hosts.bin".to_string()
}

impl Default for InputConfig {
    fn default() -> Self {
        Self {
            socket: default_socket(),
            index: default_index(),
            engine_config_path: None,
        }
    }
}

#[derive(Debug)]
pub struct PersistenceConfig {
    pub db: String,
    pub events_retention_hours: u32,
    pub aggregates_retention_days: u32,
}

fn default_db() -> String {
    "/var/dgaard/stats.sqlite".to_string()
}

fn default_events_retention_hours() -> u32 {
    72
}

fn default_aggregates_retention_days() -> u32 {
    90
}

impl Default for PersistenceConfig {
    fn default() -> Self {
        Self {
            db: default_db(),
            events_retention_hours: default_events_retention_hours(),
            aggregates_retention_days: default_aggregates_retention_days(),
        }
    }
}

// ---------------------------------------------------------------------------
// Helper extraction functions
// ---------------------------------------------------------------------------

fn get_str<'a>(
    table: &'a toml_span::value::Table<'a>,
    key: &str,
) -> Result<Option<&'a str>, ConfigError> {
    match table.get(key) {
        Some(v) => match v.as_ref() {
            ValueInner::String(s) => Ok(Some(s.as_ref())),
            _ => Err(ConfigError::InvalidType {
                key: key.to_string(),
                expected: "string",
                span: v.span,
            }),
        },
        None => Ok(None),
    }
}

fn get_bool(table: &toml_span::value::Table<'_>, key: &str) -> Result<Option<bool>, ConfigError> {
    match table.get(key) {
        Some(v) => match v.as_ref() {
            ValueInner::Boolean(b) => Ok(Some(*b)),
            _ => Err(ConfigError::InvalidType {
                key: key.to_string(),
                expected: "boolean",
                span: v.span,
            }),
        },
        None => Ok(None),
    }
}

fn get_integer(table: &toml_span::value::Table<'_>, key: &str) -> Result<Option<i64>, ConfigError> {
    match table.get(key) {
        Some(v) => match v.as_ref() {
            ValueInner::Integer(i) => Ok(Some(*i)),
            _ => Err(ConfigError::InvalidType {
                key: key.to_string(),
                expected: "integer",
                span: v.span,
            }),
        },
        None => Ok(None),
    }
}

/// Extract an optional float value from a table (also accepts integers as floats).
fn get_float(table: &toml_span::value::Table<'_>, key: &str) -> Result<Option<f64>, ConfigError> {
    match table.get(key) {
        Some(v) => match v.as_ref() {
            ValueInner::Float(f) => Ok(Some(*f)),
            ValueInner::Integer(i) => Ok(Some(*i as f64)),
            _ => Err(ConfigError::InvalidType {
                key: key.to_string(),
                expected: "float",
                span: v.span,
            }),
        },
        None => Ok(None),
    }
}

fn get_string_array(
    table: &toml_span::value::Table<'_>,
    key: &str,
) -> Result<Option<Vec<String>>, ConfigError> {
    match table.get(key) {
        Some(v) => match v.as_ref() {
            ValueInner::Array(arr) => {
                let mut result = Vec::with_capacity(arr.len());
                for item in arr.iter() {
                    match item.as_ref() {
                        ValueInner::String(s) => result.push(s.to_string()),
                        _ => {
                            return Err(ConfigError::InvalidType {
                                key: format!("{}[]", key),
                                expected: "string",
                                span: item.span,
                            });
                        }
                    }
                }
                Ok(Some(result))
            }
            _ => Err(ConfigError::InvalidType {
                key: key.to_string(),
                expected: "array",
                span: v.span,
            }),
        },
        None => Ok(None),
    }
}

fn get_table<'a>(
    table: &'a toml_span::value::Table<'a>,
    key: &str,
) -> Result<Option<&'a toml_span::value::Table<'a>>, ConfigError> {
    match table.get(key) {
        Some(v) => match v.as_ref() {
            ValueInner::Table(t) => Ok(Some(t)),
            _ => Err(ConfigError::InvalidType {
                key: key.to_string(),
                expected: "table",
                span: v.span,
            }),
        },
        None => Ok(None),
    }
}

// ---------------------------------------------------------------------------
// Section parsers
// ---------------------------------------------------------------------------

fn parse_input(table: &toml_span::value::Table<'_>) -> Result<InputConfig, ConfigError> {
    let mut cfg = InputConfig::default();
    if let Some(s) = get_str(table, "socket")? {
        cfg.socket = s.to_string();
    }
    if let Some(s) = get_str(table, "index")? {
        cfg.index = s.to_string();
    }
    if let Some(s) = get_str(table, "engine_config_path")? {
        cfg.engine_config_path = Some(s.to_string());
    }
    Ok(cfg)
}

fn parse_persistence(
    table: &toml_span::value::Table<'_>,
) -> Result<PersistenceConfig, ConfigError> {
    let mut cfg = PersistenceConfig::default();
    if let Some(s) = get_str(table, "db")? {
        cfg.db = s.to_string();
    }
    if let Some(n) = get_integer(table, "events_retention_hours")? {
        cfg.events_retention_hours = clamp_non_negative_u32(n, "events_retention_hours");
    }
    if let Some(n) = get_integer(table, "aggregates_retention_days")? {
        cfg.aggregates_retention_days = clamp_non_negative_u32(n, "aggregates_retention_days");
    }
    Ok(cfg)
}

/// Convert an i64 from TOML to u32 with explicit range validation. A
/// negative value would otherwise wrap silently to a huge u32 (e.g. -1
/// becomes 4_294_967_295) and effectively disable retention pruning.
fn clamp_non_negative_u32(n: i64, key: &str) -> u32 {
    if n < 0 {
        eprintln!("config: {key} cannot be negative ({n}); treating as 0");
        return 0;
    }
    if n > u32::MAX as i64 {
        eprintln!("config: {key} exceeds u32::MAX ({n}); capping");
        return u32::MAX;
    }
    n as u32
}

#[cfg(feature = "tui")]
fn parse_tui(table: &toml_span::value::Table<'_>) -> Result<TuiConfig, ConfigError> {
    let mut cfg = TuiConfig::default();
    if let Some(n) = get_integer(table, "tick_ms")? {
        cfg.tick_ms = n as u64;
    }
    if let Some(s) = get_str(table, "key_quit")? {
        cfg.key_quit = s.to_string();
    }
    if let Some(s) = get_str(table, "key_pause")? {
        cfg.key_pause = s.to_string();
    }
    if let Some(s) = get_str(table, "key_scroll_up")? {
        cfg.key_scroll_up = s.to_string();
    }
    if let Some(s) = get_str(table, "key_scroll_down")? {
        cfg.key_scroll_down = s.to_string();
    }
    Ok(cfg)
}

fn parse_forwarding(table: &toml_span::value::Table<'_>) -> Result<ForwardingConfig, ConfigError> {
    let mut cfg = ForwardingConfig::default();
    if let Some(s) = get_str(table, "file")? {
        cfg.file = Some(s.to_string());
    }
    if let Some(s) = get_str(table, "template")? {
        cfg.template = s.to_string();
    }
    if let Some(s) = get_str(table, "forward_url")? {
        cfg.forward_url = Some(s.to_string());
    }
    if let Some(arr) = get_string_array(table, "filter")? {
        cfg.filter = arr;
    }
    if let Some(s) = get_str(table, "format")? {
        cfg.format = match s {
            "template" => ForwardFormat::Template,
            "json" => ForwardFormat::Json,
            "syslog" => ForwardFormat::Syslog,
            "cef" => ForwardFormat::Cef,
            "elasticsearch" => ForwardFormat::Elasticsearch,
            other => {
                return Err(ConfigError::Parse(format!(
                    "invalid value '{other}' for forwarding.format; \
                     expected template, json, syslog, cef, or elasticsearch"
                )));
            }
        };
    }
    Ok(cfg)
}

#[cfg(feature = "rest")]
fn parse_server(table: &toml_span::value::Table<'_>) -> Result<ServerConfig, ConfigError> {
    let mut cfg = ServerConfig::default();
    if let Some(s) = get_str(table, "listen")? {
        cfg.listen = s.to_string();
    }
    if let Some(s) = get_str(table, "token")? {
        cfg.token = s.to_string();
    }
    Ok(cfg)
}

#[cfg(feature = "rest")]
fn parse_api(table: &toml_span::value::Table<'_>) -> Result<ApiConfig, ConfigError> {
    let mut cfg = ApiConfig::default();
    if let Some(b) = get_bool(table, "enabled")? {
        cfg.enabled = b;
    }
    if let Some(n) = get_integer(table, "port")? {
        cfg.port = n as u16;
    }
    if let Some(s) = get_str(table, "root_path")? {
        cfg.root_path = s.to_string();
    }
    Ok(cfg)
}

#[cfg(feature = "rest")]
fn parse_websocket(table: &toml_span::value::Table<'_>) -> Result<WebSocketConfig, ConfigError> {
    let mut cfg = WebSocketConfig::default();
    if let Some(b) = get_bool(table, "enabled")? {
        cfg.enabled = b;
    }
    if let Some(n) = get_integer(table, "port")? {
        cfg.port = n as u16;
    }
    if let Some(s) = get_str(table, "root_path")? {
        cfg.root_path = s.to_string();
    }
    Ok(cfg)
}

#[cfg(feature = "rest")]
fn parse_mcp(table: &toml_span::value::Table<'_>) -> Result<McpConfig, ConfigError> {
    let mut cfg = McpConfig::default();
    if let Some(b) = get_bool(table, "enabled")? {
        cfg.enabled = b;
    }
    if let Some(n) = get_integer(table, "port")? {
        cfg.port = n as u16;
    }
    if let Some(s) = get_str(table, "root_path")? {
        cfg.root_path = s.to_string();
    }
    Ok(cfg)
}

#[cfg(feature = "nats")]
fn parse_nats(table: &toml_span::value::Table<'_>) -> Result<NatsConfig, ConfigError> {
    let mut cfg = NatsConfig::default();
    if let Some(b) = get_bool(table, "enabled")? {
        cfg.enabled = b;
    }
    if let Some(s) = get_str(table, "url")? {
        cfg.url = s.to_string();
    }
    if let Some(s) = get_str(table, "publish_subject")? {
        cfg.publish_subject = s.to_string();
    }
    if let Some(s) = get_str(table, "subscribe_subject")? {
        cfg.subscribe_subject = s.to_string();
    }
    Ok(cfg)
}

#[cfg(feature = "rest")]
fn parse_web(table: &toml_span::value::Table<'_>) -> Result<WebConfig, ConfigError> {
    let mut cfg = WebConfig::default();
    if let Some(b) = get_bool(table, "enabled")? {
        cfg.enabled = b;
    }
    if let Some(n) = get_integer(table, "port")? {
        cfg.port = n as u16;
    }
    if let Some(n) = get_integer(table, "history_size")? {
        cfg.history_size = n as usize;
    }
    if let Some(n) = get_integer(table, "beaconing_min_observations")? {
        cfg.beaconing_min_observations = n as usize;
    }
    if let Some(f) = get_float(table, "beaconing_cov_threshold")? {
        cfg.beaconing_cov_threshold = f;
    }
    Ok(cfg)
}

// ---------------------------------------------------------------------------
// Config implementation
// ---------------------------------------------------------------------------

impl Config {
    pub fn parse(content: &str) -> Result<Self, ConfigError> {
        let mut cfg = Self::default();

        let value = toml_span::parse(content).map_err(|e| ConfigError::Parse(e.to_string()))?;

        let root = match value.as_ref() {
            ValueInner::Table(t) => t,
            _ => {
                return Err(ConfigError::InvalidType {
                    key: "root".to_string(),
                    expected: "table",
                    span: value.span,
                });
            }
        };

        if let Some(t) = get_table(root, "input")? {
            cfg.input = parse_input(t)?;
        }
        if let Some(t) = get_table(root, "persistence")? {
            cfg.persistence = parse_persistence(t)?;
        }
        #[cfg(feature = "tui")]
        if let Some(t) = get_table(root, "tui")? {
            cfg.tui = parse_tui(t)?;
        }
        if let Some(t) = get_table(root, "forwarding")? {
            cfg.forwarding = parse_forwarding(t)?;
        }
        #[cfg(feature = "rest")]
        if let Some(t) = get_table(root, "server")? {
            cfg.server = parse_server(t)?;
        }
        #[cfg(feature = "rest")]
        if let Some(t) = get_table(root, "api")? {
            cfg.api = parse_api(t)?;
        }
        #[cfg(feature = "rest")]
        if let Some(t) = get_table(root, "websocket")? {
            cfg.websocket = parse_websocket(t)?;
        }
        #[cfg(feature = "rest")]
        if let Some(t) = get_table(root, "mcp")? {
            cfg.mcp = parse_mcp(t)?;
        }
        #[cfg(feature = "rest")]
        if let Some(t) = get_table(root, "web")? {
            cfg.web = parse_web(t)?;
        }
        #[cfg(feature = "nats")]
        if let Some(t) = get_table(root, "nats")? {
            cfg.nats = parse_nats(t)?;
        }

        Ok(cfg)
    }

    pub fn load(path: &str) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)?;
        Self::parse(&content)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamp_non_negative_u32_handles_negative_zero_and_overflow() {
        assert_eq!(clamp_non_negative_u32(0, "k"), 0);
        assert_eq!(clamp_non_negative_u32(42, "k"), 42);
        assert_eq!(clamp_non_negative_u32(-1, "k"), 0);
        assert_eq!(clamp_non_negative_u32(i64::MIN, "k"), 0);
        assert_eq!(clamp_non_negative_u32(u32::MAX as i64, "k"), u32::MAX);
        assert_eq!(clamp_non_negative_u32(u32::MAX as i64 + 1, "k"), u32::MAX);
        assert_eq!(clamp_non_negative_u32(i64::MAX, "k"), u32::MAX);
    }

    #[test]
    fn negative_retention_clamps_to_zero_not_wraparound() {
        // Regression: i64::MIN previously wrapped to u32::MAX silently.
        let f = write_temp(
            "[persistence]\n\
             events_retention_hours = -1\n\
             aggregates_retention_days = -7\n",
        );
        let cfg = Config::load(f.path().to_str().unwrap()).unwrap();
        assert_eq!(cfg.persistence.events_retention_hours, 0);
        assert_eq!(cfg.persistence.aggregates_retention_days, 0);
    }

    fn write_temp(content: &str) -> tempfile::NamedTempFile {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f
    }

    // --- InputConfig ---

    #[test]
    fn test_input_defaults() {
        let f = write_temp("[input]\n");
        let cfg = Config::load(f.path().to_str().unwrap()).unwrap();
        assert_eq!(cfg.input.socket, "/tmp/dgaard_stats.sock");
        assert_eq!(cfg.input.index, "/var/lib/dns/hosts.bin");
    }

    #[test]
    fn test_input_custom_values() {
        let f = write_temp(
            r#"
[input]
socket = "/run/dns.sock"
index  = "/data/hosts.bin"
"#,
        );
        let cfg = Config::load(f.path().to_str().unwrap()).unwrap();
        assert_eq!(cfg.input.socket, "/run/dns.sock");
        assert_eq!(cfg.input.index, "/data/hosts.bin");
    }

    // --- PersistenceConfig ---

    #[test]
    fn test_persistence_defaults() {
        let f = write_temp("[input]\n");
        let cfg = Config::load(f.path().to_str().unwrap()).unwrap();
        assert_eq!(cfg.persistence.db, "/var/dgaard/stats.sqlite");
        assert_eq!(cfg.persistence.events_retention_hours, 72);
        assert_eq!(cfg.persistence.aggregates_retention_days, 90);
    }

    #[test]
    fn test_persistence_custom_values() {
        let f = write_temp(
            r#"
[input]
[persistence]
db = "/tmp/test.sqlite"
events_retention_hours = 24
aggregates_retention_days = 30
"#,
        );
        let cfg = Config::load(f.path().to_str().unwrap()).unwrap();
        assert_eq!(cfg.persistence.db, "/tmp/test.sqlite");
        assert_eq!(cfg.persistence.events_retention_hours, 24);
        assert_eq!(cfg.persistence.aggregates_retention_days, 30);
    }

    // --- TuiConfig ---

    #[test]
    fn test_tui_defaults() {
        let f = write_temp("[input]\n");
        let cfg = Config::load(f.path().to_str().unwrap()).unwrap();
        assert_eq!(cfg.tui.tick_ms, 250);
        assert_eq!(cfg.tui.key_quit, "q");
        assert_eq!(cfg.tui.key_pause, "space");
        assert_eq!(cfg.tui.key_scroll_up, "up");
        assert_eq!(cfg.tui.key_scroll_down, "down");
    }

    #[test]
    fn test_tui_custom_tick() {
        let f = write_temp(
            r#"
[input]
[tui]
tick_ms = 100
key_quit = "esc"
"#,
        );
        let cfg = Config::load(f.path().to_str().unwrap()).unwrap();
        assert_eq!(cfg.tui.tick_ms, 100);
        assert_eq!(cfg.tui.key_quit, "esc");
        assert_eq!(cfg.tui.key_pause, "space");
    }

    // --- ForwardFormat ---

    #[test]
    fn test_forward_format_content_type() {
        assert_eq!(
            ForwardFormat::Template.content_type(),
            "text/plain; charset=utf-8"
        );
        assert_eq!(ForwardFormat::Json.content_type(), "application/json");
        assert_eq!(
            ForwardFormat::Syslog.content_type(),
            "text/plain; charset=utf-8"
        );
        assert_eq!(
            ForwardFormat::Cef.content_type(),
            "text/plain; charset=utf-8"
        );
        assert_eq!(
            ForwardFormat::Elasticsearch.content_type(),
            "application/x-ndjson"
        );
    }

    // --- ForwardingConfig ---

    #[test]
    fn test_forwarding_defaults() {
        let f = write_temp("[input]\n");
        let cfg = Config::load(f.path().to_str().unwrap()).unwrap();
        assert!(cfg.forwarding.file.is_none());
        assert!(cfg.forwarding.forward_url.is_none());
        assert!(cfg.forwarding.filter.is_empty());
        assert_eq!(cfg.forwarding.format, ForwardFormat::Template);
        assert_eq!(
            cfg.forwarding.template,
            "{timestamp} {client_ip} {action} {domain}"
        );
    }

    #[test]
    fn test_forwarding_format_variants() {
        for (value, expected) in [
            ("template", ForwardFormat::Template),
            ("json", ForwardFormat::Json),
            ("syslog", ForwardFormat::Syslog),
            ("cef", ForwardFormat::Cef),
            ("elasticsearch", ForwardFormat::Elasticsearch),
        ] {
            let f = write_temp(&format!("[forwarding]\nformat = \"{value}\"\n"));
            let cfg = Config::load(f.path().to_str().unwrap()).unwrap();
            assert_eq!(cfg.forwarding.format, expected, "failed for value={value}");
        }
    }

    #[test]
    fn test_forwarding_invalid_format_is_parse_error() {
        let f = write_temp("[forwarding]\nformat = \"ndjson\"\n");
        let result = Config::load(f.path().to_str().unwrap());
        assert!(matches!(result, Err(ConfigError::Parse(_))));
    }

    #[test]
    fn test_forwarding_file_and_filter() {
        let f = write_temp(
            r#"
[input]
[forwarding]
file = "/var/log/dgaard/dns.log"
filter = ["Blocked", "HighlySuspicious"]
"#,
        );
        let cfg = Config::load(f.path().to_str().unwrap()).unwrap();
        assert_eq!(
            cfg.forwarding.file.as_deref(),
            Some("/var/log/dgaard/dns.log")
        );
        assert_eq!(cfg.forwarding.filter, vec!["Blocked", "HighlySuspicious"]);
    }

    #[test]
    fn test_forwarding_url() {
        let f = write_temp(
            r#"
[input]
[forwarding]
forward_url = "https://soar.internal/api/v1/dns-alert"
"#,
        );
        let cfg = Config::load(f.path().to_str().unwrap()).unwrap();
        assert_eq!(
            cfg.forwarding.forward_url.as_deref(),
            Some("https://soar.internal/api/v1/dns-alert")
        );
    }

    // --- ServerConfig ---

    #[test]
    fn test_server_defaults() {
        let f = write_temp("[input]\n");
        let cfg = Config::load(f.path().to_str().unwrap()).unwrap();
        assert_eq!(cfg.server.listen, "127.0.0.1");
        assert_eq!(cfg.server.token, "changeme");
    }

    #[test]
    fn test_server_custom_values() {
        let f = write_temp(
            r#"
[server]
listen = "0.0.0.0"
token  = "s3cr3t"
"#,
        );
        let cfg = Config::load(f.path().to_str().unwrap()).unwrap();
        assert_eq!(cfg.server.listen, "0.0.0.0");
        assert_eq!(cfg.server.token, "s3cr3t");
    }

    // --- Module sections ---

    #[test]
    fn test_modules_disabled_by_default() {
        let f = write_temp("[input]\n");
        let cfg = Config::load(f.path().to_str().unwrap()).unwrap();
        assert!(!cfg.api.enabled);
        assert!(!cfg.websocket.enabled);
        assert!(!cfg.mcp.enabled);
        assert!(!cfg.web.enabled);
        // Each module advertises its own default port.
        assert_eq!(cfg.api.port, 8080);
        assert_eq!(cfg.websocket.port, 8081);
        assert_eq!(cfg.mcp.port, 8082);
        assert_eq!(cfg.web.port, 8083);
    }

    #[test]
    fn test_api_custom_values() {
        let f = write_temp(
            r#"
[api]
enabled = true
port    = 9080
root_path = "/api/v1"
"#,
        );
        let cfg = Config::load(f.path().to_str().unwrap()).unwrap();
        assert!(cfg.api.enabled);
        assert_eq!(cfg.api.port, 9080);
        assert_eq!(cfg.api.root_path, "/api/v1");
    }

    #[test]
    fn test_websocket_and_mcp_independent() {
        let f = write_temp(
            r#"
[websocket]
enabled = true
port    = 9081
[mcp]
enabled = true
port    = 9082
"#,
        );
        let cfg = Config::load(f.path().to_str().unwrap()).unwrap();
        assert!(cfg.websocket.enabled);
        assert_eq!(cfg.websocket.port, 9081);
        assert!(cfg.mcp.enabled);
        assert_eq!(cfg.mcp.port, 9082);
        assert!(!cfg.api.enabled);
    }

    // --- WebConfig ---

    #[test]
    fn test_web_defaults() {
        let f = write_temp("[input]\n");
        let cfg = Config::load(f.path().to_str().unwrap()).unwrap();
        assert!(!cfg.web.enabled);
        assert_eq!(cfg.web.port, 8083);
        assert_eq!(cfg.web.history_size, 1000);
        assert_eq!(cfg.web.beaconing_min_observations, 5);
        assert!((cfg.web.beaconing_cov_threshold - 0.15).abs() < 1e-9);
    }

    #[test]
    fn test_web_custom_values() {
        let f = write_temp(
            r#"
[web]
enabled = true
port = 9090
history_size = 5000
beaconing_min_observations = 8
beaconing_cov_threshold = 0.2
"#,
        );
        let cfg = Config::load(f.path().to_str().unwrap()).unwrap();
        assert!(cfg.web.enabled);
        assert_eq!(cfg.web.port, 9090);
        assert_eq!(cfg.web.history_size, 5000);
        assert_eq!(cfg.web.beaconing_min_observations, 8);
        assert!((cfg.web.beaconing_cov_threshold - 0.2).abs() < 1e-9);
    }

    // --- Error handling ---

    #[test]
    fn test_missing_file_returns_io_error() {
        let result = Config::load("/nonexistent/path/config.toml");
        assert!(matches!(result, Err(ConfigError::Io(_))));
    }

    #[test]
    fn test_invalid_toml_returns_parse_error() {
        let f = write_temp("this is not valid toml ][[[");
        let result = Config::load(f.path().to_str().unwrap());
        assert!(matches!(result, Err(ConfigError::Parse(_))));
    }

    // --- NatsConfig ---

    #[cfg(feature = "nats")]
    #[test]
    fn test_nats_defaults_disabled() {
        let f = write_temp("[input]\n");
        let cfg = Config::load(f.path().to_str().unwrap()).unwrap();
        assert!(!cfg.nats.enabled);
        assert_eq!(cfg.nats.url, "nats://127.0.0.1:4222");
        assert_eq!(cfg.nats.publish_subject, "dgaard.events");
        assert!(cfg.nats.subscribe_subject.is_empty());
    }

    #[cfg(feature = "nats")]
    #[test]
    fn test_nats_custom_values() {
        let f = write_temp(
            r#"
[nats]
enabled = true
url = "nats://broker.internal:4222"
publish_subject = "site42.events"
subscribe_subject = "upstream.events"
"#,
        );
        let cfg = Config::load(f.path().to_str().unwrap()).unwrap();
        assert!(cfg.nats.enabled);
        assert_eq!(cfg.nats.url, "nats://broker.internal:4222");
        assert_eq!(cfg.nats.publish_subject, "site42.events");
        assert_eq!(cfg.nats.subscribe_subject, "upstream.events");
    }

    #[cfg(feature = "nats")]
    #[test]
    fn test_nats_invalid_type_is_rejected() {
        let f = write_temp("[nats]\nenabled = 1\n");
        let result = Config::load(f.path().to_str().unwrap());
        assert!(matches!(result, Err(ConfigError::InvalidType { .. })));
    }

    // --- Example file ---

    /// Lock the shipped example TOML to the parser: any drift between
    /// `dgaard-monitor.example.toml` and the section/field schema fails CI.
    #[test]
    fn example_file_parses_and_matches_defaults() {
        let example = include_str!("../dgaard-monitor.example.toml");
        let cfg = Config::parse(example).expect("example file must parse");

        // Server defaults inherited by every REST module.
        assert_eq!(cfg.server.listen, "127.0.0.1");
        assert_eq!(cfg.server.token, "changeme");

        // Every module ships disabled and on its documented port.
        assert!(!cfg.api.enabled);
        assert_eq!(cfg.api.port, 8080);
        assert_eq!(cfg.api.root_path, "/api/v1");
        assert!(!cfg.websocket.enabled);
        assert_eq!(cfg.websocket.port, 8081);
        assert!(!cfg.mcp.enabled);
        assert_eq!(cfg.mcp.port, 8082);
        assert!(!cfg.web.enabled);
        assert_eq!(cfg.web.port, 8083);
        assert_eq!(cfg.web.history_size, 1000);
    }
}
