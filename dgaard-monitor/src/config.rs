// Fields are declared for future use by service implementations.
#![allow(dead_code)]

use toml_span::{Span, value::ValueInner};

use thiserror::Error;

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
    pub api: ConnectivityConfig,
    pub websocket: ConnectivityConfig,
    pub mcp: ConnectivityConfig,
    pub web: WebConfig,
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

#[derive(Debug)]
pub struct TuiConfig {
    /// Terminal refresh interval in milliseconds.
    pub tick_ms: u64,
    pub key_quit: String,
    pub key_pause: String,
    pub key_scroll_up: String,
    pub key_scroll_down: String,
}

fn default_tick_ms() -> u64 {
    250
}
fn default_key_quit() -> String {
    "q".to_string()
}
fn default_key_pause() -> String {
    "space".to_string()
}
fn default_key_scroll_up() -> String {
    "up".to_string()
}
fn default_key_scroll_down() -> String {
    "down".to_string()
}

impl Default for TuiConfig {
    fn default() -> Self {
        Self {
            tick_ms: default_tick_ms(),
            key_quit: default_key_quit(),
            key_pause: default_key_pause(),
            key_scroll_up: default_key_scroll_up(),
            key_scroll_down: default_key_scroll_down(),
        }
    }
}

/// Wire format for forwarded events (file/stdout and HTTP POST).
#[derive(Debug, Default, PartialEq, Clone)]
pub enum ForwardFormat {
    /// Template string with `{timestamp}`, `{client_ip}`, `{action}`, `{domain}` placeholders.
    #[default]
    Template,
    /// Compact JSON object.
    Json,
    /// RFC 5424 syslog line with structured-data block (SD-ID `dgaard@32473`).
    Syslog,
    /// ArcSight Common Event Format v0 (`CEF:0|…`).
    Cef,
    /// Elasticsearch Bulk API NDJSON: `{"index":{}}\n{document}`.
    Elasticsearch,
}

impl ForwardFormat {
    /// HTTP `Content-Type` to use when POSTing events in this format.
    pub fn content_type(&self) -> &'static str {
        match self {
            ForwardFormat::Template | ForwardFormat::Syslog | ForwardFormat::Cef => {
                "text/plain; charset=utf-8"
            }
            ForwardFormat::Json => "application/json",
            ForwardFormat::Elasticsearch => "application/x-ndjson",
        }
    }
}

/// Controls where enriched events are forwarded.
///
/// When `file` is set events are appended to that path; otherwise they go to
/// stdout (if any forwarding option is active).  `template` is a
/// [strftime-like] format string where the following placeholders are
/// replaced: `{timestamp}`, `{client_ip}`, `{action}`, `{domain}`.
/// `forward_url` sends each matching event as an HTTP POST.
/// `filter` lists the action variants to forward; an empty list means *all*.
#[derive(Debug)]
pub struct ForwardingConfig {
    /// Append formatted lines to this file instead of stdout.
    pub file: Option<String>,
    /// Template string used when `format = "template"`.
    pub template: String,
    /// HTTP(S) endpoint to POST events to (SOAR, Slack incoming webhook, …).
    pub forward_url: Option<String>,
    /// Action variants to forward. Empty list = forward everything.
    /// Valid values: "Allowed", "Proxied", "Blocked", "Suspicious", "HighlySuspicious".
    pub filter: Vec<String>,
    /// Wire format for both file/stdout and HTTP POST output.
    /// Valid values: "template" (default), "json", "syslog", "cef", "elasticsearch".
    pub format: ForwardFormat,
}

fn default_template() -> String {
    "{timestamp} {client_ip} {action} {domain}".to_string()
}

impl Default for ForwardingConfig {
    fn default() -> Self {
        Self {
            file: None,
            template: default_template(),
            forward_url: None,
            filter: Vec::new(),
            format: ForwardFormat::default(),
        }
    }
}

/// Shared connectivity config used for the REST API, WebSocket, and MCP endpoints.
#[derive(Debug)]
pub struct ConnectivityConfig {
    pub enabled: bool,
    pub listen: String,
    pub port: u16,
    /// Static bearer token required on every request.
    pub token: String,
    pub root_path: String,
}

fn default_listen() -> String {
    "127.0.0.1".to_string()
}

fn default_token() -> String {
    "changeme".to_string()
}

fn default_root_path() -> String {
    "/".to_string()
}

impl Default for ConnectivityConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: default_listen(),
            port: 0,
            token: default_token(),
            root_path: default_root_path(),
        }
    }
}

/// Configuration for the embedded web UI server.
#[derive(Debug)]
pub struct WebConfig {
    pub enabled: bool,
    pub listen: String,
    pub port: u16,
    pub token: String,
    pub history_size: usize,
    /// Minimum number of queries from a single client to the same domain
    /// before the pair is eligible for beaconing analysis.
    pub beaconing_min_observations: usize,
    /// Coefficient of Variation threshold (std_dev / mean of inter-arrival
    /// times).  Pairs with CoV below this value are flagged as potential
    /// beacons.  Lower = stricter.
    pub beaconing_cov_threshold: f64,
}

fn default_web_port() -> u16 {
    8083
}

fn default_history_size() -> usize {
    1000
}

fn default_beaconing_min_obs() -> usize {
    5
}

fn default_beaconing_cov() -> f64 {
    0.15
}

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: default_listen(),
            port: default_web_port(),
            token: default_token(),
            history_size: default_history_size(),
            beaconing_min_observations: default_beaconing_min_obs(),
            beaconing_cov_threshold: default_beaconing_cov(),
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
        cfg.events_retention_hours = n as u32;
    }
    if let Some(n) = get_integer(table, "aggregates_retention_days")? {
        cfg.aggregates_retention_days = n as u32;
    }
    Ok(cfg)
}

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

fn parse_connectivity(
    table: &toml_span::value::Table<'_>,
) -> Result<ConnectivityConfig, ConfigError> {
    let mut cfg = ConnectivityConfig::default();
    if let Some(b) = get_bool(table, "enabled")? {
        cfg.enabled = b;
    }
    if let Some(s) = get_str(table, "listen")? {
        cfg.listen = s.to_string();
    }
    if let Some(n) = get_integer(table, "port")? {
        cfg.port = n as u16;
    }
    if let Some(s) = get_str(table, "token")? {
        cfg.token = s.to_string();
    }
    if let Some(s) = get_str(table, "root_path")? {
        cfg.root_path = s.to_string();
    }
    Ok(cfg)
}

fn parse_web(table: &toml_span::value::Table<'_>) -> Result<WebConfig, ConfigError> {
    let mut cfg = WebConfig::default();
    if let Some(b) = get_bool(table, "enabled")? {
        cfg.enabled = b;
    }
    if let Some(s) = get_str(table, "listen")? {
        cfg.listen = s.to_string();
    }
    if let Some(n) = get_integer(table, "port")? {
        cfg.port = n as u16;
    }
    if let Some(s) = get_str(table, "token")? {
        cfg.token = s.to_string();
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
        if let Some(t) = get_table(root, "tui")? {
            cfg.tui = parse_tui(t)?;
        }
        if let Some(t) = get_table(root, "forwarding")? {
            cfg.forwarding = parse_forwarding(t)?;
        }
        if let Some(t) = get_table(root, "api")? {
            cfg.api = parse_connectivity(t)?;
        }
        if let Some(t) = get_table(root, "websocket")? {
            cfg.websocket = parse_connectivity(t)?;
        }
        if let Some(t) = get_table(root, "mcp")? {
            cfg.mcp = parse_connectivity(t)?;
        }
        if let Some(t) = get_table(root, "web")? {
            cfg.web = parse_web(t)?;
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

    // --- ConnectivityConfig ---

    #[test]
    fn test_connectivity_disabled_by_default() {
        let f = write_temp("[input]\n");
        let cfg = Config::load(f.path().to_str().unwrap()).unwrap();
        assert!(!cfg.api.enabled);
        assert!(!cfg.websocket.enabled);
        assert!(!cfg.mcp.enabled);
    }

    #[test]
    fn test_api_custom_values() {
        let f = write_temp(
            r#"
[input]
[api]
enabled = true
listen  = "0.0.0.0"
port    = 8080
token   = "s3cr3t"
root_path = "/api/v1"
"#,
        );
        let cfg = Config::load(f.path().to_str().unwrap()).unwrap();
        assert!(cfg.api.enabled);
        assert_eq!(cfg.api.listen, "0.0.0.0");
        assert_eq!(cfg.api.port, 8080);
        assert_eq!(cfg.api.token, "s3cr3t");
        assert_eq!(cfg.api.root_path, "/api/v1");
    }

    #[test]
    fn test_websocket_and_mcp_independent() {
        let f = write_temp(
            r#"
[input]
[websocket]
enabled = true
port    = 8081
[mcp]
enabled = true
port    = 8082
"#,
        );
        let cfg = Config::load(f.path().to_str().unwrap()).unwrap();
        assert!(cfg.websocket.enabled);
        assert_eq!(cfg.websocket.port, 8081);
        assert!(cfg.mcp.enabled);
        assert_eq!(cfg.mcp.port, 8082);
        assert!(!cfg.api.enabled);
    }

    // --- WebConfig ---

    #[test]
    fn test_web_defaults() {
        let f = write_temp("[input]\n");
        let cfg = Config::load(f.path().to_str().unwrap()).unwrap();
        assert!(!cfg.web.enabled);
        assert_eq!(cfg.web.listen, "127.0.0.1");
        assert_eq!(cfg.web.port, 8083);
        assert_eq!(cfg.web.token, "changeme");
        assert_eq!(cfg.web.history_size, 1000);
    }

    #[test]
    fn test_web_custom_values() {
        let f = write_temp(
            r#"
[input]
[web]
enabled = true
listen = "0.0.0.0"
port = 9090
token = "mytoken"
history_size = 5000
"#,
        );
        let cfg = Config::load(f.path().to_str().unwrap()).unwrap();
        assert!(cfg.web.enabled);
        assert_eq!(cfg.web.listen, "0.0.0.0");
        assert_eq!(cfg.web.port, 9090);
        assert_eq!(cfg.web.token, "mytoken");
        assert_eq!(cfg.web.history_size, 5000);
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
}
