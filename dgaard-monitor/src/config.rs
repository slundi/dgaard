// Fields are declared for future use by service implementations.
#![allow(dead_code)]

use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse config file: {0}")]
    Parse(#[from] toml::de::Error),
}

#[derive(Debug, Deserialize)]
pub struct Config {
    pub input: InputConfig,
    #[serde(default)]
    pub persistence: PersistenceConfig,
    #[serde(default)]
    pub tui: TuiConfig,
    #[serde(default)]
    pub forwarding: ForwardingConfig,
    #[serde(default)]
    pub api: ConnectivityConfig,
    #[serde(default)]
    pub websocket: ConnectivityConfig,
    #[serde(default)]
    pub mcp: ConnectivityConfig,
}

#[derive(Debug, Deserialize)]
pub struct InputConfig {
    #[serde(default = "default_socket")]
    pub socket: String,
    #[serde(default = "default_index")]
    pub index: String,
}

fn default_socket() -> String {
    "/tmp/dns.sock".to_string()
}

fn default_index() -> String {
    "/var/lib/dns/hosts.bin".to_string()
}

impl Default for InputConfig {
    fn default() -> Self {
        Self {
            socket: default_socket(),
            index: default_index(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct PersistenceConfig {
    #[serde(default = "default_db")]
    pub db: String,
    #[serde(default = "default_events_retention_hours")]
    pub events_retention_hours: u32,
    #[serde(default = "default_aggregates_retention_days")]
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

#[derive(Debug, Deserialize)]
pub struct TuiConfig {
    /// Terminal refresh interval in milliseconds.
    #[serde(default = "default_tick_ms")]
    pub tick_ms: u64,
    #[serde(default = "default_key_quit")]
    pub key_quit: String,
    #[serde(default = "default_key_pause")]
    pub key_pause: String,
    #[serde(default = "default_key_scroll_up")]
    pub key_scroll_up: String,
    #[serde(default = "default_key_scroll_down")]
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

/// Controls where enriched events are forwarded.
///
/// When `file` is set events are appended to that path; otherwise they go to
/// stdout (if any forwarding option is active).  `template` is a
/// [strftime-like] format string where the following placeholders are
/// replaced: `{timestamp}`, `{client_ip}`, `{action}`, `{domain}`.
/// `forward_url` sends each matching event as an HTTP POST (JSON body).
/// `filter` lists the action variants to forward; an empty list means *all*.
#[derive(Debug, Deserialize)]
pub struct ForwardingConfig {
    /// Append formatted lines to this file instead of stdout.
    pub file: Option<String>,
    /// Template string for each forwarded line.
    #[serde(default = "default_template")]
    pub template: String,
    /// HTTP(S) endpoint to POST JSON events to (SOAR, Slack incoming webhook, …).
    pub forward_url: Option<String>,
    /// Action variants to forward. Empty list = forward everything.
    /// Valid values: "Allowed", "Proxied", "Blocked", "Suspicious", "HighlySuspicious".
    #[serde(default)]
    pub filter: Vec<String>,
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
        }
    }
}

/// Shared connectivity config used for the REST API, WebSocket, and MCP endpoints.
#[derive(Debug, Deserialize)]
pub struct ConnectivityConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_listen")]
    pub listen: String,
    pub port: u16,
    /// Static bearer token required on every request.
    #[serde(default = "default_token")]
    pub token: String,
    #[serde(default = "default_root_path")]
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

impl Config {
    pub fn load(path: &str) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)?;
        let config = toml::from_str(&content)?;
        Ok(config)
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
        assert_eq!(cfg.input.socket, "/tmp/dns.sock");
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

    // --- ForwardingConfig ---

    #[test]
    fn test_forwarding_defaults() {
        let f = write_temp("[input]\n");
        let cfg = Config::load(f.path().to_str().unwrap()).unwrap();
        assert!(cfg.forwarding.file.is_none());
        assert!(cfg.forwarding.forward_url.is_none());
        assert!(cfg.forwarding.filter.is_empty());
        assert_eq!(
            cfg.forwarding.template,
            "{timestamp} {client_ip} {action} {domain}"
        );
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
