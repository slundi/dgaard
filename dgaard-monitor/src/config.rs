use std::ops::RangeInclusive;

use toml_span::{Span, value::ValueInner};

use thiserror::Error;

use dgaard_monitor_core::util::ACTION_NAMES;

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

/// Valid TCP ports for the REST modules (0 would bind a random port).
#[cfg(feature = "rest")]
const PORT_RANGE: RangeInclusive<i64> = 1..=65_535;
/// TUI refresh interval, in milliseconds.
#[cfg(feature = "tui")]
const TICK_MS_RANGE: RangeInclusive<i64> = 10..=60_000;
const RETENTION_RANGE: RangeInclusive<i64> = 0..=u32::MAX as i64;
const UID_RANGE: RangeInclusive<i64> = 0..=u32::MAX as i64;
/// Capacity of the internal event bus, in events.
const EVENT_BUFFER_RANGE: RangeInclusive<i64> = 256..=65_536;
/// Sliding window of recent events, in seconds (1 minute to 1 day).
const WINDOW_SECS_RANGE: RangeInclusive<i64> = 60..=86_400;
/// Events kept in the sliding window; 0 disables it.
const MAX_WINDOW_EVENTS_RANGE: RangeInclusive<i64> = 0..=10_000_000;
#[cfg(feature = "rest")]
const HISTORY_SIZE_RANGE: RangeInclusive<i64> = 1..=1_000_000;
#[cfg(feature = "rest")]
const MIN_OBSERVATIONS_RANGE: RangeInclusive<i64> = 2..=1_000_000;

/// 1-based position in the config file, derived from a byte span.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Location {
    pub line: usize,
    pub column: usize,
}

impl Location {
    fn of(content: &str, offset: usize) -> Self {
        let before = content.get(..offset).unwrap_or(content);
        Self {
            line: before.matches('\n').count() + 1,
            column: before
                .rsplit('\n')
                .next()
                .map_or(0, |line| line.chars().count())
                + 1,
        }
    }
}

/// ` at line L, column C`, or nothing when the position is unknown.
fn at(location: &Option<Location>) -> String {
    location.map_or_else(String::new, |loc| {
        format!(" at line {}, column {}", loc.line, loc.column)
    })
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file: {0}")]
    Io(#[from] std::io::Error),
    #[error("TOML syntax error: {0}")]
    Parse(String),
    #[error("invalid type for key '{key}': expected {expected}{}", at(.location))]
    InvalidType {
        key: String,
        expected: &'static str,
        span: Span,
        location: Option<Location>,
    },
    #[error("invalid value for key '{key}': {message}{}", at(.location))]
    InvalidValue {
        key: String,
        message: String,
        span: Span,
        location: Option<Location>,
    },
    /// A key or section the parser does not know, most likely a typo that
    /// would otherwise fall back silently to the default.
    #[error("unknown key '{key}'{}", at(.location))]
    UnknownKey {
        key: String,
        span: Span,
        location: Option<Location>,
    },
}

impl ConfigError {
    fn invalid_type(key: &str, expected: &'static str, span: Span) -> Self {
        Self::InvalidType {
            key: key.to_string(),
            expected,
            span,
            location: None,
        }
    }

    fn invalid_value(key: &str, message: String, span: Span) -> Self {
        Self::InvalidValue {
            key: key.to_string(),
            message,
            span,
            location: None,
        }
    }

    /// Fill in the line and column from the span.
    fn locate(mut self, content: &str) -> Self {
        match &mut self {
            Self::InvalidType { span, location, .. }
            | Self::InvalidValue { span, location, .. }
            | Self::UnknownKey { span, location, .. } => {
                *location = Some(Location::of(content, span.start));
            }
            Self::Io(_) | Self::Parse(_) => {}
        }
        self
    }
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
    pub stats: StatsConfig,
    /// Non-fatal findings to report at startup, e.g. a section for a
    /// feature this binary was built without.
    pub warnings: Vec<String>,
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
    /// How many events a slow sink may fall behind before it loses them.
    pub event_buffer: usize,
    /// UID allowed to serve the stats socket. `None`: root, this user, or the
    /// socket's owner when it sits in a directory others cannot write to.
    pub peer_uid: Option<u32>,
}

/// Same as dgaard's `server.stats_socket_path` default, so both work together
/// out of the box (checked by a test against `dgaard-engine`).
fn default_socket() -> String {
    "/tmp/dgaard_stats.sock".to_string()
}

/// Same as dgaard's `sources.host_index_path` default.
fn default_index() -> String {
    "/var/dgaard/host_mapping.bin".to_string()
}

impl Default for InputConfig {
    fn default() -> Self {
        Self {
            socket: default_socket(),
            index: default_index(),
            engine_config_path: None,
            event_buffer: dgaard_monitor_core::state::DEFAULT_EVENT_BUFFER,
            peer_uid: None,
        }
    }
}

/// `[stats]` — in-memory statistics.
#[derive(Debug)]
pub struct StatsConfig {
    /// Length of the sliding window of recent events served by the REST
    /// services (API, MCP, web UI).
    pub window_secs: u64,
    /// Cap on events kept in that window, whatever the query rate.
    pub max_window_events: usize,
}

impl Default for StatsConfig {
    fn default() -> Self {
        Self {
            window_secs: dgaard_monitor_core::state::DEFAULT_WINDOW.as_secs(),
            max_window_events: dgaard_monitor_core::state::DEFAULT_MAX_WINDOW_EVENTS,
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
            _ => Err(ConfigError::invalid_type(key, "string", v.span)),
        },
        None => Ok(None),
    }
}

#[cfg(any(feature = "rest", feature = "nats"))]
fn get_bool(table: &toml_span::value::Table<'_>, key: &str) -> Result<Option<bool>, ConfigError> {
    match table.get(key) {
        Some(v) => match v.as_ref() {
            ValueInner::Boolean(b) => Ok(Some(*b)),
            _ => Err(ConfigError::invalid_type(key, "boolean", v.span)),
        },
        None => Ok(None),
    }
}

/// Extract an optional integer, rejecting values outside `range` instead of
/// truncating them (`port = 70000` used to become 4464), then convert it.
fn get_int_in_range<T: TryFrom<i64>>(
    table: &toml_span::value::Table<'_>,
    key: &str,
    range: RangeInclusive<i64>,
) -> Result<Option<T>, ConfigError> {
    let Some(v) = table.get(key) else {
        return Ok(None);
    };
    let ValueInner::Integer(n) = v.as_ref() else {
        return Err(ConfigError::invalid_type(key, "integer", v.span));
    };
    let out_of_range = || {
        ConfigError::invalid_value(
            key,
            format!("{n} is out of range {}..={}", range.start(), range.end()),
            v.span,
        )
    };
    if !range.contains(n) {
        return Err(out_of_range());
    }
    T::try_from(*n).map(Some).map_err(|_| out_of_range())
}

/// Extract an optional finite, strictly positive float (integers accepted).
#[cfg(feature = "rest")]
fn get_positive_float(
    table: &toml_span::value::Table<'_>,
    key: &str,
) -> Result<Option<f64>, ConfigError> {
    let Some(v) = table.get(key) else {
        return Ok(None);
    };
    let value = match v.as_ref() {
        ValueInner::Float(f) => *f,
        ValueInner::Integer(i) => *i as f64,
        _ => return Err(ConfigError::invalid_type(key, "float", v.span)),
    };
    if !value.is_finite() || value <= 0.0 {
        return Err(ConfigError::invalid_value(
            key,
            format!("{value} must be a finite number greater than 0"),
            v.span,
        ));
    }
    Ok(Some(value))
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
                            return Err(ConfigError::invalid_type(
                                &format!("{key}[]"),
                                "string",
                                item.span,
                            ));
                        }
                    }
                }
                Ok(Some(result))
            }
            _ => Err(ConfigError::invalid_type(key, "array", v.span)),
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
            _ => Err(ConfigError::invalid_type(key, "table", v.span)),
        },
        None => Ok(None),
    }
}

/// Reject keys `section` does not define: a typo would otherwise be ignored
/// and the default used without notice.
fn check_keys(
    table: &toml_span::value::Table<'_>,
    section: &str,
    known: &[&str],
) -> Result<(), ConfigError> {
    match table.keys().find(|key| !known.contains(&key.name.as_ref())) {
        Some(key) => Err(ConfigError::UnknownKey {
            key: format!("{section}.{}", key.name),
            span: key.span,
            location: None,
        }),
        None => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// Section parsers
// ---------------------------------------------------------------------------

fn parse_input(table: &toml_span::value::Table<'_>) -> Result<InputConfig, ConfigError> {
    check_keys(
        table,
        "input",
        &[
            "socket",
            "index",
            "engine_config_path",
            "event_buffer",
            "peer_uid",
        ],
    )?;
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
    if let Some(n) = get_int_in_range(table, "event_buffer", EVENT_BUFFER_RANGE)? {
        cfg.event_buffer = n;
    }
    cfg.peer_uid = get_int_in_range(table, "peer_uid", UID_RANGE)?;
    Ok(cfg)
}

fn parse_persistence(
    table: &toml_span::value::Table<'_>,
) -> Result<PersistenceConfig, ConfigError> {
    check_keys(
        table,
        "persistence",
        &["db", "events_retention_hours", "aggregates_retention_days"],
    )?;
    let mut cfg = PersistenceConfig::default();
    if let Some(s) = get_str(table, "db")? {
        cfg.db = s.to_string();
    }
    if let Some(n) = get_int_in_range(table, "events_retention_hours", RETENTION_RANGE)? {
        cfg.events_retention_hours = n;
    }
    if let Some(n) = get_int_in_range(table, "aggregates_retention_days", RETENTION_RANGE)? {
        cfg.aggregates_retention_days = n;
    }
    Ok(cfg)
}

fn parse_stats(table: &toml_span::value::Table<'_>) -> Result<StatsConfig, ConfigError> {
    check_keys(table, "stats", &["window_secs", "max_window_events"])?;
    let mut cfg = StatsConfig::default();
    if let Some(n) = get_int_in_range(table, "window_secs", WINDOW_SECS_RANGE)? {
        cfg.window_secs = n;
    }
    if let Some(n) = get_int_in_range(table, "max_window_events", MAX_WINDOW_EVENTS_RANGE)? {
        cfg.max_window_events = n;
    }
    Ok(cfg)
}

#[cfg(feature = "tui")]
fn parse_tui(table: &toml_span::value::Table<'_>) -> Result<TuiConfig, ConfigError> {
    check_keys(
        table,
        "tui",
        &[
            "tick_ms",
            "key_quit",
            "key_pause",
            "key_scroll_up",
            "key_scroll_down",
        ],
    )?;
    let mut cfg = TuiConfig::default();
    if let Some(n) = get_int_in_range(table, "tick_ms", TICK_MS_RANGE)? {
        cfg.tick_ms = n;
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
    check_keys(
        table,
        "forwarding",
        &["file", "template", "forward_url", "filter", "format"],
    )?;
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
    if let Some(entries) = get_string_array(table, "filter")? {
        let span = table.get("filter").map_or_else(Span::default, |v| v.span);
        cfg.filter = entries
            .iter()
            .map(|entry| {
                canonical_action(entry).ok_or_else(|| {
                    ConfigError::invalid_value(
                        "filter",
                        format!(
                            "unknown action '{entry}'; expected one of {}",
                            ACTION_NAMES.join(", ")
                        ),
                        span,
                    )
                })
            })
            .collect::<Result<_, _>>()?;
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

/// Match a filter entry against the action names, ignoring case, and return
/// the canonical spelling the forwarding sink compares with.
fn canonical_action(entry: &str) -> Option<String> {
    ACTION_NAMES
        .iter()
        .find(|name| name.eq_ignore_ascii_case(entry))
        .map(|name| name.to_string())
}

#[cfg(feature = "rest")]
fn parse_server(table: &toml_span::value::Table<'_>) -> Result<ServerConfig, ConfigError> {
    check_keys(table, "server", &["listen", "token"])?;
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
    check_keys(table, "api", &["enabled", "port", "root_path"])?;
    let mut cfg = ApiConfig::default();
    if let Some(b) = get_bool(table, "enabled")? {
        cfg.enabled = b;
    }
    if let Some(n) = get_int_in_range(table, "port", PORT_RANGE)? {
        cfg.port = n;
    }
    if let Some(s) = get_str(table, "root_path")? {
        cfg.root_path = s.to_string();
    }
    Ok(cfg)
}

#[cfg(feature = "rest")]
fn parse_websocket(table: &toml_span::value::Table<'_>) -> Result<WebSocketConfig, ConfigError> {
    check_keys(table, "websocket", &["enabled", "port", "root_path"])?;
    let mut cfg = WebSocketConfig::default();
    if let Some(b) = get_bool(table, "enabled")? {
        cfg.enabled = b;
    }
    if let Some(n) = get_int_in_range(table, "port", PORT_RANGE)? {
        cfg.port = n;
    }
    if let Some(s) = get_str(table, "root_path")? {
        cfg.root_path = s.to_string();
    }
    Ok(cfg)
}

#[cfg(feature = "rest")]
fn parse_mcp(table: &toml_span::value::Table<'_>) -> Result<McpConfig, ConfigError> {
    check_keys(table, "mcp", &["enabled", "port", "root_path"])?;
    let mut cfg = McpConfig::default();
    if let Some(b) = get_bool(table, "enabled")? {
        cfg.enabled = b;
    }
    if let Some(n) = get_int_in_range(table, "port", PORT_RANGE)? {
        cfg.port = n;
    }
    if let Some(s) = get_str(table, "root_path")? {
        cfg.root_path = s.to_string();
    }
    Ok(cfg)
}

#[cfg(feature = "nats")]
fn parse_nats(table: &toml_span::value::Table<'_>) -> Result<NatsConfig, ConfigError> {
    check_keys(
        table,
        "nats",
        &["enabled", "url", "publish_subject", "subscribe_subject"],
    )?;
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
    let span_of = |key: &str| table.get(key).map_or_else(Span::default, |v| v.span);
    dgaard_monitor_nats::config::validate_publish_subject(&cfg.publish_subject).map_err(|e| {
        ConfigError::invalid_value("publish_subject", e, span_of("publish_subject"))
    })?;
    dgaard_monitor_nats::config::validate_subscribe_subject(&cfg.subscribe_subject).map_err(
        |e| ConfigError::invalid_value("subscribe_subject", e, span_of("subscribe_subject")),
    )?;
    Ok(cfg)
}

#[cfg(feature = "rest")]
fn parse_web(table: &toml_span::value::Table<'_>) -> Result<WebConfig, ConfigError> {
    check_keys(
        table,
        "web",
        &[
            "enabled",
            "port",
            "history_size",
            "beaconing_min_observations",
            "beaconing_cov_threshold",
        ],
    )?;
    let mut cfg = WebConfig::default();
    if let Some(b) = get_bool(table, "enabled")? {
        cfg.enabled = b;
    }
    if let Some(n) = get_int_in_range(table, "port", PORT_RANGE)? {
        cfg.port = n;
    }
    if let Some(n) = get_int_in_range(table, "history_size", HISTORY_SIZE_RANGE)? {
        cfg.history_size = n;
    }
    if let Some(n) = get_int_in_range(table, "beaconing_min_observations", MIN_OBSERVATIONS_RANGE)?
    {
        cfg.beaconing_min_observations = n;
    }
    if let Some(f) = get_positive_float(table, "beaconing_cov_threshold")? {
        cfg.beaconing_cov_threshold = f;
    }
    Ok(cfg)
}

// ---------------------------------------------------------------------------
// Config implementation
// ---------------------------------------------------------------------------

/// Sections that exist only with a cargo feature: (section, feature, compiled in).
const FEATURE_SECTIONS: [(&str, &str, bool); 7] = [
    ("tui", "tui", cfg!(feature = "tui")),
    ("server", "rest", cfg!(feature = "rest")),
    ("api", "rest", cfg!(feature = "rest")),
    ("websocket", "rest", cfg!(feature = "rest")),
    ("mcp", "rest", cfg!(feature = "rest")),
    ("web", "rest", cfg!(feature = "rest")),
    ("nats", "nats", cfg!(feature = "nats")),
];

impl Config {
    /// Parse a config file's content. Errors carry the line and column.
    pub fn parse(content: &str) -> Result<Self, ConfigError> {
        Self::parse_root(content).map_err(|e| e.locate(content))
    }

    fn parse_root(content: &str) -> Result<Self, ConfigError> {
        let mut cfg = Self::default();

        let value = toml_span::parse(content).map_err(|e| {
            let location = Location::of(content, e.span.start);
            ConfigError::Parse(format!("{e}{}", at(&Some(location))))
        })?;

        let root = match value.as_ref() {
            ValueInner::Table(t) => t,
            _ => return Err(ConfigError::invalid_type("root", "table", value.span)),
        };

        for key in root.keys() {
            let name = key.name.as_ref();
            if let Some((_, feature, enabled)) = FEATURE_SECTIONS
                .iter()
                .find(|(section, _, _)| *section == name)
            {
                if !enabled {
                    cfg.warnings.push(format!(
                        "section [{name}] ignored: this binary was built without the `{feature}` feature"
                    ));
                }
            } else if !["input", "persistence", "forwarding", "stats"].contains(&name) {
                return Err(ConfigError::UnknownKey {
                    key: name.to_string(),
                    span: key.span,
                    location: None,
                });
            }
        }

        if let Some(t) = get_table(root, "input")? {
            cfg.input = parse_input(t)?;
        }
        if let Some(t) = get_table(root, "stats")? {
            cfg.stats = parse_stats(t)?;
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

    /// Events to keep in the sliding window: none unless a REST service
    /// that reads it (API, MCP, web UI) is enabled.
    pub fn window_capacity(&self) -> usize {
        #[cfg(feature = "rest")]
        let has_reader = self.api.enabled || self.mcp.enabled || self.web.enabled;
        #[cfg(not(feature = "rest"))]
        let has_reader = false;
        if has_reader {
            self.stats.max_window_events
        } else {
            0
        }
    }

    pub fn load(path: &str) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)?;
        Self::parse(&content)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse `content` and return the error, panicking if it parses.
    fn parse_err(content: &str) -> ConfigError {
        match Config::parse(content) {
            Ok(cfg) => panic!("expected an error, parsed {cfg:?}"),
            Err(e) => e,
        }
    }

    // --- Ranges ---

    /// Regression: negative retention used to be clamped to 0 silently.
    #[test]
    fn negative_retention_is_rejected() {
        let err = parse_err("[persistence]\nevents_retention_hours = -1\n");
        assert!(matches!(err, ConfigError::InvalidValue { .. }), "{err}");
        let err = parse_err("[persistence]\naggregates_retention_days = 4294967296\n");
        assert!(matches!(err, ConfigError::InvalidValue { .. }), "{err}");
    }

    #[test]
    fn retention_accepts_its_full_range() {
        let cfg = Config::parse(
            "[persistence]\nevents_retention_hours = 0\naggregates_retention_days = 4294967295\n",
        )
        .unwrap();
        assert_eq!(cfg.persistence.events_retention_hours, 0);
        assert_eq!(cfg.persistence.aggregates_retention_days, u32::MAX);
    }

    /// Regression: `port = 70000` used to wrap to 4464 and `-1` to 65535.
    #[cfg(feature = "rest")]
    #[test]
    fn out_of_range_ports_are_rejected() {
        for section in ["api", "websocket", "mcp", "web"] {
            for port in ["70000", "65536", "0", "-1"] {
                let err = parse_err(&format!("[{section}]\nport = {port}\n"));
                assert!(
                    matches!(err, ConfigError::InvalidValue { .. }),
                    "[{section}] port = {port}: {err}"
                );
            }
            let cfg = Config::parse(&format!("[{section}]\nport = 65535\n")).unwrap();
            let port = match section {
                "api" => cfg.api.port,
                "websocket" => cfg.websocket.port,
                "mcp" => cfg.mcp.port,
                _ => cfg.web.port,
            };
            assert_eq!(port, 65535);
        }
    }

    /// Regression: `tick_ms = 0` made the TUI panic in `tokio::time::interval`.
    #[cfg(feature = "tui")]
    #[test]
    fn zero_or_negative_tick_is_rejected() {
        for tick in ["0", "-5", "9", "60001"] {
            let err = parse_err(&format!("[tui]\ntick_ms = {tick}\n"));
            assert!(
                matches!(err, ConfigError::InvalidValue { .. }),
                "{tick}: {err}"
            );
        }
        assert_eq!(
            Config::parse("[tui]\ntick_ms = 10\n").unwrap().tui.tick_ms,
            10
        );
    }

    #[cfg(feature = "rest")]
    #[test]
    fn web_sizes_and_threshold_are_validated() {
        for bad in [
            "history_size = -1",
            "history_size = 0",
            "beaconing_min_observations = -3",
            "beaconing_min_observations = 1",
            "beaconing_cov_threshold = nan",
            "beaconing_cov_threshold = inf",
            "beaconing_cov_threshold = 0.0",
            "beaconing_cov_threshold = -0.5",
        ] {
            let err = parse_err(&format!("[web]\n{bad}\n"));
            assert!(
                matches!(err, ConfigError::InvalidValue { .. }),
                "{bad}: {err}"
            );
        }
    }

    #[test]
    fn wrong_type_is_still_an_invalid_type() {
        let err = parse_err("[persistence]\nevents_retention_hours = \"72\"\n");
        assert!(matches!(err, ConfigError::InvalidType { .. }), "{err}");
    }

    #[test]
    fn event_buffer_defaults_and_range() {
        assert_eq!(
            Config::default().input.event_buffer,
            dgaard_monitor_core::state::DEFAULT_EVENT_BUFFER
        );
        assert_eq!(
            Config::parse("[input]\nevent_buffer = 65536\n")
                .unwrap()
                .input
                .event_buffer,
            65_536
        );
        for bad in ["255", "65537", "-1"] {
            let err = parse_err(&format!("[input]\nevent_buffer = {bad}\n"));
            assert!(
                matches!(err, ConfigError::InvalidValue { .. }),
                "{bad}: {err}"
            );
        }
    }

    #[test]
    fn stats_defaults_and_ranges() {
        let cfg = Config::default();
        assert_eq!(cfg.stats.window_secs, 3600);
        assert_eq!(cfg.stats.max_window_events, 200_000);

        let cfg = Config::parse("[stats]\nwindow_secs = 600\nmax_window_events = 0\n").unwrap();
        assert_eq!(cfg.stats.window_secs, 600);
        assert_eq!(cfg.stats.max_window_events, 0);

        for bad in [
            "window_secs = 59",
            "window_secs = 86401",
            "max_window_events = -1",
            "max_window_events = 10000001",
        ] {
            let err = parse_err(&format!("[stats]\n{bad}\n"));
            assert!(
                matches!(err, ConfigError::InvalidValue { .. }),
                "{bad}: {err}"
            );
        }
        let err = parse_err("[stats]\nwindow = 60\n");
        assert!(matches!(err, ConfigError::UnknownKey { .. }), "{err}");
    }

    /// Without a REST service reading it, the window keeps nothing.
    #[test]
    fn window_is_kept_only_for_a_reader() {
        let cfg = Config::default();
        assert_eq!(cfg.window_capacity(), 0);
    }

    #[cfg(feature = "rest")]
    #[test]
    fn each_rest_reader_enables_the_window() {
        for section in ["api", "mcp", "web"] {
            let cfg = Config::parse(&format!(
                "[{section}]\nenabled = true\n[stats]\nmax_window_events = 1234\n"
            ))
            .unwrap();
            assert_eq!(cfg.window_capacity(), 1234, "[{section}]");
        }
        // The WebSocket stream reads live events, not the window.
        let cfg = Config::parse("[websocket]\nenabled = true\n").unwrap();
        assert_eq!(cfg.window_capacity(), 0);
    }

    #[test]
    fn peer_uid_is_optional_and_range_checked() {
        assert_eq!(Config::default().input.peer_uid, None);
        let cfg = Config::parse("[input]\npeer_uid = 997\n").unwrap();
        assert_eq!(cfg.input.peer_uid, Some(997));
        for bad in ["-1", "4294967296"] {
            let err = parse_err(&format!("[input]\npeer_uid = {bad}\n"));
            assert!(
                matches!(err, ConfigError::InvalidValue { .. }),
                "{bad}: {err}"
            );
        }
    }

    // --- Unknown keys and sections ---

    /// Regression: a typo like `[persistence]` fell back to the defaults.
    #[test]
    fn unknown_section_is_rejected() {
        let err = parse_err("[persistance]\ndb = \"/tmp/x.sqlite\"\n");
        match err {
            ConfigError::UnknownKey { key, .. } => assert_eq!(key, "persistance"),
            other => panic!("expected UnknownKey, got {other}"),
        }
    }

    #[test]
    fn unknown_key_in_section_is_rejected() {
        let err = parse_err("[persistence]\nevents_retention_hour = 24\n");
        match err {
            ConfigError::UnknownKey { key, .. } => {
                assert_eq!(key, "persistence.events_retention_hour");
            }
            other => panic!("expected UnknownKey, got {other}"),
        }
        let err = parse_err("[forwarding]\nfilters = [\"Blocked\"]\n");
        assert!(matches!(err, ConfigError::UnknownKey { .. }), "{err}");
    }

    #[test]
    fn known_sections_produce_no_warning_when_compiled_in() {
        let cfg = Config::parse("[input]\n[persistence]\n[forwarding]\n").unwrap();
        assert!(cfg.warnings.is_empty(), "{:?}", cfg.warnings);
    }

    /// A section for a feature this binary lacks is reported, not silently
    /// ignored (and not an error: packagers write every section).
    #[cfg(not(feature = "nats"))]
    #[test]
    fn section_of_missing_feature_is_a_warning() {
        let cfg = Config::parse("[nats]\nenabled = true\n").unwrap();
        assert_eq!(cfg.warnings.len(), 1);
        assert!(cfg.warnings[0].contains("[nats]"), "{:?}", cfg.warnings);
        assert!(
            cfg.warnings[0].contains("`nats` feature"),
            "{:?}",
            cfg.warnings
        );
    }

    #[cfg(feature = "nats")]
    #[test]
    fn section_of_compiled_feature_is_no_warning() {
        let cfg = Config::parse("[nats]\nenabled = true\n").unwrap();
        assert!(cfg.warnings.is_empty(), "{:?}", cfg.warnings);
    }

    // --- forwarding.filter ---

    /// Regression: `"blocked"` was accepted but never matched anything.
    #[test]
    fn filter_is_case_insensitive_and_canonicalized() {
        let cfg = Config::parse(
            "[forwarding]\nfilter = [\"blocked\", \"HIGHLYSUSPICIOUS\", \"override\", \"DnssecBogus\"]\n",
        )
        .unwrap();
        assert_eq!(
            cfg.forwarding.filter,
            ["Blocked", "HighlySuspicious", "Override", "DnssecBogus"]
        );
    }

    #[test]
    fn unknown_filter_action_is_rejected() {
        let err = parse_err("[forwarding]\nfilter = [\"Blocked\", \"Blockd\"]\n");
        let message = err.to_string();
        assert!(matches!(err, ConfigError::InvalidValue { .. }), "{message}");
        assert!(message.contains("'Blockd'"), "{message}");
        assert!(message.contains("UpstreamError"), "{message}");
    }

    // --- Error locations ---

    #[test]
    fn errors_report_line_and_column() {
        let err =
            parse_err("[input]\nsocket = \"/s\"\n\n[persistence]\n  events_retention_hours = -1\n");
        assert!(err.to_string().ends_with("at line 5, column 28"), "{err}");
        let err = parse_err("[input]\nsockett = \"/s\"\n");
        assert!(err.to_string().ends_with("at line 2, column 1"), "{err}");
    }

    #[test]
    fn syntax_errors_report_line_and_column() {
        let err = parse_err("[input]\nsocket = \n");
        let message = err.to_string();
        assert!(matches!(err, ConfigError::Parse(_)), "{message}");
        assert!(message.contains("at line 2"), "{message}");
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
        assert_eq!(cfg.input.index, "/var/dgaard/host_mapping.bin");
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

    /// Regression: the monitor looked for the index at /var/lib/dns/hosts.bin
    /// while dgaard writes /var/dgaard/host_mapping.bin by default. Both
    /// default paths must keep matching dgaard's.
    #[test]
    fn default_paths_match_dgaard() {
        let dgaard = dgaard_engine::Config::default();
        let monitor = Config::default();
        assert_eq!(monitor.input.socket, dgaard.server.stats_socket_path);
        assert_eq!(monitor.input.index, dgaard.sources.host_index_path);
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

    #[cfg(feature = "tui")]
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

    #[cfg(feature = "tui")]
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

    #[cfg(feature = "rest")]
    #[test]
    fn test_server_defaults() {
        let f = write_temp("[input]\n");
        let cfg = Config::load(f.path().to_str().unwrap()).unwrap();
        assert_eq!(cfg.server.listen, "127.0.0.1");
        assert_eq!(cfg.server.token, "changeme");
    }

    #[cfg(feature = "rest")]
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

    #[cfg(feature = "rest")]
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

    #[cfg(feature = "rest")]
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

    #[cfg(feature = "rest")]
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

    #[cfg(feature = "rest")]
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

    #[cfg(feature = "rest")]
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

    /// Regression: a wildcard or space in `publish_subject` made every
    /// publication fail at runtime, with one log line per event.
    #[cfg(feature = "nats")]
    #[test]
    fn test_nats_invalid_subjects_are_rejected() {
        for (key, subject) in [
            ("publish_subject", "dgaard.*"),
            ("publish_subject", "dgaard events"),
            ("subscribe_subject", "dgaard.>.events"),
            ("subscribe_subject", "a..b"),
        ] {
            let err = parse_err(&format!("[nats]\n{key} = \"{subject}\"\n"));
            let message = err.to_string();
            assert!(matches!(err, ConfigError::InvalidValue { .. }), "{message}");
            assert!(
                message.contains(key) && message.contains("line 2"),
                "{message}"
            );
        }
        let cfg = Config::parse("[nats]\nsubscribe_subject = \"dgaard.>\"\n").unwrap();
        assert_eq!(cfg.nats.subscribe_subject, "dgaard.>");
    }

    #[cfg(feature = "nats")]
    #[test]
    fn test_nats_invalid_type_is_rejected() {
        let f = write_temp("[nats]\nenabled = 1\n");
        let result = Config::load(f.path().to_str().unwrap());
        assert!(matches!(result, Err(ConfigError::InvalidType { .. })));
    }

    /// The web configurator's generated monitor configs must load with this
    /// (strict) parser; dgaard-engine has the same check for its own file.
    #[test]
    fn configurator_golden_files_parse() {
        for (name, golden) in [
            (
                "default",
                include_str!(
                    "../../dgaard-web-configurator/tests/golden/dgaard-monitor.default.annotated.toml"
                ),
            ),
            (
                "populated",
                include_str!(
                    "../../dgaard-web-configurator/tests/golden/dgaard-monitor.populated.annotated.toml"
                ),
            ),
        ] {
            if let Err(e) = Config::parse(golden) {
                panic!("configurator {name} golden does not parse: {e}");
            }
        }
    }

    // --- Example file ---

    /// Lock the shipped example TOML to the parser: any drift between
    /// `dgaard-monitor.example.toml` and the section/field schema fails CI.
    #[cfg(feature = "rest")]
    #[test]
    fn example_file_parses_and_matches_defaults() {
        let example = include_str!("../dgaard-monitor.example.toml");
        let cfg = Config::parse(example).expect("example file must parse");
        // Only a section for a feature this build lacks may warn.
        assert!(
            cfg.warnings
                .iter()
                .all(|w| w.contains("[nats]") && !cfg!(feature = "nats")),
            "{:?}",
            cfg.warnings
        );

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
