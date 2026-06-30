// REST umbrella configuration: one shared listener address + token, plus a
// per-module section that toggles each axum-mounted endpoint independently.
// Each module currently binds its own port; merging onto a single listener
// is a follow-up (roadmap step 6).

/// Shared connectivity settings inherited by every REST module
/// (`[api]`, `[websocket]`, `[mcp]`, `[web]`).
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub listen: String,
    /// Static bearer token required on every authenticated request.
    pub token: String,
}

fn default_listen() -> String {
    "127.0.0.1".to_string()
}

fn default_token() -> String {
    "changeme".to_string()
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            token: default_token(),
        }
    }
}

/// `[api]` — REST endpoints.
#[derive(Debug, Clone)]
pub struct ApiConfig {
    pub enabled: bool,
    pub port: u16,
    pub root_path: String,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            port: 8080,
            root_path: "/api/v1".to_string(),
        }
    }
}

/// `[websocket]` — live event stream.
#[derive(Debug, Clone)]
pub struct WebSocketConfig {
    pub enabled: bool,
    pub port: u16,
    pub root_path: String,
}

impl Default for WebSocketConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            port: 8081,
            root_path: "/ws".to_string(),
        }
    }
}

/// `[mcp]` — Model Context Protocol endpoint.
#[derive(Debug, Clone)]
pub struct McpConfig {
    pub enabled: bool,
    pub port: u16,
    pub root_path: String,
}

impl Default for McpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            port: 8082,
            root_path: "/mcp".to_string(),
        }
    }
}

/// `[web]` — embedded SPA + supporting endpoints. Mounted at `/`.
#[derive(Debug, Clone)]
pub struct WebConfig {
    pub enabled: bool,
    pub port: u16,
    pub history_size: usize,
    /// Minimum number of queries from a single client to the same domain
    /// before the pair is eligible for beaconing analysis.
    pub beaconing_min_observations: usize,
    /// Coefficient of Variation threshold (std_dev / mean of inter-arrival
    /// times).  Pairs with CoV below this value are flagged as potential
    /// beacons.  Lower = stricter.
    pub beaconing_cov_threshold: f64,
}

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            port: 8083,
            history_size: 1000,
            beaconing_min_observations: 5,
            beaconing_cov_threshold: 0.15,
        }
    }
}
