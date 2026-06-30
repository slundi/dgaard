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
