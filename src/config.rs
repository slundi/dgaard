use serde::Deserialize;
use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub upstream: UpstreamConfig,
    pub tld: TldConfig,
    pub dga: DgaConfig,
    pub lexical: LexicalConfig,
    pub nxdomain_hunting: NxHuntingConfig,
    pub tunneling_detection: TunnelingConfig,
    pub sources: SourcesConfig,
    pub cache: CacheConfig,
    pub memory: MemoryConfig,
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    pub listen_addr: String,
    pub allowed_networks: Vec<String>,
    pub stats_socket_path: PathBuf,
}

#[derive(Debug, Deserialize)]
pub struct UpstreamConfig {
    pub servers: Vec<String>,
    pub timeout_ms: u64,
}

#[derive(Debug, Deserialize)]
pub struct TldConfig {
    pub allow_only: Option<Vec<String>>,
    pub exclude: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct DgaConfig {
    pub enabled: bool,
    pub entropy_threshold: f32,
    pub min_length: usize,
}

#[derive(Debug, Deserialize)]
pub struct LexicalConfig {
    pub enabled: bool,
    pub consonant_ratio_threshold: f32,
    pub use_ngram_model: bool,
    pub model_path: PathBuf,
}

#[derive(Debug, Deserialize)]
pub struct NxHuntingConfig {
    pub enabled: bool,
    pub threshold: u32,
    pub window_seconds: u64,
    pub action: String,
}

#[derive(Debug, Deserialize)]
pub struct TunnelingConfig {
    pub enabled: bool,
    pub max_subdomains_per_minute: u32,
    pub max_label_length: usize,
}

#[derive(Debug, Deserialize)]
pub struct SourcesConfig {
    pub nrd_list_path: PathBuf,
    pub blacklists: Vec<PathBuf>,
    pub whitelists: Vec<PathBuf>,
}

#[derive(Debug, Deserialize)]
pub struct CacheConfig {
    pub enabled: bool,
    pub max_entries: usize,
    pub ttl_override: u32,
}

#[derive(Debug, Deserialize)]
pub struct MemoryConfig {
    pub use_bloom_filter: bool,
    pub expected_total_domains: usize,
}

impl Config {
    /// Loads and parses the TOML configuration file
    pub fn load(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }

    /// Basic validation for paths and logic
    fn validate(&self) -> Result<(), String> {
        if self.upstream.servers.is_empty() {
            return Err("At least one upstream DNS server is required".to_string());
        }

        // Ensure NRD path is defined if file exists check is needed
        if !self.sources.nrd_list_path.exists() {
            println!(
                "Warning: NRD list path {:?} does not exist yet.",
                self.sources.nrd_list_path
            );
        }

        Ok(())
    }
}
