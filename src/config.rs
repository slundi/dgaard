use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Path discovery
// ---------------------------------------------------------------------------

/// System-wide configuration path (e.g., installed via package manager).
const SYSTEM_PATH: &str = "/etc/dgaard/config.toml";

/// Local development / working-directory configuration path.
const LOCAL_PATH: &str = "dgaard.toml";

/// Resolve the configuration file path using the following priority:
///
/// 1. Explicit `--config <FILE>` CLI override — returned as-is, no existence
///    check (the caller is responsible for the path being valid).
/// 2. System path: `/etc/dgaard/config.toml`.
/// 3. Local path: `./dgaard.toml` (relative to CWD).
///
/// Returns `None` if no file is found at any location.
pub fn discover_path(override_path: Option<&str>) -> Option<PathBuf> {
    discover_from_candidates(override_path, &[SYSTEM_PATH, LOCAL_PATH])
}

/// Inner implementation that accepts an explicit candidate list so tests can
/// inject temporary paths without touching the real filesystem locations.
fn discover_from_candidates(override_path: Option<&str>, candidates: &[&str]) -> Option<PathBuf> {
    if let Some(path) = override_path {
        return Some(PathBuf::from(path));
    }

    for candidate in candidates {
        let path = Path::new(candidate);
        if path.exists() {
            return Some(path.to_path_buf());
        }
    }

    None
}

// ---------------------------------------------------------------------------
// Configuration structures
// ---------------------------------------------------------------------------

/// Controls how many worker threads the Tokio runtime spawns.
///
/// `Auto` uses the number of logical CPU cores available on the host.
/// `Count(n)` forces exactly `n` threads — useful on OpenWrt where RAM is
/// precious and the CPU is single- or dual-core.
#[derive(Debug, PartialEq)]
pub enum WorkerThreads {
    /// Use one thread per logical CPU core (recommended for desktop/server).
    Auto,
    /// Force a specific thread count (recommended for embedded targets).
    Count(usize),
}

impl Default for WorkerThreads {
    fn default() -> Self {
        Self::Auto
    }
}

/// Tokio runtime tuning parameters.
///
/// These map to `[server.runtime]` in the configuration file.
#[derive(Debug, PartialEq)]
pub struct RuntimeConfig {
    /// `"auto"` or an integer thread count.
    /// On OpenWrt, pin this to 1 or 2 to avoid over-subscribing the CPU.
    pub worker_threads: WorkerThreads,

    /// Stack size in bytes per worker thread.
    /// Reduce to `2097152` (2 MiB) on memory-constrained targets.
    pub stack_size: usize,

    /// Depth of the per-worker blocking task queue before new requests are
    /// rejected with a backpressure error.
    pub max_blocking_threads: usize,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            worker_threads: WorkerThreads::Auto,
            stack_size: 2 * 1024 * 1024, // 2 MiB
            max_blocking_threads: 512,
        }
    }
}

/// Ordered list of processing stages executed for every DNS query.
///
/// The pipeline runs left-to-right; the first stage that produces a definitive
/// verdict (`Allow` or `Block`) short-circuits the remaining stages.
#[derive(Debug, Clone, PartialEq)]
pub enum PipelineStep {
    /// Instant pass — domain is on the personal / CDN whitelist.
    Whitelist,
    /// In-process LRU cache hit — avoids upstream round-trip.
    HotCache,
    /// Exact-match lookup against the compiled blocklist (rkyv / XXH3).
    StaticBlock,
    /// Wildcard / suffix match using a Finite State Transducer.
    SuffixMatch,
    /// DGA detection: Shannon entropy, N-gram, consonant clustering.
    Heuristics,
    /// Forward clean queries to the configured upstream resolver.
    Upstream,
}

/// Top-level server configuration.
///
/// Maps to `[server]` in the configuration file.
#[derive(Debug)]
pub struct ServerConfig {
    /// Socket address (`ip:port`) on which the DNS proxy listens.
    /// Use port 53 for production; an unprivileged port for development.
    pub listen_addr: String,

    /// CIDR ranges whose queries are accepted.
    /// Queries from addresses outside this list are silently dropped.
    pub allowed_networks: Vec<String>,

    /// Filesystem path of the Unix-domain socket used to stream telemetry
    /// to the dashboard / TUI.
    pub stats_socket_path: String,

    /// When `true`, domains that contain non-ASCII (Punycode / IDN) labels
    /// are blocked before any other filter runs.
    /// Must be `false` to enable fine-grained IDN filtering via
    /// [`IdnConfig`].
    pub block_idn: bool,

    /// Ordered sequence of processing stages applied to every query.
    pub pipeline: Vec<PipelineStep>,

    /// Tokio runtime tuning parameters.
    pub runtime: RuntimeConfig,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: String::from("127.0.0.1:53"),
            allowed_networks: vec![
                String::from("127.0.0.1/32"),
                String::from("192.168.1.0/24"),
            ],
            stats_socket_path: String::from("/tmp/dgaard_stats.sock"),
            block_idn: true,
            pipeline: vec![
                PipelineStep::Whitelist,
                PipelineStep::HotCache,
                PipelineStep::StaticBlock,
                PipelineStep::SuffixMatch,
                PipelineStep::Heuristics,
                PipelineStep::Upstream,
            ],
            runtime: RuntimeConfig::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// [security.structure]
// ---------------------------------------------------------------------------

/// Structural / syntactic sanity checks applied to every query label.
///
/// These are the cheapest filters in the pipeline (no allocations, O(1)) and
/// run first to drop obviously malformed or tunneling traffic early.
///
/// Maps to `[security.structure]` in the configuration file.
#[derive(Debug, PartialEq)]
pub struct StructureConfig {
    /// Maximum number of dot-separated labels in the FQDN.
    /// Domains deeper than this are characteristic of DNS-tunnel payloads
    /// (e.g., `data.part1.bin.zone.attacker.com`).
    pub max_subdomain_depth: u8,

    /// Maximum total length of the FQDN in bytes.
    /// RFC 1035 allows up to 253 characters; tighten this for embedded use.
    pub max_domain_length: u16,

    /// Reject queries whose labels contain characters outside `[a-z0-9.\-_]`.
    /// When `true`, Punycode / IDN labels are also rejected unless
    /// [`ServerConfig::block_idn`] is `false` and [`IdnConfig`] is
    /// configured.
    pub force_lowercase_ascii: bool,

    /// Maximum byte-length of a single TXT record value.
    /// Legitimate SPF / DKIM records are typically < 200 bytes; DNS exfiltration
    /// tools exploit the 255-byte maximum.
    pub max_txt_record_length: u16,

    /// Block responses that contain more answer records than this threshold.
    /// Excessive records in a single response are unusual and may indicate
    /// exfiltration.
    pub max_answers_per_query: u8,
}

impl Default for StructureConfig {
    fn default() -> Self {
        Self {
            max_subdomain_depth: 5,
            max_domain_length: 128,
            force_lowercase_ascii: true,
            max_txt_record_length: 128,
            max_answers_per_query: 10,
        }
    }
}

// ---------------------------------------------------------------------------
// [security.intelligence]
// ---------------------------------------------------------------------------

/// Lexical / statistical analysis of domain names (the "Brain").
///
/// Detects Algorithmically Generated Domains (DGAs) and other machine-crafted
/// names that evade blocklist-only defences.
///
/// Maps to `[security.intelligence]` in the configuration file.
#[derive(Debug, PartialEq)]
pub struct IntelligenceConfig {
    /// Master switch — set to `false` to skip all heuristic checks and rely
    /// solely on static lists.
    pub enabled: bool,

    /// Shannon entropy threshold for the second-level domain (SLD).
    /// Values above this are flagged as potential DGA names.
    /// Typical range: 3.5 (strict) – 4.5 (lenient). Default: 4.0.
    pub entropy_threshold: f64,

    /// Minimum SLD length (in bytes) before entropy and N-gram analysis are
    /// applied.  Short labels like `t.co` are skipped to avoid false positives.
    pub min_word_length: usize,

    /// Maximum ratio of consonants to total characters before a label is
    /// considered unpronounceable / machine-generated (e.g., `bcdfgh`).
    pub consonant_ratio_threshold: f64,

    /// Enable N-gram language-model scoring.  When `true`, each domain is
    /// scored against every model in [`ngram_models`]; if all scores fall
    /// below [`ngram_probability_threshold`] the domain is blocked.
    pub use_ngram_model: bool,

    /// Paths to pre-computed binary N-gram model files.
    /// One file per language (e.g., `english.bin`, `french.bin`).
    pub ngram_models: Vec<String>,

    /// Minimum acceptable N-gram log-probability.  A domain must score above
    /// this value in **at least one** loaded model to pass.
    pub ngram_probability_threshold: f64,
}

impl Default for IntelligenceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            entropy_threshold: 4.0,
            min_word_length: 8,
            consonant_ratio_threshold: 0.6,
            use_ngram_model: false,
            ngram_models: vec![
                String::from("/etc/dgaard/models/english.bin"),
                String::from("/etc/dgaard/models/french.bin"),
            ],
            ngram_probability_threshold: 0.05,
        }
    }
}

// ---------------------------------------------------------------------------
// [security.idn]
// ---------------------------------------------------------------------------

/// Internationalized Domain Name (IDN) filtering policy.
///
/// `force_lowercase_ascii` in [`StructureConfig`] must be `false` for this
/// filter to receive any traffic.
#[derive(Debug, PartialEq)]
pub enum IdnMode {
    /// IDN filtering is disabled; all Unicode labels pass through.
    Off,
    /// Block every non-ASCII label unconditionally (recommended for embedded
    /// deployments with no multilingual users).
    Strict,
    /// Allow scripts listed in [`IdnConfig::allowed_scripts`] and block the
    /// rest.  Balances security with usability for European users.
    Smart,
}

impl Default for IdnMode {
    fn default() -> Self {
        Self::Smart
    }
}

/// Fine-grained Internationalized Domain Name policy.
///
/// Maps to `[security.idn]` in the configuration file.
#[derive(Debug, PartialEq)]
pub struct IdnConfig {
    /// Filtering mode — see [`IdnMode`] for semantics.
    pub mode: IdnMode,

    /// Unicode script identifiers that are permitted in `Smart` mode.
    /// Labels using any other script are blocked.
    /// Example: `["Latin", "WesternEuropean"]`.
    pub allowed_scripts: Vec<String>,
}

impl Default for IdnConfig {
    fn default() -> Self {
        Self {
            mode: IdnMode::Smart,
            allowed_scripts: vec![
                String::from("Latin"),
                String::from("WesternEuropean"),
            ],
        }
    }
}

// ---------------------------------------------------------------------------
// [security.behavior]
// ---------------------------------------------------------------------------

/// Client-level behavioural anomaly detection.
///
/// These counters are maintained per source IP and reset on a sliding window.
/// They detect infected hosts exhibiting botnet / C2 scanning patterns.
///
/// Maps to `[security.behavior]` in the configuration file.
#[derive(Debug, PartialEq)]
pub struct BehaviorConfig {
    /// Number of NXDOMAIN responses a single client may receive within
    /// [`nxdomain_window`] seconds before being flagged as a potential
    /// botnet scanner.
    pub nxdomain_threshold: u32,

    /// Sliding window duration in seconds for the NXDOMAIN counter.
    pub nxdomain_window: u32,

    /// Maximum number of distinct subdomains under a single SLD that a client
    /// may query within one minute before being suspected of DNS exfiltration.
    pub max_subdomains_per_minute: u32,

    /// Maximum byte-length of a single DNS label (dot-delimited segment).
    /// Base64-encoded payloads in tunnel traffic produce very long labels.
    pub max_label_length: u8,
}

impl Default for BehaviorConfig {
    fn default() -> Self {
        Self {
            nxdomain_threshold: 15,
            nxdomain_window: 60,
            max_subdomains_per_minute: 50,
            max_label_length: 60,
        }
    }
}

// ---------------------------------------------------------------------------
// [security]
// ---------------------------------------------------------------------------

/// Aggregated security sub-configuration.
///
/// Maps to the `[security.*]` family of sections in the configuration file.
#[derive(Debug, PartialEq)]
pub struct SecurityConfig {
    /// Structural / syntactic label validation.
    pub structure: StructureConfig,
    /// Heuristic DGA and lexical analysis.
    pub intelligence: IntelligenceConfig,
    /// Internationalized domain name policy.
    pub idn: IdnConfig,
    /// Per-client behavioural anomaly thresholds.
    pub behavior: BehaviorConfig,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            structure: StructureConfig::default(),
            intelligence: IntelligenceConfig::default(),
            idn: IdnConfig::default(),
            behavior: BehaviorConfig::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// [upstream]
// ---------------------------------------------------------------------------

/// Upstream resolver configuration.
///
/// Clean queries that pass all filters are forwarded to one of these servers.
/// Maps to `[upstream]` in the configuration file.
#[derive(Debug, PartialEq)]
pub struct UpstreamConfig {
    /// Ordered list of resolver addresses in `ip:port` format.
    /// Supports both plain UDP (`:53`) and DNS-over-HTTPS addresses.
    pub servers: Vec<String>,

    /// Per-query timeout in milliseconds.  Queries unanswered within this
    /// window are retried on the next server in the list.
    pub timeout_ms: u64,
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        Self {
            servers: vec![
                String::from("1.1.1.1:53"),
                String::from("9.9.9.9:53"),
            ],
            timeout_ms: 2000,
        }
    }
}

// ---------------------------------------------------------------------------
// [tld]
// ---------------------------------------------------------------------------

/// Top-Level Domain (TLD) filtering rules.
///
/// Maps to `[tld]` in the configuration file.
#[derive(Debug, PartialEq, Default)]
pub struct TldConfig {
    /// If non-empty, **only** these TLDs are resolved; all others are blocked.
    /// Leave empty to allow all TLDs (then use `exclude` for targeted blocks).
    /// Example: `[".com", ".net", ".org", ".io"]`.
    pub allow_only: Vec<String>,

    /// TLDs that are always blocked regardless of other filters.
    /// Populated with high-risk TLDs commonly abused by malware and DGA
    /// operators.
    pub exclude: Vec<String>,
}

// ---------------------------------------------------------------------------
// [nxdomain_hunting]
// ---------------------------------------------------------------------------

/// Action taken when a client trips the NXDOMAIN threshold.
#[derive(Debug, PartialEq)]
pub enum NxdomainAction {
    /// Record the event in the structured log; do not block the client.
    Log,
    /// Insert a firewall rule to drop all traffic from the offending client
    /// IP for the remainder of the detection window.
    BlockClient,
}

impl Default for NxdomainAction {
    fn default() -> Self {
        Self::Log
    }
}

/// NXDOMAIN hunting — detects botnet C2 beacon scanning.
///
/// Maps to `[nxdomain_hunting]` in the configuration file.
///
/// Note: overlaps with [`BehaviorConfig`]; the top-level section is
/// intended for operators who prefer a flat configuration layout.
#[derive(Debug, PartialEq)]
pub struct NxdomainHuntingConfig {
    /// Enable or disable NXDOMAIN hunting entirely.
    pub enabled: bool,

    /// Number of NXDOMAIN responses within [`window_seconds`] that triggers
    /// the configured [`action`].
    pub threshold: u32,

    /// Sliding-window duration in seconds.
    pub window_seconds: u32,

    /// What to do when a client crosses the threshold.
    pub action: NxdomainAction,
}

impl Default for NxdomainHuntingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            threshold: 15,
            window_seconds: 60,
            action: NxdomainAction::Log,
        }
    }
}

// ---------------------------------------------------------------------------
// [tunneling_detection]
// ---------------------------------------------------------------------------

/// DNS tunneling / exfiltration detection.
///
/// Monitors the rate and structure of subdomains to detect covert channels
/// that encode data in DNS labels (e.g., `aGVsbG8=.attacker.com`).
///
/// Maps to `[tunneling_detection]` in the configuration file.
#[derive(Debug, PartialEq)]
pub struct TunnelingDetectionConfig {
    /// Enable or disable tunneling detection entirely.
    pub enabled: bool,

    /// Maximum number of unique subdomains under a single SLD that any client
    /// may query within a 60-second window.
    pub max_subdomains_per_minute: u32,

    /// Maximum byte-length of a single DNS label.  Base64 / hex-encoded
    /// payloads typically produce labels much longer than legitimate names.
    pub max_label_length: u8,
}

impl Default for TunnelingDetectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_subdomains_per_minute: 50,
            max_label_length: 60,
        }
    }
}

// ---------------------------------------------------------------------------
// [sources]
// ---------------------------------------------------------------------------

/// File-based domain list sources.
///
/// Dgaard refreshes these lists on the configured schedule and compiles them
/// into the in-memory data structures (rkyv / Bloom filter).
///
/// Maps to `[sources]` in the configuration file.
#[derive(Debug, PartialEq)]
pub struct SourcesConfig {
    /// Path to the Newly Registered Domains (NRD) plain-text file.
    /// Should be refreshed daily via cron.
    pub nrd_list_path: String,

    /// Paths to plain-text blocklist files (one domain per line, hosts format
    /// or bare domain format — both are supported).
    pub blacklists: Vec<String>,

    /// Paths to plain-text whitelist files.  Entries here override **all**
    /// other filters, including heuristics.
    pub whitelists: Vec<String>,

    /// How often (in hours) the list files are re-fetched from their source.
    pub update_interval_hours: u32,

    /// How long (in minutes) to wait before retrying after a failed download.
    pub retry_delay_mins: u32,
}

impl Default for SourcesConfig {
    fn default() -> Self {
        Self {
            nrd_list_path: String::from("/tmp/nrd_daily.txt"),
            blacklists: vec![
                String::from("/etc/dgaard/lists/adaway.txt"),
                String::from("/etc/dgaard/lists/malware_domains.txt"),
            ],
            whitelists: vec![
                String::from("/etc/dgaard/lists/personal_whitelist.txt"),
                String::from("/etc/dgaard/lists/cdn_providers.txt"),
            ],
            update_interval_hours: 24,
            retry_delay_mins: 30,
        }
    }
}

// ---------------------------------------------------------------------------
// [abp]
// ---------------------------------------------------------------------------

/// AdBlock Plus (ABP) filter list settings.
///
/// ABP lists contain cosmetic (CSS) and network rules; Dgaard only extracts
/// the network / domain rules.
///
/// Maps to `[abp]` in the configuration file.
#[derive(Debug, PartialEq)]
pub struct AbpConfig {
    /// When `true`, only plain domain-level rules are extracted from ABP
    /// lists; complex CSS cosmetic rules are silently skipped.
    pub extract_domain_only: bool,

    /// How often (in hours) to refresh and re-compile ABP filter lists.
    pub update_interval: u32,
}

impl Default for AbpConfig {
    fn default() -> Self {
        Self {
            extract_domain_only: true,
            update_interval: 24,
        }
    }
}

// ---------------------------------------------------------------------------
// [cache]
// ---------------------------------------------------------------------------

/// DNS response cache configuration.
///
/// Caching successful upstream responses avoids redundant round-trips and
/// dramatically reduces latency for frequently queried domains.
///
/// Maps to `[cache]` in the configuration file.
#[derive(Debug, PartialEq)]
pub struct CacheConfig {
    /// Enable or disable response caching entirely.
    pub enabled: bool,

    /// Maximum number of cached entries.  When the cache is full, the
    /// least-recently-used entry is evicted.
    pub max_entries: usize,

    /// Override the DNS TTL for cached records (in seconds).
    /// `0` means use the TTL value returned by the upstream resolver.
    pub ttl_override: u32,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_entries: 10_000,
            ttl_override: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// [memory]
// ---------------------------------------------------------------------------

/// In-process memory structure tuning.
///
/// Controls the LRU hot cache and the optional Bloom filter used to avoid
/// deserializing the full rkyv blocklist for every miss.
///
/// Maps to `[memory]` in the configuration file.
#[derive(Debug, PartialEq)]
pub struct MemoryConfig {
    /// Enable the LRU hot cache for the most-frequently queried domains.
    pub cache_enabled: bool,

    /// LRU cache capacity in number of entries.
    pub cache_size: usize,

    /// Enable a Bloom filter in front of the static blocklist.
    /// The Bloom filter provides a probabilistic "quick no" that prevents
    /// the rkyv zero-copy lookup for domains that are definitely not blocked,
    /// saving CPU cycles on embedded targets.
    pub use_bloom_filter: bool,

    /// Expected total number of domains in the blocklist.
    /// Used to size the Bloom filter bit-array; under-sizing increases the
    /// false-positive rate while over-sizing wastes RAM.
    pub expected_total_domains: usize,
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            cache_enabled: true,
            cache_size: 5_000,
            use_bloom_filter: true,
            expected_total_domains: 1_000_000,
        }
    }
}

// ---------------------------------------------------------------------------
// Top-level Config
// ---------------------------------------------------------------------------

/// Complete runtime configuration for the Dgaard DNS proxy.
///
/// Every field mirrors a TOML section from `dgaard.toml` / `config.example.toml`.
/// Instantiate via [`Config::default()`] to obtain the recommended baseline
/// for an OpenWrt / embedded deployment, then override individual fields
/// before the runtime starts.
#[derive(Debug)]
pub struct Config {
    /// Networking and runtime settings.
    pub server: ServerConfig,
    /// The full security pipeline configuration.
    pub security: SecurityConfig,
    /// Upstream resolver addresses and timeout.
    pub upstream: UpstreamConfig,
    /// TLD allow/block lists.
    pub tld: TldConfig,
    /// NXDOMAIN botnet-scanner detection.
    pub nxdomain_hunting: NxdomainHuntingConfig,
    /// DNS tunneling / exfiltration detection.
    pub tunneling_detection: TunnelingDetectionConfig,
    /// File-based domain list sources and refresh schedule.
    pub sources: SourcesConfig,
    /// AdBlock Plus filter list settings.
    pub abp: AbpConfig,
    /// DNS response cache.
    pub cache: CacheConfig,
    /// In-process memory structure tuning.
    pub memory: MemoryConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            security: SecurityConfig::default(),
            upstream: UpstreamConfig::default(),
            tld: TldConfig::default(),
            nxdomain_hunting: NxdomainHuntingConfig::default(),
            tunneling_detection: TunnelingDetectionConfig::default(),
            sources: SourcesConfig::default(),
            abp: AbpConfig::default(),
            cache: CacheConfig::default(),
            memory: MemoryConfig::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::env;

    fn create_temp_dir() -> PathBuf {
        let dir = env::temp_dir().join(format!("dgaard_test_{}", std::process::id()));
        fs::create_dir_all(&dir).expect("failed to create temp dir");
        dir
    }

    fn cleanup(dir: &Path) {
        let _ = fs::remove_dir_all(dir);
    }

    // -----------------------------------------------------------------------
    // Path discovery
    // -----------------------------------------------------------------------

    #[test]
    fn explicit_override_is_returned_unconditionally() {
        let result = discover_from_candidates(Some("/custom/dgaard.toml"), &[]);
        assert_eq!(result, Some(PathBuf::from("/custom/dgaard.toml")));
    }

    #[test]
    fn explicit_override_does_not_check_existence() {
        // Even a path that does not exist must be returned when explicitly given.
        let result = discover_from_candidates(Some("/nonexistent/path.toml"), &[]);
        assert_eq!(result, Some(PathBuf::from("/nonexistent/path.toml")));
    }

    #[test]
    fn no_candidates_returns_none() {
        let result = discover_from_candidates(None, &[]);
        assert!(result.is_none());
    }

    #[test]
    fn absent_candidates_return_none() {
        let result = discover_from_candidates(None, &["/no/such/file.toml", "/also/missing.toml"]);
        assert!(result.is_none());
    }

    #[test]
    fn first_existing_candidate_is_returned() {
        let dir = create_temp_dir();
        let first = dir.join("system.toml");
        let second = dir.join("local.toml");

        fs::write(&first, "").unwrap();
        fs::write(&second, "").unwrap();

        let first_str = first.to_str().unwrap();
        let second_str = second.to_str().unwrap();

        let result = discover_from_candidates(None, &[first_str, second_str]);
        assert_eq!(result, Some(first.clone()));

        cleanup(&dir);
    }

    #[test]
    fn second_candidate_used_when_first_absent() {
        let dir = create_temp_dir();
        let missing = dir.join("missing.toml");
        let present = dir.join("local.toml");

        fs::write(&present, "").unwrap();

        let missing_str = missing.to_str().unwrap();
        let present_str = present.to_str().unwrap();

        let result = discover_from_candidates(None, &[missing_str, present_str]);
        assert_eq!(result, Some(present.clone()));

        cleanup(&dir);
    }

    #[test]
    fn override_wins_over_existing_candidate() {
        let dir = create_temp_dir();
        let candidate = dir.join("candidate.toml");
        fs::write(&candidate, "").unwrap();

        let result = discover_from_candidates(
            Some("/explicit/override.toml"),
            &[candidate.to_str().unwrap()],
        );
        assert_eq!(result, Some(PathBuf::from("/explicit/override.toml")));

        cleanup(&dir);
    }

    #[test]
    fn public_api_smoke_test() {
        // discover_path uses the real system/local paths; just ensure it doesn't panic
        // and returns the correct type. We can't control whether a file exists.
        let _result: Option<PathBuf> = discover_path(None);
        let explicit = discover_path(Some("/tmp/smoke.toml"));
        assert_eq!(explicit, Some(PathBuf::from("/tmp/smoke.toml")));
    }

    // -----------------------------------------------------------------------
    // WorkerThreads
    // -----------------------------------------------------------------------

    #[test]
    fn worker_threads_default_is_auto() {
        assert_eq!(WorkerThreads::default(), WorkerThreads::Auto);
    }

    #[test]
    fn worker_threads_count_variant() {
        let wt = WorkerThreads::Count(4);
        assert_eq!(wt, WorkerThreads::Count(4));
        assert_ne!(wt, WorkerThreads::Auto);
    }

    // -----------------------------------------------------------------------
    // RuntimeConfig
    // -----------------------------------------------------------------------

    #[test]
    fn runtime_config_defaults() {
        let rt = RuntimeConfig::default();
        assert_eq!(rt.worker_threads, WorkerThreads::Auto);
        assert_eq!(rt.stack_size, 2 * 1024 * 1024);
        assert_eq!(rt.max_blocking_threads, 512);
    }

    // -----------------------------------------------------------------------
    // PipelineStep
    // -----------------------------------------------------------------------

    #[test]
    fn default_pipeline_has_six_steps_in_order() {
        let server = ServerConfig::default();
        let expected = vec![
            PipelineStep::Whitelist,
            PipelineStep::HotCache,
            PipelineStep::StaticBlock,
            PipelineStep::SuffixMatch,
            PipelineStep::Heuristics,
            PipelineStep::Upstream,
        ];
        assert_eq!(server.pipeline, expected);
    }

    // -----------------------------------------------------------------------
    // StructureConfig
    // -----------------------------------------------------------------------

    #[test]
    fn structure_config_defaults_match_example_toml() {
        let s = StructureConfig::default();
        assert_eq!(s.max_subdomain_depth, 5);
        assert_eq!(s.max_domain_length, 128);
        assert!(s.force_lowercase_ascii);
        assert_eq!(s.max_txt_record_length, 128);
        assert_eq!(s.max_answers_per_query, 10);
    }

    // -----------------------------------------------------------------------
    // IntelligenceConfig
    // -----------------------------------------------------------------------

    #[test]
    fn intelligence_config_defaults_match_example_toml() {
        let i = IntelligenceConfig::default();
        assert!(i.enabled);
        assert!((i.entropy_threshold - 4.0).abs() < f64::EPSILON);
        assert_eq!(i.min_word_length, 8);
        assert!((i.consonant_ratio_threshold - 0.6).abs() < f64::EPSILON);
        assert!(!i.use_ngram_model);
        assert_eq!(i.ngram_models.len(), 2);
        assert!((i.ngram_probability_threshold - 0.05).abs() < f64::EPSILON);
    }

    // -----------------------------------------------------------------------
    // IdnMode & IdnConfig
    // -----------------------------------------------------------------------

    #[test]
    fn idn_mode_default_is_smart() {
        assert_eq!(IdnMode::default(), IdnMode::Smart);
    }

    #[test]
    fn idn_config_defaults() {
        let idn = IdnConfig::default();
        assert_eq!(idn.mode, IdnMode::Smart);
        assert_eq!(idn.allowed_scripts, vec!["Latin", "WesternEuropean"]);
    }

    #[test]
    fn idn_mode_variants_are_distinct() {
        assert_ne!(IdnMode::Off, IdnMode::Strict);
        assert_ne!(IdnMode::Strict, IdnMode::Smart);
        assert_ne!(IdnMode::Off, IdnMode::Smart);
    }

    // -----------------------------------------------------------------------
    // BehaviorConfig
    // -----------------------------------------------------------------------

    #[test]
    fn behavior_config_defaults_match_example_toml() {
        let b = BehaviorConfig::default();
        assert_eq!(b.nxdomain_threshold, 15);
        assert_eq!(b.nxdomain_window, 60);
        assert_eq!(b.max_subdomains_per_minute, 50);
        assert_eq!(b.max_label_length, 60);
    }

    // -----------------------------------------------------------------------
    // SecurityConfig
    // -----------------------------------------------------------------------

    #[test]
    fn security_config_composes_sub_configs() {
        let sec = SecurityConfig::default();
        assert_eq!(sec.structure, StructureConfig::default());
        assert_eq!(sec.intelligence, IntelligenceConfig::default());
        assert_eq!(sec.idn, IdnConfig::default());
        assert_eq!(sec.behavior, BehaviorConfig::default());
    }

    // -----------------------------------------------------------------------
    // UpstreamConfig
    // -----------------------------------------------------------------------

    #[test]
    fn upstream_config_defaults_match_example_toml() {
        let u = UpstreamConfig::default();
        assert_eq!(u.servers, vec!["1.1.1.1:53", "9.9.9.9:53"]);
        assert_eq!(u.timeout_ms, 2000);
    }

    // -----------------------------------------------------------------------
    // TldConfig
    // -----------------------------------------------------------------------

    #[test]
    fn tld_config_default_allows_all_no_exclusions() {
        let t = TldConfig::default();
        assert!(t.allow_only.is_empty());
        assert!(t.exclude.is_empty());
    }

    // -----------------------------------------------------------------------
    // NxdomainAction & NxdomainHuntingConfig
    // -----------------------------------------------------------------------

    #[test]
    fn nxdomain_action_default_is_log() {
        assert_eq!(NxdomainAction::default(), NxdomainAction::Log);
    }

    #[test]
    fn nxdomain_hunting_defaults_match_example_toml() {
        let nx = NxdomainHuntingConfig::default();
        assert!(nx.enabled);
        assert_eq!(nx.threshold, 15);
        assert_eq!(nx.window_seconds, 60);
        assert_eq!(nx.action, NxdomainAction::Log);
    }

    // -----------------------------------------------------------------------
    // TunnelingDetectionConfig
    // -----------------------------------------------------------------------

    #[test]
    fn tunneling_detection_defaults_match_example_toml() {
        let td = TunnelingDetectionConfig::default();
        assert!(td.enabled);
        assert_eq!(td.max_subdomains_per_minute, 50);
        assert_eq!(td.max_label_length, 60);
    }

    // -----------------------------------------------------------------------
    // SourcesConfig
    // -----------------------------------------------------------------------

    #[test]
    fn sources_config_defaults_match_example_toml() {
        let s = SourcesConfig::default();
        assert_eq!(s.nrd_list_path, "/tmp/nrd_daily.txt");
        assert_eq!(s.blacklists.len(), 2);
        assert_eq!(s.whitelists.len(), 2);
        assert_eq!(s.update_interval_hours, 24);
        assert_eq!(s.retry_delay_mins, 30);
    }

    // -----------------------------------------------------------------------
    // AbpConfig
    // -----------------------------------------------------------------------

    #[test]
    fn abp_config_defaults_match_example_toml() {
        let a = AbpConfig::default();
        assert!(a.extract_domain_only);
        assert_eq!(a.update_interval, 24);
    }

    // -----------------------------------------------------------------------
    // CacheConfig
    // -----------------------------------------------------------------------

    #[test]
    fn cache_config_defaults_match_example_toml() {
        let c = CacheConfig::default();
        assert!(c.enabled);
        assert_eq!(c.max_entries, 10_000);
        assert_eq!(c.ttl_override, 0);
    }

    // -----------------------------------------------------------------------
    // MemoryConfig
    // -----------------------------------------------------------------------

    #[test]
    fn memory_config_defaults_match_example_toml() {
        let m = MemoryConfig::default();
        assert!(m.cache_enabled);
        assert_eq!(m.cache_size, 5_000);
        assert!(m.use_bloom_filter);
        assert_eq!(m.expected_total_domains, 1_000_000);
    }

    // -----------------------------------------------------------------------
    // Top-level Config
    // -----------------------------------------------------------------------

    #[test]
    fn config_default_constructs_without_panic() {
        let _cfg = Config::default();
    }

    #[test]
    fn config_default_server_listen_addr_is_loopback() {
        let cfg = Config::default();
        assert!(cfg.server.listen_addr.starts_with("127.0.0.1"));
    }

    #[test]
    fn config_default_security_intelligence_enabled() {
        let cfg = Config::default();
        assert!(cfg.security.intelligence.enabled);
    }

    #[test]
    fn config_default_cache_and_memory_enabled() {
        let cfg = Config::default();
        assert!(cfg.cache.enabled);
        assert!(cfg.memory.cache_enabled);
        assert!(cfg.memory.use_bloom_filter);
    }
}
