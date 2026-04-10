//! Configuration model types for Dgaard DNS proxy.
//!
//! All structures have sensible defaults for OpenWrt / embedded deployment.

// ---------------------------------------------------------------------------
// [server.runtime]
// ---------------------------------------------------------------------------

/// Controls how many worker threads the Tokio runtime spawns.
///
/// `Auto` uses the number of logical CPU cores available on the host.
/// `Count(n)` forces exactly `n` threads — useful on OpenWrt where RAM is
/// precious and the CPU is single- or dual-core.
#[derive(Debug, Default, PartialEq, Clone)]
pub enum WorkerThreads {
    /// Use one thread per logical CPU core (recommended for desktop/server).
    #[default]
    Auto,
    /// Force a specific thread count (recommended for embedded targets).
    Count(usize),
}

/// Tokio runtime tuning parameters.
///
/// These map to `[server.runtime]` in the configuration file.
#[derive(Debug, PartialEq, Clone)]
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

// ---------------------------------------------------------------------------
// [server]
// ---------------------------------------------------------------------------

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
#[derive(Debug, PartialEq, Clone)]
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
            allowed_networks: vec![String::from("127.0.0.1/32"), String::from("192.168.1.0/24")],
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
#[derive(Debug, PartialEq, Clone)]
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
#[derive(Debug, PartialEq, Clone)]
pub struct IntelligenceConfig {
    /// Master switch — set to `false` to skip all heuristic checks and rely
    /// solely on static lists.
    pub enabled: bool,

    /// Shannon entropy threshold for the second-level domain (SLD).
    /// Values above this are flagged as potential DGA names.
    /// Typical range: 3.5 (strict) – 4.5 (lenient). Default: 4.0.
    pub entropy_threshold: f32,

    /// Use the fast (ASCII-only, zero-allocation) entropy algorithm.
    /// When `true`, uses a fixed-size array for byte counting (ideal for
    /// embedded/OpenWrt targets). When `false`, uses a HashMap-based
    /// implementation with full Unicode support.
    /// Default: `true` (optimized for embedded deployment).
    pub entropy_fast: bool,

    /// Minimum SLD length (in bytes) before entropy and N-gram analysis are
    /// applied.  Short labels like `t.co` are skipped to avoid false positives.
    pub min_word_length: usize,

    /// Maximum ratio of consonants to total characters before a label is
    /// considered unpronounceable / machine-generated (e.g., `bcdfgh`).
    pub consonant_ratio_threshold: f32,

    /// Maximum consecutive consonants allowed before flagging as suspicious.
    /// Normal English words rarely exceed 4 consecutive consonants.
    /// Default: 5.
    pub max_consonant_sequence: usize,

    /// Enable N-gram language-model scoring.  When `true`, each domain is
    /// scored against every model in [`ngram_models`]; if all scores fall
    /// below [`ngram_probability_threshold`] the domain is blocked.
    pub use_ngram_model: bool,

    /// Use embedded Markov transition matrices instead of external files.
    ///
    /// When `true` (default), uses compact 26×26 character transition matrices
    /// embedded directly in the binary (~2.7 KB per language). This is the
    /// recommended mode for OpenWrt / embedded deployments as it requires no
    /// external files and has zero runtime allocation.
    ///
    /// When `false`, loads full N-gram frequency tables from the files
    /// specified in [`ngram_models`]. This mode offers higher accuracy but
    /// requires external `.bin` files (2-5 MB per language).
    pub ngram_use_embedded: bool,

    /// Languages to use for embedded N-gram scoring.
    /// Only used when [`ngram_use_embedded`] is `true`.
    /// Supported values: "english", "french", "german", "spanish", "italian".
    /// A domain passes if it scores above threshold in ANY of these languages.
    pub ngram_embedded_languages: Vec<String>,

    /// Paths to pre-computed binary N-gram model files.
    /// Only used when [`ngram_use_embedded`] is `false`.
    /// One file per language (e.g., `english.bin`, `french.bin`).
    pub ngram_models: Vec<String>,

    /// Minimum acceptable N-gram log-probability.  A domain must score above
    /// this value in **at least one** loaded model to pass.
    pub ngram_probability_threshold: f32,
}

impl Default for IntelligenceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            entropy_threshold: 4.0,
            entropy_fast: true,
            min_word_length: 8,
            consonant_ratio_threshold: 0.6,
            max_consonant_sequence: 5,
            use_ngram_model: false,
            ngram_use_embedded: true,
            ngram_embedded_languages: vec![String::from("english"), String::from("french")],
            ngram_models: vec![
                String::from("/etc/dgaard/models/english.bin"),
                String::from("/etc/dgaard/models/french.bin"),
            ],
            ngram_probability_threshold: -4.0,
        }
    }
}

// ---------------------------------------------------------------------------
// [security.lexical]
// ---------------------------------------------------------------------------

/// Smart keyword filtering for parental control and content blocking.
///
/// Unlike traditional blocklists that require millions of domain entries,
/// this filter uses label-aware keyword matching to block entire categories
/// of content (adult, gambling, etc.) with minimal memory footprint.
///
/// Uses the Aho-Corasick algorithm for efficient multi-pattern matching.
///
/// Maps to `[security.lexical]` in the configuration file.
#[derive(Debug, PartialEq, Clone)]
pub struct LexicalConfig {
    /// Master switch — set to `false` to disable keyword filtering entirely.
    pub enabled: bool,

    /// List of keywords to block.
    ///
    /// When `strict_matching` is `true`, keywords only trigger a block if:
    /// - The keyword is a complete DNS label (e.g., `casino` in `casino.com`)
    /// - The keyword is separated by a hyphen (e.g., `play-casino.net`)
    ///
    /// When `strict_matching` is `false`, a simple substring match is used
    /// (more aggressive, higher false-positive rate).
    ///
    /// Example: `["porno", "casino", "drogue", "bet", "sex", "gambling"]`
    pub banned_keywords: Vec<String>,

    /// Enable label-aware matching to reduce false positives.
    ///
    /// When `true` (recommended): Keywords must match complete labels or
    /// hyphen-separated segments. This avoids the "Scunthorpe problem" where
    /// innocent words contain forbidden substrings.
    ///
    /// When `false`: Simple `.contains()` matching is used — more aggressive
    /// but may block legitimate domains.
    pub strict_keyword_matching: bool,
}

impl Default for LexicalConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            banned_keywords: Vec::new(),
            strict_keyword_matching: true,
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
#[derive(Debug, Default, PartialEq, Clone)]
pub enum IdnMode {
    /// IDN filtering is disabled; all Unicode labels pass through.
    Off,
    /// Block every non-ASCII label unconditionally (recommended for embedded
    /// deployments with no multilingual users).
    Strict,
    /// Allow scripts listed in [`IdnConfig::allowed_scripts`] and block the
    /// rest.  Balances security with usability for European users.
    #[default]
    Smart,
}

/// Fine-grained Internationalized Domain Name policy.
///
/// Maps to `[security.idn]` in the configuration file.
#[derive(Debug, PartialEq, Clone)]
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
            allowed_scripts: vec![String::from("Latin"), String::from("WesternEuropean")],
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
#[derive(Debug, PartialEq, Clone)]
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
// [security.qtype_warden]
// ---------------------------------------------------------------------------

/// Query-type (QType) policy enforcement.
///
/// Blocks DNS queries whose record type is in the `blocked_types` list before
/// any domain-level processing occurs. This is the cheapest possible filter —
/// it requires no string comparison, only a u16 lookup in a short list.
///
/// Maps to `[security.qtype_warden]` in the configuration file.
///
/// ## Well-known suspicious types
/// | Type | Code | Threat vector |
/// |------|------|---------------|
/// | NULL | 10   | DNS tunneling (iodine, dnscat2) |
/// | HINFO | 13  | Host info leakage |
/// | ANY  | 255  | DNS amplification attacks |
/// | AXFR | 252  | Zone transfer (should never come from clients) |
#[derive(Debug, PartialEq, Clone)]
pub struct QTypeWardenConfig {
    /// Master switch — set to `false` to pass all query types through.
    pub enabled: bool,

    /// DNS record type numbers (RFC 1035 §3.2.2) to block unconditionally.
    /// Encoded as raw `u16` values so no hickory-proto dependency leaks into
    /// the config layer.
    pub blocked_types: Vec<u16>,
}

impl Default for QTypeWardenConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            // NULL (10), HINFO (13), ANY (255)
            blocked_types: vec![10, 13, 255],
        }
    }
}

// ---------------------------------------------------------------------------
// [security.low_ttl]
// ---------------------------------------------------------------------------

/// Low-TTL suspicion scoring configuration.
///
/// DNS responses with a very short TTL are characteristic of fast-flux malware
/// infrastructure, where IP addresses rotate rapidly to evade static blocklists.
/// Legitimate CDNs can also use short TTLs, so this check adds suspicion points
/// rather than blocking outright — it contributes to the cumulative score.
///
/// Maps to `[security.low_ttl]` in the configuration file.
#[derive(Debug, PartialEq, Clone)]
pub struct LowTtlConfig {
    /// Master switch — set to `false` to skip TTL-based scoring.
    pub enabled: bool,
    /// TTL threshold in seconds. Responses with `min_ttl < threshold_secs`
    /// add `LOW_TTL` suspicion points (default: 10 s).
    pub threshold_secs: u32,
}

impl Default for LowTtlConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            threshold_secs: 10,
        }
    }
}

// ---------------------------------------------------------------------------
// [security.rebinding_shield]
// ---------------------------------------------------------------------------

/// DNS Rebinding Shield configuration.
///
/// Rejects upstream DNS answers that map a public domain to a private or
/// reserved IP address. This closes the DNS rebinding attack vector where
/// an attacker's domain briefly resolves to a LAN IP to reach internal hosts.
///
/// Maps to `[security.rebinding_shield]` in the configuration file.
///
/// ## Covered private ranges
/// | Range           | Spec       | Threat                              |
/// |-----------------|------------|-------------------------------------|
/// | 0.0.0.0/8       | RFC 1122   | "This" network, unroutable          |
/// | 10.0.0.0/8      | RFC 1918   | Private LAN                         |
/// | 100.64.0.0/10   | RFC 6598   | Shared address space / CGNAT        |
/// | 127.0.0.0/8     | RFC 1122   | Loopback                            |
/// | 169.254.0.0/16  | RFC 3927   | Link-local / APIPA                  |
/// | 172.16.0.0/12   | RFC 1918   | Private LAN                         |
/// | 192.168.0.0/16  | RFC 1918   | Private LAN                         |
/// | ::1/128         | RFC 4291   | IPv6 loopback                       |
/// | fc00::/7        | RFC 4193   | IPv6 unique local                   |
/// | fe80::/10       | RFC 4291   | IPv6 link-local                     |
#[derive(Debug, PartialEq, Clone)]
pub struct RebindingShieldConfig {
    /// Master switch — set to `false` to allow private-IP answers through.
    pub enabled: bool,
}

impl Default for RebindingShieldConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

// ---------------------------------------------------------------------------
// [security.asn_filter]
// ---------------------------------------------------------------------------

/// ASN (Autonomous System Number) IP-range filtering.
///
/// Blocks DNS responses that resolve to IP addresses within user-configured
/// CIDR ranges. Intended to block known-malicious autonomous systems such as
/// crypto mining pools, bulletproof hosting providers, or C2 infrastructure.
///
/// Unlike real-time ASN lookups (which require external databases), this filter
/// uses a pre-configured list of CIDR ranges that the operator derives from
/// threat intelligence feeds.
///
/// Maps to `[security.asn_filter]` in the configuration file.
#[derive(Debug, PartialEq, Clone)]
pub struct AsnFilterConfig {
    /// Master switch — set to `false` to disable ASN range filtering entirely.
    pub enabled: bool,

    /// IPv4 and IPv6 CIDR ranges to block.
    ///
    /// Both address families are supported in the same list:
    /// - IPv4: `"203.0.113.0/24"`
    /// - IPv6: `"2001:db8::/32"`
    ///
    /// Ranges are parsed once at engine build time for zero-allocation hot-path
    /// matching. Invalid entries are skipped with a warning.
    pub blocked_ranges: Vec<String>,
}

impl Default for AsnFilterConfig {
    fn default() -> Self {
        // Disabled by default: requires explicit operator configuration.
        Self {
            enabled: false,
            blocked_ranges: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// [security]
// ---------------------------------------------------------------------------

/// Aggregated security sub-configuration.
///
/// Maps to the `[security.*]` family of sections in the configuration file.
#[derive(Debug, Default, PartialEq, Clone)]
pub struct SecurityConfig {
    /// Structural / syntactic label validation.
    pub structure: StructureConfig,
    /// Heuristic DGA and lexical analysis.
    pub intelligence: IntelligenceConfig,
    pub lexical: LexicalConfig,
    /// Internationalized domain name policy.
    pub idn: IdnConfig,
    /// Per-client behavioural anomaly thresholds.
    pub behavior: BehaviorConfig,
    /// Query-type (QType) policy enforcement.
    pub qtype_warden: QTypeWardenConfig,
    /// DNS Rebinding Shield: reject answers resolving to private/reserved IPs.
    pub rebinding_shield: RebindingShieldConfig,
    /// Low-TTL suspicion scoring.
    pub low_ttl: LowTtlConfig,
    /// ASN IP-range filtering: block responses resolving into known-bad CIDR ranges.
    pub asn_filter: AsnFilterConfig,
}

// ---------------------------------------------------------------------------
// [upstream]
// ---------------------------------------------------------------------------

/// Upstream resolver configuration.
///
/// Clean queries that pass all filters are forwarded to one of these servers.
/// Maps to `[upstream]` in the configuration file.
#[derive(Debug, PartialEq, Clone)]
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
            servers: vec![String::from("1.1.1.1:53"), String::from("9.9.9.9:53")],
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
#[derive(Debug, PartialEq, Default, Clone)]
pub struct TldConfig {
    /// If non-empty, **only** these TLDs are resolved; all others are blocked.
    /// Leave empty to allow all TLDs (then use `exclude` for targeted blocks).
    /// Example: `[".com", ".net", ".org", ".io"]`.
    pub allow_only: Vec<String>,

    /// TLDs that are always blocked regardless of other filters.
    /// Populated with high-risk TLDs commonly abused by malware and DGA
    /// operators.
    pub exclude: Vec<String>,

    /// Conditional blocking: block only if domain contains a banned keyword
    /// AND uses one of these TLDs.
    ///
    /// This is useful for "grey-zone" filtering where common TLDs like `.com`
    /// might have legitimate uses of certain keywords.
    ///
    /// Example: `[".biz", ".top", ".xyz"]`
    pub suspicious_tlds: Vec<String>,
}

// ---------------------------------------------------------------------------
// [nxdomain_hunting]
// ---------------------------------------------------------------------------

/// Action taken when a client trips the NXDOMAIN threshold.
#[derive(Debug, Default, PartialEq, Clone)]
pub enum NxdomainAction {
    /// Record the event in the structured log; do not block the client.
    #[default]
    Log,
    /// Insert a firewall rule to drop all traffic from the offending client
    /// IP for the remainder of the detection window.
    BlockClient,
}

/// NXDOMAIN hunting — detects botnet C2 beacon scanning.
///
/// Maps to `[nxdomain_hunting]` in the configuration file.
///
/// Note: overlaps with [`BehaviorConfig`]; the top-level section is
/// intended for operators who prefer a flat configuration layout.
#[derive(Debug, PartialEq, Clone)]
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
#[derive(Debug, PartialEq, Clone)]
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
#[derive(Debug, PartialEq, Clone)]
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

    /// Output path for the host index binary file.
    ///
    /// When set, dgaard writes a compact binary index mapping every xxh3_64
    /// hash to its source domain string after loading lists.  External tools
    /// (dashboard, scripts) can use this file to resolve a hash back to a
    /// human-readable domain without loading the full blocklist.
    ///
    /// Set to an empty string `""` to disable index generation.
    pub host_index_path: String,
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
            host_index_path: String::from("/var/dgaard/host_mapping.bin"),
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
#[derive(Debug, PartialEq, Clone)]
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
#[derive(Debug, PartialEq, Clone)]
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
#[derive(Debug, PartialEq, Clone)]
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
#[derive(Debug, Default, Clone)]
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!((i.entropy_threshold - 4.0).abs() < f32::EPSILON);
        assert!(i.entropy_fast);
        assert_eq!(i.min_word_length, 8);
        assert!((i.consonant_ratio_threshold - 0.6).abs() < f32::EPSILON);
        assert_eq!(i.max_consonant_sequence, 5);
        assert!(!i.use_ngram_model);
        assert!(i.ngram_use_embedded);
        assert_eq!(i.ngram_embedded_languages, vec!["english", "french"]);
        assert_eq!(i.ngram_models.len(), 2);
        assert!((i.ngram_probability_threshold - (-4.0)).abs() < f32::EPSILON);
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
    // LexicalConfig
    // -----------------------------------------------------------------------

    #[test]
    fn lexical_config_defaults() {
        let l = LexicalConfig::default();
        assert!(l.enabled);
        assert!(l.banned_keywords.is_empty());
        assert!(l.strict_keyword_matching);
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
        assert_eq!(sec.lexical, LexicalConfig::default());
        assert_eq!(sec.idn, IdnConfig::default());
        assert_eq!(sec.behavior, BehaviorConfig::default());
        assert_eq!(sec.rebinding_shield, RebindingShieldConfig::default());
        assert_eq!(sec.low_ttl, LowTtlConfig::default());
        assert_eq!(sec.asn_filter, AsnFilterConfig::default());
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
        assert_eq!(s.host_index_path, "/var/dgaard/host_mapping.bin");
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
