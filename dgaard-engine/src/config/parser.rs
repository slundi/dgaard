//! TOML configuration parser using `toml-span` without serde.
//!
//! This module provides zero-copy parsing of the Dgaard configuration file.

use std::path::Path;

use thiserror::Error;
use toml_span::{Span, value::ValueInner};

use super::model::*;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors that can occur during configuration loading and parsing.
#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("failed to read config file: {0}")]
    Io(#[from] std::io::Error),

    #[error("TOML syntax error: {0}")]
    Parse(String),

    #[error("Missing required key '{key}' at {span:?}")]
    MissingKey { key: String, span: Span },

    #[error("Invalid type for key '{key}': expected {expected} at {span:?}")]
    InvalidType {
        key: String,
        expected: &'static str,
        span: Span,
    },

    #[error("invalid value for key '{key}': {message} at {span:?}")]
    InvalidValue {
        key: String,
        message: String,
        span: Span,
    },
}

// ---------------------------------------------------------------------------
// Helper extraction functions
// ---------------------------------------------------------------------------

/// Extract a string value from a table, returning `None` if key is absent.
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

/// Extract a required string value from a table.
#[allow(dead_code)]
fn require_str<'a>(
    table: &'a toml_span::value::Table<'a>,
    key: &str,
    parent_span: Span,
) -> Result<&'a str, ConfigError> {
    get_str(table, key)?.ok_or_else(|| ConfigError::MissingKey {
        key: key.to_string(),
        span: parent_span,
    })
}

/// Extract an optional boolean value from a table.
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

/// Extract an optional integer value from a table.
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

/// Extract and range-validate an optional integer, converting it to the
/// target unsigned type `T` via `TryFrom<i64>`.
///
/// Returns `ConfigError::InvalidValue` — with the problematic value and the
/// source span — when the TOML integer is negative or exceeds `T::MAX`.
fn get_typed_integer<T>(
    table: &toml_span::value::Table<'_>,
    key: &str,
) -> Result<Option<T>, ConfigError>
where
    T: TryFrom<i64>,
{
    match table.get(key) {
        Some(v) => match v.as_ref() {
            ValueInner::Integer(n) => {
                T::try_from(*n)
                    .map(Some)
                    .map_err(|_| ConfigError::InvalidValue {
                        key: key.to_string(),
                        message: format!("value {} is out of range for this field", n),
                        span: v.span,
                    })
            }
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
fn get_float(table: &toml_span::value::Table<'_>, key: &str) -> Result<Option<f32>, ConfigError> {
    match table.get(key) {
        Some(v) => match v.as_ref() {
            ValueInner::Float(f) => Ok(Some((*f) as f32)),
            ValueInner::Integer(i) => Ok(Some((*i) as f32)),
            _ => Err(ConfigError::InvalidType {
                key: key.to_string(),
                expected: "float",
                span: v.span,
            }),
        },
        None => Ok(None),
    }
}

/// Extract an optional array of strings from a table.
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

/// Extract an optional array of integers from a table.
fn get_integer_array(
    table: &toml_span::value::Table<'_>,
    key: &str,
) -> Result<Option<Vec<i64>>, ConfigError> {
    match table.get(key) {
        Some(v) => match v.as_ref() {
            ValueInner::Array(arr) => {
                let mut result = Vec::with_capacity(arr.len());
                for item in arr.iter() {
                    match item.as_ref() {
                        ValueInner::Integer(n) => result.push(*n),
                        _ => {
                            return Err(ConfigError::InvalidType {
                                key: format!("{}[]", key),
                                expected: "integer",
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

/// Extract an optional nested table from a table.
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

/// Extract an optional array of tables from a table (for `[[section]]` entries).
fn get_table_array<'a>(
    table: &'a toml_span::value::Table<'a>,
    key: &str,
) -> Result<Option<Vec<&'a toml_span::value::Table<'a>>>, ConfigError> {
    match table.get(key) {
        Some(v) => match v.as_ref() {
            ValueInner::Array(arr) => {
                let mut result = Vec::with_capacity(arr.len());
                for item in arr.iter() {
                    match item.as_ref() {
                        ValueInner::Table(t) => result.push(t),
                        _ => {
                            return Err(ConfigError::InvalidType {
                                key: format!("{}[]", key),
                                expected: "table",
                                span: item.span,
                            });
                        }
                    }
                }
                Ok(Some(result))
            }
            _ => Err(ConfigError::InvalidType {
                key: key.to_string(),
                expected: "array of tables",
                span: v.span,
            }),
        },
        None => Ok(None),
    }
}

// ---------------------------------------------------------------------------
// Section parsers
// ---------------------------------------------------------------------------

/// Parse `[server.runtime]` section.
fn parse_runtime(table: &toml_span::value::Table<'_>) -> Result<RuntimeConfig, ConfigError> {
    let mut cfg = RuntimeConfig::default();

    // worker_threads can be "auto" or an integer
    if let Some(v) = table.get("worker_threads") {
        match v.as_ref() {
            ValueInner::String(s) if s.as_ref() == "auto" => {
                cfg.worker_threads = WorkerThreads::Auto;
            }
            ValueInner::Integer(n) => {
                let count = usize::try_from(*n).ok().filter(|&c| c > 0).ok_or_else(|| {
                    ConfigError::InvalidValue {
                        key: "worker_threads".to_string(),
                        message: format!("thread count must be a positive integer, got {}", n),
                        span: v.span,
                    }
                })?;
                cfg.worker_threads = WorkerThreads::Count(count);
            }
            ValueInner::String(s) => {
                return Err(ConfigError::InvalidValue {
                    key: "worker_threads".to_string(),
                    message: format!("expected \"auto\" or integer, got \"{}\"", s),
                    span: v.span,
                });
            }
            _ => {
                return Err(ConfigError::InvalidType {
                    key: "worker_threads".to_string(),
                    expected: "string or integer",
                    span: v.span,
                });
            }
        }
    }

    if let Some(n) = get_typed_integer::<usize>(table, "stack_size")? {
        cfg.stack_size = n;
    }
    if let Some(n) = get_typed_integer::<usize>(table, "max_blocking_threads")? {
        cfg.max_blocking_threads = n;
    }
    if let Some(n) = get_typed_integer::<usize>(table, "max_concurrent_queries")? {
        cfg.max_concurrent_queries = n;
    }

    Ok(cfg)
}

/// Parse `[server]` section.
fn parse_server(table: &toml_span::value::Table<'_>) -> Result<ServerConfig, ConfigError> {
    let mut cfg = ServerConfig::default();

    if let Some(s) = get_str(table, "listen_addr")? {
        cfg.listen_addr = s.to_string();
    }
    if let Some(arr) = get_string_array(table, "allowed_networks")? {
        cfg.allowed_networks = arr;
    }
    if let Some(s) = get_str(table, "stats_socket_path")? {
        cfg.stats_socket_path = s.to_string();
    }
    if let Some(b) = get_bool(table, "block_idn")? {
        cfg.block_idn = b;
    }

    // Parse pipeline array
    if let Some(v) = table.get("pipeline") {
        match v.as_ref() {
            ValueInner::Array(arr) => {
                let mut steps = Vec::with_capacity(arr.len());
                for item in arr.iter() {
                    match item.as_ref() {
                        ValueInner::String(s) => {
                            let step = match s.as_ref() {
                                "Whitelist" => PipelineStep::Whitelist,
                                "HotCache" => PipelineStep::HotCache,
                                "StaticBlock" => PipelineStep::StaticBlock,
                                "SuffixMatch" => PipelineStep::SuffixMatch,
                                "Heuristics" => PipelineStep::Heuristics,
                                "Upstream" => PipelineStep::Upstream,
                                other => {
                                    return Err(ConfigError::InvalidValue {
                                        key: "pipeline".to_string(),
                                        message: format!("unknown pipeline step: {}", other),
                                        span: item.span,
                                    });
                                }
                            };
                            steps.push(step);
                        }
                        _ => {
                            return Err(ConfigError::InvalidType {
                                key: "pipeline[]".to_string(),
                                expected: "string",
                                span: item.span,
                            });
                        }
                    }
                }
                cfg.pipeline = steps;
            }
            _ => {
                return Err(ConfigError::InvalidType {
                    key: "pipeline".to_string(),
                    expected: "array",
                    span: v.span,
                });
            }
        }
    }

    // Parse nested runtime section
    if let Some(rt_table) = get_table(table, "runtime")? {
        cfg.runtime = parse_runtime(rt_table)?;
    }

    Ok(cfg)
}

/// Parse `[security.structure]` section.
fn parse_structure(table: &toml_span::value::Table<'_>) -> Result<StructureConfig, ConfigError> {
    let mut cfg = StructureConfig::default();

    if let Some(n) = get_typed_integer::<u8>(table, "max_subdomain_depth")? {
        cfg.max_subdomain_depth = n;
    }
    if let Some(n) = get_typed_integer::<u16>(table, "max_domain_length")? {
        cfg.max_domain_length = n;
    }
    if let Some(b) = get_bool(table, "force_lowercase_ascii")? {
        cfg.force_lowercase_ascii = b;
    }
    if let Some(n) = get_typed_integer::<u16>(table, "max_txt_record_length")? {
        cfg.max_txt_record_length = n;
    }
    if let Some(n) = get_typed_integer::<u8>(table, "max_answers_per_query")? {
        cfg.max_answers_per_query = n;
    }
    if let Some(b) = get_bool(table, "block_chaos_class")? {
        cfg.block_chaos_class = b;
    }

    Ok(cfg)
}

/// Parse `[security.lexical]` section.
fn parse_lexical(table: &toml_span::value::Table<'_>) -> Result<LexicalConfig, ConfigError> {
    let mut cfg = LexicalConfig::default();
    if let Some(b) = get_bool(table, "enabled")? {
        cfg.enabled = b;
    }
    if let Some(b) = get_bool(table, "strict_keyword_matching")? {
        cfg.strict_keyword_matching = b;
    }
    if let Some(arr) = get_string_array(table, "banned_keywords")? {
        cfg.banned_keywords = arr;
    }
    Ok(cfg)
}

/// Parse `[security.intelligence]` section.
fn parse_intelligence(
    table: &toml_span::value::Table<'_>,
) -> Result<IntelligenceConfig, ConfigError> {
    let mut cfg = IntelligenceConfig::default();

    if let Some(b) = get_bool(table, "enabled")? {
        cfg.enabled = b;
    }
    if let Some(f) = get_float(table, "entropy_threshold")? {
        cfg.entropy_threshold = f;
    }
    if let Some(b) = get_bool(table, "entropy_fast")? {
        cfg.entropy_fast = b;
    }
    if let Some(n) = get_typed_integer::<usize>(table, "min_word_length")? {
        cfg.min_word_length = n;
    }
    if let Some(f) = get_float(table, "consonant_ratio_threshold")? {
        cfg.consonant_ratio_threshold = f;
    }
    if let Some(n) = get_typed_integer::<usize>(table, "max_consonant_sequence")? {
        cfg.max_consonant_sequence = n;
    }
    if let Some(b) = get_bool(table, "use_ngram_model")? {
        cfg.use_ngram_model = b;
    }
    if let Some(b) = get_bool(table, "ngram_use_embedded")? {
        cfg.ngram_use_embedded = b;
    }
    if let Some(arr) = get_string_array(table, "ngram_embedded_languages")? {
        cfg.ngram_embedded_languages = arr;
    }
    if let Some(arr) = get_string_array(table, "ngram_models")? {
        cfg.ngram_models = arr;
    }
    if let Some(f) = get_float(table, "ngram_probability_threshold")? {
        cfg.ngram_probability_threshold = f;
    }

    Ok(cfg)
}

/// Parse `[security.idn]` section.
fn parse_idn(table: &toml_span::value::Table<'_>) -> Result<IdnConfig, ConfigError> {
    let mut cfg = IdnConfig::default();

    if let Some(s) = get_str(table, "mode")? {
        cfg.mode = match s {
            "Off" => IdnMode::Off,
            "Strict" => IdnMode::Strict,
            "Smart" => IdnMode::Smart,
            other => {
                return Err(ConfigError::InvalidValue {
                    key: "mode".to_string(),
                    message: format!("expected Off, Strict, or Smart, got \"{}\"", other),
                    span: table.get("mode").unwrap().span,
                });
            }
        };
    }
    if let Some(arr) = get_string_array(table, "allowed_scripts")? {
        cfg.allowed_scripts = arr;
    }

    Ok(cfg)
}

/// Parse `[security.behavior]` section.
fn parse_behavior(table: &toml_span::value::Table<'_>) -> Result<BehaviorConfig, ConfigError> {
    let mut cfg = BehaviorConfig::default();

    if let Some(n) = get_typed_integer::<u32>(table, "nxdomain_threshold")? {
        cfg.nxdomain_threshold = n;
    }
    if let Some(n) = get_typed_integer::<u32>(table, "nxdomain_window")? {
        cfg.nxdomain_window = n;
    }
    if let Some(n) = get_typed_integer::<u32>(table, "max_subdomains_per_minute")? {
        cfg.max_subdomains_per_minute = n;
    }
    if let Some(n) = get_typed_integer::<u8>(table, "max_label_length")? {
        cfg.max_label_length = n;
    }

    Ok(cfg)
}

/// Parse `[security.qtype_warden]` section.
fn parse_qtype_warden(
    table: &toml_span::value::Table<'_>,
) -> Result<QTypeWardenConfig, ConfigError> {
    let mut cfg = QTypeWardenConfig::default();

    if let Some(b) = get_bool(table, "enabled")? {
        cfg.enabled = b;
    }
    if let Some(arr) = get_integer_array(table, "blocked_types")? {
        let mut types = Vec::with_capacity(arr.len());
        for n in arr {
            types.push(u16::try_from(n).map_err(|_| ConfigError::InvalidValue {
                key: "blocked_types".to_string(),
                message: format!("DNS type value {} is out of range 0–65535", n),
                span: toml_span::Span::default(),
            })?);
        }
        cfg.blocked_types = types;
    }

    Ok(cfg)
}

/// Parse `[security.low_ttl]` section.
fn parse_low_ttl(table: &toml_span::value::Table<'_>) -> Result<LowTtlConfig, ConfigError> {
    let mut cfg = LowTtlConfig::default();

    if let Some(b) = get_bool(table, "enabled")? {
        cfg.enabled = b;
    }
    if let Some(n) = get_typed_integer::<u32>(table, "threshold_secs")? {
        cfg.threshold_secs = n;
    }
    if let Some(n) = get_typed_integer::<u32>(table, "min_ttl_floor_secs")? {
        cfg.min_ttl_floor_secs = Some(n);
    }

    Ok(cfg)
}

/// Parse `[security.asn_filter]` section.
fn parse_asn_filter(table: &toml_span::value::Table<'_>) -> Result<AsnFilterConfig, ConfigError> {
    let mut cfg = AsnFilterConfig::default();

    if let Some(b) = get_bool(table, "enabled")? {
        cfg.enabled = b;
    }
    if let Some(arr) = get_string_array(table, "blocked_ranges")? {
        // checks are done later
        cfg.blocked_ranges = arr;
    }

    Ok(cfg)
}

/// Parse `[security.rebinding_shield]` section.
fn parse_rebinding_shield(
    table: &toml_span::value::Table<'_>,
) -> Result<RebindingShieldConfig, ConfigError> {
    let mut cfg = RebindingShieldConfig::default();

    if let Some(b) = get_bool(table, "enabled")? {
        cfg.enabled = b;
    }
    if let Some(b) = get_bool(table, "block_ptr_leak")? {
        cfg.block_ptr_leak = b;
    }

    Ok(cfg)
}

/// Parse `[security.special_use]` section.
fn parse_special_use(table: &toml_span::value::Table<'_>) -> Result<SpecialUseConfig, ConfigError> {
    let mut cfg = SpecialUseConfig::default();

    if let Some(b) = get_bool(table, "enabled")? {
        cfg.enabled = b;
    }
    if let Some(arr) = get_string_array(table, "extra_local_tlds")? {
        cfg.extra_local_tlds = arr;
    }

    Ok(cfg)
}

/// Parse `[security.geo_ip]` section.
fn parse_geo_ip(table: &toml_span::value::Table<'_>) -> Result<GeoIpConfig, ConfigError> {
    let mut cfg = GeoIpConfig::default();

    if let Some(b) = get_bool(table, "enabled")? {
        cfg.enabled = b;
    }
    if let Some(s) = get_str(table, "database_path")? {
        cfg.database_path = s.to_string();
    }
    if let Some(arr) = get_string_array(table, "suspicious_countries")? {
        cfg.suspicious_countries = arr;
    }
    if let Some(n) = get_typed_integer::<u8>(table, "suspicious_country_score")? {
        cfg.suspicious_country_score = n;
    }

    Ok(cfg)
}

/// Parse `[security.scoring]` section.
fn parse_scoring(table: &toml_span::value::Table<'_>) -> Result<ScoringConfig, ConfigError> {
    let mut cfg = ScoringConfig::default();

    if let Some(n) = get_typed_integer::<u8>(table, "blocking_threshold")? {
        cfg.blocking_threshold = n;
    }
    if let Some(n) = get_typed_integer::<u8>(table, "highly_suspicious_threshold")? {
        cfg.highly_suspicious_threshold = n;
    }
    if let Some(n) = get_typed_integer::<u8>(table, "suspicious_threshold")? {
        cfg.suspicious_threshold = n;
    }
    if let Some(b) = get_bool(table, "log_suspicious")? {
        cfg.log_suspicious = b;
    }

    Ok(cfg)
}

/// Parse a single `[[security.custom_flags]]` entry.
fn parse_custom_flag(
    table: &toml_span::value::Table<'_>,
    parent_span: toml_span::Span,
) -> Result<CustomFlagConfig, ConfigError> {
    let bit = get_integer(table, "bit")?.ok_or_else(|| ConfigError::MissingKey {
        key: "bit".to_string(),
        span: parent_span,
    })?;

    if !(16..=31).contains(&bit) {
        return Err(ConfigError::InvalidValue {
            key: "bit".to_string(),
            message: format!("must be in range 16–31, got {}", bit),
            span: parent_span,
        });
    }

    let code = get_str(table, "code")?
        .ok_or_else(|| ConfigError::MissingKey {
            key: "code".to_string(),
            span: parent_span,
        })?
        .to_string();

    let name = get_str(table, "name")?.unwrap_or("").to_string();
    let description = get_str(table, "description")?.unwrap_or("").to_string();

    let suspicious_score: u8 = get_typed_integer(table, "suspicious_score")?.unwrap_or(1);

    let list_path = get_string_array(table, "list_path")?.unwrap_or_default();

    Ok(CustomFlagConfig {
        bit: bit as u8,
        code,
        name,
        description,
        suspicious_score,
        list_path,
    })
}

/// Parse `[[security.custom_flags]]` array and validate constraints.
fn parse_custom_flags(
    table: &toml_span::value::Table<'_>,
) -> Result<Vec<CustomFlagConfig>, ConfigError> {
    let entries = match get_table_array(table, "custom_flags")? {
        Some(v) => v,
        None => return Ok(Vec::new()),
    };

    if entries.len() > 16 {
        return Err(ConfigError::InvalidValue {
            key: "custom_flags".to_string(),
            message: format!(
                "at most 16 custom flags are allowed (bits 16–31), got {}",
                entries.len()
            ),
            span: toml_span::Span::default(),
        });
    }

    let mut flags = Vec::with_capacity(entries.len());
    let mut seen_bits = std::collections::HashSet::new();

    for entry_table in entries {
        let flag = parse_custom_flag(entry_table, toml_span::Span::default())?;

        if !seen_bits.insert(flag.bit) {
            return Err(ConfigError::InvalidValue {
                key: "bit".to_string(),
                message: format!("duplicate custom flag bit {}", flag.bit),
                span: toml_span::Span::default(),
            });
        }

        flags.push(flag);
    }

    Ok(flags)
}

/// Parse `[security]` section with all sub-sections.
fn parse_security(table: &toml_span::value::Table<'_>) -> Result<SecurityConfig, ConfigError> {
    let mut cfg = SecurityConfig::default();

    if let Some(t) = get_table(table, "structure")? {
        cfg.structure = parse_structure(t)?;
    }
    if let Some(t) = get_table(table, "intelligence")? {
        cfg.intelligence = parse_intelligence(t)?;
    }
    if let Some(t) = get_table(table, "lexical")? {
        cfg.lexical = parse_lexical(t)?;
    }
    if let Some(t) = get_table(table, "idn")? {
        cfg.idn = parse_idn(t)?;
    }
    if let Some(t) = get_table(table, "behavior")? {
        cfg.behavior = parse_behavior(t)?;
    }
    if let Some(t) = get_table(table, "qtype_warden")? {
        cfg.qtype_warden = parse_qtype_warden(t)?;
    }
    if let Some(t) = get_table(table, "rebinding_shield")? {
        cfg.rebinding_shield = parse_rebinding_shield(t)?;
    }
    if let Some(t) = get_table(table, "low_ttl")? {
        cfg.low_ttl = parse_low_ttl(t)?;
    }
    if let Some(t) = get_table(table, "asn_filter")? {
        cfg.asn_filter = parse_asn_filter(t)?;
    }
    if let Some(t) = get_table(table, "scoring")? {
        cfg.scoring = parse_scoring(t)?;
    }
    if let Some(t) = get_table(table, "geo_ip")? {
        cfg.geo_ip = parse_geo_ip(t)?;
    }
    if let Some(t) = get_table(table, "special_use")? {
        cfg.special_use = parse_special_use(t)?;
    }

    cfg.custom_flags = parse_custom_flags(table)?;

    Ok(cfg)
}

/// Parse `[upstream]` section.
fn parse_upstream(table: &toml_span::value::Table<'_>) -> Result<UpstreamConfig, ConfigError> {
    let mut cfg = UpstreamConfig::default();

    if let Some(arr) = get_string_array(table, "servers")? {
        cfg.servers = arr;
    }
    if let Some(n) = get_typed_integer::<u64>(table, "timeout_ms")? {
        cfg.timeout_ms = n;
    }
    if let Some(b) = get_bool(table, "use_0x20_randomization")? {
        cfg.use_0x20_randomization = b;
    }

    Ok(cfg)
}

/// Parse `[tld]` section.
fn parse_tld(table: &toml_span::value::Table<'_>) -> Result<TldConfig, ConfigError> {
    let mut cfg = TldConfig::default();

    if let Some(arr) = get_string_array(table, "allow_only")? {
        cfg.allow_only = arr;
    }
    if let Some(arr) = get_string_array(table, "exclude")? {
        cfg.exclude = arr;
    }
    if let Some(arr) = get_string_array(table, "suspicious_tlds")? {
        cfg.suspicious_tlds = arr;
    }
    Ok(cfg)
}

/// Parse `[nxdomain_hunting]` section.
fn parse_nxdomain_hunting(
    table: &toml_span::value::Table<'_>,
) -> Result<NxdomainHuntingConfig, ConfigError> {
    let mut cfg = NxdomainHuntingConfig::default();

    if let Some(b) = get_bool(table, "enabled")? {
        cfg.enabled = b;
    }
    if let Some(n) = get_typed_integer::<u32>(table, "threshold")? {
        cfg.threshold = n;
    }
    if let Some(n) = get_typed_integer::<u32>(table, "window_seconds")? {
        cfg.window_seconds = n;
    }
    if let Some(s) = get_str(table, "action")? {
        cfg.action = match s {
            "log" => NxdomainAction::Log,
            "block_client" => NxdomainAction::BlockClient,
            other => {
                return Err(ConfigError::InvalidValue {
                    key: "action".to_string(),
                    message: format!("expected \"log\" or \"block_client\", got \"{}\"", other),
                    span: table.get("action").unwrap().span,
                });
            }
        };
    }

    Ok(cfg)
}

/// Parse `[tunneling_detection]` section.
fn parse_tunneling_detection(
    table: &toml_span::value::Table<'_>,
) -> Result<TunnelingDetectionConfig, ConfigError> {
    let mut cfg = TunnelingDetectionConfig::default();

    if let Some(b) = get_bool(table, "enabled")? {
        cfg.enabled = b;
    }
    if let Some(n) = get_typed_integer::<u32>(table, "max_subdomains_per_minute")? {
        cfg.max_subdomains_per_minute = n;
    }
    if let Some(n) = get_typed_integer::<u8>(table, "max_label_length")? {
        cfg.max_label_length = n;
    }

    Ok(cfg)
}

/// Parse `[sources]` section.
fn parse_sources(table: &toml_span::value::Table<'_>) -> Result<SourcesConfig, ConfigError> {
    let mut cfg = SourcesConfig::default();

    if let Some(s) = get_str(table, "nrd_list_path")? {
        cfg.nrd_list_path = s.to_string();
    }
    if let Some(arr) = get_string_array(table, "blacklists")? {
        cfg.blacklists = arr;
    }
    if let Some(arr) = get_string_array(table, "whitelists")? {
        cfg.whitelists = arr;
    }
    if let Some(n) = get_typed_integer::<u32>(table, "update_interval_hours")? {
        cfg.update_interval_hours = n;
    }
    if let Some(n) = get_typed_integer::<u32>(table, "retry_delay_mins")? {
        cfg.retry_delay_mins = n;
    }
    if let Some(s) = get_str(table, "host_index_path")? {
        cfg.host_index_path = s.to_string();
    }
    if let Some(s) = get_str(table, "browser_rules_path")? {
        cfg.browser_rules_path = s.to_string();
    }
    if let Some(n) = get_typed_integer::<u32>(table, "reload_timeout_secs")? {
        cfg.reload_timeout_secs = n;
    }

    Ok(cfg)
}

/// Parse `[abp]` section.
fn parse_abp(table: &toml_span::value::Table<'_>) -> Result<AbpConfig, ConfigError> {
    let mut cfg = AbpConfig::default();

    if let Some(b) = get_bool(table, "extract_domain_only")? {
        cfg.extract_domain_only = b;
    }
    if let Some(n) = get_typed_integer::<u32>(table, "update_interval")? {
        cfg.update_interval = n;
    }

    Ok(cfg)
}

/// Parse `[cache]` section.
fn parse_cache(table: &toml_span::value::Table<'_>) -> Result<CacheConfig, ConfigError> {
    let mut cfg = CacheConfig::default();

    if let Some(b) = get_bool(table, "enabled")? {
        cfg.enabled = b;
    }
    if let Some(n) = get_typed_integer::<usize>(table, "max_entries")? {
        cfg.max_entries = n;
    }
    if let Some(n) = get_typed_integer::<u32>(table, "ttl_override")? {
        cfg.ttl_override = n;
    }

    Ok(cfg)
}

/// Parse `[memory]` section.
fn parse_memory(table: &toml_span::value::Table<'_>) -> Result<MemoryConfig, ConfigError> {
    let mut cfg = MemoryConfig::default();

    if let Some(b) = get_bool(table, "cache_enabled")? {
        cfg.cache_enabled = b;
    }
    if let Some(n) = get_typed_integer::<usize>(table, "cache_size")? {
        cfg.cache_size = n;
    }
    if let Some(b) = get_bool(table, "use_bloom_filter")? {
        cfg.use_bloom_filter = b;
    }
    if let Some(n) = get_typed_integer::<usize>(table, "expected_total_domains")? {
        cfg.expected_total_domains = n;
    }

    Ok(cfg)
}

// ---------------------------------------------------------------------------
// Config implementation
// ---------------------------------------------------------------------------

impl Config {
    /// Parse configuration from a TOML string.
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

        // Parse each top-level section
        if let Some(t) = get_table(root, "server")? {
            cfg.server = parse_server(t)?;
        }
        if let Some(t) = get_table(root, "security")? {
            cfg.security = parse_security(t)?;
        }
        if let Some(t) = get_table(root, "upstream")? {
            cfg.upstream = parse_upstream(t)?;
        }
        if let Some(t) = get_table(root, "tld")? {
            cfg.tld = parse_tld(t)?;
        }
        if let Some(t) = get_table(root, "nxdomain_hunting")? {
            cfg.nxdomain_hunting = parse_nxdomain_hunting(t)?;
        }
        if let Some(t) = get_table(root, "tunneling_detection")? {
            cfg.tunneling_detection = parse_tunneling_detection(t)?;
        }
        if let Some(t) = get_table(root, "sources")? {
            cfg.sources = parse_sources(t)?;
        }
        if let Some(t) = get_table(root, "abp")? {
            cfg.abp = parse_abp(t)?;
        }
        if let Some(t) = get_table(root, "cache")? {
            cfg.cache = parse_cache(t)?;
        }
        if let Some(t) = get_table(root, "memory")? {
            cfg.memory = parse_memory(t)?;
        }

        Ok(cfg)
    }

    /// Load and parse configuration from a file path.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)?;
        Self::parse(&content)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use core::f32;
    use std::env;
    use std::fs;
    use std::path::PathBuf;

    fn temp_file(name: &str, content: &str) -> PathBuf {
        let dir = env::temp_dir().join(format!("dgaard_parser_test_{}", std::process::id()));
        fs::create_dir_all(&dir).expect("failed to create temp dir");
        let path = dir.join(name);
        fs::write(&path, content).expect("failed to write temp file");
        path
    }

    fn cleanup(path: &Path) {
        if let Some(parent) = path.parent() {
            let _ = fs::remove_dir_all(parent);
        }
    }

    // -----------------------------------------------------------------------
    // Empty / minimal config
    // -----------------------------------------------------------------------

    #[test]
    fn parse_empty_config_returns_defaults() {
        let cfg = Config::parse("").unwrap();
        assert_eq!(cfg.server.listen_addr, "127.0.0.1:53");
        assert_eq!(cfg.upstream.servers, vec!["1.1.1.1:53", "9.9.9.9:53"]);
    }

    #[test]
    fn parse_minimal_server_config() {
        let toml = r#"
            [server]
            listen_addr = "0.0.0.0:5353"
        "#;
        let cfg = Config::parse(toml).unwrap();
        assert_eq!(cfg.server.listen_addr, "0.0.0.0:5353");
        // Other fields should be defaults
        assert!(cfg.server.block_idn);
    }

    // -----------------------------------------------------------------------
    // Server section
    // -----------------------------------------------------------------------

    #[test]
    fn parse_server_all_fields() {
        let toml = r#"
            [server]
            listen_addr = "192.168.1.1:53"
            allowed_networks = ["10.0.0.0/8", "172.16.0.0/12"]
            stats_socket_path = "/var/run/dgaard.sock"
            block_idn = false
            pipeline = ["Whitelist", "StaticBlock", "Upstream"]
        "#;
        let cfg = Config::parse(toml).unwrap();
        assert_eq!(cfg.server.listen_addr, "192.168.1.1:53");
        assert_eq!(
            cfg.server.allowed_networks,
            vec!["10.0.0.0/8", "172.16.0.0/12"]
        );
        assert_eq!(cfg.server.stats_socket_path, "/var/run/dgaard.sock");
        assert!(!cfg.server.block_idn);
        assert_eq!(
            cfg.server.pipeline,
            vec![
                PipelineStep::Whitelist,
                PipelineStep::StaticBlock,
                PipelineStep::Upstream
            ]
        );
    }

    #[test]
    fn parse_server_runtime_auto() {
        let toml = r#"
            [server.runtime]
            worker_threads = "auto"
            stack_size = 1048576
            max_blocking_threads = 256
        "#;
        let cfg = Config::parse(toml).unwrap();
        assert_eq!(cfg.server.runtime.worker_threads, WorkerThreads::Auto);
        assert_eq!(cfg.server.runtime.stack_size, 1048576);
        assert_eq!(cfg.server.runtime.max_blocking_threads, 256);
    }

    #[test]
    fn parse_server_runtime_count() {
        let toml = r#"
            [server.runtime]
            worker_threads = 4
        "#;
        let cfg = Config::parse(toml).unwrap();
        assert_eq!(cfg.server.runtime.worker_threads, WorkerThreads::Count(4));
    }

    #[test]
    fn parse_invalid_pipeline_step_returns_error() {
        let toml = r#"
            [server]
            pipeline = ["Whitelist", "InvalidStep"]
        "#;
        let result = Config::parse(toml);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue { .. }));
    }

    #[test]
    fn parse_invalid_worker_threads_string_returns_error() {
        let toml = r#"
            [server.runtime]
            worker_threads = "invalid"
        "#;
        let result = Config::parse(toml);
        assert!(result.is_err());
    }

    #[test]
    fn parse_negative_worker_threads_returns_error() {
        let toml = r#"
            [server.runtime]
            worker_threads = -1
        "#;
        assert!(matches!(
            Config::parse(toml),
            Err(ConfigError::InvalidValue { .. })
        ));
    }

    #[test]
    fn parse_zero_worker_threads_returns_error() {
        let toml = r#"
            [server.runtime]
            worker_threads = 0
        "#;
        assert!(matches!(
            Config::parse(toml),
            Err(ConfigError::InvalidValue { .. })
        ));
    }

    #[test]
    fn parse_negative_stack_size_returns_error() {
        let toml = r#"
            [server.runtime]
            stack_size = -1
        "#;
        assert!(matches!(
            Config::parse(toml),
            Err(ConfigError::InvalidValue { .. })
        ));
    }

    // -----------------------------------------------------------------------
    // Integer range validation
    // -----------------------------------------------------------------------

    #[test]
    fn parse_negative_max_subdomain_depth_returns_error() {
        let toml = r#"
            [security.structure]
            max_subdomain_depth = -1
        "#;
        assert!(matches!(
            Config::parse(toml),
            Err(ConfigError::InvalidValue { .. })
        ));
    }

    #[test]
    fn parse_overflow_max_subdomain_depth_returns_error() {
        let toml = r#"
            [security.structure]
            max_subdomain_depth = 256
        "#;
        assert!(matches!(
            Config::parse(toml),
            Err(ConfigError::InvalidValue { .. })
        ));
    }

    #[test]
    fn parse_negative_max_domain_length_returns_error() {
        let toml = r#"
            [security.structure]
            max_domain_length = -1
        "#;
        assert!(matches!(
            Config::parse(toml),
            Err(ConfigError::InvalidValue { .. })
        ));
    }

    #[test]
    fn parse_negative_max_answers_per_query_returns_error() {
        let toml = r#"
            [security.structure]
            max_answers_per_query = -1
        "#;
        assert!(matches!(
            Config::parse(toml),
            Err(ConfigError::InvalidValue { .. })
        ));
    }

    #[test]
    fn parse_negative_min_word_length_returns_error() {
        let toml = r#"
            [security.intelligence]
            min_word_length = -5
        "#;
        assert!(matches!(
            Config::parse(toml),
            Err(ConfigError::InvalidValue { .. })
        ));
    }

    #[test]
    fn parse_negative_max_label_length_returns_error() {
        let toml = r#"
            [security.behavior]
            max_label_length = -1
        "#;
        assert!(matches!(
            Config::parse(toml),
            Err(ConfigError::InvalidValue { .. })
        ));
    }

    #[test]
    fn parse_negative_blocking_threshold_returns_error() {
        let toml = r#"
            [security.scoring]
            blocking_threshold = -1
        "#;
        assert!(matches!(
            Config::parse(toml),
            Err(ConfigError::InvalidValue { .. })
        ));
    }

    #[test]
    fn parse_negative_timeout_ms_returns_error() {
        let toml = r#"
            [upstream]
            timeout_ms = -500
        "#;
        assert!(matches!(
            Config::parse(toml),
            Err(ConfigError::InvalidValue { .. })
        ));
    }

    #[test]
    fn parse_negative_threshold_secs_returns_error() {
        let toml = r#"
            [security.low_ttl]
            threshold_secs = -10
        "#;
        assert!(matches!(
            Config::parse(toml),
            Err(ConfigError::InvalidValue { .. })
        ));
    }

    #[test]
    fn parse_negative_blocked_type_returns_error() {
        let toml = r#"
            [security.qtype_warden]
            blocked_types = [-1, 255]
        "#;
        assert!(matches!(
            Config::parse(toml),
            Err(ConfigError::InvalidValue { .. })
        ));
    }

    #[test]
    fn parse_overflow_blocked_type_returns_error() {
        let toml = r#"
            [security.qtype_warden]
            blocked_types = [65536]
        "#;
        assert!(matches!(
            Config::parse(toml),
            Err(ConfigError::InvalidValue { .. })
        ));
    }

    #[test]
    fn parse_negative_update_interval_hours_returns_error() {
        let toml = r#"
            [sources]
            update_interval_hours = -24
        "#;
        assert!(matches!(
            Config::parse(toml),
            Err(ConfigError::InvalidValue { .. })
        ));
    }

    #[test]
    fn parse_negative_cache_size_returns_error() {
        let toml = r#"
            [memory]
            cache_size = -1
        "#;
        assert!(matches!(
            Config::parse(toml),
            Err(ConfigError::InvalidValue { .. })
        ));
    }

    // -----------------------------------------------------------------------
    // Security section
    // -----------------------------------------------------------------------

    #[test]
    fn parse_security_structure() {
        let toml = r#"
            [security.structure]
            max_subdomain_depth = 3
            max_domain_length = 64
            force_lowercase_ascii = false
            max_txt_record_length = 200
            max_answers_per_query = 5
            block_chaos_class = false
        "#;
        let cfg = Config::parse(toml).unwrap();
        assert_eq!(cfg.security.structure.max_subdomain_depth, 3);
        assert_eq!(cfg.security.structure.max_domain_length, 64);
        assert!(!cfg.security.structure.force_lowercase_ascii);
        assert_eq!(cfg.security.structure.max_txt_record_length, 200);
        assert_eq!(cfg.security.structure.max_answers_per_query, 5);
        assert!(!cfg.security.structure.block_chaos_class);
    }

    #[test]
    fn parse_security_structure_defaults() {
        let cfg = Config::parse("").unwrap();
        assert!(cfg.security.structure.block_chaos_class);
    }

    #[test]
    fn parse_security_intelligence() {
        let toml = r#"
            [security.intelligence]
            enabled = false
            entropy_threshold = 3.5
            entropy_fast = false
            min_word_length = 6
            consonant_ratio_threshold = 0.7
            max_consonant_sequence = 4
            use_ngram_model = true
            ngram_use_embedded = false
            ngram_embedded_languages = ["english", "german"]
            ngram_models = ["/path/to/model.bin"]
            ngram_probability_threshold = -5.0
        "#;
        let cfg = Config::parse(toml).unwrap();
        assert!(!cfg.security.intelligence.enabled);
        assert!((cfg.security.intelligence.entropy_threshold - 3.5).abs() < f32::EPSILON);
        assert!(!cfg.security.intelligence.entropy_fast);
        assert_eq!(cfg.security.intelligence.min_word_length, 6);
        assert!((cfg.security.intelligence.consonant_ratio_threshold - 0.7).abs() < f32::EPSILON);
        assert_eq!(cfg.security.intelligence.max_consonant_sequence, 4);
        assert!(cfg.security.intelligence.use_ngram_model);
        assert!(!cfg.security.intelligence.ngram_use_embedded);
        assert_eq!(
            cfg.security.intelligence.ngram_embedded_languages,
            vec!["english", "german"]
        );
        assert_eq!(
            cfg.security.intelligence.ngram_models,
            vec!["/path/to/model.bin"]
        );
        assert!(
            (cfg.security.intelligence.ngram_probability_threshold - (-5.0)).abs() < f32::EPSILON
        );
    }

    #[test]
    fn parse_security_intelligence_entropy_fast_default_is_true() {
        // When entropy_fast is not specified, it should default to true
        let toml = r#"
            [security.intelligence]
            enabled = true
        "#;
        let cfg = Config::parse(toml).unwrap();
        assert!(cfg.security.intelligence.entropy_fast);
    }

    #[test]
    fn parse_security_intelligence_entropy_fast_explicit_true() {
        let toml = r#"
            [security.intelligence]
            entropy_fast = true
        "#;
        let cfg = Config::parse(toml).unwrap();
        assert!(cfg.security.intelligence.entropy_fast);
    }

    #[test]
    fn parse_security_lexical_all_fields() {
        let toml = r#"
            [security.lexical]
            enabled = true
            banned_keywords = ["porno", "casino", "drogue"]
            strict_keyword_matching = false
            [tld]
            suspicious_tlds = [".biz", ".top", ".xyz"]
        "#;
        let cfg = Config::parse(toml).unwrap();
        assert!(cfg.security.lexical.enabled);
        assert_eq!(
            cfg.security.lexical.banned_keywords,
            vec!["porno", "casino", "drogue"]
        );
        assert!(!cfg.security.lexical.strict_keyword_matching);
        assert_eq!(cfg.tld.suspicious_tlds, vec![".biz", ".top", ".xyz"]);
    }

    #[test]
    fn parse_security_lexical_defaults() {
        // With just enabled, other fields should be defaults
        let toml = r#"
            [security.lexical]
            enabled = false
        "#;
        let cfg = Config::parse(toml).unwrap();
        assert!(!cfg.security.lexical.enabled);
        assert!(cfg.security.lexical.banned_keywords.is_empty());
        assert!(cfg.security.lexical.strict_keyword_matching); // default is true
        assert!(cfg.tld.suspicious_tlds.is_empty());
    }

    #[test]
    fn parse_security_idn_modes() {
        for (mode_str, expected) in [
            ("Off", IdnMode::Off),
            ("Strict", IdnMode::Strict),
            ("Smart", IdnMode::Smart),
        ] {
            let toml = format!(
                r#"
                [security.idn]
                mode = "{}"
            "#,
                mode_str
            );
            let cfg = Config::parse(&toml).unwrap();
            assert_eq!(cfg.security.idn.mode, expected);
        }
    }

    #[test]
    fn parse_security_idn_invalid_mode() {
        let toml = r#"
            [security.idn]
            mode = "invalid"
        "#;
        let result = Config::parse(toml);
        assert!(result.is_err());
    }

    #[test]
    fn parse_security_behavior() {
        let toml = r#"
            [security.behavior]
            nxdomain_threshold = 20
            nxdomain_window = 120
            max_subdomains_per_minute = 100
            max_label_length = 40
        "#;
        let cfg = Config::parse(toml).unwrap();
        assert_eq!(cfg.security.behavior.nxdomain_threshold, 20);
        assert_eq!(cfg.security.behavior.nxdomain_window, 120);
        assert_eq!(cfg.security.behavior.max_subdomains_per_minute, 100);
        assert_eq!(cfg.security.behavior.max_label_length, 40);
    }

    // -----------------------------------------------------------------------
    // Rebinding Shield section
    // -----------------------------------------------------------------------

    #[test]
    fn parse_security_rebinding_shield_all_fields() {
        let toml = r#"
            [security.rebinding_shield]
            enabled = true
            block_ptr_leak = false
        "#;
        let cfg = Config::parse(toml).unwrap();
        assert!(cfg.security.rebinding_shield.enabled);
        assert!(!cfg.security.rebinding_shield.block_ptr_leak);
    }

    #[test]
    fn parse_security_rebinding_shield_defaults() {
        let cfg = Config::parse("").unwrap();
        assert!(cfg.security.rebinding_shield.enabled);
        assert!(cfg.security.rebinding_shield.block_ptr_leak);
    }

    // -----------------------------------------------------------------------
    // Low TTL section
    // -----------------------------------------------------------------------

    #[test]
    fn parse_security_low_ttl_all_fields() {
        let toml = r#"
            [security.low_ttl]
            enabled = true
            threshold_secs = 5
            min_ttl_floor_secs = 30
        "#;
        let cfg = Config::parse(toml).unwrap();
        assert!(cfg.security.low_ttl.enabled);
        assert_eq!(cfg.security.low_ttl.threshold_secs, 5);
        assert_eq!(cfg.security.low_ttl.min_ttl_floor_secs, Some(30));
    }

    #[test]
    fn parse_security_low_ttl_no_floor() {
        let toml = r#"
            [security.low_ttl]
            enabled = true
            threshold_secs = 10
        "#;
        let cfg = Config::parse(toml).unwrap();
        assert_eq!(cfg.security.low_ttl.min_ttl_floor_secs, None);
    }

    #[test]
    fn parse_security_low_ttl_defaults() {
        let cfg = Config::parse("").unwrap();
        assert!(cfg.security.low_ttl.enabled);
        assert_eq!(cfg.security.low_ttl.threshold_secs, 10);
        assert_eq!(cfg.security.low_ttl.min_ttl_floor_secs, None);
    }

    // -----------------------------------------------------------------------
    // SpecialUse section
    // -----------------------------------------------------------------------

    #[test]
    fn parse_security_special_use_all_fields() {
        let toml = r#"
            [security.special_use]
            enabled = true
            extra_local_tlds = [".corp", ".lan", "internal"]
        "#;
        let cfg = Config::parse(toml).unwrap();
        assert!(cfg.security.special_use.enabled);
        assert_eq!(
            cfg.security.special_use.extra_local_tlds,
            vec![".corp", ".lan", "internal"]
        );
    }

    #[test]
    fn parse_security_special_use_disabled() {
        let toml = r#"
            [security.special_use]
            enabled = false
        "#;
        let cfg = Config::parse(toml).unwrap();
        assert!(!cfg.security.special_use.enabled);
        assert!(cfg.security.special_use.extra_local_tlds.is_empty());
    }

    #[test]
    fn parse_security_special_use_defaults() {
        let cfg = Config::parse("").unwrap();
        assert!(cfg.security.special_use.enabled);
        assert!(cfg.security.special_use.extra_local_tlds.is_empty());
    }

    // -----------------------------------------------------------------------
    // GeoIP section
    // -----------------------------------------------------------------------

    #[test]
    fn parse_security_geo_ip_all_fields() {
        let toml = r#"
            [security.geo_ip]
            enabled = true
            database_path = "/tmp/GeoLite2-Country.mmdb"
            suspicious_countries = ["RU", "CN", "KP", "IR"]
            suspicious_country_score = 5
        "#;
        let cfg = Config::parse(toml).unwrap();
        assert!(cfg.security.geo_ip.enabled);
        assert_eq!(
            cfg.security.geo_ip.database_path,
            "/tmp/GeoLite2-Country.mmdb"
        );
        assert_eq!(
            cfg.security.geo_ip.suspicious_countries,
            vec!["RU", "CN", "KP", "IR"]
        );
        assert_eq!(cfg.security.geo_ip.suspicious_country_score, 5);
    }

    #[test]
    fn parse_security_geo_ip_defaults() {
        let cfg = Config::parse("").unwrap();
        assert!(!cfg.security.geo_ip.enabled);
        assert_eq!(
            cfg.security.geo_ip.database_path,
            "/etc/dgaard/GeoLite2-Country.mmdb"
        );
        assert!(cfg.security.geo_ip.suspicious_countries.is_empty());
        assert_eq!(cfg.security.geo_ip.suspicious_country_score, 3);
    }

    // -----------------------------------------------------------------------
    // ASN filter section
    // -----------------------------------------------------------------------

    #[test]
    fn parse_security_asn_filter_all_fields() {
        let toml = r#"
            [security.asn_filter]
            enabled = true
            blocked_ranges = ["203.0.113.0/24", "198.51.100.0/24", "2001:db8::/32"]
        "#;
        let cfg = Config::parse(toml).unwrap();
        assert!(cfg.security.asn_filter.enabled);
        assert_eq!(
            cfg.security.asn_filter.blocked_ranges,
            vec!["203.0.113.0/24", "198.51.100.0/24", "2001:db8::/32"]
        );
    }

    #[test]
    fn parse_security_asn_filter_defaults() {
        let cfg = Config::parse("").unwrap();
        assert!(!cfg.security.asn_filter.enabled);
        assert!(cfg.security.asn_filter.blocked_ranges.is_empty());
    }

    #[test]
    fn parse_security_asn_filter_disabled_empty_ranges() {
        let toml = r#"
            [security.asn_filter]
            enabled = false
        "#;
        let cfg = Config::parse(toml).unwrap();
        assert!(!cfg.security.asn_filter.enabled);
        assert!(cfg.security.asn_filter.blocked_ranges.is_empty());
    }

    // -----------------------------------------------------------------------
    // Upstream section
    // -----------------------------------------------------------------------

    #[test]
    fn parse_upstream() {
        let toml = r#"
            [upstream]
            servers = ["8.8.8.8:53", "8.8.4.4:53"]
            timeout_ms = 5000
            use_0x20_randomization = false
        "#;
        let cfg = Config::parse(toml).unwrap();
        assert_eq!(cfg.upstream.servers, vec!["8.8.8.8:53", "8.8.4.4:53"]);
        assert_eq!(cfg.upstream.timeout_ms, 5000);
        assert!(!cfg.upstream.use_0x20_randomization);
    }

    #[test]
    fn parse_upstream_0x20_defaults_true() {
        let cfg = Config::parse("").unwrap();
        assert!(cfg.upstream.use_0x20_randomization);
    }

    // -----------------------------------------------------------------------
    // TLD section
    // -----------------------------------------------------------------------

    #[test]
    fn parse_tld() {
        let toml = r#"
            [tld]
            allow_only = [".com", ".org"]
            exclude = [".top", ".xyz"]
        "#;
        let cfg = Config::parse(toml).unwrap();
        assert_eq!(cfg.tld.allow_only, vec![".com", ".org"]);
        assert_eq!(cfg.tld.exclude, vec![".top", ".xyz"]);
    }

    // -----------------------------------------------------------------------
    // NXDOMAIN hunting section
    // -----------------------------------------------------------------------

    #[test]
    fn parse_nxdomain_hunting_log() {
        let toml = r#"
            [nxdomain_hunting]
            enabled = true
            threshold = 10
            window_seconds = 30
            action = "log"
        "#;
        let cfg = Config::parse(toml).unwrap();
        assert!(cfg.nxdomain_hunting.enabled);
        assert_eq!(cfg.nxdomain_hunting.threshold, 10);
        assert_eq!(cfg.nxdomain_hunting.window_seconds, 30);
        assert_eq!(cfg.nxdomain_hunting.action, NxdomainAction::Log);
    }

    #[test]
    fn parse_nxdomain_hunting_block() {
        let toml = r#"
            [nxdomain_hunting]
            action = "block_client"
        "#;
        let cfg = Config::parse(toml).unwrap();
        assert_eq!(cfg.nxdomain_hunting.action, NxdomainAction::BlockClient);
    }

    #[test]
    fn parse_nxdomain_hunting_invalid_action() {
        let toml = r#"
            [nxdomain_hunting]
            action = "invalid"
        "#;
        let result = Config::parse(toml);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Tunneling detection section
    // -----------------------------------------------------------------------

    #[test]
    fn parse_tunneling_detection() {
        let toml = r#"
            [tunneling_detection]
            enabled = false
            max_subdomains_per_minute = 25
            max_label_length = 30
        "#;
        let cfg = Config::parse(toml).unwrap();
        assert!(!cfg.tunneling_detection.enabled);
        assert_eq!(cfg.tunneling_detection.max_subdomains_per_minute, 25);
        assert_eq!(cfg.tunneling_detection.max_label_length, 30);
    }

    // -----------------------------------------------------------------------
    // Sources section
    // -----------------------------------------------------------------------

    #[test]
    fn parse_sources() {
        let toml = r#"
            [sources]
            nrd_list_path = "/custom/nrd.txt"
            blacklists = ["/list1.txt", "/list2.txt", "/list3.txt"]
            whitelists = ["/whitelist.txt"]
            update_interval_hours = 12
            retry_delay_mins = 15
            host_index_path = "/tmp/my_index.bin"
            browser_rules_path = "/tmp/browser.txt"
            reload_timeout_secs = 30
        "#;
        let cfg = Config::parse(toml).unwrap();
        assert_eq!(cfg.sources.nrd_list_path, "/custom/nrd.txt");
        assert_eq!(
            cfg.sources.blacklists,
            vec!["/list1.txt", "/list2.txt", "/list3.txt"]
        );
        assert_eq!(cfg.sources.whitelists, vec!["/whitelist.txt"]);
        assert_eq!(cfg.sources.update_interval_hours, 12);
        assert_eq!(cfg.sources.retry_delay_mins, 15);
        assert_eq!(cfg.sources.host_index_path, "/tmp/my_index.bin");
        assert_eq!(cfg.sources.browser_rules_path, "/tmp/browser.txt");
        assert_eq!(cfg.sources.reload_timeout_secs, 30);
    }

    #[test]
    fn parse_sources_reload_timeout_default() {
        let cfg = Config::parse("[sources]").unwrap();
        assert_eq!(cfg.sources.reload_timeout_secs, 15);
    }

    #[test]
    fn parse_sources_reload_timeout_zero_disables() {
        let toml = r#"
            [sources]
            reload_timeout_secs = 0
        "#;
        let cfg = Config::parse(toml).unwrap();
        assert_eq!(cfg.sources.reload_timeout_secs, 0);
    }

    #[test]
    fn parse_sources_host_index_disabled() {
        let toml = r#"
            [sources]
            host_index_path = ""
        "#;
        let cfg = Config::parse(toml).unwrap();
        assert_eq!(cfg.sources.host_index_path, "");
    }

    #[test]
    fn parse_sources_browser_rules_disabled() {
        let toml = r#"
            [sources]
            browser_rules_path = ""
        "#;
        let cfg = Config::parse(toml).unwrap();
        assert_eq!(cfg.sources.browser_rules_path, "");
    }

    // -----------------------------------------------------------------------
    // ABP section
    // -----------------------------------------------------------------------

    #[test]
    fn parse_abp() {
        let toml = r#"
            [abp]
            extract_domain_only = false
            update_interval = 48
        "#;
        let cfg = Config::parse(toml).unwrap();
        assert!(!cfg.abp.extract_domain_only);
        assert_eq!(cfg.abp.update_interval, 48);
    }

    // -----------------------------------------------------------------------
    // Cache section
    // -----------------------------------------------------------------------

    #[test]
    fn parse_cache() {
        let toml = r#"
            [cache]
            enabled = false
            max_entries = 50000
            ttl_override = 300
        "#;
        let cfg = Config::parse(toml).unwrap();
        assert!(!cfg.cache.enabled);
        assert_eq!(cfg.cache.max_entries, 50000);
        assert_eq!(cfg.cache.ttl_override, 300);
    }

    // -----------------------------------------------------------------------
    // Memory section
    // -----------------------------------------------------------------------

    #[test]
    fn parse_memory() {
        let toml = r#"
            [memory]
            cache_enabled = false
            cache_size = 10000
            use_bloom_filter = false
            expected_total_domains = 500000
        "#;
        let cfg = Config::parse(toml).unwrap();
        assert!(!cfg.memory.cache_enabled);
        assert_eq!(cfg.memory.cache_size, 10000);
        assert!(!cfg.memory.use_bloom_filter);
        assert_eq!(cfg.memory.expected_total_domains, 500000);
    }

    // -----------------------------------------------------------------------
    // Full example config
    // -----------------------------------------------------------------------

    #[test]
    fn parse_example_config_file() {
        let path = temp_file(
            "config.toml",
            r#"
            [server]
            listen_addr = "192.168.1.1:53"
            allowed_networks = ["127.0.0.1/32", "192.168.1.0/24"]
            stats_socket_path = "/tmp/dgaard_stats.sock"
            block_idn = true
            pipeline = ["Whitelist", "HotCache", "StaticBlock", "SuffixMatch", "Heuristics", "Upstream"]

            [server.runtime]
            worker_threads = "auto"
            stack_size = 2097152
            max_blocking_threads = 512

            [security.structure]
            max_subdomain_depth = 5
            max_domain_length = 128
            force_lowercase_ascii = true
            max_txt_record_length = 128
            max_answers_per_query = 10

            [security.intelligence]
            enabled = true
            entropy_threshold = 4.0
            min_word_length = 8
            consonant_ratio_threshold = 0.6
            max_consonant_sequence = 5
            use_ngram_model = false
            ngram_use_embedded = true
            ngram_embedded_languages = ["english", "french"]
            ngram_models = ["/etc/dgaard/models/english.bin", "/etc/dgaard/models/french.bin"]
            ngram_probability_threshold = -4.0

            [security.idn]
            mode = "Smart"
            allowed_scripts = ["Latin", "WesternEuropean"]

            [security.behavior]
            nxdomain_threshold = 15
            nxdomain_window = 60
            max_subdomains_per_minute = 50
            max_label_length = 60

            [upstream]
            servers = ["1.1.1.1:53", "9.9.9.9:53"]
            timeout_ms = 2000

            [tld]
            exclude = [".top", ".xyz", ".bid"]

            [nxdomain_hunting]
            enabled = true
            threshold = 15
            window_seconds = 60
            action = "log"

            [tunneling_detection]
            enabled = true
            max_subdomains_per_minute = 50
            max_label_length = 60

            [sources]
            nrd_list_path = "/tmp/nrd_daily.txt"
            blacklists = ["/etc/dgaard/lists/adaway.txt", "/etc/dgaard/lists/malware_domains.txt"]
            whitelists = ["/etc/dgaard/lists/personal_whitelist.txt", "/etc/dgaard/lists/cdn_providers.txt"]
            update_interval_hours = 24
            retry_delay_mins = 30

            [abp]
            extract_domain_only = true
            update_interval = 24

            [cache]
            enabled = true
            max_entries = 10000
            ttl_override = 0

            [memory]
            cache_enabled = true
            cache_size = 5000
            use_bloom_filter = true
            expected_total_domains = 1000000
        "#,
        );

        let cfg = Config::load(&path).unwrap();

        // Verify key fields
        assert_eq!(cfg.server.listen_addr, "192.168.1.1:53");
        assert!(cfg.server.block_idn);
        assert_eq!(cfg.server.pipeline.len(), 6);
        assert_eq!(cfg.server.runtime.worker_threads, WorkerThreads::Auto);

        assert_eq!(cfg.security.structure.max_subdomain_depth, 5);
        assert!(cfg.security.intelligence.enabled);
        assert_eq!(cfg.security.idn.mode, IdnMode::Smart);
        assert_eq!(cfg.security.behavior.nxdomain_threshold, 15);

        assert_eq!(cfg.upstream.servers, vec!["1.1.1.1:53", "9.9.9.9:53"]);
        assert_eq!(cfg.tld.exclude, vec![".top", ".xyz", ".bid"]);

        assert!(cfg.nxdomain_hunting.enabled);
        assert!(cfg.tunneling_detection.enabled);

        assert_eq!(cfg.sources.blacklists.len(), 2);
        assert!(cfg.abp.extract_domain_only);
        assert!(cfg.cache.enabled);
        assert!(cfg.memory.use_bloom_filter);

        cleanup(&path);
    }

    // -----------------------------------------------------------------------
    // Error handling
    // -----------------------------------------------------------------------

    #[test]
    fn parse_invalid_toml_syntax() {
        let toml = r#"
            [server
            listen_addr = "127.0.0.1:53"
        "#;
        let result = Config::parse(toml);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ConfigError::Parse(_)));
    }

    #[test]
    fn parse_wrong_type_for_string() {
        let toml = r#"
            [server]
            listen_addr = 12345
        "#;
        let result = Config::parse(toml);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ConfigError::InvalidType { .. }
        ));
    }

    #[test]
    fn parse_wrong_type_for_bool() {
        let toml = r#"
            [server]
            block_idn = "yes"
        "#;
        let result = Config::parse(toml);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ConfigError::InvalidType { .. }
        ));
    }

    #[test]
    fn parse_wrong_type_for_integer() {
        let toml = r#"
            [upstream]
            timeout_ms = "fast"
        "#;
        let result = Config::parse(toml);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ConfigError::InvalidType { .. }
        ));
    }

    #[test]
    fn parse_wrong_type_for_array() {
        let toml = r#"
            [upstream]
            servers = "1.1.1.1:53"
        "#;
        let result = Config::parse(toml);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ConfigError::InvalidType { .. }
        ));
    }

    #[test]
    fn load_nonexistent_file_returns_io_error() {
        let result = Config::load(Path::new("/nonexistent/path/to/config.toml"));
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ConfigError::Io(_)));
    }

    // -----------------------------------------------------------------------
    // Integer-as-float parsing
    // -----------------------------------------------------------------------

    #[test]
    fn parse_integer_as_float() {
        let toml = r#"
            [security.intelligence]
            entropy_threshold = 4
        "#;
        let cfg = Config::parse(toml).unwrap();
        assert!((cfg.security.intelligence.entropy_threshold - 4.0).abs() < f32::EPSILON);
    }

    // -----------------------------------------------------------------------
    // Helper function unit tests
    // -----------------------------------------------------------------------

    /// Parse a TOML key=value string and call `f` with the root table.
    fn with_table<F, R>(toml: &str, f: F) -> R
    where
        F: for<'a> FnOnce(&'a toml_span::value::Table<'a>) -> R,
    {
        let val = toml_span::parse(toml).unwrap();
        match val.as_ref() {
            ValueInner::Table(t) => f(t),
            _ => panic!("expected table"),
        }
    }

    // --- get_str ---

    #[test]
    fn get_str_returns_value_for_existing_key() {
        with_table(r#"name = "dgaard""#, |t| {
            assert_eq!(get_str(t, "name").unwrap(), Some("dgaard"));
        });
    }

    #[test]
    fn get_str_returns_none_for_missing_key() {
        with_table(r#"name = "dgaard""#, |t| {
            assert_eq!(get_str(t, "missing").unwrap(), None);
        });
    }

    #[test]
    fn get_str_returns_error_for_wrong_type() {
        with_table(r#"port = 53"#, |t| {
            let err = get_str(t, "port").unwrap_err();
            assert!(matches!(err, ConfigError::InvalidType { ref key, .. } if key == "port"));
        });
    }

    // --- require_str ---

    #[test]
    fn require_str_returns_value_for_existing_key() {
        with_table(r#"addr = "127.0.0.1""#, |t| {
            let span = toml_span::Span::default();
            assert_eq!(require_str(t, "addr", span).unwrap(), "127.0.0.1");
        });
    }

    #[test]
    fn require_str_returns_missing_key_error() {
        with_table(r#"addr = "127.0.0.1""#, |t| {
            let span = toml_span::Span::default();
            let err = require_str(t, "host", span).unwrap_err();
            assert!(matches!(err, ConfigError::MissingKey { ref key, .. } if key == "host"));
        });
    }

    // --- get_bool ---

    #[test]
    fn get_bool_returns_true() {
        with_table(r#"enabled = true"#, |t| {
            assert_eq!(get_bool(t, "enabled").unwrap(), Some(true));
        });
    }

    #[test]
    fn get_bool_returns_false() {
        with_table(r#"enabled = false"#, |t| {
            assert_eq!(get_bool(t, "enabled").unwrap(), Some(false));
        });
    }

    #[test]
    fn get_bool_returns_none_for_missing_key() {
        with_table(r#"x = 1"#, |t| {
            assert_eq!(get_bool(t, "enabled").unwrap(), None);
        });
    }

    #[test]
    fn get_bool_returns_error_for_wrong_type() {
        with_table(r#"enabled = "yes""#, |t| {
            let err = get_bool(t, "enabled").unwrap_err();
            assert!(matches!(err, ConfigError::InvalidType { ref key, .. } if key == "enabled"));
        });
    }

    // --- get_integer ---

    #[test]
    fn get_integer_returns_value() {
        with_table(r#"port = 5353"#, |t| {
            assert_eq!(get_integer(t, "port").unwrap(), Some(5353));
        });
    }

    #[test]
    fn get_integer_returns_negative_value() {
        with_table(r#"offset = -42"#, |t| {
            assert_eq!(get_integer(t, "offset").unwrap(), Some(-42));
        });
    }

    #[test]
    fn get_integer_returns_none_for_missing_key() {
        with_table(r#"x = 1"#, |t| {
            assert_eq!(get_integer(t, "port").unwrap(), None);
        });
    }

    #[test]
    fn get_integer_returns_error_for_wrong_type() {
        with_table(r#"port = "53""#, |t| {
            let err = get_integer(t, "port").unwrap_err();
            assert!(matches!(err, ConfigError::InvalidType { ref key, .. } if key == "port"));
        });
    }

    // --- get_float ---

    #[test]
    fn get_float_returns_float_value() {
        with_table(r#"threshold = 3.25"#, |t| {
            let v = get_float(t, "threshold").unwrap().unwrap();
            assert!((v - 3.25_f32).abs() < f32::EPSILON);
        });
    }

    #[test]
    fn get_float_coerces_integer() {
        with_table(r#"threshold = 4"#, |t| {
            let v = get_float(t, "threshold").unwrap().unwrap();
            assert!((v - 4.0).abs() < f32::EPSILON);
        });
    }

    #[test]
    fn get_float_returns_none_for_missing_key() {
        with_table(r#"x = 1"#, |t| {
            assert_eq!(get_float(t, "threshold").unwrap(), None);
        });
    }

    #[test]
    fn get_float_returns_error_for_wrong_type() {
        with_table(r#"threshold = "high""#, |t| {
            let err = get_float(t, "threshold").unwrap_err();
            assert!(matches!(err, ConfigError::InvalidType { ref key, .. } if key == "threshold"));
        });
    }

    // --- get_string_array ---

    #[test]
    fn get_string_array_returns_vec() {
        with_table(r#"servers = ["1.1.1.1", "9.9.9.9"]"#, |t| {
            assert_eq!(
                get_string_array(t, "servers").unwrap(),
                Some(vec!["1.1.1.1".to_string(), "9.9.9.9".to_string()])
            );
        });
    }

    #[test]
    fn get_string_array_returns_empty_vec() {
        with_table(r#"servers = []"#, |t| {
            assert_eq!(get_string_array(t, "servers").unwrap(), Some(vec![]));
        });
    }

    #[test]
    fn get_string_array_returns_none_for_missing_key() {
        with_table(r#"x = 1"#, |t| {
            assert_eq!(get_string_array(t, "servers").unwrap(), None);
        });
    }

    #[test]
    fn get_string_array_returns_error_for_non_array() {
        with_table(r#"servers = "1.1.1.1""#, |t| {
            let err = get_string_array(t, "servers").unwrap_err();
            assert!(matches!(err, ConfigError::InvalidType { ref key, .. } if key == "servers"));
        });
    }

    #[test]
    fn get_string_array_returns_error_for_non_string_element() {
        with_table(r#"ports = [53, 853]"#, |t| {
            let err = get_string_array(t, "ports").unwrap_err();
            assert!(matches!(err, ConfigError::InvalidType { ref key, .. } if key == "ports[]"));
        });
    }

    // --- get_table ---

    #[test]
    fn get_table_returns_nested_table() {
        with_table(
            r#"
            [server]
            port = 53
        "#,
            |t| {
                let nested = get_table(t, "server").unwrap();
                assert!(nested.is_some());
                let server = nested.unwrap();
                assert!(server.get("port").is_some());
            },
        );
    }

    #[test]
    fn get_table_returns_none_for_missing_key() {
        with_table(r#"x = 1"#, |t| {
            assert!(get_table(t, "server").unwrap().is_none());
        });
    }

    #[test]
    fn get_table_returns_error_for_non_table() {
        with_table(r#"server = "localhost""#, |t| {
            let err = get_table(t, "server").unwrap_err();
            assert!(matches!(err, ConfigError::InvalidType { ref key, .. } if key == "server"));
        });
    }

    // -----------------------------------------------------------------------
    // custom_flags
    // -----------------------------------------------------------------------

    fn toml_config(content: &str) -> tempfile::NamedTempFile {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f
    }

    #[test]
    fn parse_custom_flags_empty_when_absent() {
        let f = toml_config("[security]\n");
        let cfg = Config::load(f.path()).unwrap();
        assert!(cfg.security.custom_flags.is_empty());
    }

    #[test]
    fn parse_custom_flags_single_entry() {
        let f = toml_config(
            r#"
[[security.custom_flags]]
bit = 16
code = "AI_GENERATED"
name = "AI-Generated Domain"
description = "Domains flagged as AI-generated."
suspicious_score = 4
list_path = ["/etc/dgaard/ai-domains.txt"]
"#,
        );
        let cfg = Config::load(f.path()).unwrap();
        assert_eq!(cfg.security.custom_flags.len(), 1);
        let flag = &cfg.security.custom_flags[0];
        assert_eq!(flag.bit, 16);
        assert_eq!(flag.code, "AI_GENERATED");
        assert_eq!(flag.name, "AI-Generated Domain");
        assert_eq!(flag.suspicious_score, 4);
        assert_eq!(flag.list_path, vec!["/etc/dgaard/ai-domains.txt"]);
    }

    #[test]
    fn parse_custom_flags_multiple_entries() {
        let f = toml_config(
            r#"
[[security.custom_flags]]
bit = 16
code = "AI_GENERATED"
suspicious_score = 4
list_path = []

[[security.custom_flags]]
bit = 17
code = "HONEYPOT"
suspicious_score = 8
list_path = ["/etc/dgaard/honeypots.txt"]
"#,
        );
        let cfg = Config::load(f.path()).unwrap();
        assert_eq!(cfg.security.custom_flags.len(), 2);
        assert_eq!(cfg.security.custom_flags[0].bit, 16);
        assert_eq!(cfg.security.custom_flags[1].bit, 17);
        assert_eq!(cfg.security.custom_flags[1].code, "HONEYPOT");
    }

    #[test]
    fn parse_custom_flags_bit_below_16_is_rejected() {
        let f = toml_config(
            r#"
[[security.custom_flags]]
bit = 15
code = "BAD"
suspicious_score = 1
list_path = []
"#,
        );
        assert!(
            Config::load(f.path()).is_err(),
            "bit 15 (built-in range) should be rejected"
        );
    }

    #[test]
    fn parse_custom_flags_bit_above_31_is_rejected() {
        let f = toml_config(
            r#"
[[security.custom_flags]]
bit = 32
code = "BAD"
suspicious_score = 1
list_path = []
"#,
        );
        assert!(
            Config::load(f.path()).is_err(),
            "bit 32 (out of u32 custom range) should be rejected"
        );
    }

    #[test]
    fn parse_custom_flags_duplicate_bit_is_rejected() {
        let f = toml_config(
            r#"
[[security.custom_flags]]
bit = 20
code = "FIRST"
suspicious_score = 2
list_path = []

[[security.custom_flags]]
bit = 20
code = "SECOND"
suspicious_score = 3
list_path = []
"#,
        );
        assert!(
            Config::load(f.path()).is_err(),
            "duplicate bit index should be rejected"
        );
    }

    #[test]
    fn parse_custom_flags_max_16_entries_accepted() {
        let mut toml = String::new();
        for i in 0..16u8 {
            toml.push_str(&format!(
                "[[security.custom_flags]]\nbit = {}\ncode = \"F{}\"\nsuspicious_score = 1\nlist_path = []\n\n",
                16 + i, i
            ));
        }
        let f = toml_config(&toml);
        let cfg = Config::load(f.path()).unwrap();
        assert_eq!(cfg.security.custom_flags.len(), 16);
    }

    #[test]
    fn parse_custom_flags_17_entries_rejected() {
        let mut toml = String::new();
        for i in 0..17u8 {
            toml.push_str(&format!(
                "[[security.custom_flags]]\nbit = {}\ncode = \"F{}\"\nsuspicious_score = 1\nlist_path = []\n\n",
                16 + i, i
            ));
        }
        let f = toml_config(&toml);
        assert!(
            Config::load(f.path()).is_err(),
            "17 entries (> max 16) should be rejected"
        );
    }

    #[test]
    fn parse_custom_flags_missing_bit_is_rejected() {
        let f = toml_config(
            r#"
[[security.custom_flags]]
code = "NOBIT"
suspicious_score = 1
list_path = []
"#,
        );
        assert!(
            Config::load(f.path()).is_err(),
            "missing required 'bit' field should be rejected"
        );
    }

    #[test]
    fn parse_custom_flags_missing_code_is_rejected() {
        let f = toml_config(
            r#"
[[security.custom_flags]]
bit = 16
suspicious_score = 1
list_path = []
"#,
        );
        assert!(
            Config::load(f.path()).is_err(),
            "missing required 'code' field should be rejected"
        );
    }

    #[test]
    fn parse_custom_flags_optional_fields_default() {
        let f = toml_config(
            r#"
[[security.custom_flags]]
bit = 31
code = "MINIMAL"
"#,
        );
        let cfg = Config::load(f.path()).unwrap();
        let flag = &cfg.security.custom_flags[0];
        assert_eq!(flag.bit, 31);
        assert_eq!(flag.name, "");
        assert_eq!(flag.description, "");
        assert_eq!(flag.suspicious_score, 1);
        assert!(flag.list_path.is_empty());
    }
}
