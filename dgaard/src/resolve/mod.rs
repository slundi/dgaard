//! DNS query resolution with configurable filter pipeline.
//!
//! This module implements the core domain resolution logic that checks
//! incoming DNS queries against various filters (whitelist, blocklist,
//! heuristics, etc.) based on the configured pipeline order.
//!
//! Pipeline flow:
//! ```
//!   Domain → Whitelist → HotCache → StaticBlock → SuffixMatch → Heuristics → Upstream
//!                                                                 ↓
//!                                                 ┌─────────────────────────────────┐
//!                                                 │ 1. Entropy check (threshold)    │
//!                                                 │ 2. Consonant ratio/sequence     │
//!                                                 │ 3. N-gram language models (OR)  │
//!                                                 └─────────────────────────────────┘
//! ``````

mod heuristics;
mod matcher;
mod patterns;
mod qtype;
mod scoring;

pub use qtype::check_qtype;
pub use scoring::{compute_score, score_answer};

use crate::CONFIG;
use crate::config::PipelineStep;
use crate::model::{Action, BlockReason, SuspicionScore};
use crate::resolve::heuristics::{check_dga_heuristics, check_lexical, is_illegal_idn};
use crate::resolve::matcher::{is_blocked, is_suffix_blocked, is_whitelisted};
use crate::resolve::patterns::{is_regex_blocked, is_wildcard_pattern_blocked};

/// Result of checking a domain against the filter engine.
#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)] // For future engine query API
pub enum FilterResult {
    /// Domain is whitelisted - allow immediately
    Whitelisted,
    /// Domain is blocked by static list
    Blocked,
    /// Domain matches a regex pattern
    RegexBlocked,
    /// Domain is not found in any list
    NotFound,
}

/// Check if domain exceeds structural limits (depth, length).
pub fn is_structure_invalid(domain: &str) -> bool {
    let config = CONFIG.load();
    let structure = &config.security.structure;

    // Check total length
    if domain.len() > structure.max_domain_length as usize {
        return true;
    }

    // Check subdomain depth (number of dots)
    let depth = domain.bytes().filter(|&b| b == b'.').count();
    if depth > structure.max_subdomain_depth as usize {
        return true;
    }

    // Check ASCII-only requirement
    if structure.force_lowercase_ascii && !domain.is_ascii() {
        return true;
    }

    false
}

/// Result of domain resolution including the suspicion score.
#[derive(Debug, Clone)]
pub struct ResolveResult {
    /// The action to take for this query
    pub action: Action,
    /// Computed suspicion score (for logging/telemetry)
    pub score: SuspicionScore,
}

/// Resolution function that also returns the computed suspicion score.
///
/// Use this when you need access to the suspicion score for logging or telemetry.
/// The score is computed but does NOT currently affect blocking decisions.
///
/// # Arguments
/// * `domain` - The domain name to resolve (lowercase, no trailing dot)
///
/// # Returns
/// A `ResolveResult` containing the action and suspicion score.
pub fn resolve_with_score(domain: &str) -> ResolveResult {
    let config = CONFIG.load();

    // Compute suspicion score (for logging/telemetry - not blocking yet)
    let score = compute_score(domain);

    // Pre-pipeline: structural sanity checks (gatekeeper)
    if is_structure_invalid(domain) {
        return ResolveResult {
            action: Action::Block(BlockReason::InvalidStructure),
            score,
        };
    }

    // Pre-pipeline: IDN check if enabled
    if is_illegal_idn(domain) {
        return ResolveResult {
            action: Action::Block(BlockReason::SuspiciousIdn),
            score,
        };
    }

    // Process each pipeline step in order
    for step in &config.server.pipeline {
        match step {
            PipelineStep::Whitelist => {
                if is_whitelisted(domain) {
                    return ResolveResult {
                        action: Action::Allow,
                        score,
                    };
                }
            }
            PipelineStep::HotCache => {
                // TODO: Implement LRU cache lookup
                // For now, skip this step
            }
            PipelineStep::StaticBlock => {
                if is_blocked(domain) {
                    return ResolveResult {
                        action: Action::Block(BlockReason::StaticBlacklist(String::from(
                            "blocklist",
                        ))),
                        score,
                    };
                }
            }
            PipelineStep::SuffixMatch => {
                if is_suffix_blocked(domain) {
                    return ResolveResult {
                        action: Action::Block(BlockReason::AbpRule(String::from("wildcard"))),
                        score,
                    };
                }
                if is_wildcard_pattern_blocked(domain) {
                    return ResolveResult {
                        action: Action::Block(BlockReason::AbpRule(String::from("glob"))),
                        score,
                    };
                }
                if is_regex_blocked(domain) {
                    return ResolveResult {
                        action: Action::Block(BlockReason::AbpRule(String::from("regex"))),
                        score,
                    };
                }
            }
            PipelineStep::Heuristics => {
                // Lexical/keyword filtering (parental control)
                if let Some(reason) = check_lexical(domain) {
                    return ResolveResult {
                        action: Action::Block(reason),
                        score,
                    };
                }
                // DGA heuristics (entropy, consonant clustering, n-grams)
                if let Some(reason) = check_dga_heuristics(domain) {
                    return ResolveResult {
                        action: Action::Block(reason),
                        score,
                    };
                }
            }
            PipelineStep::Upstream => {
                return ResolveResult {
                    action: Action::ProxyToUpstream,
                    score,
                };
            }
        }
    }

    // Safety fallback if pipeline doesn't end with Upstream
    ResolveResult {
        action: Action::ProxyToUpstream,
        score,
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::filter::engine::FilterEngine;
    use crate::model::DomainEntryFlags;
    use crate::{CURRENT_ENGINE, GLOBAL_SEED};
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;
    use std::sync::atomic::Ordering;

    pub fn init_test_env() {
        GLOBAL_SEED.store(42, Ordering::Relaxed);
    }

    pub fn create_test_engine(
        blocklist: &[&str],
        whitelist: &[&str],
        wildcards: &[&str],
    ) -> FilterEngine {
        let mut fast_map = HashMap::new();

        // Add blocked domains
        for domain in blocklist {
            let hash = twox_hash::XxHash64::oneshot(42, domain.as_bytes());
            fast_map.insert(hash, DomainEntryFlags::NONE.bits());
        }

        // Add whitelisted domains
        for domain in whitelist {
            let hash = twox_hash::XxHash64::oneshot(42, domain.as_bytes());
            fast_map.insert(hash, DomainEntryFlags::WHITELIST.bits());
        }

        // Add wildcard domains to hierarchical list
        let mut hierarchical_list = Vec::new();
        for domain in wildcards {
            let hash = twox_hash::XxHash64::oneshot(42, domain.as_bytes());
            hierarchical_list.push(crate::model::DomainEntry {
                hash,
                flags: DomainEntryFlags::WILDCARD,
                depth: domain.bytes().filter(|&b| b == b'.').count() as u8,
                data_idx: 0,
            });
        }
        hierarchical_list.sort_by_key(|e| e.hash);

        FilterEngine {
            fast_map,
            hierarchical_list,
            regex_pool: Vec::new(),
            wildcard_patterns: Vec::new(),
            keyword_automaton: None,
            keyword_patterns: Vec::new(),
            suspicious_tld_hashes: HashSet::new(),
            lexical_strict: true,
            blocked_asn_v4: Vec::new(),
            blocked_asn_v6: Vec::new(),
        }
    }

    #[test]
    fn test_is_structure_invalid_depth() {
        init_test_env();
        // Normal depth
        assert!(!is_structure_invalid("sub.example.com"));

        // Excessive depth (tunneling-like)
        assert!(is_structure_invalid("a.b.c.d.e.f.g.h.i.j.k.example.com"));
    }

    #[test]
    fn test_is_structure_invalid_length() {
        init_test_env();
        // Very long domain
        let long_domain = format!("{}.com", "a".repeat(200));
        assert!(is_structure_invalid(&long_domain));
    }

    #[test]
    fn test_resolve_blocked_domain() {
        init_test_env();
        let engine = create_test_engine(&["ads.tracker.com"], &[], &[]);
        CURRENT_ENGINE.store(Arc::new(engine));

        let action = resolve_with_score("ads.tracker.com").action;
        assert!(matches!(
            action,
            Action::Block(BlockReason::StaticBlacklist(_))
        ));
    }

    #[test]
    fn test_resolve_whitelisted_domain() {
        init_test_env();
        let engine = create_test_engine(&[], &["trusted.example.com"], &[]);
        CURRENT_ENGINE.store(Arc::new(engine));

        let action = resolve_with_score("trusted.example.com").action;
        assert!(matches!(action, Action::Allow));
    }

    #[test]
    fn test_resolve_unknown_domain_proxied() {
        init_test_env();
        let engine = create_test_engine(&[], &[], &[]);
        CURRENT_ENGINE.store(Arc::new(engine));

        let action = resolve_with_score("unknown.example.com").action;
        assert!(matches!(action, Action::ProxyToUpstream));
    }

    #[test]
    fn test_resolve_invalid_structure_blocked() {
        init_test_env();
        let engine = create_test_engine(&[], &[], &[]);
        CURRENT_ENGINE.store(Arc::new(engine));

        // Excessive subdomain depth
        let action = resolve_with_score("a.b.c.d.e.f.g.h.i.j.k.example.com").action;
        assert!(matches!(
            action,
            Action::Block(BlockReason::InvalidStructure)
        ));
    }

    #[test]
    fn test_resolve_idn_blocked() {
        init_test_env();
        let engine = create_test_engine(&[], &[], &[]);
        CURRENT_ENGINE.store(Arc::new(engine));

        let action = resolve_with_score("xn--pple-43d.com").action;
        assert!(matches!(action, Action::Block(BlockReason::SuspiciousIdn)));
    }

    // --- Tests for TLD blocking ---

    pub fn create_engine_with_tld_block(tlds: &[&str]) -> FilterEngine {
        let mut hierarchical_list = Vec::new();
        for tld in tlds {
            // Strip leading dot if present (mimics load_tld_filters behavior)
            let tld_clean = tld.strip_prefix('.').unwrap_or(tld);
            let hash = twox_hash::XxHash64::oneshot(42, tld_clean.as_bytes());
            hierarchical_list.push(crate::model::DomainEntry {
                hash,
                flags: DomainEntryFlags::WILDCARD,
                depth: 0,
                data_idx: 0,
            });
        }
        hierarchical_list.sort_by_key(|e| e.hash);

        FilterEngine {
            fast_map: HashMap::new(),
            hierarchical_list,
            regex_pool: Vec::new(),
            wildcard_patterns: Vec::new(),
            keyword_automaton: None,
            keyword_patterns: Vec::new(),
            suspicious_tld_hashes: HashSet::new(),
            lexical_strict: true,
            blocked_asn_v4: Vec::new(),
            blocked_asn_v6: Vec::new(),
        }
    }

    #[test]
    fn test_resolve_tld_blocked_domain() {
        init_test_env();
        let engine = create_engine_with_tld_block(&["xyz"]);
        CURRENT_ENGINE.store(Arc::new(engine));

        let action = resolve_with_score("malware.xyz").action;
        assert!(
            matches!(action, Action::Block(BlockReason::AbpRule(_))),
            "Domain under blocked TLD should be blocked, got: {:?}",
            action
        );
    }

    // --- Tests for wildcard pattern matching ---

    pub fn create_engine_with_wildcard_patterns(patterns: &[&str]) -> FilterEngine {
        FilterEngine {
            fast_map: HashMap::new(),
            hierarchical_list: Vec::new(),
            regex_pool: Vec::new(),
            wildcard_patterns: patterns.iter().map(|s| s.to_string()).collect(),
            keyword_automaton: None,
            keyword_patterns: Vec::new(),
            suspicious_tld_hashes: HashSet::new(),
            lexical_strict: true,
            blocked_asn_v4: Vec::new(),
            blocked_asn_v6: Vec::new(),
        }
    }

    #[test]
    fn test_resolve_wildcard_pattern_blocked() {
        init_test_env();
        let engine = create_engine_with_wildcard_patterns(&["ads*.example.com"]);
        CURRENT_ENGINE.store(Arc::new(engine));

        let action = resolve_with_score("ads1.example.com").action;
        assert!(
            matches!(action, Action::Block(BlockReason::AbpRule(ref s)) if s == "glob"),
            "Domain matching wildcard pattern should be blocked with 'glob' reason, got: {:?}",
            action
        );
    }

    #[test]
    fn test_resolve_wildcard_pattern_not_matched() {
        init_test_env();
        let engine = create_engine_with_wildcard_patterns(&["ads*.example.com"]);
        CURRENT_ENGINE.store(Arc::new(engine));

        let action = resolve_with_score("safe.example.com").action;
        assert!(
            matches!(action, Action::ProxyToUpstream),
            "Domain not matching pattern should be proxied, got: {:?}",
            action
        );
    }

    // --- Tests for lexical/keyword filtering (parental control) ---

    pub fn create_lexical_config(
        keywords: &[&str],
        strict: bool,
        suspicious_tlds: &[&str],
    ) -> crate::config::Config {
        let mut config = crate::config::Config::default();
        config.security.lexical.enabled = true;
        config.security.lexical.banned_keywords = keywords.iter().map(|s| s.to_string()).collect();
        config.security.lexical.strict_keyword_matching = strict;
        config.tld.suspicious_tlds = suspicious_tlds.iter().map(|s| s.to_string()).collect();
        config
    }

    pub fn create_lexical_engine(
        keywords: &[&str],
        strict: bool,
        suspicious_tlds: &[&str],
    ) -> FilterEngine {
        use aho_corasick::AhoCorasick;

        let keyword_patterns: Vec<String> = keywords.iter().map(|k| k.to_lowercase()).collect();
        let keyword_automaton = if keyword_patterns.is_empty() {
            None
        } else {
            AhoCorasick::new(&keyword_patterns).ok()
        };

        let suspicious_tld_hashes: HashSet<u64> = suspicious_tlds
            .iter()
            .map(|tld| {
                let tld_clean = tld.strip_prefix('.').unwrap_or(tld).to_ascii_lowercase();
                twox_hash::XxHash64::oneshot(42, tld_clean.as_bytes())
            })
            .collect();

        FilterEngine {
            fast_map: HashMap::new(),
            hierarchical_list: Vec::new(),
            regex_pool: Vec::new(),
            wildcard_patterns: Vec::new(),
            keyword_automaton,
            keyword_patterns,
            suspicious_tld_hashes,
            lexical_strict: strict,
            blocked_asn_v4: Vec::new(),
            blocked_asn_v6: Vec::new(),
        }
    }

    #[test]
    fn test_resolve_lexical_blocked() {
        init_test_env();
        let config = create_lexical_config(&["porno"], true, &[]);
        crate::CONFIG.store(Arc::new(config));
        let engine = create_lexical_engine(&["porno"], true, &[]);
        CURRENT_ENGINE.store(Arc::new(engine));

        let action = resolve_with_score("porno.com").action;
        assert!(
            matches!(action, Action::Block(BlockReason::BannedKeyword(ref k)) if k == "porno"),
            "Domain with banned keyword should be blocked, got: {:?}",
            action
        );
    }

    #[test]
    fn test_resolve_lexical_allowed() {
        init_test_env();
        let config = create_lexical_config(&["porno"], true, &[]);
        crate::CONFIG.store(Arc::new(config));
        let engine = create_lexical_engine(&["porno"], true, &[]);
        CURRENT_ENGINE.store(Arc::new(engine));

        let action = resolve_with_score("google.com").action;
        assert!(
            matches!(action, Action::ProxyToUpstream),
            "Domain without banned keyword should be proxied, got: {:?}",
            action
        );
    }

    // --- Tests for resolve_with_score ---

    #[test]
    fn test_resolve_with_score_normal_domain() {
        init_test_env();
        let engine = create_test_engine(&[], &[], &[]);
        CURRENT_ENGINE.store(Arc::new(engine));

        let result = super::resolve_with_score("google.com");
        assert!(matches!(result.action, Action::ProxyToUpstream));
        assert_eq!(result.score.total, 0);
    }

    #[test]
    fn test_resolve_with_score_suspicious_domain() {
        init_test_env();
        let engine = create_test_engine(&[], &[], &[]);
        CURRENT_ENGINE.store(Arc::new(engine));

        // Punycode domain should have non-zero score
        let result = super::resolve_with_score("xn--pple-43d.com");
        // Domain is blocked by IDN check in resolve, but score is computed
        assert!(matches!(
            result.action,
            Action::Block(BlockReason::SuspiciousIdn)
        ));
        assert!(
            result.score.total > 0,
            "Expected non-zero score for IDN domain"
        );
    }

    #[test]
    fn test_resolve_with_score_high_entropy() {
        init_test_env();
        let config = crate::config::Config::default();
        crate::CONFIG.store(Arc::new(config));
        let engine = create_test_engine(&[], &[], &[]);
        CURRENT_ENGINE.store(Arc::new(engine));

        // High entropy domain (random-looking SLD)
        let result = super::resolve_with_score("a1b2c3d4e5f6g7h8i9j0.com");
        // Score should reflect high entropy
        assert!(
            result.score.total >= 4,
            "Expected entropy score >= 4, got {}",
            result.score.total
        );
    }

    #[test]
    fn test_resolve_with_score_whitelisted() {
        init_test_env();
        let engine = create_test_engine(&[], &["trusted.example.com"], &[]);
        CURRENT_ENGINE.store(Arc::new(engine));

        let result = super::resolve_with_score("trusted.example.com");
        assert!(matches!(result.action, Action::Allow));
        // Score is still computed for whitelisted domains
        assert_eq!(result.score.total, 0);
    }
}
