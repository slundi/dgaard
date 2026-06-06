//! DNS query resolution with configurable filter pipeline.

mod heuristics;
mod matcher;
mod patterns;
mod qtype;
mod scoring;

pub use heuristics::{check_dga_heuristics, check_lexical, is_illegal_idn};
pub use matcher::{is_blocked, is_nrd, is_suffix_blocked, is_whitelisted};
pub use patterns::{is_regex_blocked, is_wildcard_pattern_blocked};
pub use qtype::check_qtype;
pub use scoring::{compute_score, score_answer};

use crate::config::{Config, PipelineStep};
use crate::filter::engine::FilterEngine;
use crate::model::{Action, BlockReason, SuspicionScore};

/// Check if domain exceeds structural limits (depth, length).
pub fn is_structure_invalid(domain: &str, config: &Config) -> bool {
    let structure = &config.security.structure;

    if domain.len() > structure.max_domain_length as usize {
        return true;
    }

    let depth = domain.bytes().filter(|&b| b == b'.').count();
    if depth > structure.max_subdomain_depth as usize {
        return true;
    }

    if structure.force_lowercase_ascii && !domain.is_ascii() {
        return true;
    }

    false
}

/// Result of domain resolution including the suspicion score.
#[derive(Debug, Clone)]
pub struct ResolveResult {
    pub action: Action,
    pub score: SuspicionScore,
}

/// Resolution function that returns the computed suspicion score.
pub fn resolve_with_score(domain: &str, filter: &FilterEngine, config: &Config) -> ResolveResult {
    let score = compute_score(domain, filter, config);

    if is_structure_invalid(domain, config) {
        return ResolveResult {
            action: Action::Block(BlockReason::InvalidStructure),
            score,
        };
    }

    if is_illegal_idn(domain, config) {
        return ResolveResult {
            action: Action::Block(BlockReason::SuspiciousIdn),
            score,
        };
    }

    for step in &config.server.pipeline {
        match step {
            PipelineStep::Whitelist => {
                if is_whitelisted(domain, filter) {
                    return ResolveResult {
                        action: Action::Allow,
                        score,
                    };
                }
            }
            PipelineStep::HotCache => {
                // TODO: Implement LRU cache lookup
            }
            PipelineStep::StaticBlock => {
                if is_blocked(domain, filter) {
                    return ResolveResult {
                        action: Action::Block(BlockReason::StaticBlacklist(String::from(
                            "blocklist",
                        ))),
                        score,
                    };
                }
            }
            PipelineStep::SuffixMatch => {
                if is_suffix_blocked(domain, filter) {
                    return ResolveResult {
                        action: Action::Block(BlockReason::AbpRule(String::from("wildcard"))),
                        score,
                    };
                }
                if is_wildcard_pattern_blocked(domain, filter) {
                    return ResolveResult {
                        action: Action::Block(BlockReason::AbpRule(String::from("glob"))),
                        score,
                    };
                }
                if is_regex_blocked(domain, filter) {
                    return ResolveResult {
                        action: Action::Block(BlockReason::AbpRule(String::from("regex"))),
                        score,
                    };
                }
            }
            PipelineStep::Heuristics => {
                if let Some(reason) = check_lexical(domain, filter) {
                    return ResolveResult {
                        action: Action::Block(reason),
                        score,
                    };
                }
                if let Some(reason) = check_dga_heuristics(domain, config) {
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
    use std::collections::{HashMap, HashSet};

    const SEED: u64 = 42;

    pub fn init_test_engine() -> FilterEngine {
        FilterEngine::empty()
    }

    pub fn create_test_engine(
        blocklist: &[&str],
        whitelist: &[&str],
        wildcards: &[&str],
    ) -> FilterEngine {
        let mut fast_map = HashMap::new();

        for domain in blocklist {
            let hash = twox_hash::XxHash64::oneshot(SEED, domain.as_bytes());
            fast_map.insert(hash, DomainEntryFlags::NONE.bits());
        }

        for domain in whitelist {
            let hash = twox_hash::XxHash64::oneshot(SEED, domain.as_bytes());
            fast_map.insert(hash, DomainEntryFlags::WHITELIST.bits());
        }

        let mut hierarchical_list = Vec::new();
        for domain in wildcards {
            let hash = twox_hash::XxHash64::oneshot(SEED, domain.as_bytes());
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
            seed: SEED,
        }
    }

    pub fn create_engine_with_tld_block(tlds: &[&str]) -> FilterEngine {
        let mut hierarchical_list = Vec::new();
        for tld in tlds {
            let tld_clean = tld.strip_prefix('.').unwrap_or(tld);
            let hash = twox_hash::XxHash64::oneshot(SEED, tld_clean.as_bytes());
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
            seed: SEED,
        }
    }

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
            seed: SEED,
        }
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
                twox_hash::XxHash64::oneshot(SEED, tld_clean.as_bytes())
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
            seed: SEED,
        }
    }

    #[test]
    fn test_is_structure_invalid_depth() {
        let config = Config::default();
        assert!(!is_structure_invalid("sub.example.com", &config));
        assert!(is_structure_invalid(
            "a.b.c.d.e.f.g.h.i.j.k.example.com",
            &config
        ));
    }

    #[test]
    fn test_is_structure_invalid_length() {
        let config = Config::default();
        let long_domain = format!("{}.com", "a".repeat(200));
        assert!(is_structure_invalid(&long_domain, &config));
    }

    #[test]
    fn test_resolve_blocked_domain() {
        let engine = create_test_engine(&["ads.tracker.com"], &[], &[]);
        let config = Config::default();
        let action = resolve_with_score("ads.tracker.com", &engine, &config).action;
        assert!(matches!(
            action,
            Action::Block(BlockReason::StaticBlacklist(_))
        ));
    }

    #[test]
    fn test_resolve_whitelisted_domain() {
        let engine = create_test_engine(&[], &["trusted.example.com"], &[]);
        let config = Config::default();
        let action = resolve_with_score("trusted.example.com", &engine, &config).action;
        assert!(matches!(action, Action::Allow));
    }

    #[test]
    fn test_resolve_unknown_domain_proxied() {
        let engine = create_test_engine(&[], &[], &[]);
        let config = Config::default();
        let action = resolve_with_score("unknown.example.com", &engine, &config).action;
        assert!(matches!(action, Action::ProxyToUpstream));
    }

    #[test]
    fn test_resolve_invalid_structure_blocked() {
        let engine = create_test_engine(&[], &[], &[]);
        let config = Config::default();
        let action =
            resolve_with_score("a.b.c.d.e.f.g.h.i.j.k.example.com", &engine, &config).action;
        assert!(matches!(
            action,
            Action::Block(BlockReason::InvalidStructure)
        ));
    }

    #[test]
    fn test_resolve_idn_blocked() {
        let engine = create_test_engine(&[], &[], &[]);
        let config = Config::default();
        let action = resolve_with_score("xn--pple-43d.com", &engine, &config).action;
        assert!(matches!(action, Action::Block(BlockReason::SuspiciousIdn)));
    }

    #[test]
    fn test_resolve_tld_blocked_domain() {
        let engine = create_engine_with_tld_block(&["xyz"]);
        let config = Config::default();
        let action = resolve_with_score("malware.xyz", &engine, &config).action;
        assert!(
            matches!(action, Action::Block(BlockReason::AbpRule(_))),
            "Domain under blocked TLD should be blocked, got: {:?}",
            action
        );
    }

    #[test]
    fn test_resolve_wildcard_pattern_blocked() {
        let engine = create_engine_with_wildcard_patterns(&["ads*.example.com"]);
        let config = Config::default();
        let action = resolve_with_score("ads1.example.com", &engine, &config).action;
        assert!(
            matches!(action, Action::Block(BlockReason::AbpRule(ref s)) if s == "glob"),
            "Got: {:?}",
            action
        );
    }

    #[test]
    fn test_resolve_lexical_blocked() {
        let mut config = Config::default();
        config.security.lexical.enabled = true;
        config.security.lexical.banned_keywords = vec!["porno".to_string()];
        config.security.lexical.strict_keyword_matching = true;
        let engine = create_lexical_engine(&["porno"], true, &[]);

        let action = resolve_with_score("porno.com", &engine, &config).action;
        assert!(
            matches!(action, Action::Block(BlockReason::BannedKeyword(ref k)) if k == "porno"),
            "Got: {:?}",
            action
        );
    }

    #[test]
    fn test_resolve_with_score_normal_domain() {
        let engine = create_test_engine(&[], &[], &[]);
        let config = Config::default();
        let result = resolve_with_score("google.com", &engine, &config);
        assert!(matches!(result.action, Action::ProxyToUpstream));
        assert_eq!(result.score.total, 0);
    }

    #[test]
    fn test_resolve_with_score_whitelisted() {
        let engine = create_test_engine(&[], &["trusted.example.com"], &[]);
        let config = Config::default();
        let result = resolve_with_score("trusted.example.com", &engine, &config);
        assert!(matches!(result.action, Action::Allow));
        assert_eq!(result.score.total, 0);
    }
}
