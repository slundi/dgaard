//! DNS query resolution with configurable filter pipeline.
//!
//! This module implements the core domain resolution logic that checks
//! incoming DNS queries against various filters (whitelist, blocklist,
//! heuristics, etc.) based on the configured pipeline order.

use core::sync::atomic::Ordering;

use crate::config::PipelineStep;
use crate::dga::calculate_entropy_fast;
use crate::model::DomainEntryFlags;
use crate::{CONFIG, CURRENT_ENGINE, GLOBAL_SEED};
use dgaard::{Action, BlockReason};

/// Result of checking a domain against the filter engine.
#[derive(Debug, Clone, PartialEq)]
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

/// Check if a domain is in the fast lookup map (exact match).
/// Returns the flags if found.
fn fast_lookup(domain: &str) -> Option<DomainEntryFlags> {
    let engine = CURRENT_ENGINE.load();
    let hash = twox_hash::XxHash64::oneshot(GLOBAL_SEED.load(Ordering::Relaxed), domain.as_bytes());

    engine
        .fast_map
        .get(&hash)
        .map(|&flags_bits| DomainEntryFlags::from_bits_truncate(flags_bits))
}

/// Check if a domain matches any regex in the pool.
fn regex_lookup(domain: &str) -> bool {
    let engine = CURRENT_ENGINE.load();
    engine.regex_pool.iter().any(|re| re.is_match(domain))
}

/// Check if domain is whitelisted (exact match in fast_map with WHITELIST flag).
pub fn is_whitelisted(domain: &str) -> bool {
    if let Some(flags) = fast_lookup(domain) {
        return flags.contains(DomainEntryFlags::WHITELIST);
    }

    // Check parent domains for wildcard whitelist
    // e.g., for "sub.example.com", also check "example.com"
    let mut parts: Vec<&str> = domain.split('.').collect();
    while parts.len() > 1 {
        parts.remove(0);
        let parent = parts.join(".");
        if let Some(flags) = fast_lookup(&parent) {
            if flags.contains(DomainEntryFlags::WHITELIST | DomainEntryFlags::WILDCARD) {
                return true;
            }
        }
    }

    false
}

/// Check if domain is blocked by static list (exact match without WHITELIST flag).
pub fn is_blocked(domain: &str) -> bool {
    if let Some(flags) = fast_lookup(domain) {
        return !flags.contains(DomainEntryFlags::WHITELIST);
    }
    false
}

/// Check if domain matches any suffix/wildcard pattern.
/// Checks parent domains for wildcard matches.
pub fn is_suffix_blocked(domain: &str) -> bool {
    let engine = CURRENT_ENGINE.load();

    // Check each parent domain level
    let mut parts: Vec<&str> = domain.split('.').collect();
    while parts.len() > 1 {
        parts.remove(0);
        let parent = parts.join(".");
        let hash =
            twox_hash::XxHash64::oneshot(GLOBAL_SEED.load(Ordering::Relaxed), parent.as_bytes());

        // Binary search in hierarchical list
        if let Ok(idx) = engine
            .hierarchical_list
            .binary_search_by_key(&hash, |e| e.hash)
        {
            let entry = &engine.hierarchical_list[idx];
            if entry.flags.contains(DomainEntryFlags::WILDCARD)
                && !entry.flags.contains(DomainEntryFlags::WHITELIST)
            {
                return true;
            }
        }
    }

    false
}

/// Check if domain matches any regex pattern in the pool.
pub fn is_regex_blocked(domain: &str) -> bool {
    regex_lookup(domain)
}

/// Check if domain is suspicious based on DGA heuristics.
/// Uses Shannon entropy on the second-level domain (SLD).
pub fn is_dga_suspicious(domain: &str) -> bool {
    let config = CONFIG.load();
    let intel = &config.security.intelligence;

    if !intel.enabled {
        return false;
    }

    // Extract the second-level domain (SLD)
    // "sub.example.com" -> "example"
    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() < 2 {
        return false;
    }

    let sld = parts[parts.len() - 2];

    // Skip short domains to avoid false positives
    if sld.len() < intel.min_word_length {
        return false;
    }

    let entropy = calculate_entropy_fast(sld);
    entropy > intel.entropy_threshold
}

/// Check if domain contains illegal IDN/Punycode characters.
pub fn is_illegal_idn(domain: &str) -> bool {
    let config = CONFIG.load();
    if !config.server.block_idn {
        return false;
    }

    // Check for Punycode prefix in any segment
    if domain.split('.').any(|part| part.starts_with("xn--")) {
        return true;
    }

    // Check for raw non-ASCII characters
    !domain.is_ascii()
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

/// Main resolution function that processes a domain through the configured pipeline.
///
/// This function iterates through the pipeline steps defined in the configuration
/// and returns an Action as soon as a definitive verdict is reached.
///
/// # Arguments
/// * `domain` - The domain name to resolve (lowercase, no trailing dot)
///
/// # Returns
/// An `Action` indicating what should be done with the DNS query.
pub fn resolve(domain: &str) -> Action {
    let config = CONFIG.load();

    // Pre-pipeline: structural sanity checks (gatekeeper)
    if is_structure_invalid(domain) {
        return Action::Block(BlockReason::InvalidStructure);
    }

    // Pre-pipeline: IDN check if enabled
    if is_illegal_idn(domain) {
        return Action::Block(BlockReason::SuspiciousIdn);
    }

    // Process each pipeline step in order
    for step in &config.server.pipeline {
        match step {
            PipelineStep::Whitelist => {
                if is_whitelisted(domain) {
                    return Action::Allow;
                }
            }
            PipelineStep::HotCache => {
                // TODO: Implement LRU cache lookup
                // For now, skip this step
            }
            PipelineStep::StaticBlock => {
                if is_blocked(domain) {
                    return Action::Block(BlockReason::StaticBlacklist(String::from("blocklist")));
                }
            }
            PipelineStep::SuffixMatch => {
                if is_suffix_blocked(domain) {
                    return Action::Block(BlockReason::AbpRule(String::from("wildcard")));
                }
                if is_regex_blocked(domain) {
                    return Action::Block(BlockReason::AbpRule(String::from("regex")));
                }
            }
            PipelineStep::Heuristics => {
                if is_dga_suspicious(domain) {
                    let entropy = calculate_entropy_fast(domain);
                    return Action::Block(BlockReason::HighEntropy(entropy));
                }
            }
            PipelineStep::Upstream => {
                return Action::ProxyToUpstream;
            }
        }
    }

    // Safety fallback if pipeline doesn't end with Upstream
    Action::ProxyToUpstream
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CURRENT_ENGINE;
    use crate::filter::FilterEngine;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn init_test_env() {
        GLOBAL_SEED.store(42, Ordering::Relaxed);
    }

    fn create_test_engine(
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
        }
    }

    #[test]
    fn test_is_whitelisted_exact_match() {
        init_test_env();
        let engine = create_test_engine(&[], &["safe.example.com"], &[]);
        CURRENT_ENGINE.store(Arc::new(engine));

        assert!(is_whitelisted("safe.example.com"));
        assert!(!is_whitelisted("unsafe.example.com"));
    }

    #[test]
    fn test_is_blocked_exact_match() {
        init_test_env();
        let engine = create_test_engine(&["ads.tracker.com"], &[], &[]);
        CURRENT_ENGINE.store(Arc::new(engine));

        assert!(is_blocked("ads.tracker.com"));
        assert!(!is_blocked("safe.example.com"));
    }

    #[test]
    fn test_whitelist_takes_precedence() {
        init_test_env();
        // Same domain in both lists - whitelist flag should indicate whitelisted
        let engine = create_test_engine(&[], &["example.com"], &[]);
        CURRENT_ENGINE.store(Arc::new(engine));

        assert!(is_whitelisted("example.com"));
        assert!(!is_blocked("example.com"));
    }

    #[test]
    fn test_is_suffix_blocked() {
        init_test_env();
        let engine = create_test_engine(&[], &[], &["tracking.com"]);
        CURRENT_ENGINE.store(Arc::new(engine));

        assert!(is_suffix_blocked("sub.tracking.com"));
        assert!(is_suffix_blocked("deep.sub.tracking.com"));
        assert!(!is_suffix_blocked("tracking.com")); // exact match, not suffix
    }

    #[test]
    fn test_is_dga_suspicious_high_entropy() {
        init_test_env();
        // High entropy domain (SLD has random characters)
        // The function checks the second-level domain (SLD), not the subdomain
        // Entropy threshold is 4.0, need at least 17+ unique chars for entropy > 4.0
        // "a1b2c3d4e5f6g7h8i9j0.com" -> SLD is "a1b2c3d4e5f6g7h8i9j0" (entropy ~4.32)
        assert!(is_dga_suspicious("a1b2c3d4e5f6g7h8i9j0.com"));
        // With subdomain: "sub.qwertasdfzxcv1234567890.net" -> SLD has entropy ~4.52
        assert!(is_dga_suspicious("sub.qwertasdfzxcv1234567890.net"));

        // Normal domains (SLD has low entropy - readable words)
        // "google" entropy ~1.92, "facebook" entropy ~2.75
        assert!(!is_dga_suspicious("google.com"));
        assert!(!is_dga_suspicious("facebook.com"));
        assert!(!is_dga_suspicious("sub.example.org"));
    }

    #[test]
    fn test_is_dga_suspicious_short_domain_skipped() {
        init_test_env();
        // Short domains should be skipped
        assert!(!is_dga_suspicious("t.co"));
        assert!(!is_dga_suspicious("fb.com"));
    }

    #[test]
    fn test_is_illegal_idn_punycode() {
        init_test_env();
        // Punycode domain
        assert!(is_illegal_idn("xn--pple-43d.com")); // fake apple with Cyrillic

        // Normal ASCII domain
        assert!(!is_illegal_idn("apple.com"));
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

        let action = resolve("ads.tracker.com");
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

        let action = resolve("trusted.example.com");
        assert!(matches!(action, Action::Allow));
    }

    #[test]
    fn test_resolve_unknown_domain_proxied() {
        init_test_env();
        let engine = create_test_engine(&[], &[], &[]);
        CURRENT_ENGINE.store(Arc::new(engine));

        let action = resolve("unknown.example.com");
        assert!(matches!(action, Action::ProxyToUpstream));
    }

    #[test]
    fn test_resolve_invalid_structure_blocked() {
        init_test_env();
        let engine = create_test_engine(&[], &[], &[]);
        CURRENT_ENGINE.store(Arc::new(engine));

        // Excessive subdomain depth
        let action = resolve("a.b.c.d.e.f.g.h.i.j.k.example.com");
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

        let action = resolve("xn--pple-43d.com");
        assert!(matches!(action, Action::Block(BlockReason::SuspiciousIdn)));
    }

    // --- Tests for TLD blocking ---

    fn create_engine_with_tld_block(tlds: &[&str]) -> FilterEngine {
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
        }
    }

    #[test]
    fn test_is_suffix_blocked_by_tld() {
        init_test_env();
        let engine = create_engine_with_tld_block(&["xyz"]);
        CURRENT_ENGINE.store(Arc::new(engine));

        // Any domain under .xyz should be blocked
        assert!(is_suffix_blocked("malware.xyz"));
        assert!(is_suffix_blocked("sub.domain.xyz"));
        assert!(is_suffix_blocked("deep.nested.sub.xyz"));

        // Other TLDs should not be blocked
        assert!(!is_suffix_blocked("example.com"));
        assert!(!is_suffix_blocked("safe.org"));
    }

    #[test]
    fn test_is_suffix_blocked_by_multiple_tlds() {
        init_test_env();
        let engine = create_engine_with_tld_block(&["xyz", "top", "bid"]);
        CURRENT_ENGINE.store(Arc::new(engine));

        assert!(is_suffix_blocked("spam.xyz"));
        assert!(is_suffix_blocked("malware.top"));
        assert!(is_suffix_blocked("phishing.bid"));
        assert!(!is_suffix_blocked("safe.com"));
    }

    #[test]
    fn test_resolve_tld_blocked_domain() {
        init_test_env();
        let engine = create_engine_with_tld_block(&["xyz"]);
        CURRENT_ENGINE.store(Arc::new(engine));

        let action = resolve("malware.xyz");
        assert!(
            matches!(action, Action::Block(BlockReason::AbpRule(_))),
            "Domain under blocked TLD should be blocked, got: {:?}",
            action
        );
    }

    #[test]
    fn test_tld_block_with_leading_dot_in_config() {
        init_test_env();
        // Simulate config format with leading dot
        let engine = create_engine_with_tld_block(&[".xyz", ".top"]);
        CURRENT_ENGINE.store(Arc::new(engine));

        assert!(is_suffix_blocked("spam.xyz"));
        assert!(is_suffix_blocked("malware.top"));
    }
}
