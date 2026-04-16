use core::sync::atomic::Ordering;

use crate::{CURRENT_ENGINE, GLOBAL_SEED, model::DomainEntryFlags};

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
        if let Some(flags) = fast_lookup(&parent)
            && flags.contains(DomainEntryFlags::WHITELIST | DomainEntryFlags::WILDCARD)
        {
            return true;
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

/// Check if domain is on the Newly Registered Domain list.
pub fn is_nrd(domain: &str) -> bool {
    fast_lookup(domain)
        .map(|flags| flags.contains(DomainEntryFlags::NRD))
        .unwrap_or(false)
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

#[cfg(test)]
mod tests {
    use crate::resolve::tests::{create_engine_with_tld_block, create_test_engine, init_test_env};
    use std::sync::Arc;

    use super::*;
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
    fn test_tld_block_with_leading_dot_in_config() {
        init_test_env();
        // Simulate config format with leading dot
        let engine = create_engine_with_tld_block(&[".xyz", ".top"]);
        CURRENT_ENGINE.store(Arc::new(engine));

        assert!(is_suffix_blocked("spam.xyz"));
        assert!(is_suffix_blocked("malware.top"));
    }
}
