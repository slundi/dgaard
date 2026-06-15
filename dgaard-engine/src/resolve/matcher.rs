use crate::{filter::engine::FilterEngine, model::DomainEntryFlags};

/// Check if a domain is in the fast lookup map (exact match).
fn fast_lookup(domain: &str, filter: &FilterEngine) -> Option<DomainEntryFlags> {
    let hash = twox_hash::XxHash64::oneshot(filter.seed, domain.as_bytes());
    filter
        .fast_map
        .get(&hash)
        .and_then(|(flags_bits, stored_domain)| {
            if stored_domain.as_ref() == domain {
                Some(DomainEntryFlags::from_bits_truncate(*flags_bits))
            } else {
                None
            }
        })
}

/// Check if domain is whitelisted (exact match in fast_map with WHITELIST flag).
pub fn is_whitelisted(domain: &str, filter: &FilterEngine) -> bool {
    if let Some(flags) = fast_lookup(domain, filter) {
        return flags.contains(DomainEntryFlags::WHITELIST);
    }

    let mut parts: Vec<&str> = domain.split('.').collect();
    while parts.len() > 1 {
        parts.remove(0);
        let parent = parts.join(".");
        if let Some(flags) = fast_lookup(&parent, filter)
            && flags.contains(DomainEntryFlags::WHITELIST | DomainEntryFlags::WILDCARD)
        {
            return true;
        }
    }

    false
}

/// Check if domain is blocked by static list (exact match without WHITELIST flag).
pub fn is_blocked(domain: &str, filter: &FilterEngine) -> bool {
    if let Some(flags) = fast_lookup(domain, filter) {
        return !flags.contains(DomainEntryFlags::WHITELIST);
    }
    false
}

/// Check if domain is on the Newly Registered Domain list.
pub fn is_nrd(domain: &str, filter: &FilterEngine) -> bool {
    fast_lookup(domain, filter)
        .map(|flags| flags.contains(DomainEntryFlags::NRD))
        .unwrap_or(false)
}

/// Check if domain matches any suffix/wildcard pattern.
pub fn is_suffix_blocked(domain: &str, filter: &FilterEngine) -> bool {
    let mut parts: Vec<&str> = domain.split('.').collect();
    while parts.len() > 1 {
        parts.remove(0);
        let parent = parts.join(".");
        let hash = twox_hash::XxHash64::oneshot(filter.seed, parent.as_bytes());

        if let Ok(idx) = filter
            .hierarchical_list
            .binary_search_by_key(&hash, |e| e.hash)
        {
            let entry = &filter.hierarchical_list[idx];
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
    use super::*;
    use crate::resolve::tests::{create_engine_with_tld_block, create_test_engine};

    #[test]
    fn test_is_whitelisted_exact_match() {
        let engine = create_test_engine(&[], &["safe.example.com"], &[]);
        assert!(is_whitelisted("safe.example.com", &engine));
        assert!(!is_whitelisted("unsafe.example.com", &engine));
    }

    #[test]
    fn test_is_blocked_exact_match() {
        let engine = create_test_engine(&["ads.tracker.com"], &[], &[]);
        assert!(is_blocked("ads.tracker.com", &engine));
        assert!(!is_blocked("safe.example.com", &engine));
    }

    #[test]
    fn test_whitelist_takes_precedence() {
        let engine = create_test_engine(&[], &["example.com"], &[]);
        assert!(is_whitelisted("example.com", &engine));
        assert!(!is_blocked("example.com", &engine));
    }

    #[test]
    fn test_is_suffix_blocked() {
        let engine = create_test_engine(&[], &[], &["tracking.com"]);
        assert!(is_suffix_blocked("sub.tracking.com", &engine));
        assert!(is_suffix_blocked("deep.sub.tracking.com", &engine));
        assert!(!is_suffix_blocked("tracking.com", &engine));
    }

    #[test]
    fn test_is_suffix_blocked_by_tld() {
        let engine = create_engine_with_tld_block(&["xyz"]);
        assert!(is_suffix_blocked("malware.xyz", &engine));
        assert!(is_suffix_blocked("sub.domain.xyz", &engine));
        assert!(!is_suffix_blocked("example.com", &engine));
    }
}
