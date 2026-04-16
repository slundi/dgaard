use crate::CURRENT_ENGINE;

/// Check if a domain matches any regex in the pool.
pub fn regex_lookup(domain: &str) -> bool {
    let engine = CURRENT_ENGINE.load();
    engine.regex_pool.iter().any(|re| re.is_match(domain))
}

/// Match a single domain segment against a pattern segment.
/// `*` matches any sequence of characters within the segment.
fn segment_matches(domain_seg: &str, pattern_seg: &str) -> bool {
    if pattern_seg == "*" {
        return true;
    }

    if !pattern_seg.contains('*') {
        return domain_seg == pattern_seg;
    }

    // Handle patterns like `ads*` or `*tracker` or `ad*s`
    let parts: Vec<&str> = pattern_seg.split('*').collect();

    if parts.len() == 2 {
        // Single wildcard: prefix*suffix
        let prefix = parts[0];
        let suffix = parts[1];
        return domain_seg.starts_with(prefix)
            && domain_seg.ends_with(suffix)
            && domain_seg.len() >= prefix.len() + suffix.len();
    }

    // Multiple wildcards: use greedy matching
    let mut pos = 0;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if let Some(found) = domain_seg[pos..].find(part) {
            if i == 0 && found != 0 {
                // First part must match at start
                return false;
            }
            pos += found + part.len();
        } else {
            return false;
        }
    }

    // Last part must match at end (if not empty)
    if let Some(&last) = parts.last()
        && !last.is_empty()
        && !domain_seg.ends_with(last)
    {
        return false;
    }

    true
}

/// Match a domain against a glob-style pattern with `*` wildcard.
/// The `*` matches any sequence of characters (except `.`).
fn matches_glob_pattern(domain: &str, pattern: &str) -> bool {
    // Split pattern and domain into segments by '.'
    let pattern_parts: Vec<&str> = pattern.split('.').collect();
    let domain_parts: Vec<&str> = domain.split('.').collect();

    // Must have same number of segments (unless pattern starts with *)
    if pattern_parts.len() != domain_parts.len() {
        // Handle leading wildcard like `*.example.com`
        if pattern_parts.first() == Some(&"*") && domain_parts.len() > pattern_parts.len() {
            // Match trailing segments
            let offset = domain_parts.len() - pattern_parts.len() + 1;
            return pattern_parts[1..]
                .iter()
                .zip(domain_parts[offset..].iter())
                .all(|(p, d)| segment_matches(d, p));
        }
        return false;
    }

    // Match each segment
    pattern_parts
        .iter()
        .zip(domain_parts.iter())
        .all(|(p, d)| segment_matches(d, p))
}

/// Check if domain matches any regex pattern in the pool.
pub fn is_regex_blocked(domain: &str) -> bool {
    regex_lookup(domain)
}

/// Check if domain matches any glob-style wildcard pattern.
/// Patterns like `ads*.example.com` match `ads1.example.com`, `ads-banner.example.com`.
pub fn is_wildcard_pattern_blocked(domain: &str) -> bool {
    let engine = CURRENT_ENGINE.load();

    for pattern in &engine.wildcard_patterns {
        if matches_glob_pattern(domain, pattern) {
            return true;
        }
    }

    false
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::resolve::tests::{create_engine_with_wildcard_patterns, init_test_env};
    use std::sync::Arc;

    #[test]
    fn test_segment_matches_exact() {
        assert!(segment_matches("ads", "ads"));
        assert!(!segment_matches("ads", "ad"));
        assert!(!segment_matches("ad", "ads"));
    }

    #[test]
    fn test_segment_matches_star_only() {
        assert!(segment_matches("anything", "*"));
        assert!(segment_matches("", "*"));
        assert!(segment_matches("ads123", "*"));
    }

    #[test]
    fn test_segment_matches_prefix_wildcard() {
        // Pattern `ads*` should match `ads`, `ads1`, `ads-banner`
        assert!(segment_matches("ads", "ads*"));
        assert!(segment_matches("ads1", "ads*"));
        assert!(segment_matches("ads-banner", "ads*"));
        assert!(!segment_matches("myads", "ads*"));
        assert!(!segment_matches("ad", "ads*"));
    }

    #[test]
    fn test_segment_matches_suffix_wildcard() {
        // Pattern `*tracker` should match `tracker`, `adtracker`, `mytracker`
        assert!(segment_matches("tracker", "*tracker"));
        assert!(segment_matches("adtracker", "*tracker"));
        assert!(segment_matches("mytracker", "*tracker"));
        assert!(!segment_matches("trackers", "*tracker"));
    }

    #[test]
    fn test_segment_matches_middle_wildcard() {
        // Pattern `ad*s` should match `ads`, `ad123s`, `adbanners`
        assert!(segment_matches("ads", "ad*s"));
        assert!(segment_matches("ad123s", "ad*s"));
        assert!(segment_matches("adbanners", "ad*s"));
        assert!(!segment_matches("ad", "ad*s"));
        assert!(!segment_matches("ads1", "ad*s"));
    }

    #[test]
    fn test_matches_glob_pattern_simple() {
        // Pattern `ads*.example.com` should match domains with ads prefix
        assert!(matches_glob_pattern("ads1.example.com", "ads*.example.com"));
        assert!(matches_glob_pattern(
            "ads-banner.example.com",
            "ads*.example.com"
        ));
        assert!(matches_glob_pattern("ads.example.com", "ads*.example.com"));
        assert!(!matches_glob_pattern(
            "myads.example.com",
            "ads*.example.com"
        ));
        assert!(!matches_glob_pattern(
            "tracking.example.com",
            "ads*.example.com"
        ));
    }

    #[test]
    fn test_matches_glob_pattern_suffix() {
        // Pattern `*tracker.example.com` should match domains ending with tracker
        assert!(matches_glob_pattern(
            "adtracker.example.com",
            "*tracker.example.com"
        ));
        assert!(matches_glob_pattern(
            "tracker.example.com",
            "*tracker.example.com"
        ));
        assert!(!matches_glob_pattern(
            "trackers.example.com",
            "*tracker.example.com"
        ));
    }

    #[test]
    fn test_matches_glob_pattern_star_segment() {
        // Pattern `*.tracking.com` - leading * matches any subdomain
        assert!(matches_glob_pattern("sub.tracking.com", "*.tracking.com"));
        assert!(matches_glob_pattern(
            "deep.sub.tracking.com",
            "*.tracking.com"
        ));
        assert!(!matches_glob_pattern("tracking.com", "*.tracking.com"));
    }

    #[test]
    fn test_matches_glob_pattern_multiple_wildcards() {
        // Pattern `ad*.*track*.example.com`
        assert!(matches_glob_pattern(
            "ads.mytracker.example.com",
            "ad*.*track*.example.com"
        ));
        assert!(matches_glob_pattern(
            "advert.subtracking.example.com",
            "ad*.*track*.example.com"
        ));
    }

    #[test]
    fn test_matches_glob_pattern_different_depth() {
        // Patterns with different segment counts should not match
        assert!(!matches_glob_pattern(
            "ads.sub.example.com",
            "ads*.example.com"
        ));
        assert!(!matches_glob_pattern(
            "ads.example.com",
            "ads*.sub.example.com"
        ));
    }

    #[test]
    fn test_is_wildcard_pattern_blocked() {
        init_test_env();
        let engine = create_engine_with_wildcard_patterns(&[
            "ads*.example.com",
            "*tracker.analytics.com",
            "banner*.ad.net",
        ]);
        CURRENT_ENGINE.store(Arc::new(engine));

        // Should match ads*.example.com
        assert!(is_wildcard_pattern_blocked("ads1.example.com"));
        assert!(is_wildcard_pattern_blocked("ads-banner.example.com"));

        // Should match *tracker.analytics.com
        assert!(is_wildcard_pattern_blocked("adtracker.analytics.com"));
        assert!(is_wildcard_pattern_blocked("tracker.analytics.com"));

        // Should match banner*.ad.net
        assert!(is_wildcard_pattern_blocked("banner1.ad.net"));
        assert!(is_wildcard_pattern_blocked("banner-top.ad.net"));

        // Should NOT match
        assert!(!is_wildcard_pattern_blocked("safe.example.com"));
        assert!(!is_wildcard_pattern_blocked("myads.example.com"));
        assert!(!is_wildcard_pattern_blocked("trackers.analytics.com"));
    }
}
