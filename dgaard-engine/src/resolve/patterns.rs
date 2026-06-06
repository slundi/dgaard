use crate::filter::engine::FilterEngine;

/// Check if a domain matches any regex in the pool.
pub fn is_regex_blocked(domain: &str, filter: &FilterEngine) -> bool {
    filter.regex_pool.iter().any(|re| re.is_match(domain))
}

/// Match a single domain segment against a pattern segment.
fn segment_matches(domain_seg: &str, pattern_seg: &str) -> bool {
    if pattern_seg == "*" {
        return true;
    }

    if !pattern_seg.contains('*') {
        return domain_seg == pattern_seg;
    }

    let parts: Vec<&str> = pattern_seg.split('*').collect();

    if parts.len() == 2 {
        let prefix = parts[0];
        let suffix = parts[1];
        return domain_seg.starts_with(prefix)
            && domain_seg.ends_with(suffix)
            && domain_seg.len() >= prefix.len() + suffix.len();
    }

    let mut pos = 0;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if let Some(found) = domain_seg[pos..].find(part) {
            if i == 0 && found != 0 {
                return false;
            }
            pos += found + part.len();
        } else {
            return false;
        }
    }

    if let Some(&last) = parts.last()
        && !last.is_empty()
        && !domain_seg.ends_with(last)
    {
        return false;
    }

    true
}

/// Match a domain against a glob-style pattern with `*` wildcard.
fn matches_glob_pattern(domain: &str, pattern: &str) -> bool {
    let pattern_parts: Vec<&str> = pattern.split('.').collect();
    let domain_parts: Vec<&str> = domain.split('.').collect();

    if pattern_parts.len() != domain_parts.len() {
        if pattern_parts.first() == Some(&"*") && domain_parts.len() > pattern_parts.len() {
            let offset = domain_parts.len() - pattern_parts.len() + 1;
            return pattern_parts[1..]
                .iter()
                .zip(domain_parts[offset..].iter())
                .all(|(p, d)| segment_matches(d, p));
        }
        return false;
    }

    pattern_parts
        .iter()
        .zip(domain_parts.iter())
        .all(|(p, d)| segment_matches(d, p))
}

/// Check if domain matches any glob-style wildcard pattern.
pub fn is_wildcard_pattern_blocked(domain: &str, filter: &FilterEngine) -> bool {
    filter
        .wildcard_patterns
        .iter()
        .any(|pattern| matches_glob_pattern(domain, pattern))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolve::tests::create_engine_with_wildcard_patterns;

    #[test]
    fn test_segment_matches_exact() {
        assert!(segment_matches("ads", "ads"));
        assert!(!segment_matches("ads", "ad"));
    }

    #[test]
    fn test_segment_matches_star_only() {
        assert!(segment_matches("anything", "*"));
        assert!(segment_matches("", "*"));
    }

    #[test]
    fn test_segment_matches_prefix_wildcard() {
        assert!(segment_matches("ads1", "ads*"));
        assert!(!segment_matches("myads", "ads*"));
    }

    #[test]
    fn test_matches_glob_pattern_simple() {
        assert!(matches_glob_pattern("ads1.example.com", "ads*.example.com"));
        assert!(!matches_glob_pattern(
            "myads.example.com",
            "ads*.example.com"
        ));
    }

    #[test]
    fn test_matches_glob_pattern_star_segment() {
        assert!(matches_glob_pattern("sub.tracking.com", "*.tracking.com"));
        assert!(matches_glob_pattern(
            "deep.sub.tracking.com",
            "*.tracking.com"
        ));
        assert!(!matches_glob_pattern("tracking.com", "*.tracking.com"));
    }

    #[test]
    fn test_is_wildcard_pattern_blocked() {
        let engine =
            create_engine_with_wildcard_patterns(&["ads*.example.com", "*tracker.analytics.com"]);
        assert!(is_wildcard_pattern_blocked("ads1.example.com", &engine));
        assert!(is_wildcard_pattern_blocked(
            "adtracker.analytics.com",
            &engine
        ));
        assert!(!is_wildcard_pattern_blocked("safe.example.com", &engine));
    }
}
