use crate::filter::engine::FilterEngine;

/// Check if a domain matches any regex rule.
pub fn is_regex_blocked(domain: &str, filter: &FilterEngine) -> bool {
    let domain = super::normalize_domain(domain);
    filter.regex_rules.is_match(domain.as_ref())
}

/// Check if domain matches any glob-style wildcard pattern.
pub fn is_wildcard_pattern_blocked(domain: &str, filter: &FilterEngine) -> bool {
    let domain = super::normalize_domain(domain);
    filter.glob_rules.is_match(domain.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::rules::RegexRules;
    use crate::resolve::tests::create_engine_with_wildcard_patterns;

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
        // Normalized like every other entry point.
        assert!(is_wildcard_pattern_blocked("ADS1.Example.com.", &engine));
    }

    #[test]
    fn test_is_regex_blocked() {
        let mut engine = FilterEngine::empty();
        engine.regex_rules = RegexRules::new(vec![regex::Regex::new(r"^ads\d+\.").unwrap()]);
        assert!(is_regex_blocked("ads7.example.com", &engine));
        assert!(is_regex_blocked("ADS7.example.com.", &engine));
        assert!(!is_regex_blocked("example.com", &engine));
    }
}
