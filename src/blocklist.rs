use addr::parse_domain_name;
use regex::RegexSet;
use std::collections::HashSet; // From 'addr' crate to handle TLDs/Public Suffixes

pub struct Blocklist {
    // Exact matches: 'google-analytics.com'
    // O(1) lookup.
    pub exact_domains: HashSet<String>,

    // Wildcard matches: '*.doubleclick.net'
    // We store these as reversed strings ('ten.kcilcelbuod.*')
    // to match suffixes efficiently.
    pub wildcards: HashSet<String>,

    // Complex patterns: '/^ads\d+\./'
    // RegexSet is much faster than Vec<Regex> because it
    // matches all patterns in a single pass.
    pub regex_patterns: RegexSet,
}

impl Blocklist {
    pub fn is_blocked(&self, domain: &str) -> bool {
        // 1. Check exact match (Fastest)
        if self.exact_domains.contains(domain) {
            return true;
        }

        // 2. Check wildcards (Iterative suffix check)
        // For 'sub.example.com', check 'example.com', then 'com'
        if self.check_wildcards(domain) {
            return true;
        }

        // 3. Check Regex (Slowest - only runs if others miss)
        if self.regex_patterns.is_match(domain) {
            return true;
        }

        false
    }

    fn check_wildcards(&self, domain: &str) -> bool {
        let parts: Vec<&str> = domain.split('.').collect();
        for i in 0..parts.len() {
            let suffix = parts[i..].join(".");
            if self.wildcards.contains(&suffix) {
                return true;
            }
        }
        false
    }
}
