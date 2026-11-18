//! Pattern rules matched on every query: ABP regexes and glob patterns.
//!
//! Both are indexed once at build time so a lookup does not test every rule
//! in turn: regexes share one [`RegexSet`] automaton, globs are bucketed by
//! their trailing literal labels.

use std::collections::HashMap;

use regex::{Regex, RegexSet};

/// ABP regex rules (`/…/`).
#[derive(Debug, Default)]
pub struct RegexRules {
    /// Every rule in one automaton: a single pass over the domain.
    set: Option<RegexSet>,
    /// The rules one by one; only kept when they could not be combined
    /// (the set exceeded the regex size limit).
    linear: Vec<Regex>,
}

impl RegexRules {
    /// Combine `rules`, already validated one by one at load time.
    pub fn new(rules: Vec<Regex>) -> Self {
        if rules.is_empty() {
            return Self::default();
        }
        match RegexSet::new(rules.iter().map(Regex::as_str)) {
            Ok(set) => Self {
                set: Some(set),
                linear: Vec::new(),
            },
            Err(e) => {
                eprintln!(
                    "Warning: {} regex rules cannot be combined ({e}); matching them one by one",
                    rules.len()
                );
                Self {
                    set: None,
                    linear: rules,
                }
            }
        }
    }

    /// `true` when any rule matches `domain`.
    pub fn is_match(&self, domain: &str) -> bool {
        match &self.set {
            Some(set) => set.is_match(domain),
            None => self.linear.iter().any(|re| re.is_match(domain)),
        }
    }

    pub fn len(&self) -> usize {
        self.set.as_ref().map_or(self.linear.len(), RegexSet::len)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Glob rules (`||ads*.example.com^`): `*` matches within a label, and a
/// leading `*` label matches one or more labels.
#[derive(Debug, Default)]
pub struct GlobRules {
    /// Patterns keyed by their trailing literal labels
    /// (`ads*.example.com` → `example.com`).
    by_tail: HashMap<Box<str>, Vec<Box<str>>>,
    /// Patterns whose last label holds a `*`: nothing to key on, so they
    /// are tested on every query.
    untailed: Vec<Box<str>>,
}

impl GlobRules {
    pub fn new<I, S>(patterns: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<Box<str>>,
    {
        let mut rules = Self::default();
        for pattern in patterns {
            let pattern: Box<str> = pattern.into();
            match literal_tail(&pattern) {
                Some(tail) => rules.by_tail.entry(tail.into()).or_default().push(pattern),
                None => rules.untailed.push(pattern),
            }
        }
        for bucket in rules.by_tail.values_mut() {
            bucket.sort_unstable();
            bucket.dedup();
        }
        rules.untailed.sort_unstable();
        rules.untailed.dedup();
        rules
    }

    /// `true` when any pattern matches `domain`.
    ///
    /// Matching aligns pattern labels with domain labels from the right, so
    /// a pattern can only match a domain ending with its literal tail: only
    /// the buckets of `domain` and its parents are tested.
    pub fn is_match(&self, domain: &str) -> bool {
        let suffixes = std::iter::once(domain)
            .chain(domain.match_indices('.').map(|(idx, _)| &domain[idx + 1..]));
        suffixes
            .filter_map(|suffix| self.by_tail.get(suffix))
            .flatten()
            .chain(&self.untailed)
            .any(|pattern| matches_glob_pattern(domain, pattern))
    }

    pub fn len(&self) -> usize {
        self.untailed.len() + self.by_tail.values().map(Vec::len).sum::<usize>()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Labels after the last label holding a `*`, or the whole pattern when it
/// has no `*`; `None` when the last label itself holds one.
fn literal_tail(pattern: &str) -> Option<&str> {
    let Some(star) = pattern.rfind('*') else {
        return Some(pattern);
    };
    let dot = pattern[star..].find('.')?;
    Some(&pattern[star + dot + 1..])
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

#[cfg(test)]
mod tests {
    use super::*;

    fn regexes(patterns: &[&str]) -> Vec<Regex> {
        patterns.iter().map(|p| Regex::new(p).unwrap()).collect()
    }

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
    fn literal_tail_is_the_labels_after_the_last_star() {
        assert_eq!(literal_tail("ads*.example.com"), Some("example.com"));
        assert_eq!(literal_tail("*.tracking.com"), Some("tracking.com"));
        assert_eq!(literal_tail("a*.b*.c.com"), Some("c.com"));
        assert_eq!(literal_tail("plain.com"), Some("plain.com"));
        assert_eq!(literal_tail("ads.*"), None);
        assert_eq!(literal_tail("ads.ex*le"), None);
    }

    #[test]
    fn regex_rules_match_through_the_set() {
        let rules = RegexRules::new(regexes(&[r"^ads\d+\.", r"tracker\.net$"]));
        assert!(rules.set.is_some());
        assert_eq!(rules.len(), 2);
        assert!(rules.is_match("ads42.example.com"));
        assert!(rules.is_match("cdn.tracker.net"));
        assert!(!rules.is_match("example.com"));
    }

    #[test]
    fn regex_rules_empty_never_match() {
        let rules = RegexRules::new(Vec::new());
        assert!(rules.is_empty());
        assert!(!rules.is_match("example.com"));
    }

    #[test]
    fn regex_rules_linear_fallback_matches_the_same() {
        let rules = RegexRules {
            set: None,
            linear: regexes(&[r"^ads\d+\.", r"tracker\.net$"]),
        };
        assert_eq!(rules.len(), 2);
        assert!(rules.is_match("ads42.example.com"));
        assert!(!rules.is_match("example.com"));
    }

    /// Patterns covering every bucket kind, and domains around them.
    const GLOBS: [&str; 6] = [
        "ads*.example.com",
        "*tracker.analytics.com",
        "*.tracking.com",
        "a*.b*.c.com",
        "ads.*",
        "metrics.ex*le",
    ];
    const DOMAINS: [&str; 16] = [
        "ads1.example.com",
        "myads.example.com",
        "example.com",
        "adtracker.analytics.com",
        "analytics.com",
        "sub.tracking.com",
        "deep.sub.tracking.com",
        "tracking.com",
        "ax.by.c.com",
        "x.by.c.com",
        "ads.anything",
        "ads.example.org",
        "metrics.example",
        "metrics.exle",
        "metrics.other",
        "unrelated.net",
    ];

    #[test]
    fn glob_rules_agree_with_testing_every_pattern() {
        let rules = GlobRules::new(GLOBS);
        assert_eq!(rules.len(), GLOBS.len());
        for domain in DOMAINS {
            let expected = GLOBS
                .iter()
                .any(|pattern| matches_glob_pattern(domain, pattern));
            assert_eq!(rules.is_match(domain), expected, "{domain}");
        }
    }

    #[test]
    fn glob_rules_bucket_by_tail() {
        let rules = GlobRules::new(GLOBS);
        assert_eq!(rules.by_tail["example.com"], ["ads*.example.com".into()]);
        assert_eq!(rules.by_tail["c.com"], ["a*.b*.c.com".into()]);
        assert_eq!(rules.untailed.len(), 2);
    }

    #[test]
    fn glob_rules_dedup_and_empty() {
        let rules = GlobRules::new(["ads*.example.com", "ads*.example.com"]);
        assert_eq!(rules.len(), 1);
        let empty = GlobRules::default();
        assert!(empty.is_empty());
        assert!(!empty.is_match("ads1.example.com"));
    }
}
