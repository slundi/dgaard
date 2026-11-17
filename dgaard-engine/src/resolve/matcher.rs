use crate::{filter::engine::FilterEngine, model::DomainEntryFlags, utils::count_dots};

/// Check if a domain is in the fast lookup map (exact match).
fn fast_lookup(domain: &str, filter: &FilterEngine) -> Option<DomainEntryFlags> {
    let hash = twox_hash::XxHash64::oneshot(filter.seed, domain.as_bytes());
    fast_lookup_hashed(domain, hash, filter)
}

fn fast_lookup_hashed(domain: &str, hash: u64, filter: &FilterEngine) -> Option<DomainEntryFlags> {
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

/// Parent domains, most specific first: `a.b.c` yields `b.c` then `c`.
fn parents(domain: &str) -> impl Iterator<Item = &str> {
    domain
        .match_indices('.')
        .map(move |(idx, _)| &domain[idx + 1..])
}

/// Suffix rules attached to one parent domain.
#[derive(Default)]
struct SuffixRules {
    /// A blocking rule covers every subdomain of the parent.
    blocks: bool,
    /// A whitelist rule covers every subdomain of the parent.
    allows: bool,
}

/// Collect the suffix rules on `parent` from both stores:
/// - `fast_map`: `@@||parent^` (WHITELIST | WILDCARD);
/// - `hierarchical_list`: `||parent^`, `||*.parent^`, `@@||*.parent^`, and
///   `tld.exclude` entries. The builder keeps one suffix entry per
///   `(depth, hash)` key with merged flags (`normalize_hierarchical`); the
///   whole key range is still scanned and its flags OR-ed, so the result
///   never depends on which entry a search lands on, even for a list built
///   by hand. Glob and regex entries carry `data_idx > 0` and are skipped.
fn suffix_rules(parent: &str, filter: &FilterEngine) -> SuffixRules {
    let hash = twox_hash::XxHash64::oneshot(filter.seed, parent.as_bytes());
    let key = (count_dots(parent), hash);
    let mut rules = SuffixRules {
        blocks: false,
        allows: fast_lookup_hashed(parent, hash, filter).is_some_and(|flags| {
            flags.contains(DomainEntryFlags::WHITELIST | DomainEntryFlags::WILDCARD)
        }),
    };

    // hierarchical_list is sorted by (depth, hash).
    let list = &filter.hierarchical_list;
    let start = list.partition_point(|entry| (entry.depth, entry.hash) < key);
    for entry in list[start..]
        .iter()
        .take_while(|entry| (entry.depth, entry.hash) == key)
        .filter(|entry| entry.data_idx == 0 && entry.flags.contains(DomainEntryFlags::WILDCARD))
    {
        if entry.flags.contains(DomainEntryFlags::WHITELIST) {
            rules.allows = true;
        } else {
            rules.blocks = true;
        }
    }
    rules
}

/// Return `true` when some parent of `domain` carries a whitelist suffix rule.
fn has_whitelisted_parent(domain: &str, filter: &FilterEngine) -> bool {
    parents(domain).any(|parent| suffix_rules(parent, filter).allows)
}

/// Check if domain is whitelisted: exact match in fast_map with WHITELIST flag,
/// or a parent whitelisted as a suffix (`@@||parent^`, `@@||*.parent^`).
///
/// A whitelist always wins over block rules, however specific they are.
pub fn is_whitelisted(domain: &str, filter: &FilterEngine) -> bool {
    let domain = super::normalize_domain(domain);
    let domain = domain.as_ref();
    // An exact blacklist hit must not hide a parent suffix exception.
    if fast_lookup(domain, filter).is_some_and(|flags| flags.contains(DomainEntryFlags::WHITELIST))
    {
        return true;
    }
    has_whitelisted_parent(domain, filter)
}

/// Check if domain is blocked by static list (exact match without WHITELIST
/// flag, and no whitelist suffix rule on a parent).
pub fn is_blocked(domain: &str, filter: &FilterEngine) -> bool {
    let domain = super::normalize_domain(domain);
    let domain = domain.as_ref();
    fast_lookup(domain, filter).is_some_and(|flags| !flags.contains(DomainEntryFlags::WHITELIST))
        && !has_whitelisted_parent(domain, filter)
}

/// Check if domain is on the Newly Registered Domain list.
pub fn is_nrd(domain: &str, filter: &FilterEngine) -> bool {
    let domain = super::normalize_domain(domain);
    let domain = domain.as_ref();
    fast_lookup(domain, filter)
        .map(|flags| flags.contains(DomainEntryFlags::NRD))
        .unwrap_or(false)
}

/// Check if a parent of `domain` carries a blocking suffix rule and no
/// whitelist (exact or suffix) covers `domain`.
///
/// The whitelist check makes the result independent of the pipeline order and
/// keeps callers outside the pipeline (CNAME cloaking) consistent with it.
pub fn is_suffix_blocked(domain: &str, filter: &FilterEngine) -> bool {
    let domain = super::normalize_domain(domain);
    let domain = domain.as_ref();
    if fast_lookup(domain, filter).is_some_and(|flags| flags.contains(DomainEntryFlags::WHITELIST))
    {
        return false;
    }

    // A whitelist on a less specific parent still wins: walk every parent.
    let mut blocked = false;
    for parent in parents(domain) {
        let rules = suffix_rules(parent, filter);
        if rules.allows {
            return false;
        }
        blocked |= rules.blocks;
    }
    blocked
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::DomainEntry;
    use crate::resolve::tests::{create_engine_with_tld_block, create_test_engine};

    const SEED: u64 = 42;

    fn hierarchical(domain: &str, flags: DomainEntryFlags, data_idx: usize) -> DomainEntry {
        DomainEntry {
            hash: twox_hash::XxHash64::oneshot(SEED, domain.as_bytes()),
            flags,
            depth: count_dots(domain),
            data_idx,
        }
    }

    fn sort(engine: &mut FilterEngine) {
        engine
            .hierarchical_list
            .sort_by(|a, b| a.depth.cmp(&b.depth).then(a.hash.cmp(&b.hash)));
    }

    #[test]
    fn test_parents_most_specific_first() {
        assert_eq!(
            parents("a.b.example.com").collect::<Vec<_>>(),
            ["b.example.com", "example.com", "com"]
        );
        assert_eq!(parents("localhost").count(), 0);
    }

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

    #[test]
    fn test_suffix_rules_scans_whole_key_range() {
        // Block and whitelist entries for the same key: both must be seen,
        // whatever order the sort leaves them in.
        let mut engine = create_test_engine(&[], &[], &[]);
        let both = DomainEntryFlags::WHITELIST | DomainEntryFlags::WILDCARD;
        engine.hierarchical_list = vec![
            hierarchical("evil.com", DomainEntryFlags::WILDCARD, 0),
            hierarchical("evil.com", both, 0),
            hierarchical("evil.com", DomainEntryFlags::WILDCARD, 0),
        ];
        sort(&mut engine);
        let rules = suffix_rules("evil.com", &engine);
        assert!(rules.blocks);
        assert!(rules.allows);
    }

    #[test]
    fn test_suffix_rules_skips_pattern_entries() {
        let mut engine = create_test_engine(&[], &[], &[]);
        // A glob/regex entry whose key happens to equal the parent's.
        engine.hierarchical_list = vec![hierarchical("evil.com", DomainEntryFlags::WILDCARD, 1)];
        assert!(!suffix_rules("evil.com", &engine).blocks);
        assert!(!is_suffix_blocked("a.evil.com", &engine));
    }

    #[test]
    fn test_suffix_whitelist_on_parent_wins_over_more_specific_block() {
        let mut engine = create_test_engine(&[], &[], &["ads.ok.com"]);
        let both = DomainEntryFlags::WHITELIST | DomainEntryFlags::WILDCARD;
        engine
            .hierarchical_list
            .push(hierarchical("ok.com", both, 0));
        sort(&mut engine);
        assert!(is_whitelisted("x.ads.ok.com", &engine));
        assert!(!is_suffix_blocked("x.ads.ok.com", &engine));
    }

    #[test]
    fn test_fast_map_whitelist_suffix_disables_suffix_block() {
        let mut engine = create_test_engine(&[], &[], &["evil.com"]);
        let hash = twox_hash::XxHash64::oneshot(SEED, b"ok.evil.com");
        let both = DomainEntryFlags::WHITELIST | DomainEntryFlags::WILDCARD;
        engine
            .fast_map
            .insert(hash, (both.bits(), "ok.evil.com".into()));
        assert!(is_suffix_blocked("a.evil.com", &engine));
        assert!(!is_suffix_blocked("a.ok.evil.com", &engine));
        assert!(!is_suffix_blocked("ok.evil.com", &engine));
    }

    #[test]
    fn test_is_blocked_yields_to_parent_whitelist_suffix() {
        let mut engine = create_test_engine(&["s.youtube.com"], &[], &[]);
        assert!(is_blocked("s.youtube.com", &engine));
        let both = DomainEntryFlags::WHITELIST | DomainEntryFlags::WILDCARD;
        engine
            .hierarchical_list
            .push(hierarchical("youtube.com", both, 0));
        sort(&mut engine);
        assert!(!is_blocked("s.youtube.com", &engine));
    }
}
