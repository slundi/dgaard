//! End-to-end list semantics: raw list text → `FilterEngine::build_from_files`
//! (the parsing path the daemon uses) → `resolve_with_score`.
//!
//! Unit tests that build a `FilterEngine` by hand never exercise the
//! parser → matcher chain, which is how `||domain^` silently stopped covering
//! subdomains. These tests go through the real loaders only.

use std::io::Write as _;

use dgaard_engine::{Action, BlockReason, Config, FilterEngine, resolve_with_score};
use tempfile::NamedTempFile;

const SEED: u64 = 42;

/// Build an engine from in-memory blacklist and whitelist contents.
fn engine_from(black: &str, white: &str) -> (FilterEngine, Config) {
    let mut files = Vec::new();
    let mut config = Config::default();
    for (content, is_white) in [(black, false), (white, true)] {
        if content.is_empty() {
            continue;
        }
        let mut file = NamedTempFile::new().expect("create temp list");
        file.write_all(content.as_bytes()).expect("write temp list");
        let path = file.path().to_string_lossy().into_owned();
        if is_white {
            config.sources.whitelists.push(path);
        } else {
            config.sources.blacklists.push(path);
        }
        files.push(file);
    }
    let engine = FilterEngine::build_from_files(&config, SEED);
    (engine, config)
}

fn action(black: &str, white: &str, query: &str) -> Action {
    let (engine, config) = engine_from(black, white);
    resolve_with_score(query, &engine, &config).action
}

fn is_blocked(action: &Action) -> bool {
    matches!(action, Action::Block(_))
}

#[test]
fn abp_domain_rule_blocks_domain_itself() {
    let result = action("||ads.com^", "", "ads.com");
    assert!(
        matches!(result, Action::Block(BlockReason::StaticBlacklist(_))),
        "got {result:?}"
    );
}

#[test]
fn abp_domain_rule_blocks_subdomains() {
    for query in ["x.ads.com", "deep.x.ads.com"] {
        let result = action("||ads.com^", "", query);
        assert!(
            matches!(result, Action::Block(BlockReason::AbpRule(_))),
            "{query}: got {result:?}"
        );
    }
}

#[test]
fn abp_domain_rule_does_not_block_lookalike_or_parent() {
    // Suffix matching is label-aligned: `badads.com` is not under `ads.com`.
    assert!(!is_blocked(&action("||ads.com^", "", "badads.com")));
    assert!(!is_blocked(&action("||sub.ads.com^", "", "ads.com")));
}

#[test]
fn abp_domain_rule_with_options_still_suffix() {
    let result = action("||ads.com^$third-party", "", "x.ads.com");
    assert!(is_blocked(&result), "got {result:?}");
}

#[test]
fn hosts_entry_stays_exact() {
    // A hosts file maps names, not zones: no implicit subdomain coverage.
    assert!(is_blocked(&action("0.0.0.0 ads.com", "", "ads.com")));
    assert!(!is_blocked(&action("0.0.0.0 ads.com", "", "x.ads.com")));
}

#[test]
fn hosts_parent_does_not_swallow_listed_subdomain() {
    // Regression: `sub.ads.com` used to be dropped as "redundant" because the
    // exact `ads.com` was present, leaving it unblocked.
    let black = "0.0.0.0 ads.com\n0.0.0.0 sub.ads.com";
    assert!(is_blocked(&action(black, "", "sub.ads.com")));
    assert!(is_blocked(&action(black, "", "ads.com")));
}

#[test]
fn abp_parent_covers_listed_subdomain() {
    let black = "||ads.com^\n0.0.0.0 sub.ads.com";
    assert!(is_blocked(&action(black, "", "sub.ads.com")));
    assert!(is_blocked(&action(black, "", "other.ads.com")));
}

#[test]
fn exact_and_suffix_rule_for_same_domain_are_deterministic() {
    // Same (depth, hash) key reached from both an exact and a suffix rule,
    // in both orders: the subdomain must be blocked either way.
    for black in [
        "0.0.0.0 ads.com\n||ads.com^",
        "||ads.com^\n0.0.0.0 ads.com",
        "ads.com\n||ads.com^\n||ads.com^$important",
    ] {
        assert!(
            is_blocked(&action(black, "", "x.ads.com")),
            "list: {black:?}"
        );
    }
}

#[test]
fn mixed_case_entries_match_lowercase_queries() {
    assert!(is_blocked(&action(
        "0.0.0.0 Tracker.COM",
        "",
        "tracker.com"
    )));
    assert!(is_blocked(&action("Tracker.COM", "", "tracker.com")));
    assert!(is_blocked(&action("||Ads.COM^", "", "x.ads.com")));
}

#[test]
fn trailing_dot_entries_match() {
    assert!(is_blocked(&action("tracker.com.", "", "tracker.com")));
    assert!(is_blocked(&action(
        "0.0.0.0 tracker.com.",
        "",
        "tracker.com"
    )));
}

#[test]
fn tab_separated_hosts_are_loaded() {
    assert!(is_blocked(&action("0.0.0.0\tads.com", "", "ads.com")));
}

#[test]
fn hosts_line_with_several_names_blocks_each() {
    let black = "0.0.0.0 a.com b.com\tc.com # inline comment";
    for query in ["a.com", "b.com", "c.com"] {
        assert!(is_blocked(&action(black, "", query)), "{query}");
    }
    // The comment is not parsed as names.
    assert!(!is_blocked(&action(black, "", "comment")));
}

#[test]
fn exact_whitelist_overrides_only_itself() {
    let black = "||ads.com^";
    assert!(matches!(action(black, "ads.com", "ads.com"), Action::Allow));
    // An exact whitelist must not widen into a subdomain exception just
    // because the blacklist rule for the same name is a suffix rule.
    assert!(is_blocked(&action(black, "ads.com", "x.ads.com")));
}

#[test]
fn abp_whitelist_suffix_overrides_subdomains() {
    let black = "||ads.com^\n0.0.0.0 img.cdn.ads.com";
    let white = "@@||cdn.ads.com^";
    assert!(matches!(action(black, white, "cdn.ads.com"), Action::Allow));
    assert!(matches!(
        action(black, white, "img.cdn.ads.com"),
        Action::Allow
    ));
    assert!(is_blocked(&action(black, white, "other.ads.com")));
}
