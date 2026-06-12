pub use dgaard_engine::model::{BlockReason, SuspicionScore};
pub use dgaard_engine::resolve::ResolveResult;

use dgaard_engine::model::InspectedAnswer;
use dgaard_engine::resolve::{
    check_qclass as engine_check_qclass, check_qtype as engine_check_qtype,
    resolve_with_score as engine_resolve, score_answer as engine_score_answer,
};

use crate::{CONFIG, CURRENT_ENGINE};

/// Run the filter pipeline for a domain, loading globals.
///
/// Thin wrapper that loads `CURRENT_ENGINE` and `CONFIG` and delegates
/// to `dgaard_engine::resolve::resolve_with_score`.
pub fn resolve_with_score(domain: &str) -> ResolveResult {
    let filter = CURRENT_ENGINE.load();
    let config = CONFIG.load();
    engine_resolve(domain, &filter, &config)
}

/// Check if a query type is explicitly forbidden by the QType Warden policy.
pub fn check_qtype(qtype: u16) -> Option<BlockReason> {
    let config = CONFIG.load();
    engine_check_qtype(qtype, &config)
}

/// Check if a query class should be blocked (e.g. CHAOS class reconnaissance).
pub fn check_qclass(qclass: u16) -> Option<BlockReason> {
    let config = CONFIG.load();
    engine_check_qclass(qclass, &config)
}

/// Score the upstream DNS answer, accumulating DPI signals into the score.
pub fn score_answer(score: &mut SuspicionScore, answer: &InspectedAnswer) {
    let filter = CURRENT_ENGINE.load();
    let config = CONFIG.load();
    engine_score_answer(score, answer, &filter, &config);
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::{CONFIG, CURRENT_ENGINE, GLOBAL_SEED};
    use dgaard_engine::filter::engine::FilterEngine;
    use dgaard_engine::model::{Action, DomainEntry, DomainEntryFlags};
    use std::collections::{HashMap, HashSet};
    use std::sync::atomic::Ordering;
    use std::sync::{Arc, LazyLock, Mutex, MutexGuard};

    // Serialise all tests that mutate shared globals (CURRENT_ENGINE, CONFIG).
    static TEST_MUTEX: LazyLock<Mutex<()>> = LazyLock::new(Mutex::default);

    pub fn init_test_env() -> MutexGuard<'static, ()> {
        let guard = TEST_MUTEX.lock().unwrap();
        GLOBAL_SEED.store(42, Ordering::Relaxed);
        guard
    }

    pub fn create_test_engine(
        blocklist: &[&str],
        whitelist: &[&str],
        wildcards: &[&str],
    ) -> FilterEngine {
        let mut fast_map = HashMap::new();
        for domain in blocklist {
            let hash = twox_hash::XxHash64::oneshot(42, domain.as_bytes());
            fast_map.insert(hash, DomainEntryFlags::NONE.bits());
        }
        for domain in whitelist {
            let hash = twox_hash::XxHash64::oneshot(42, domain.as_bytes());
            fast_map.insert(hash, DomainEntryFlags::WHITELIST.bits());
        }
        let mut hierarchical_list: Vec<DomainEntry> = Vec::new();
        for domain in wildcards {
            let hash = twox_hash::XxHash64::oneshot(42, domain.as_bytes());
            hierarchical_list.push(DomainEntry {
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
            keyword_automaton: None,
            keyword_patterns: Vec::new(),
            suspicious_tld_hashes: HashSet::new(),
            lexical_strict: true,
            blocked_asn_v4: Vec::new(),
            blocked_asn_v6: Vec::new(),
            geoip_reader: None,
            geoip_file_meta: None,
            suspicious_country_codes: HashSet::new(),
            suspicious_country_score: 3,
            custom_flag_maps: Vec::new(),
            seed: 42,
        }
    }

    pub fn create_engine_with_tld_block(tlds: &[&str]) -> FilterEngine {
        let mut hierarchical_list: Vec<DomainEntry> = Vec::new();
        for tld in tlds {
            let tld_clean = tld.strip_prefix('.').unwrap_or(tld);
            let hash = twox_hash::XxHash64::oneshot(42, tld_clean.as_bytes());
            hierarchical_list.push(DomainEntry {
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
            keyword_automaton: None,
            keyword_patterns: Vec::new(),
            suspicious_tld_hashes: HashSet::new(),
            lexical_strict: true,
            blocked_asn_v4: Vec::new(),
            blocked_asn_v6: Vec::new(),
            geoip_reader: None,
            geoip_file_meta: None,
            suspicious_country_codes: HashSet::new(),
            suspicious_country_score: 3,
            custom_flag_maps: Vec::new(),
            seed: 42,
        }
    }

    pub fn create_engine_with_wildcard_patterns(patterns: &[&str]) -> FilterEngine {
        FilterEngine {
            fast_map: HashMap::new(),
            hierarchical_list: Vec::new(),
            regex_pool: Vec::new(),
            wildcard_patterns: patterns.iter().map(|s| s.to_string()).collect(),
            keyword_automaton: None,
            keyword_patterns: Vec::new(),
            suspicious_tld_hashes: HashSet::new(),
            lexical_strict: true,
            blocked_asn_v4: Vec::new(),
            blocked_asn_v6: Vec::new(),
            geoip_reader: None,
            geoip_file_meta: None,
            suspicious_country_codes: HashSet::new(),
            suspicious_country_score: 3,
            custom_flag_maps: Vec::new(),
            seed: 42,
        }
    }

    pub fn create_lexical_engine(
        keywords: &[&str],
        strict: bool,
        suspicious_tlds: &[&str],
    ) -> FilterEngine {
        use aho_corasick::AhoCorasick;

        let keyword_patterns: Vec<String> = keywords.iter().map(|k| k.to_lowercase()).collect();
        let keyword_automaton = if keyword_patterns.is_empty() {
            None
        } else {
            AhoCorasick::new(&keyword_patterns).ok()
        };

        let suspicious_tld_hashes: HashSet<u64> = suspicious_tlds
            .iter()
            .map(|tld| {
                let tld_clean = tld.strip_prefix('.').unwrap_or(tld).to_ascii_lowercase();
                twox_hash::XxHash64::oneshot(42, tld_clean.as_bytes())
            })
            .collect();

        FilterEngine {
            fast_map: HashMap::new(),
            hierarchical_list: Vec::new(),
            regex_pool: Vec::new(),
            wildcard_patterns: Vec::new(),
            keyword_automaton,
            keyword_patterns,
            suspicious_tld_hashes,
            lexical_strict: strict,
            blocked_asn_v4: Vec::new(),
            blocked_asn_v6: Vec::new(),
            geoip_reader: None,
            geoip_file_meta: None,
            suspicious_country_codes: HashSet::new(),
            suspicious_country_score: 3,
            custom_flag_maps: Vec::new(),
            seed: 42,
        }
    }

    #[test]
    fn test_resolve_blocked_domain() {
        let _guard = init_test_env();
        let engine = create_test_engine(&["ads.tracker.com"], &[], &[]);
        CURRENT_ENGINE.store(Arc::new(engine));

        let action = resolve_with_score("ads.tracker.com").action;
        assert!(matches!(
            action,
            Action::Block(BlockReason::StaticBlacklist(_))
        ));
    }

    #[test]
    fn test_resolve_whitelisted_domain() {
        let _guard = init_test_env();
        let engine = create_test_engine(&[], &["trusted.example.com"], &[]);
        CURRENT_ENGINE.store(Arc::new(engine));

        let action = resolve_with_score("trusted.example.com").action;
        assert!(matches!(action, Action::Allow));
    }

    #[test]
    fn test_resolve_unknown_domain_proxied() {
        let _guard = init_test_env();
        let engine = create_test_engine(&[], &[], &[]);
        CURRENT_ENGINE.store(Arc::new(engine));

        let action = resolve_with_score("unknown.example.com").action;
        assert!(matches!(action, Action::ProxyToUpstream));
    }

    #[test]
    fn test_resolve_invalid_structure_blocked() {
        let _guard = init_test_env();
        let engine = create_test_engine(&[], &[], &[]);
        CURRENT_ENGINE.store(Arc::new(engine));

        let action = resolve_with_score("a.b.c.d.e.f.g.h.i.j.k.example.com").action;
        assert!(matches!(
            action,
            Action::Block(BlockReason::InvalidStructure)
        ));
    }

    #[test]
    fn test_resolve_idn_blocked() {
        let _guard = init_test_env();
        let engine = create_test_engine(&[], &[], &[]);
        CURRENT_ENGINE.store(Arc::new(engine));

        let action = resolve_with_score("xn--pple-43d.com").action;
        assert!(matches!(action, Action::Block(BlockReason::SuspiciousIdn)));
    }

    #[test]
    fn test_resolve_tld_blocked_domain() {
        let _guard = init_test_env();
        let engine = create_engine_with_tld_block(&["xyz"]);
        CURRENT_ENGINE.store(Arc::new(engine));

        let action = resolve_with_score("malware.xyz").action;
        assert!(
            matches!(action, Action::Block(BlockReason::AbpRule(_))),
            "Domain under blocked TLD should be blocked, got: {:?}",
            action
        );
    }

    #[test]
    fn test_resolve_wildcard_pattern_blocked() {
        let _guard = init_test_env();
        let engine = create_engine_with_wildcard_patterns(&["ads*.example.com"]);
        CURRENT_ENGINE.store(Arc::new(engine));

        let action = resolve_with_score("ads1.example.com").action;
        assert!(
            matches!(action, Action::Block(BlockReason::AbpRule(ref s)) if s == "glob"),
            "Domain matching wildcard pattern should be blocked with 'glob', got: {:?}",
            action
        );
    }

    #[test]
    fn test_resolve_lexical_blocked() {
        let _guard = init_test_env();
        let mut config = dgaard_engine::config::Config::default();
        config.security.lexical.enabled = true;
        config.security.lexical.banned_keywords = vec!["porno".to_string()];
        config.security.lexical.strict_keyword_matching = true;
        CONFIG.store(Arc::new(config));
        let engine = create_lexical_engine(&["porno"], true, &[]);
        CURRENT_ENGINE.store(Arc::new(engine));

        let action = resolve_with_score("porno.com").action;
        assert!(
            matches!(action, Action::Block(BlockReason::BannedKeyword(ref k)) if k == "porno"),
            "Domain with banned keyword should be blocked, got: {:?}",
            action
        );
    }

    #[test]
    fn test_resolve_with_score_normal_domain() {
        let _guard = init_test_env();
        let engine = create_test_engine(&[], &[], &[]);
        CURRENT_ENGINE.store(Arc::new(engine));

        let result = resolve_with_score("google.com");
        assert!(matches!(result.action, Action::ProxyToUpstream));
        assert_eq!(result.score.total, 0);
    }

    #[test]
    fn test_resolve_with_score_whitelisted() {
        let _guard = init_test_env();
        let engine = create_test_engine(&[], &["trusted.example.com"], &[]);
        CURRENT_ENGINE.store(Arc::new(engine));

        let result = resolve_with_score("trusted.example.com");
        assert!(matches!(result.action, Action::Allow));
        assert_eq!(result.score.total, 0);
    }

    #[test]
    fn test_resolve_with_score_high_entropy() {
        let _guard = init_test_env();
        CONFIG.store(Arc::new(dgaard_engine::config::Config::default()));
        let engine = create_test_engine(&[], &[], &[]);
        CURRENT_ENGINE.store(Arc::new(engine));

        let result = resolve_with_score("a1b2c3d4e5f6g7h8i9j0.com");
        assert!(
            result.score.total >= 4,
            "Expected entropy score >= 4, got {}",
            result.score.total
        );
    }
}
