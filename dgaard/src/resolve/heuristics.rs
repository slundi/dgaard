use crate::dga::{
    entropy::{calculate_entropy, calculate_entropy_fast, is_consonant_suspicious},
    ngram::{NgramLanguage, ngram_check_embedded},
};
use crate::model::BlockReason;
use crate::{CONFIG, CURRENT_ENGINE};

/// Check lexical/keyword filtering for parental control.
///
/// This function implements label-aware keyword matching to block domains
/// containing banned keywords (e.g., adult, gambling content).
///
/// Uses Aho-Corasick automaton for O(n) multi-pattern matching and xxh3
/// hash lookup for O(1) TLD verification.
///
/// Matching modes:
/// - Strict (default): Keyword must be a complete label or hyphen-separated segment
/// - Loose: Simple substring match (higher false-positive rate)
///
/// If `suspicious_tlds` is configured, the domain must also use one of those TLDs.
///
/// Returns `Some(BlockReason::BannedKeyword)` if blocked, `None` if allowed.
pub fn check_lexical(domain: &str) -> Option<BlockReason> {
    let engine = CURRENT_ENGINE.load();

    // Early exit if no automaton or no keywords configured
    let automaton = engine.keyword_automaton.as_ref()?;

    // Extract TLD and check via O(1) hash lookup
    let tld = domain.rsplit('.').next()?;
    if !engine.is_suspicious_tld(tld) {
        return None;
    }

    let domain_lower = domain.to_ascii_lowercase();

    if engine.lexical_strict {
        // Strict mode: verify match is at label or hyphen boundary
        for mat in automaton.find_iter(&domain_lower) {
            let start = mat.start();
            let end = mat.end();

            // Check if match is at valid boundary (start of domain, after '.' or '-')
            let valid_start =
                start == 0 || matches!(domain_lower.as_bytes().get(start - 1), Some(b'.' | b'-'));

            // Check if match ends at valid boundary (end of domain, before '.' or '-')
            let valid_end = end == domain_lower.len()
                || matches!(domain_lower.as_bytes().get(end), Some(b'.' | b'-'));

            if valid_start && valid_end {
                let keyword = &engine.keyword_patterns[mat.pattern().as_usize()];
                return Some(BlockReason::BannedKeyword(keyword.clone()));
            }
        }
    } else {
        // Loose mode: any substring match
        if let Some(mat) = automaton.find(&domain_lower) {
            let keyword = &engine.keyword_patterns[mat.pattern().as_usize()];
            return Some(BlockReason::BannedKeyword(keyword.clone()));
        }
    }

    None
}

/// Check DGA heuristics and return the specific BlockReason if suspicious.
///
/// This function applies multiple heuristics in order:
/// 1. Shannon entropy check (detects random character strings)
/// 2. Consonant clustering check (detects unpronounceable patterns)
/// 3. N-gram language model check (detects non-natural language patterns)
///
/// Returns `Some(BlockReason)` if the domain fails any check, `None` if it passes.
pub fn check_dga_heuristics(domain: &str) -> Option<BlockReason> {
    let config = CONFIG.load();
    let intel = &config.security.intelligence;

    if !intel.enabled {
        return None;
    }

    // Extract the second-level domain (SLD)
    // "sub.example.com" -> "example"
    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() < 2 {
        return None;
    }

    let sld = parts[parts.len() - 2];

    // Skip short domains to avoid false positives
    if sld.len() < intel.min_word_length {
        return None;
    }

    // 1. Shannon entropy check
    let entropy = if intel.entropy_fast {
        calculate_entropy_fast(sld)
    } else {
        calculate_entropy(sld)
    };
    if entropy > intel.entropy_threshold {
        return Some(BlockReason::HighEntropy(entropy));
    }

    // 2. Consonant clustering check
    if is_consonant_suspicious(
        sld,
        intel.consonant_ratio_threshold,
        intel.max_consonant_sequence,
    ) {
        return Some(BlockReason::LexicalAnalysis);
    }

    // 3. N-gram language model check (if enabled)
    if intel.use_ngram_model && intel.ngram_use_embedded {
        let languages: Vec<NgramLanguage> = intel
            .ngram_embedded_languages
            .iter()
            .filter_map(|s| NgramLanguage::from_str(s))
            .collect();

        // If domain fails ALL language models, it's suspicious
        if !languages.is_empty()
            && !ngram_check_embedded(sld, &languages, intel.ngram_probability_threshold)
        {
            return Some(BlockReason::LexicalAnalysis);
        }
    }

    None
}

/// Check if domain is suspicious based on DGA heuristics.
/// Uses Shannon entropy on the second-level domain (SLD).
#[allow(dead_code)] // Public API for external callers
pub fn is_dga_suspicious(domain: &str) -> bool {
    check_dga_heuristics(domain).is_some()
}

/// Check if domain contains illegal IDN/Punycode characters.
pub fn is_illegal_idn(domain: &str) -> bool {
    let config = CONFIG.load();
    if !config.server.block_idn {
        return false;
    }

    // Check for Punycode prefix in any segment
    if domain.split('.').any(|part| part.starts_with("xn--")) {
        return true;
    }

    // Check for raw non-ASCII characters
    !domain.is_ascii()
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::CURRENT_ENGINE;
    use crate::resolve::tests::{create_lexical_engine, create_test_engine, init_test_env};
    use std::sync::Arc;

    #[test]
    fn test_is_dga_suspicious_high_entropy() {
        init_test_env();
        // High entropy domain (SLD has random characters)
        // The function checks the second-level domain (SLD), not the subdomain
        // Entropy threshold is 4.0, need at least 17+ unique chars for entropy > 4.0
        // "a1b2c3d4e5f6g7h8i9j0.com" -> SLD is "a1b2c3d4e5f6g7h8i9j0" (entropy ~4.32)
        assert!(is_dga_suspicious("a1b2c3d4e5f6g7h8i9j0.com"));
        // With subdomain: "sub.qwertasdfzxcv1234567890.net" -> SLD has entropy ~4.52
        assert!(is_dga_suspicious("sub.qwertasdfzxcv1234567890.net"));

        // Normal domains (SLD has low entropy - readable words)
        // "google" entropy ~1.92, "facebook" entropy ~2.75
        assert!(!is_dga_suspicious("google.com"));
        assert!(!is_dga_suspicious("facebook.com"));
        assert!(!is_dga_suspicious("sub.example.org"));
    }

    #[test]
    fn test_is_dga_suspicious_short_domain_skipped() {
        init_test_env();
        // Short domains should be skipped
        assert!(!is_dga_suspicious("t.co"));
        assert!(!is_dga_suspicious("fb.com"));
    }

    #[test]
    fn test_is_illegal_idn_punycode() {
        init_test_env();
        // Punycode domain
        assert!(is_illegal_idn("xn--pple-43d.com")); // fake apple with Cyrillic

        // Normal ASCII domain
        assert!(!is_illegal_idn("apple.com"));
    }

    #[test]
    fn test_check_lexical_strict_exact_label_match() {
        init_test_env();
        let engine = create_lexical_engine(&["casino", "porno"], true, &[]);
        CURRENT_ENGINE.store(Arc::new(engine));

        // Exact label match should block
        assert!(check_lexical("casino.com").is_some());
        assert!(check_lexical("www.casino.net").is_some());
        assert!(check_lexical("porno.site.org").is_some());
    }

    #[test]
    fn test_check_lexical_strict_hyphen_separated() {
        init_test_env();
        let engine = create_lexical_engine(&["casino"], true, &[]);
        CURRENT_ENGINE.store(Arc::new(engine));

        // Hyphen-separated segment should block
        assert!(check_lexical("play-casino.net").is_some());
        assert!(check_lexical("online-casino-games.com").is_some());
    }

    #[test]
    fn test_check_lexical_strict_no_substring_match() {
        init_test_env();
        let engine = create_lexical_engine(&["casino"], true, &[]);
        CURRENT_ENGINE.store(Arc::new(engine));

        // Substring within a word should NOT block in strict mode (Scunthorpe problem)
        assert!(check_lexical("casinon-les-bains.fr").is_none()); // French town
        assert!(check_lexical("mycasinoapp.com").is_none());
    }

    #[test]
    fn test_check_lexical_loose_substring_match() {
        init_test_env();
        let engine = create_lexical_engine(&["casino"], false, &[]); // strict = false
        CURRENT_ENGINE.store(Arc::new(engine));

        // Loose mode should block on substring
        assert!(check_lexical("mycasinoapp.com").is_some());
        assert!(check_lexical("casinon-les-bains.fr").is_some());
    }

    #[test]
    fn test_check_lexical_case_insensitive() {
        init_test_env();
        let engine = create_lexical_engine(&["Casino", "PORNO"], true, &[]);
        CURRENT_ENGINE.store(Arc::new(engine));

        // Should match regardless of case
        assert!(check_lexical("casino.com").is_some());
        assert!(check_lexical("CASINO.COM").is_some());
        assert!(check_lexical("porno.net").is_some());
    }

    #[test]
    fn test_check_lexical_with_suspicious_tlds() {
        init_test_env();
        let engine = create_lexical_engine(&["casino"], true, &[".biz", ".top"]);
        CURRENT_ENGINE.store(Arc::new(engine));

        // Should only block if TLD matches
        assert!(check_lexical("casino.biz").is_some());
        assert!(check_lexical("casino.top").is_some());

        // Should NOT block for other TLDs (even with keyword match)
        assert!(check_lexical("casino.com").is_none());
        assert!(check_lexical("casino.org").is_none());
    }

    #[test]
    fn test_check_lexical_disabled() {
        init_test_env();
        // Disabled = no automaton built
        let engine = create_test_engine(&[], &[], &[]);
        CURRENT_ENGINE.store(Arc::new(engine));

        // Should not block when no automaton
        assert!(check_lexical("casino.com").is_none());
    }

    #[test]
    fn test_check_lexical_empty_keywords() {
        init_test_env();
        let engine = create_lexical_engine(&[], true, &[]);
        CURRENT_ENGINE.store(Arc::new(engine));

        // Should not block with no keywords
        assert!(check_lexical("casino.com").is_none());
        assert!(check_lexical("anything.net").is_none());
    }
}
