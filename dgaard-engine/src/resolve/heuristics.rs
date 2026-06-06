use crate::config::Config;
use crate::dga::{
    entropy::{calculate_entropy, calculate_entropy_fast, is_consonant_suspicious},
    ngram::{NgramLanguage, ngram_check_embedded},
};
use crate::filter::engine::FilterEngine;
use crate::model::BlockReason;

/// Check lexical/keyword filtering for parental control.
///
/// Uses Aho-Corasick automaton for O(n) multi-pattern matching and xxh3
/// hash lookup for O(1) TLD verification.
///
/// Matching modes:
/// - Strict (default): Keyword must be a complete label or hyphen-separated segment
/// - Loose: Simple substring match (higher false-positive rate)
pub fn check_lexical(domain: &str, filter: &FilterEngine) -> Option<BlockReason> {
    let automaton = filter.keyword_automaton.as_ref()?;

    let tld = domain.rsplit('.').next()?;
    if !filter.is_suspicious_tld(tld) {
        return None;
    }

    let domain_lower = domain.to_ascii_lowercase();

    if filter.lexical_strict {
        for mat in automaton.find_iter(&domain_lower) {
            let start = mat.start();
            let end = mat.end();

            let valid_start =
                start == 0 || matches!(domain_lower.as_bytes().get(start - 1), Some(b'.' | b'-'));
            let valid_end = end == domain_lower.len()
                || matches!(domain_lower.as_bytes().get(end), Some(b'.' | b'-'));

            if valid_start && valid_end {
                let keyword = &filter.keyword_patterns[mat.pattern().as_usize()];
                return Some(BlockReason::BannedKeyword(keyword.clone()));
            }
        }
    } else if let Some(mat) = automaton.find(&domain_lower) {
        let keyword = &filter.keyword_patterns[mat.pattern().as_usize()];
        return Some(BlockReason::BannedKeyword(keyword.clone()));
    }

    None
}

/// Check DGA heuristics: entropy, consonant clustering, n-gram models.
pub fn check_dga_heuristics(domain: &str, config: &Config) -> Option<BlockReason> {
    let intel = &config.security.intelligence;

    if !intel.enabled {
        return None;
    }

    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() < 2 {
        return None;
    }

    let sld = parts[parts.len() - 2];

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

    // 3. N-gram language model check
    if intel.use_ngram_model && intel.ngram_use_embedded {
        let languages: Vec<NgramLanguage> = intel
            .ngram_embedded_languages
            .iter()
            .filter_map(|s| NgramLanguage::parse(s))
            .collect();

        if !languages.is_empty()
            && !ngram_check_embedded(sld, &languages, intel.ngram_probability_threshold)
        {
            return Some(BlockReason::LexicalAnalysis);
        }
    }

    None
}

/// Check if domain is suspicious based on DGA heuristics.
#[allow(dead_code)]
pub fn is_dga_suspicious(domain: &str, config: &Config) -> bool {
    check_dga_heuristics(domain, config).is_some()
}

/// Check if domain contains illegal IDN/Punycode characters.
pub fn is_illegal_idn(domain: &str, config: &Config) -> bool {
    if !config.server.block_idn {
        return false;
    }

    if domain.split('.').any(|part| part.starts_with("xn--")) {
        return true;
    }

    !domain.is_ascii()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolve::tests::{create_lexical_engine, create_test_engine};

    #[test]
    fn test_is_dga_suspicious_high_entropy() {
        let config = Config::default();
        assert!(is_dga_suspicious("a1b2c3d4e5f6g7h8i9j0.com", &config));
        assert!(!is_dga_suspicious("google.com", &config));
        assert!(!is_dga_suspicious("facebook.com", &config));
    }

    #[test]
    fn test_is_dga_suspicious_short_domain_skipped() {
        let config = Config::default();
        assert!(!is_dga_suspicious("t.co", &config));
        assert!(!is_dga_suspicious("fb.com", &config));
    }

    #[test]
    fn test_is_illegal_idn_punycode() {
        let config = Config::default();
        assert!(is_illegal_idn("xn--pple-43d.com", &config));
        assert!(!is_illegal_idn("apple.com", &config));
    }

    #[test]
    fn test_check_lexical_strict_exact_label_match() {
        let engine = create_lexical_engine(&["casino", "porno"], true, &[]);
        assert!(check_lexical("casino.com", &engine).is_some());
        assert!(check_lexical("www.casino.net", &engine).is_some());
    }

    #[test]
    fn test_check_lexical_strict_no_substring_match() {
        let engine = create_lexical_engine(&["casino"], true, &[]);
        assert!(check_lexical("casinon-les-bains.fr", &engine).is_none());
        assert!(check_lexical("mycasinoapp.com", &engine).is_none());
    }

    #[test]
    fn test_check_lexical_loose_substring_match() {
        let engine = create_lexical_engine(&["casino"], false, &[]);
        assert!(check_lexical("mycasinoapp.com", &engine).is_some());
    }

    #[test]
    fn test_check_lexical_with_suspicious_tlds() {
        let engine = create_lexical_engine(&["casino"], true, &[".biz", ".top"]);
        assert!(check_lexical("casino.biz", &engine).is_some());
        assert!(check_lexical("casino.com", &engine).is_none());
    }

    #[test]
    fn test_check_lexical_disabled() {
        let engine = create_test_engine(&[], &[], &[]);
        assert!(check_lexical("casino.com", &engine).is_none());
    }
}
