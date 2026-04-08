//! Domain suspicion scoring engine.
//!
//! This module computes a suspicion score for domains based on multiple heuristic
//! signals. The scoring is cumulative - each signal adds points to the total.
//!
//! Scoring is designed to be computed early and cheaply, running lightweight checks
//! first and short-circuiting if the threshold is already exceeded.

use crate::dga::entropy::{calculate_entropy, calculate_entropy_fast, is_consonant_suspicious};
use crate::model::{BlockReason, SuspicionScore, score_points};
use crate::{CONFIG, CURRENT_ENGINE};

/// Maximum domain length before adding suspicion points.
const LONG_DOMAIN_THRESHOLD: usize = 60;

/// Subdomain depth (number of dots) before adding suspicion points.
const DEEP_SUBDOMAIN_THRESHOLD: usize = 5;

/// Compute the suspicion score for a domain.
///
/// This function evaluates multiple signals in order of computational cost:
/// 1. Structural checks (very fast, O(n) string scan)
/// 2. TLD checks (O(1) hash lookup)
/// 3. IDN/Punycode check (O(n) string scan)
/// 4. Entropy check (O(n) with small constant)
/// 5. Consonant clustering (O(n))
///
/// The function short-circuits if the score already exceeds the malicious threshold.
///
/// # Arguments
/// * `domain` - The domain name to score (lowercase, no trailing dot)
///
/// # Returns
/// A `SuspicionScore` containing the total score and contributing reasons.
pub fn compute_score(domain: &str) -> SuspicionScore {
    let mut score = SuspicionScore::new();
    let config = CONFIG.load();
    let engine = CURRENT_ENGINE.load();

    // 1. Long domain check (very cheap)
    if domain.len() > LONG_DOMAIN_THRESHOLD {
        score.add(score_points::LONG_DOMAIN, BlockReason::InvalidStructure);
        if score.is_malicious() {
            return score;
        }
    }

    // 2. Deep subdomain check (cheap - count dots)
    let depth = domain.bytes().filter(|&b| b == b'.').count();
    if depth >= DEEP_SUBDOMAIN_THRESHOLD {
        score.add(score_points::DEEP_SUBDOMAIN, BlockReason::InvalidStructure);
        if score.is_malicious() {
            return score;
        }
    }

    // 3. Suspicious TLD check (O(1) hash lookup)
    // Only add points if suspicious TLDs are explicitly configured
    if !engine.suspicious_tld_hashes.is_empty()
        && let Some(tld) = domain.rsplit('.').next()
        && engine.is_suspicious_tld(tld)
    {
        score.add(score_points::SUSPICIOUS_TLD, BlockReason::TldExcluded);
        if score.is_malicious() {
            return score;
        }
    }

    // 4. IDN/Punycode homograph check
    if is_idn_suspicious(domain) {
        score.add(score_points::IDN_HOMOGRAPH, BlockReason::SuspiciousIdn);
        if score.is_malicious() {
            return score;
        }
    }

    // 5. Entropy and consonant clustering (need to extract SLD)
    let intel = &config.security.intelligence;
    if intel.enabled
        && let Some(sld) = extract_sld(domain)
    {
        // Skip very short SLDs
        if sld.len() >= intel.min_word_length {
            // Entropy check
            let entropy = if intel.entropy_fast {
                calculate_entropy_fast(sld)
            } else {
                calculate_entropy(sld)
            };

            if entropy > intel.entropy_threshold {
                score.add(
                    score_points::ENTROPY_HIGH,
                    BlockReason::HighEntropy(entropy),
                );
                if score.is_malicious() {
                    return score;
                }
            }

            // Consonant clustering check
            if is_consonant_suspicious(
                sld,
                intel.consonant_ratio_threshold,
                intel.max_consonant_sequence,
            ) {
                score.add(
                    score_points::CONSONANT_CLUSTER,
                    BlockReason::LexicalAnalysis,
                );
            }
        }
    }

    score
}

/// Extract the second-level domain (SLD) from a domain name.
///
/// Examples:
/// - "sub.example.com" -> Some("example")
/// - "example.com" -> Some("example")
/// - "com" -> None
fn extract_sld(domain: &str) -> Option<&str> {
    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() >= 2 {
        Some(parts[parts.len() - 2])
    } else {
        None
    }
}

/// Check if domain contains suspicious IDN/Punycode patterns.
fn is_idn_suspicious(domain: &str) -> bool {
    // Check for Punycode prefix in any segment
    if domain.split('.').any(|part| part.starts_with("xn--")) {
        return true;
    }

    // Check for raw non-ASCII characters
    !domain.is_ascii()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolve::tests::init_test_env;
    use std::sync::Arc;

    fn setup_test_config() {
        init_test_env();
        let config = crate::config::Config::default();
        crate::CONFIG.store(Arc::new(config));
    }

    #[test]
    fn test_compute_score_normal_domain() {
        setup_test_config();
        let score = compute_score("google.com");
        assert_eq!(score.total, 0);
        assert!(score.reasons.is_empty());
        assert!(!score.is_suspicious());
    }

    #[test]
    fn test_compute_score_long_domain() {
        setup_test_config();
        // Domain > 60 chars
        let long_domain = format!("{}.com", "a".repeat(65));
        let score = compute_score(&long_domain);
        assert_eq!(score.total, score_points::LONG_DOMAIN);
        // 3 points is below the suspicious threshold (4)
        assert!(!score.is_suspicious());
    }

    #[test]
    fn test_compute_score_deep_subdomain() {
        setup_test_config();
        // 5+ levels of subdomains
        let score = compute_score("a.b.c.d.e.f.example.com");
        assert!(score.total >= score_points::DEEP_SUBDOMAIN);
    }

    #[test]
    fn test_compute_score_punycode() {
        setup_test_config();
        // Punycode domain (IDN homograph)
        let score = compute_score("xn--pple-43d.com");
        // IDN adds 6 points, plus possible entropy/consonant from the encoded SLD
        assert!(
            score.total >= score_points::IDN_HOMOGRAPH,
            "Expected at least {} for IDN, got {}",
            score_points::IDN_HOMOGRAPH,
            score.total
        );
        assert!(score.is_suspicious());
        // Verify IDN reason is included
        assert!(
            score
                .reasons
                .iter()
                .any(|r| matches!(r, BlockReason::SuspiciousIdn)),
            "Expected SuspiciousIdn reason, got: {:?}",
            score.reasons
        );
    }

    #[test]
    fn test_compute_score_high_entropy() {
        setup_test_config();
        // High entropy SLD (random-looking characters)
        // Need 17+ unique chars for entropy > 4.0
        let score = compute_score("a1b2c3d4e5f6g7h8i9j0.com");
        assert!(score.total >= score_points::ENTROPY_HIGH);
        assert!(
            score
                .reasons
                .iter()
                .any(|r| matches!(r, BlockReason::HighEntropy(_))),
            "Expected HighEntropy reason, got: {:?}",
            score.reasons
        );
    }

    #[test]
    fn test_compute_score_cumulative() {
        setup_test_config();
        // Long + deep subdomains + punycode = cumulative score
        let long_deep_idn = format!("xn--test.{}.{}.com", "a".repeat(30), "b.c.d.e.f");
        let score = compute_score(&long_deep_idn);
        // Should have multiple signals
        assert!(score.total >= score_points::IDN_HOMOGRAPH);
    }

    #[test]
    fn test_compute_score_short_sld_skipped() {
        setup_test_config();
        // Short SLD should not trigger entropy/consonant checks
        let score = compute_score("t.co");
        // Only structural checks apply, entropy is skipped
        assert_eq!(score.total, 0);
    }

    #[test]
    fn test_extract_sld() {
        assert_eq!(extract_sld("sub.example.com"), Some("example"));
        assert_eq!(extract_sld("example.com"), Some("example"));
        assert_eq!(extract_sld("deep.sub.example.com"), Some("example"));
        assert_eq!(extract_sld("com"), None);
    }

    #[test]
    fn test_is_idn_suspicious() {
        // Punycode
        assert!(is_idn_suspicious("xn--pple-43d.com"));
        // Non-ASCII
        assert!(is_idn_suspicious("exämple.com"));
        // Normal ASCII
        assert!(!is_idn_suspicious("example.com"));
        assert!(!is_idn_suspicious("sub.example.co.uk"));
    }

    #[test]
    fn test_score_threshold_malicious() {
        setup_test_config();
        // Create a domain that should hit the malicious threshold
        // IDN (6) + deep subdomain (3) + long domain (3) = 12 >= 10
        let malicious = format!("xn--evil.{}.a.b.c.d.e.example.com", "x".repeat(50));
        let score = compute_score(&malicious);
        assert!(
            score.is_malicious(),
            "Expected malicious score >= 10, got {}",
            score.total
        );
    }
}
