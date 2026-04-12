//! Domain suspicion scoring engine.
//!
//! This module computes a suspicion score for domains based on multiple heuristic
//! signals. The scoring is cumulative - each signal adds points to the total.
//!
//! Scoring is designed to be computed early and cheaply, running lightweight checks
//! first and short-circuiting if the threshold is already exceeded.

use super::heuristics::check_lexical;
use super::matcher::{is_blocked, is_nrd, is_suffix_blocked};
use crate::dga::entropy::{calculate_entropy, calculate_entropy_fast, is_consonant_suspicious};
use crate::dns::InspectedAnswer;
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
    let blocking_threshold = config.security.scoring.blocking_threshold;

    // 1. Long domain check (very cheap)
    if domain.len() > LONG_DOMAIN_THRESHOLD {
        score.add(score_points::LONG_DOMAIN, BlockReason::InvalidStructure);
        if score.total >= blocking_threshold {
            return score;
        }
    }

    // 2. Deep subdomain check (cheap - count dots)
    let depth = domain.bytes().filter(|&b| b == b'.').count();
    if depth >= DEEP_SUBDOMAIN_THRESHOLD {
        score.add(score_points::DEEP_SUBDOMAIN, BlockReason::InvalidStructure);
        if score.total >= blocking_threshold {
            return score;
        }
    }

    // 3. Suspicious TLD check (O(1) hash lookup)
    // Only add points if suspicious TLDs are explicitly configured
    if !engine.suspicious_tld_hashes.is_empty()
        && let Some(tld) = domain.rsplit('.').next()
        && engine.is_suspicious_tld(tld)
    {
        // Keyword + suspicious TLD is a stronger combined signal.
        // check_lexical returns Some only when both keyword and TLD conditions are met.
        if let Some(keyword_reason) = check_lexical(domain) {
            score.add(score_points::KEYWORD_SUSPICIOUS_TLD, keyword_reason);
        } else {
            score.add(score_points::SUSPICIOUS_TLD, BlockReason::TldExcluded);
        }
        if score.total >= blocking_threshold {
            return score;
        }
    }

    // 4. IDN/Punycode homograph check
    if is_idn_suspicious(domain) {
        score.add(score_points::IDN_HOMOGRAPH, BlockReason::SuspiciousIdn);
        if score.total >= blocking_threshold {
            return score;
        }
    }

    // 5. NRD check: newly registered domains are inherently more suspicious
    if is_nrd(domain) {
        score.add(score_points::NRD, BlockReason::NrdList);
        if score.total >= blocking_threshold {
            return score;
        }
    }

    // 6. Entropy and consonant clustering (need to extract SLD)
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
                if score.total >= blocking_threshold {
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

/// Apply suspicion scoring from a parsed DNS answer section.
///
/// Validates the upstream response records against structural config limits
/// defined in `security.structure`:
/// - `max_answers_per_query`: flags bloated responses (potential exfiltration)
/// - `max_txt_record_length`: flags oversized TXT records (DNS tunneling)
///
/// Also performs **CNAME unmasking**: each CNAME target in the answer
/// section is checked against the static blocklist and suffix/wildcard matchers.
/// A CNAME chain leading to a known-bad domain is a definitive cloaking signal
/// and immediately hits the malicious threshold.
///
/// # Arguments
/// * `score` - Mutable score to accumulate into
/// * `answer` - Parsed answer section from the upstream DNS response
pub fn score_answer(score: &mut SuspicionScore, answer: &InspectedAnswer) {
    let config = CONFIG.load();
    let structure = &config.security.structure;
    let blocking_threshold = config.security.scoring.blocking_threshold;

    // Check total answer record count across all types
    let total = answer.a_records.len()
        + answer.aaaa_records.len()
        + answer.txt_records.len()
        + answer.cname_targets.len();
    if total > structure.max_answers_per_query as usize {
        score.add(
            score_points::EXCESSIVE_ANSWERS,
            BlockReason::InvalidStructure,
        );
        if score.total >= blocking_threshold {
            return;
        }
    }

    // Low-TTL check: short TTLs are characteristic of fast-flux
    // malware infrastructure. Legitimate CDNs occasionally use short TTLs too,
    // so this adds suspicion points rather than blocking outright.
    let low_ttl_cfg = &config.security.low_ttl;
    if low_ttl_cfg.enabled
        && let Some(ttl) = answer.min_ttl
        && ttl < low_ttl_cfg.threshold_secs
    {
        score.add(score_points::LOW_TTL, BlockReason::LowTtl(ttl));
        if score.total >= blocking_threshold {
            return;
        }
    }

    // Check TXT record lengths — oversized segments suggest tunnel payloads.
    // One penalty per response to avoid inflating score for bulk records.
    for txt in &answer.txt_records {
        if txt.len() > structure.max_txt_record_length as usize {
            score.add(
                score_points::TXT_RECORD_TOO_LONG,
                BlockReason::InvalidStructure,
            );
            if score.total >= blocking_threshold {
                return;
            }
            break;
        }
    }

    // DNS Rebinding Shield: reject answers that map a public domain
    // to a private/reserved IP. An attacker-controlled domain resolving to a LAN
    // address can bypass same-origin policy and reach internal services via a
    // browser tab. One private record in the answer is conclusive.
    if config.security.rebinding_shield.enabled {
        for ip in &answer.a_records {
            if is_private_ipv4(*ip) {
                score.add(score_points::DNS_REBINDING, BlockReason::DnsRebinding);
                return;
            }
        }
        for ip in &answer.aaaa_records {
            if is_private_ipv6(*ip) {
                score.add(score_points::DNS_REBINDING, BlockReason::DnsRebinding);
                return;
            }
        }
    }

    // ASN filtering: block responses resolving into user-configured CIDR ranges
    // known to belong to malicious autonomous systems (crypto mining pools,
    // bulletproof hosting, C2 infrastructure, etc.).
    // Ranges are pre-parsed at engine build time — check cost is O(answers × ranges).
    let engine = CURRENT_ENGINE.load();
    if config.security.asn_filter.enabled
        && (!engine.blocked_asn_v4.is_empty() || !engine.blocked_asn_v6.is_empty())
    {
        for ip in &answer.a_records {
            if engine.is_asn_blocked_v4(*ip) {
                score.add(score_points::ASN_BLOCKED, BlockReason::AsnBlocked);
                return;
            }
        }
        for ip in &answer.aaaa_records {
            if engine.is_asn_blocked_v6(*ip) {
                score.add(score_points::ASN_BLOCKED, BlockReason::AsnBlocked);
                return;
            }
        }
    }

    // CNAME unmasking: check each CNAME target against the blocklist.
    // A domain that appears clean but resolves via CNAME to a known-bad target
    // is using CNAME cloaking to evade domain-level filters.
    for target in &answer.cname_targets {
        if is_blocked(target) || is_suffix_blocked(target) {
            score.add(score_points::CNAME_CLOAKING, BlockReason::CnameCloaking);
            return; // One match is conclusive — cloaking confirmed.
        }
    }
}

/// Check if an IPv4 address falls in a private or reserved range.
///
/// Covered ranges (RFC 1918 + special-use per RFC 1122 / RFC 3927 / RFC 6598):
/// - 0.0.0.0/8      — "This" network
/// - 10.0.0.0/8     — RFC 1918 private
/// - 100.64.0.0/10  — RFC 6598 Shared Address Space (CGNAT)
/// - 127.0.0.0/8    — Loopback
/// - 169.254.0.0/16 — Link-local (APIPA)
/// - 172.16.0.0/12  — RFC 1918 private
/// - 192.168.0.0/16 — RFC 1918 private
fn is_private_ipv4(ip: std::net::Ipv4Addr) -> bool {
    let [a, b, _, _] = ip.octets();
    matches!(a, 0 | 10 | 127)
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
}

/// Check if an IPv6 address falls in a private or reserved range.
///
/// Covered ranges:
/// - ::1/128    — Loopback (RFC 4291)
/// - fc00::/7   — Unique local (RFC 4193): covers fc00:: – fdff::
/// - fe80::/10  — Link-local (RFC 4291)
fn is_private_ipv6(ip: std::net::Ipv6Addr) -> bool {
    let [a, b, ..] = ip.octets();
    ip.is_loopback()
        || (a & 0xFE == 0xFC) // fc00::/7 unique local
        || (a == 0xFE && (b & 0xC0) == 0x80) // fe80::/10 link-local
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
    }

    #[test]
    fn test_compute_score_long_domain() {
        setup_test_config();
        // Domain > 60 chars
        let long_domain = format!("{}.com", "a".repeat(65));
        let score = compute_score(&long_domain);
        assert_eq!(score.total, score_points::LONG_DOMAIN);
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

    // -----------------------------------------------------------------------
    // score_answer tests
    // -----------------------------------------------------------------------

    /// Build an `InspectedAnswer` directly from its public fields for testing.
    fn make_answer(
        a_count: usize,
        aaaa_count: usize,
        cname_count: usize,
        txt_payloads: &[&[u8]],
    ) -> crate::dns::InspectedAnswer {
        use std::net::{Ipv4Addr, Ipv6Addr};
        // Use a public IP so existing tests don't trigger the rebinding shield.
        let public_v4 = Ipv4Addr::new(1, 2, 3, 4);
        let public_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        crate::dns::InspectedAnswer {
            a_records: vec![public_v4; a_count],
            aaaa_records: vec![public_v6; aaaa_count],
            cname_targets: vec![String::new(); cname_count],
            txt_records: txt_payloads.iter().map(|b| b.to_vec()).collect(),
            min_ttl: None,
        }
    }

    /// Build an `InspectedAnswer` with explicit CNAME targets.
    fn make_answer_with_cnames(cname_targets: &[&str]) -> crate::dns::InspectedAnswer {
        crate::dns::InspectedAnswer {
            a_records: vec![],
            aaaa_records: vec![],
            cname_targets: cname_targets.iter().map(|s| s.to_string()).collect(),
            txt_records: vec![],
            min_ttl: None,
        }
    }

    #[test]
    fn test_score_answer_clean() {
        setup_test_config();
        let mut score = SuspicionScore::new();
        // 1 A record, 1 short TXT — well within structural limits
        let answer = make_answer(1, 0, 0, &[b"v=spf1 include:example.com ~all"]);
        score_answer(&mut score, &answer);
        assert_eq!(score.total, 0);
    }

    #[test]
    fn test_score_answer_empty() {
        setup_test_config();
        let mut score = SuspicionScore::new();
        let answer = make_answer(0, 0, 0, &[]);
        score_answer(&mut score, &answer);
        assert_eq!(score.total, 0);
    }

    #[test]
    fn test_score_answer_excessive_answers() {
        setup_test_config();
        let mut score = SuspicionScore::new();
        // Default max_answers_per_query = 10; create 11 A records
        let answer = make_answer(11, 0, 0, &[]);
        score_answer(&mut score, &answer);
        assert_eq!(score.total, score_points::EXCESSIVE_ANSWERS);
        assert!(
            score
                .reasons
                .iter()
                .any(|r| matches!(r, BlockReason::InvalidStructure))
        );
    }

    #[test]
    fn test_score_answer_txt_too_long() {
        setup_test_config();
        let mut score = SuspicionScore::new();
        // Default max_txt_record_length = 128; create a 200-byte TXT record
        let long_payload = vec![b'A'; 200];
        let answer = make_answer(0, 0, 0, &[long_payload.as_slice()]);
        score_answer(&mut score, &answer);
        assert_eq!(score.total, score_points::TXT_RECORD_TOO_LONG);
        assert!(
            score
                .reasons
                .iter()
                .any(|r| matches!(r, BlockReason::InvalidStructure))
        );
    }

    #[test]
    fn test_score_answer_txt_too_long_only_one_penalty() {
        setup_test_config();
        let mut score = SuspicionScore::new();
        // Multiple oversized TXT records — only one penalty applied
        let long_payload = vec![b'X'; 200];
        let answer = make_answer(0, 0, 0, &[long_payload.as_slice(), long_payload.as_slice()]);
        score_answer(&mut score, &answer);
        assert_eq!(score.total, score_points::TXT_RECORD_TOO_LONG);
    }

    #[test]
    fn test_score_answer_both_violations() {
        setup_test_config();
        let mut score = SuspicionScore::new();
        // 11 records (exceeds max_answers_per_query=10) + oversized TXT
        let long_payload = vec![b'B'; 200];
        let answer = make_answer(10, 0, 0, &[long_payload.as_slice()]);
        score_answer(&mut score, &answer);
        // total=11 triggers excessive, TXT triggers txt_too_long
        assert_eq!(
            score.total,
            score_points::EXCESSIVE_ANSWERS + score_points::TXT_RECORD_TOO_LONG
        );
    }

    // -----------------------------------------------------------------------
    // CNAME unmasking tests (phase 8.3)
    // -----------------------------------------------------------------------

    #[test]
    fn test_score_answer_cname_clean() {
        use crate::CURRENT_ENGINE;
        use std::sync::Arc;
        setup_test_config();
        // CNAME target not in blocklist → no score added
        let engine = crate::resolve::tests::create_test_engine(&[], &[], &[]);
        CURRENT_ENGINE.store(Arc::new(engine));

        let mut score = SuspicionScore::new();
        let answer = make_answer_with_cnames(&["cdn.clean.com"]);
        score_answer(&mut score, &answer);
        assert_eq!(score.total, 0);
    }

    #[test]
    fn test_score_answer_cname_blocked_exact() {
        use crate::CURRENT_ENGINE;
        use std::sync::Arc;
        setup_test_config();
        // CNAME target is in the exact-match blocklist → cloaking detected
        let engine = crate::resolve::tests::create_test_engine(&["ad-server.net"], &[], &[]);
        CURRENT_ENGINE.store(Arc::new(engine));

        let mut score = SuspicionScore::new();
        let answer = make_answer_with_cnames(&["ad-server.net"]);
        score_answer(&mut score, &answer);
        assert_eq!(score.total, score_points::CNAME_CLOAKING);
        assert!(
            score
                .reasons
                .iter()
                .any(|r| matches!(r, BlockReason::CnameCloaking))
        );
    }

    #[test]
    fn test_score_answer_cname_blocked_suffix() {
        use crate::CURRENT_ENGINE;
        use std::sync::Arc;
        setup_test_config();
        // CNAME target matches a wildcard suffix rule → cloaking detected
        let engine = crate::resolve::tests::create_test_engine(&[], &[], &["tracking.evil.net"]);
        CURRENT_ENGINE.store(Arc::new(engine));

        let mut score = SuspicionScore::new();
        let answer = make_answer_with_cnames(&["pixel.tracking.evil.net"]);
        score_answer(&mut score, &answer);
        assert_eq!(score.total, score_points::CNAME_CLOAKING);
    }

    #[test]
    fn test_score_answer_cname_first_clean_second_blocked() {
        use crate::CURRENT_ENGINE;
        use std::sync::Arc;
        setup_test_config();
        // Chain: first target is clean, second is blocked — still detected
        let engine = crate::resolve::tests::create_test_engine(&["malware.io"], &[], &[]);
        CURRENT_ENGINE.store(Arc::new(engine));

        let mut score = SuspicionScore::new();
        let answer = make_answer_with_cnames(&["clean-relay.com", "malware.io"]);
        score_answer(&mut score, &answer);
        assert_eq!(score.total, score_points::CNAME_CLOAKING);
    }

    #[test]
    fn test_score_answer_no_cnames() {
        use crate::CURRENT_ENGINE;
        use std::sync::Arc;
        setup_test_config();
        let engine = crate::resolve::tests::create_test_engine(&["bad.com"], &[], &[]);
        CURRENT_ENGINE.store(Arc::new(engine));

        let mut score = SuspicionScore::new();
        // No CNAME records in answer → no CNAME penalty
        let answer = make_answer(1, 0, 0, &[]);
        score_answer(&mut score, &answer);
        assert_eq!(score.total, 0);
    }

    // -----------------------------------------------------------------------
    // DNS Rebinding Shield tests
    // -----------------------------------------------------------------------

    fn make_answer_with_ips(
        a_addrs: &[std::net::Ipv4Addr],
        aaaa_addrs: &[std::net::Ipv6Addr],
    ) -> crate::dns::InspectedAnswer {
        crate::dns::InspectedAnswer {
            a_records: a_addrs.to_vec(),
            aaaa_records: aaaa_addrs.to_vec(),
            cname_targets: vec![],
            txt_records: vec![],
            min_ttl: None,
        }
    }

    #[test]
    fn test_is_private_ipv4_rfc1918() {
        assert!(is_private_ipv4("10.0.0.1".parse().unwrap()));
        assert!(is_private_ipv4("172.16.0.1".parse().unwrap()));
        assert!(is_private_ipv4("172.31.255.255".parse().unwrap()));
        assert!(is_private_ipv4("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn test_is_private_ipv4_special() {
        assert!(is_private_ipv4("0.0.0.0".parse().unwrap())); // "this" network
        assert!(is_private_ipv4("127.0.0.1".parse().unwrap())); // loopback
        assert!(is_private_ipv4("169.254.1.1".parse().unwrap())); // link-local
        assert!(is_private_ipv4("100.64.0.1".parse().unwrap())); // CGNAT start
        assert!(is_private_ipv4("100.127.255.255".parse().unwrap())); // CGNAT end
    }

    #[test]
    fn test_is_private_ipv4_public() {
        assert!(!is_private_ipv4("1.1.1.1".parse().unwrap()));
        assert!(!is_private_ipv4("8.8.8.8".parse().unwrap()));
        assert!(!is_private_ipv4("93.184.216.34".parse().unwrap()));
        assert!(!is_private_ipv4("172.15.255.255".parse().unwrap())); // just below private
        assert!(!is_private_ipv4("172.32.0.0".parse().unwrap())); // just above private
        assert!(!is_private_ipv4("100.63.255.255".parse().unwrap())); // just below CGNAT
        assert!(!is_private_ipv4("100.128.0.0".parse().unwrap())); // just above CGNAT
    }

    #[test]
    fn test_is_private_ipv6_loopback() {
        assert!(is_private_ipv6("::1".parse().unwrap()));
    }

    #[test]
    fn test_is_private_ipv6_unique_local() {
        assert!(is_private_ipv6("fc00::1".parse().unwrap()));
        assert!(is_private_ipv6("fd00::1".parse().unwrap()));
        assert!(is_private_ipv6("fdff:ffff::1".parse().unwrap()));
    }

    #[test]
    fn test_is_private_ipv6_link_local() {
        assert!(is_private_ipv6("fe80::1".parse().unwrap()));
        assert!(is_private_ipv6("fe80::abcd:ef01".parse().unwrap()));
    }

    #[test]
    fn test_is_private_ipv6_public() {
        assert!(!is_private_ipv6("2001:db8::1".parse().unwrap()));
        assert!(!is_private_ipv6("2606:4700::1".parse().unwrap()));
        assert!(!is_private_ipv6("::".parse().unwrap())); // unspecified, not private
    }

    #[test]
    fn test_score_answer_rebinding_rfc1918_ipv4() {
        setup_test_config();
        let mut score = SuspicionScore::new();
        let answer = make_answer_with_ips(&["192.168.1.1".parse().unwrap()], &[]);
        score_answer(&mut score, &answer);
        assert_eq!(score.total, score_points::DNS_REBINDING);
        assert!(
            score
                .reasons
                .iter()
                .any(|r| matches!(r, BlockReason::DnsRebinding))
        );
    }

    #[test]
    fn test_score_answer_rebinding_loopback_ipv4() {
        setup_test_config();
        let mut score = SuspicionScore::new();
        let answer = make_answer_with_ips(&["127.0.0.1".parse().unwrap()], &[]);
        score_answer(&mut score, &answer);
    }

    #[test]
    fn test_score_answer_rebinding_private_ipv6() {
        setup_test_config();
        let mut score = SuspicionScore::new();
        let answer = make_answer_with_ips(&[], &["fd00::1".parse().unwrap()]);
        score_answer(&mut score, &answer);
        assert_eq!(score.total, score_points::DNS_REBINDING);
    }

    #[test]
    fn test_score_answer_rebinding_public_ip_clean() {
        setup_test_config();
        let mut score = SuspicionScore::new();
        let answer = make_answer_with_ips(&["1.1.1.1".parse().unwrap()], &[]);
        score_answer(&mut score, &answer);
        assert_eq!(score.total, 0);
    }

    #[test]
    fn test_score_answer_rebinding_disabled() {
        use std::sync::Arc;
        let mut config = crate::config::Config::default();
        config.security.rebinding_shield.enabled = false;
        crate::CONFIG.store(Arc::new(config));

        let mut score = SuspicionScore::new();
        let answer = make_answer_with_ips(&["192.168.1.1".parse().unwrap()], &[]);
        score_answer(&mut score, &answer);
        assert_eq!(score.total, 0); // Shield disabled — no penalty
    }

    // -----------------------------------------------------------------------
    // Low-TTL scoring tests
    // -----------------------------------------------------------------------

    fn make_answer_with_ttl(ttl: u32) -> crate::dns::InspectedAnswer {
        crate::dns::InspectedAnswer {
            a_records: vec!["1.2.3.4".parse().unwrap()],
            aaaa_records: vec![],
            cname_targets: vec![],
            txt_records: vec![],
            min_ttl: Some(ttl),
        }
    }

    #[test]
    fn test_score_answer_low_ttl_below_threshold() {
        setup_test_config();
        let mut score = SuspicionScore::new();
        // Default threshold is 10s — TTL of 5 should trigger
        let answer = make_answer_with_ttl(5);
        score_answer(&mut score, &answer);
        assert_eq!(score.total, score_points::LOW_TTL);
        assert!(
            score
                .reasons
                .iter()
                .any(|r| matches!(r, BlockReason::LowTtl(5)))
        );
    }

    #[test]
    fn test_score_answer_low_ttl_at_threshold_not_triggered() {
        setup_test_config();
        let mut score = SuspicionScore::new();
        // TTL exactly at the threshold (10s) — not strictly less, no penalty
        let answer = make_answer_with_ttl(10);
        score_answer(&mut score, &answer);
        assert_eq!(score.total, 0);
    }

    #[test]
    fn test_score_answer_low_ttl_above_threshold_clean() {
        setup_test_config();
        let mut score = SuspicionScore::new();
        let answer = make_answer_with_ttl(300);
        score_answer(&mut score, &answer);
        assert_eq!(score.total, 0);
    }

    #[test]
    fn test_score_answer_low_ttl_zero() {
        setup_test_config();
        let mut score = SuspicionScore::new();
        let answer = make_answer_with_ttl(0);
        score_answer(&mut score, &answer);
        assert_eq!(score.total, score_points::LOW_TTL);
    }

    #[test]
    fn test_score_answer_low_ttl_no_min_ttl_skipped() {
        setup_test_config();
        let mut score = SuspicionScore::new();
        // No TTL in answer (empty response) — no penalty
        let answer = make_answer(0, 0, 0, &[]);
        score_answer(&mut score, &answer);
        assert_eq!(score.total, 0);
    }

    #[test]
    fn test_score_answer_low_ttl_disabled() {
        use std::sync::Arc;
        let mut config = crate::config::Config::default();
        config.security.low_ttl.enabled = false;
        crate::CONFIG.store(Arc::new(config));

        let mut score = SuspicionScore::new();
        let answer = make_answer_with_ttl(1);
        score_answer(&mut score, &answer);
        assert_eq!(score.total, 0); // Disabled — no penalty
    }

    #[test]
    fn test_score_answer_low_ttl_custom_threshold() {
        use std::sync::Arc;
        let mut config = crate::config::Config::default();
        config.security.low_ttl.threshold_secs = 60;
        crate::CONFIG.store(Arc::new(config));

        let mut score = SuspicionScore::new();
        // TTL=30 is below custom threshold of 60
        let answer = make_answer_with_ttl(30);
        score_answer(&mut score, &answer);
        assert_eq!(score.total, score_points::LOW_TTL);
    }

    // -----------------------------------------------------------------------
    // ASN filtering tests
    // -----------------------------------------------------------------------

    fn make_engine_with_asn(
        v4_cidrs: &[&str],
        v6_cidrs: &[&str],
    ) -> crate::filter::engine::FilterEngine {
        use crate::filter::engine::FilterEngine;
        let mut engine = FilterEngine::empty();

        // Manually parse and load CIDR ranges to avoid depending on CONFIG
        // in tests that test the scoring logic directly.
        for cidr in v4_cidrs {
            let mut cfg = crate::config::Config::default();
            cfg.security.asn_filter.enabled = true;
            cfg.security.asn_filter.blocked_ranges = vec![cidr.to_string()];
            crate::CONFIG.store(std::sync::Arc::new(cfg));
            engine.load_asn_filters();
        }
        for cidr in v6_cidrs {
            let mut cfg = crate::config::Config::default();
            cfg.security.asn_filter.enabled = true;
            cfg.security.asn_filter.blocked_ranges = vec![cidr.to_string()];
            crate::CONFIG.store(std::sync::Arc::new(cfg));
            engine.load_asn_filters();
        }
        engine
    }

    #[test]
    fn test_score_answer_asn_blocked_ipv4() {
        use std::sync::Arc;
        setup_test_config();
        let mut cfg = crate::config::Config::default();
        cfg.security.asn_filter.enabled = true;
        cfg.security.asn_filter.blocked_ranges = vec![String::from("203.0.113.0/24")];
        crate::CONFIG.store(Arc::new(cfg));

        let engine = make_engine_with_asn(&["203.0.113.0/24"], &[]);
        crate::CURRENT_ENGINE.store(Arc::new(engine));

        let mut score = SuspicionScore::new();
        let answer = make_answer_with_ips(&["203.0.113.42".parse().unwrap()], &[]);
        score_answer(&mut score, &answer);
        assert_eq!(score.total, score_points::ASN_BLOCKED);
        assert!(
            score
                .reasons
                .iter()
                .any(|r| matches!(r, BlockReason::AsnBlocked))
        );
    }

    #[test]
    fn test_score_answer_asn_blocked_ipv6() {
        use std::sync::Arc;
        let mut cfg = crate::config::Config::default();
        cfg.security.asn_filter.enabled = true;
        cfg.security.asn_filter.blocked_ranges = vec![String::from("2001:db8::/32")];
        crate::CONFIG.store(Arc::new(cfg));

        let engine = make_engine_with_asn(&[], &["2001:db8::/32"]);
        crate::CURRENT_ENGINE.store(Arc::new(engine));

        let mut score = SuspicionScore::new();
        let answer = make_answer_with_ips(&[], &["2001:db8::cafe".parse().unwrap()]);
        score_answer(&mut score, &answer);
        assert_eq!(score.total, score_points::ASN_BLOCKED);
    }

    #[test]
    fn test_score_answer_asn_not_blocked_outside_range() {
        use std::sync::Arc;
        let mut cfg = crate::config::Config::default();
        cfg.security.asn_filter.enabled = true;
        cfg.security.asn_filter.blocked_ranges = vec![String::from("203.0.113.0/24")];
        crate::CONFIG.store(Arc::new(cfg));

        let engine = make_engine_with_asn(&["203.0.113.0/24"], &[]);
        crate::CURRENT_ENGINE.store(Arc::new(engine));

        let mut score = SuspicionScore::new();
        // 1.2.3.4 is NOT in 203.0.113.0/24
        let answer = make_answer_with_ips(&["1.2.3.4".parse().unwrap()], &[]);
        score_answer(&mut score, &answer);
        assert_eq!(score.total, 0);
    }

    #[test]
    fn test_score_answer_asn_disabled() {
        use std::sync::Arc;
        // Build the engine first (make_engine_with_asn temporarily sets enabled=true in CONFIG)
        let engine = make_engine_with_asn(&["203.0.113.0/24"], &[]);
        crate::CURRENT_ENGINE.store(Arc::new(engine));

        // Now override CONFIG with asn_filter disabled — this is what score_answer reads
        let mut cfg = crate::config::Config::default();
        cfg.security.asn_filter.enabled = false;
        crate::CONFIG.store(Arc::new(cfg));

        let mut score = SuspicionScore::new();
        let answer = make_answer_with_ips(&["203.0.113.42".parse().unwrap()], &[]);
        score_answer(&mut score, &answer);
        assert_eq!(score.total, 0); // Disabled — no penalty
    }

    #[test]
    fn test_score_answer_asn_empty_ranges() {
        use std::sync::Arc;
        let mut cfg = crate::config::Config::default();
        cfg.security.asn_filter.enabled = true;
        cfg.security.asn_filter.blocked_ranges = vec![];
        crate::CONFIG.store(Arc::new(cfg));

        let engine = crate::filter::engine::FilterEngine::empty();
        crate::CURRENT_ENGINE.store(Arc::new(engine));

        let mut score = SuspicionScore::new();
        let answer = make_answer_with_ips(&["203.0.113.42".parse().unwrap()], &[]);
        score_answer(&mut score, &answer);
        assert_eq!(score.total, 0); // No ranges configured
    }

    #[test]
    fn test_score_answer_asn_multiple_ranges_first_match() {
        use std::sync::Arc;
        let mut cfg = crate::config::Config::default();
        cfg.security.asn_filter.enabled = true;
        cfg.security.asn_filter.blocked_ranges = vec![
            String::from("198.51.100.0/24"),
            String::from("203.0.113.0/24"),
        ];
        crate::CONFIG.store(Arc::new(cfg));

        let engine = make_engine_with_asn(&["198.51.100.0/24", "203.0.113.0/24"], &[]);
        crate::CURRENT_ENGINE.store(Arc::new(engine));

        let mut score = SuspicionScore::new();
        // Matches second range
        let answer = make_answer_with_ips(&["203.0.113.1".parse().unwrap()], &[]);
        score_answer(&mut score, &answer);
        assert_eq!(score.total, score_points::ASN_BLOCKED);
    }
}
