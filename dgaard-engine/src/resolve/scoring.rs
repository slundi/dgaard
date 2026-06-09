//! Domain suspicion scoring engine.

use super::heuristics::check_lexical;
use super::matcher::{is_blocked, is_nrd, is_suffix_blocked};
use crate::config::Config;
use crate::dga::entropy::{calculate_entropy, calculate_entropy_fast, is_consonant_suspicious};
use crate::filter::engine::FilterEngine;
use crate::model::{BlockReason, InspectedAnswer, SuspicionScore, score_points};

/// Maximum domain length before adding suspicion points.
const LONG_DOMAIN_THRESHOLD: usize = 60;

/// Subdomain depth (number of dots) before adding suspicion points.
const DEEP_SUBDOMAIN_THRESHOLD: usize = 5;

/// Compute the suspicion score for a domain.
pub fn compute_score(domain: &str, filter: &FilterEngine, config: &Config) -> SuspicionScore {
    let mut score = SuspicionScore::new();
    let blocking_threshold = config.security.scoring.blocking_threshold;

    // 1. Long domain check
    if domain.len() > LONG_DOMAIN_THRESHOLD {
        score.add(score_points::LONG_DOMAIN, BlockReason::InvalidStructure);
        if score.total >= blocking_threshold {
            return score;
        }
    }

    // 2. Deep subdomain check
    let depth = domain.bytes().filter(|&b| b == b'.').count();
    if depth >= DEEP_SUBDOMAIN_THRESHOLD {
        score.add(score_points::DEEP_SUBDOMAIN, BlockReason::InvalidStructure);
        if score.total >= blocking_threshold {
            return score;
        }
    }

    // 3. Suspicious TLD check
    if !filter.suspicious_tld_hashes.is_empty()
        && let Some(tld) = domain.rsplit('.').next()
        && filter.is_suspicious_tld(tld)
    {
        if let Some(keyword_reason) = check_lexical(domain, filter) {
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

    // 5. NRD check
    if is_nrd(domain, filter) {
        score.add(score_points::NRD, BlockReason::NrdList);
        if score.total >= blocking_threshold {
            return score;
        }
    }

    // 6. Entropy and consonant clustering
    let intel = &config.security.intelligence;
    if intel.enabled
        && let Some(sld) = extract_sld(domain)
        && sld.len() >= intel.min_word_length
    {
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

    score
}

/// Apply suspicion scoring from a parsed DNS answer section.
pub fn score_answer(
    score: &mut SuspicionScore,
    answer: &InspectedAnswer,
    filter: &FilterEngine,
    config: &Config,
) {
    let structure = &config.security.structure;
    let blocking_threshold = config.security.scoring.blocking_threshold;

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

    if config.security.asn_filter.enabled
        && (!filter.blocked_asn_v4.is_empty() || !filter.blocked_asn_v6.is_empty())
    {
        for ip in &answer.a_records {
            if filter.is_asn_blocked_v4(*ip) {
                score.add(score_points::ASN_BLOCKED, BlockReason::AsnBlocked);
                return;
            }
        }
        for ip in &answer.aaaa_records {
            if filter.is_asn_blocked_v6(*ip) {
                score.add(score_points::ASN_BLOCKED, BlockReason::AsnBlocked);
                return;
            }
        }
    }

    for target in &answer.cname_targets {
        if is_blocked(target, filter) || is_suffix_blocked(target, filter) {
            score.add(score_points::CNAME_CLOAKING, BlockReason::CnameCloaking);
            return;
        }
    }

    if config.security.geo_ip.enabled && filter.geoip_reader.is_some() {
        for ip in &answer.a_records {
            if let Some(code) = filter.geoip_country_suspicious_v4(*ip) {
                score.add(
                    filter.suspicious_country_score,
                    BlockReason::GeoIpSuspicious(code),
                );
                if score.total >= blocking_threshold {
                    return;
                }
            }
        }
        for ip in &answer.aaaa_records {
            if let Some(code) = filter.geoip_country_suspicious_v6(*ip) {
                score.add(
                    filter.suspicious_country_score,
                    BlockReason::GeoIpSuspicious(code),
                );
                if score.total >= blocking_threshold {
                    return;
                }
            }
        }
    }
}

/// Check if an IPv4 address falls in a private or reserved range.
pub(crate) fn is_private_ipv4(ip: std::net::Ipv4Addr) -> bool {
    let [a, b, _, _] = ip.octets();
    matches!(a, 0 | 10 | 127)
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
}

/// Check if an IPv6 address falls in a private or reserved range.
pub(crate) fn is_private_ipv6(ip: std::net::Ipv6Addr) -> bool {
    let [a, b, ..] = ip.octets();
    ip.is_loopback() || (a & 0xFE == 0xFC) || (a == 0xFE && (b & 0xC0) == 0x80)
}

/// Extract the second-level domain (SLD) from a domain name.
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
    if domain.split('.').any(|part| part.starts_with("xn--")) {
        return true;
    }
    !domain.is_ascii()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolve::tests::{create_test_engine, init_test_engine};

    fn default_config() -> Config {
        Config::default()
    }

    #[test]
    fn test_compute_score_normal_domain() {
        let engine = create_test_engine(&[], &[], &[]);
        let config = default_config();
        let score = compute_score("google.com", &engine, &config);
        assert_eq!(score.total, 0);
    }

    #[test]
    fn test_compute_score_long_domain() {
        let engine = create_test_engine(&[], &[], &[]);
        let config = default_config();
        let long_domain = format!("{}.com", "a".repeat(65));
        let score = compute_score(&long_domain, &engine, &config);
        assert_eq!(score.total, score_points::LONG_DOMAIN);
    }

    #[test]
    fn test_compute_score_deep_subdomain() {
        let engine = create_test_engine(&[], &[], &[]);
        let config = default_config();
        let score = compute_score("a.b.c.d.e.f.example.com", &engine, &config);
        assert!(score.total >= score_points::DEEP_SUBDOMAIN);
    }

    #[test]
    fn test_compute_score_punycode() {
        let engine = create_test_engine(&[], &[], &[]);
        let config = default_config();
        let score = compute_score("xn--pple-43d.com", &engine, &config);
        assert!(score.total >= score_points::IDN_HOMOGRAPH);
        assert!(
            score
                .reasons
                .iter()
                .any(|r| matches!(r, BlockReason::SuspiciousIdn))
        );
    }

    #[test]
    fn test_compute_score_high_entropy() {
        let engine = create_test_engine(&[], &[], &[]);
        let config = default_config();
        let score = compute_score("a1b2c3d4e5f6g7h8i9j0.com", &engine, &config);
        assert!(score.total >= score_points::ENTROPY_HIGH);
    }

    #[test]
    fn test_extract_sld() {
        assert_eq!(extract_sld("sub.example.com"), Some("example"));
        assert_eq!(extract_sld("example.com"), Some("example"));
        assert_eq!(extract_sld("com"), None);
    }

    #[test]
    fn test_is_idn_suspicious() {
        assert!(is_idn_suspicious("xn--pple-43d.com"));
        assert!(is_idn_suspicious("exämple.com"));
        assert!(!is_idn_suspicious("example.com"));
    }

    #[test]
    fn test_is_private_ipv4_rfc1918() {
        assert!(is_private_ipv4("10.0.0.1".parse().unwrap()));
        assert!(is_private_ipv4("172.16.0.1".parse().unwrap()));
        assert!(is_private_ipv4("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn test_is_private_ipv4_public() {
        assert!(!is_private_ipv4("1.1.1.1".parse().unwrap()));
        assert!(!is_private_ipv4("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn test_is_private_ipv6_loopback() {
        assert!(is_private_ipv6("::1".parse().unwrap()));
    }

    #[test]
    fn test_is_private_ipv6_unique_local() {
        assert!(is_private_ipv6("fc00::1".parse().unwrap()));
        assert!(is_private_ipv6("fd00::1".parse().unwrap()));
    }

    #[test]
    fn test_is_private_ipv6_public() {
        assert!(!is_private_ipv6("2001:db8::1".parse().unwrap()));
    }

    fn make_answer(
        a_count: usize,
        aaaa_count: usize,
        cname_count: usize,
        txt_payloads: &[&[u8]],
    ) -> InspectedAnswer {
        use std::net::{Ipv4Addr, Ipv6Addr};
        let public_v4 = Ipv4Addr::new(1, 2, 3, 4);
        let public_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        InspectedAnswer {
            a_records: vec![public_v4; a_count],
            aaaa_records: vec![public_v6; aaaa_count],
            cname_targets: vec![String::new(); cname_count],
            txt_records: txt_payloads.iter().map(|b| b.to_vec()).collect(),
            min_ttl: None,
        }
    }

    #[test]
    fn test_score_answer_clean() {
        let engine = init_test_engine();
        let config = default_config();
        let mut score = SuspicionScore::new();
        let answer = make_answer(1, 0, 0, &[b"v=spf1 include:example.com ~all"]);
        score_answer(&mut score, &answer, &engine, &config);
        assert_eq!(score.total, 0);
    }

    #[test]
    fn test_score_answer_excessive_answers() {
        let engine = init_test_engine();
        let config = default_config();
        let mut score = SuspicionScore::new();
        let answer = make_answer(11, 0, 0, &[]);
        score_answer(&mut score, &answer, &engine, &config);
        assert_eq!(score.total, score_points::EXCESSIVE_ANSWERS);
    }

    #[test]
    fn test_score_answer_txt_too_long() {
        let engine = init_test_engine();
        let config = default_config();
        let mut score = SuspicionScore::new();
        let long_payload = vec![b'A'; 200];
        let answer = make_answer(0, 0, 0, &[long_payload.as_slice()]);
        score_answer(&mut score, &answer, &engine, &config);
        assert_eq!(score.total, score_points::TXT_RECORD_TOO_LONG);
    }

    #[test]
    fn test_score_answer_rebinding_rfc1918_ipv4() {
        let engine = init_test_engine();
        let config = default_config();
        let mut score = SuspicionScore::new();
        let answer = InspectedAnswer {
            a_records: vec!["192.168.1.1".parse().unwrap()],
            aaaa_records: vec![],
            cname_targets: vec![],
            txt_records: vec![],
            min_ttl: None,
        };
        score_answer(&mut score, &answer, &engine, &config);
        assert_eq!(score.total, score_points::DNS_REBINDING);
    }

    #[test]
    fn test_score_answer_rebinding_disabled() {
        let engine = init_test_engine();
        let mut config = default_config();
        config.security.rebinding_shield.enabled = false;
        let mut score = SuspicionScore::new();
        let answer = InspectedAnswer {
            a_records: vec!["192.168.1.1".parse().unwrap()],
            aaaa_records: vec![],
            cname_targets: vec![],
            txt_records: vec![],
            min_ttl: None,
        };
        score_answer(&mut score, &answer, &engine, &config);
        assert_eq!(score.total, 0);
    }

    #[test]
    fn test_score_answer_cname_blocked_exact() {
        let engine = create_test_engine(&["ad-server.net"], &[], &[]);
        let config = default_config();
        let mut score = SuspicionScore::new();
        let answer = InspectedAnswer {
            a_records: vec![],
            aaaa_records: vec![],
            cname_targets: vec!["ad-server.net".to_string()],
            txt_records: vec![],
            min_ttl: None,
        };
        score_answer(&mut score, &answer, &engine, &config);
        assert_eq!(score.total, score_points::CNAME_CLOAKING);
    }

    #[test]
    fn test_score_answer_geoip_disabled_no_score() {
        let engine = init_test_engine();
        let mut config = default_config();
        config.security.geo_ip.enabled = false;
        let mut score = SuspicionScore::new();
        let answer = make_answer(1, 0, 0, &[]);
        score_answer(&mut score, &answer, &engine, &config);
        assert_eq!(score.total, 0);
    }

    #[test]
    fn test_score_answer_geoip_enabled_no_reader_no_score() {
        // enabled=true but no reader loaded → no score added
        let engine = init_test_engine();
        let mut config = default_config();
        config.security.geo_ip.enabled = true;
        config.security.geo_ip.suspicious_countries = vec!["RU".to_string()];
        let mut score = SuspicionScore::new();
        let answer = make_answer(1, 0, 0, &[]);
        score_answer(&mut score, &answer, &engine, &config);
        assert_eq!(score.total, 0);
    }

    #[test]
    fn test_score_answer_low_ttl_below_threshold() {
        let engine = init_test_engine();
        let config = default_config();
        let mut score = SuspicionScore::new();
        let answer = InspectedAnswer {
            a_records: vec!["1.2.3.4".parse().unwrap()],
            aaaa_records: vec![],
            cname_targets: vec![],
            txt_records: vec![],
            min_ttl: Some(5),
        };
        score_answer(&mut score, &answer, &engine, &config);
        assert_eq!(score.total, score_points::LOW_TTL);
    }
}
