use std::net::IpAddr;

use bitflags::bitflags;

use crate::model::BlockReason;

#[derive(Debug, Clone)]
pub enum Action {
    /// The domain is safe and was found in the local cache or whitelist.
    /// Returns the cached IP address.
    #[allow(dead_code)] // For future cache implementation
    LocalResolve(IpAddr),

    /// The domain passed all filters and must be sent to the upstream provider.
    ProxyToUpstream,

    /// The query was intentionally blocked.
    /// Carries the reason for the dashboard/TUI logs.
    /// We should return an NXDOMAIN or a 0.0.0.0 response.
    Block(BlockReason),

    /// A specialized internal response (e.g., redirecting to a local landing page).
    #[allow(dead_code)] // For future landing page feature
    InternalRedirect(IpAddr),

    /// The query was ignored or dropped (e.g., malformed or from unauthorized ACL).
    #[allow(dead_code)] // For future ACL implementation
    Drop,

    /// The domain is safe. Forward the original query to the upstream DNS.
    Allow,

    /// The domain is in our "Hot Cache" or "Favorites".
    /// We can return this IP immediately without asking an upstream server.
    #[allow(dead_code)] // For future cache implementation
    Respond(IpAddr),

    /// Optional: The query is redirected to a local landing page (e.g., for a "Blocked" UI).
    #[allow(dead_code)] // For future landing page feature
    Redirect(IpAddr),
}

/// Compact representation of the action taken for a DNS query.
/// Used in StatEvent for efficient serialization.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum StatAction {
    /// Query was allowed (whitelist hit or passed all filters)
    Allowed,
    /// Query was proxied to upstream DNS
    Proxied,
    /// Query was blocked with a specific reason
    Blocked(StatBlockReason),
    /// Query was forwarded but scored above the suspicious threshold.
    /// Carries the primary contributing reason for telemetry.
    Suspicious(StatBlockReason),
    /// Query was forwarded but scored above the highly-suspicious threshold.
    /// Carries the primary contributing reason for telemetry.
    HighlySuspicious(StatBlockReason),
}

bitflags! {
    /// Compact block reason flags for telemetry (u32 bitflags).
    /// Bits 0–15 are built-in reasons. Bits 16–31 are user-defined custom flags
    /// configured via `[[security.custom_flags]]` in the TOML config.
    /// Multiple reasons can be combined with `|` to represent composite signals.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct StatBlockReason: u32 {
        /// Hit a static blacklist
        const STATIC_BLACKLIST = 1 << 0;
        /// Matched an ABP/wildcard rule
        const ABP_RULE = 1 << 1;
        /// High Shannon entropy (DGA detection)
        const HIGH_ENTROPY = 1 << 2;
        /// Failed lexical analysis
        const LEXICAL_ANALYSIS = 1 << 3;
        /// Blocked by parental control keyword
        const BANNED_KEYWORD = 1 << 4;
        /// Invalid structure (depth, length)
        const INVALID_STRUCTURE = 1 << 5;
        /// Suspicious IDN/Punycode
        const SUSPICIOUS_IDN = 1 << 6;
        /// Newly Registered Domain
        const NRD_LIST = 1 << 7;
        /// Excluded TLD
        const TLD_EXCLUDED = 1 << 8;
        /// Generic suspicious activity (score-based)
        const SUSPICIOUS = 1 << 9;
        /// CNAME chain resolves to a known-blacklisted domain (cloaking)
        const CNAME_CLOAKING = 1 << 10;
        /// Query type is blocked by the QType Warden policy
        const FORBIDDEN_QTYPE = 1 << 11;
        /// Upstream response resolves a public domain to a private/reserved IP (DNS rebinding)
        const DNS_REBINDING = 1 << 12;
        /// Abnormally low TTL — fast-flux or short-lived malware infrastructure
        const LOW_TTL = 1 << 13;
        /// Response resolves to an IP in a user-configured blocked ASN range
        const ASN_BLOCKED = 1 << 14;
        /// Response resolves to an IP in a suspicious GeoIP country
        const SUSPICIOUS_GEO_IP = 1 << 15;
        // Bits 16–31 are reserved for user-defined custom flags (custom_flags feature).
    }
}

impl From<&BlockReason> for StatBlockReason {
    fn from(reason: &BlockReason) -> Self {
        match reason {
            BlockReason::StaticBlacklist(_) => StatBlockReason::STATIC_BLACKLIST,
            BlockReason::AbpRule(_) => StatBlockReason::ABP_RULE,
            BlockReason::HighEntropy(_) => StatBlockReason::HIGH_ENTROPY,
            BlockReason::LexicalAnalysis => StatBlockReason::LEXICAL_ANALYSIS,
            BlockReason::BannedKeyword(_) => StatBlockReason::BANNED_KEYWORD,
            BlockReason::InvalidStructure => StatBlockReason::INVALID_STRUCTURE,
            BlockReason::SuspiciousIdn => StatBlockReason::SUSPICIOUS_IDN,
            BlockReason::NrdList => StatBlockReason::NRD_LIST,
            BlockReason::TldExcluded => StatBlockReason::TLD_EXCLUDED,
            BlockReason::Suspicious => StatBlockReason::SUSPICIOUS,
            BlockReason::CnameCloaking => StatBlockReason::CNAME_CLOAKING,
            BlockReason::ForbiddenQType(_) => StatBlockReason::FORBIDDEN_QTYPE,
            BlockReason::DnsRebinding => StatBlockReason::DNS_REBINDING,
            BlockReason::LowTtl(_) => StatBlockReason::LOW_TTL,
            BlockReason::AsnBlocked => StatBlockReason::ASN_BLOCKED,
            BlockReason::GeoIpSuspicious(_) => StatBlockReason::SUSPICIOUS_GEO_IP,
            // StatBlockReason is a u16 with all 16 bits allocated. SpecialUseDomain shares
            // INVALID_STRUCTURE until StatBlockReason is widened to u32 (custom_flags feature).
            // SpecialUseDomain, PtrLeak, ChaosClass previously shared built-in bits
            // while StatBlockReason was u16. Now that the field is u32 they could have
            // dedicated bits, but they are not yet assigned — keep sharing for now so
            // existing dashboards/decoders see no change in the built-in bit layout.
            BlockReason::SpecialUseDomain => StatBlockReason::INVALID_STRUCTURE,
            BlockReason::PtrLeak => StatBlockReason::DNS_REBINDING,
            BlockReason::ChaosClass => StatBlockReason::FORBIDDEN_QTYPE,
            // User-defined custom flag: set the bit at position `bit` (valid range 16–31).
            BlockReason::CustomFlag(bit) => StatBlockReason::from_bits_retain(1u32 << bit),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stat_block_reason_from_block_reason() {
        assert_eq!(
            StatBlockReason::from(&BlockReason::StaticBlacklist("test".into())),
            StatBlockReason::STATIC_BLACKLIST
        );
        assert_eq!(
            StatBlockReason::from(&BlockReason::AbpRule("rule".into())),
            StatBlockReason::ABP_RULE
        );
        assert_eq!(
            StatBlockReason::from(&BlockReason::HighEntropy(4.5)),
            StatBlockReason::HIGH_ENTROPY
        );
        assert_eq!(
            StatBlockReason::from(&BlockReason::LexicalAnalysis),
            StatBlockReason::LEXICAL_ANALYSIS
        );
        assert_eq!(
            StatBlockReason::from(&BlockReason::InvalidStructure),
            StatBlockReason::INVALID_STRUCTURE
        );
        assert_eq!(
            StatBlockReason::from(&BlockReason::SuspiciousIdn),
            StatBlockReason::SUSPICIOUS_IDN
        );
        assert_eq!(
            StatBlockReason::from(&BlockReason::NrdList),
            StatBlockReason::NRD_LIST
        );
        assert_eq!(
            StatBlockReason::from(&BlockReason::TldExcluded),
            StatBlockReason::TLD_EXCLUDED
        );
        assert_eq!(
            StatBlockReason::from(&BlockReason::Suspicious),
            StatBlockReason::SUSPICIOUS
        );
        assert_eq!(
            StatBlockReason::from(&BlockReason::CnameCloaking),
            StatBlockReason::CNAME_CLOAKING
        );
        assert_eq!(
            StatBlockReason::from(&BlockReason::ForbiddenQType(255)),
            StatBlockReason::FORBIDDEN_QTYPE
        );
        assert_eq!(
            StatBlockReason::from(&BlockReason::DnsRebinding),
            StatBlockReason::DNS_REBINDING
        );
        assert_eq!(
            StatBlockReason::from(&BlockReason::LowTtl(5)),
            StatBlockReason::LOW_TTL
        );
        assert_eq!(
            StatBlockReason::from(&BlockReason::AsnBlocked),
            StatBlockReason::ASN_BLOCKED
        );
        assert_eq!(
            StatBlockReason::from(&BlockReason::GeoIpSuspicious("RU".into())),
            StatBlockReason::SUSPICIOUS_GEO_IP
        );
        assert_eq!(
            StatBlockReason::from(&BlockReason::SpecialUseDomain),
            StatBlockReason::INVALID_STRUCTURE
        );
        assert_eq!(
            StatBlockReason::from(&BlockReason::PtrLeak),
            StatBlockReason::DNS_REBINDING
        );
        assert_eq!(
            StatBlockReason::from(&BlockReason::ChaosClass),
            StatBlockReason::FORBIDDEN_QTYPE
        );
    }

    #[test]
    fn test_stat_block_reason_bitflags_combine() {
        let combined = StatBlockReason::HIGH_ENTROPY | StatBlockReason::SUSPICIOUS_IDN;
        assert!(combined.contains(StatBlockReason::HIGH_ENTROPY));
        assert!(combined.contains(StatBlockReason::SUSPICIOUS_IDN));
        assert!(!combined.contains(StatBlockReason::ABP_RULE));
        assert_eq!(combined.bits(), (1 << 2) | (1 << 6));
    }

    #[test]
    fn test_stat_block_reason_is_u32() {
        // Ensure the backing type is u32 so bits 16–31 are available.
        let all_built_in = StatBlockReason::SUSPICIOUS_GEO_IP.bits();
        assert_eq!(all_built_in, 1u32 << 15);
    }

    #[test]
    fn test_custom_flag_bit_16_maps_to_correct_mask() {
        let r = StatBlockReason::from(&BlockReason::CustomFlag(16));
        assert_eq!(r.bits(), 1u32 << 16);
    }

    #[test]
    fn test_custom_flag_bit_31_maps_to_correct_mask() {
        let r = StatBlockReason::from(&BlockReason::CustomFlag(31));
        assert_eq!(r.bits(), 1u32 << 31);
    }

    #[test]
    fn test_custom_flag_does_not_overlap_built_in_bits() {
        for bit in 16u8..=31 {
            let custom = StatBlockReason::from(&BlockReason::CustomFlag(bit));
            // No built-in constant should share a bit with any custom flag.
            let built_in_mask: u32 = 0x0000_FFFF;
            assert_eq!(
                custom.bits() & built_in_mask,
                0,
                "custom bit {} overlaps built-in bits",
                bit
            );
        }
    }
}
