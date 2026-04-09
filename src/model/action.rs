use std::net::IpAddr;

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
}

/// Compact block reason for telemetry (uses u8 discriminants).
/// Maps to the more detailed BlockReason enum used internally.
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum StatBlockReason {
    /// Hit a static blacklist
    StaticBlacklist = 0,
    /// Matched an ABP/wildcard rule
    AbpRule = 1,
    /// High Shannon entropy (DGA detection)
    HighEntropy = 2,
    /// Failed lexical analysis
    LexicalAnalysis = 3,
    /// Blocked by parental control keyword
    BannedKeyword = 4,
    /// Invalid structure (depth, length)
    InvalidStructure = 5,
    /// Suspicious IDN/Punycode
    SuspiciousIdn = 6,
    /// Newly Registered Domain
    NrdList = 7,
    /// Excluded TLD
    TldExcluded = 8,
    /// Generic suspicious activity (score-based)
    Suspicious = 9,
    /// CNAME chain resolves to a known-blacklisted domain (cloaking)
    CnameCloaking = 10,
    /// Query type is blocked by the QType Warden policy
    ForbiddenQType = 11,
}

impl TryFrom<u8> for StatBlockReason {
    type Error = ();

    /// Convert from u8 discriminant.
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(StatBlockReason::StaticBlacklist),
            1 => Ok(StatBlockReason::AbpRule),
            2 => Ok(StatBlockReason::HighEntropy),
            3 => Ok(StatBlockReason::LexicalAnalysis),
            4 => Ok(StatBlockReason::BannedKeyword),
            5 => Ok(StatBlockReason::InvalidStructure),
            6 => Ok(StatBlockReason::SuspiciousIdn),
            7 => Ok(StatBlockReason::NrdList),
            8 => Ok(StatBlockReason::TldExcluded),
            9 => Ok(StatBlockReason::Suspicious),
            10 => Ok(StatBlockReason::CnameCloaking),
            11 => Ok(StatBlockReason::ForbiddenQType),
            _ => Err(()),
        }
    }
}

impl From<&BlockReason> for StatBlockReason {
    fn from(reason: &BlockReason) -> Self {
        match reason {
            BlockReason::StaticBlacklist(_) => StatBlockReason::StaticBlacklist,
            BlockReason::AbpRule(_) => StatBlockReason::AbpRule,
            BlockReason::HighEntropy(_) => StatBlockReason::HighEntropy,
            BlockReason::LexicalAnalysis => StatBlockReason::LexicalAnalysis,
            BlockReason::BannedKeyword(_) => StatBlockReason::BannedKeyword,
            BlockReason::InvalidStructure => StatBlockReason::InvalidStructure,
            BlockReason::SuspiciousIdn => StatBlockReason::SuspiciousIdn,
            BlockReason::NrdList => StatBlockReason::NrdList,
            BlockReason::TldExcluded => StatBlockReason::TldExcluded,
            BlockReason::Suspicious => StatBlockReason::Suspicious,
            BlockReason::CnameCloaking => StatBlockReason::CnameCloaking,
            BlockReason::ForbiddenQType(_) => StatBlockReason::ForbiddenQType,
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
            StatBlockReason::StaticBlacklist
        );
        assert_eq!(
            StatBlockReason::from(&BlockReason::AbpRule("rule".into())),
            StatBlockReason::AbpRule
        );
        assert_eq!(
            StatBlockReason::from(&BlockReason::HighEntropy(4.5)),
            StatBlockReason::HighEntropy
        );
        assert_eq!(
            StatBlockReason::from(&BlockReason::LexicalAnalysis),
            StatBlockReason::LexicalAnalysis
        );
        assert_eq!(
            StatBlockReason::from(&BlockReason::InvalidStructure),
            StatBlockReason::InvalidStructure
        );
        assert_eq!(
            StatBlockReason::from(&BlockReason::SuspiciousIdn),
            StatBlockReason::SuspiciousIdn
        );
        assert_eq!(
            StatBlockReason::from(&BlockReason::NrdList),
            StatBlockReason::NrdList
        );
        assert_eq!(
            StatBlockReason::from(&BlockReason::TldExcluded),
            StatBlockReason::TldExcluded
        );
        assert_eq!(
            StatBlockReason::from(&BlockReason::Suspicious),
            StatBlockReason::Suspicious
        );
        assert_eq!(
            StatBlockReason::from(&BlockReason::CnameCloaking),
            StatBlockReason::CnameCloaking
        );
        assert_eq!(
            StatBlockReason::from(&BlockReason::ForbiddenQType(255)),
            StatBlockReason::ForbiddenQType
        );
    }
}
