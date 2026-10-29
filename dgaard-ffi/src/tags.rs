//! C-visible discriminants and the lossless projection of `BlockReason`.
//!
//! The numeric values below are **append-only**: they are part of the ABI and
//! must never be renumbered. `dgaard_abi_version` is bumped when a variant is
//! added so a consumer can tell whether a tag it does not recognise is new or
//! corrupt.

use std::net::IpAddr;

use ::dgaard_engine::{Action, BlockReason};

/// Action the caller should take for a domain.
//
// The variant names are the C API surface — cbindgen copies them verbatim
// into `dgaard.h`, so they are spelled the way C consumers read them rather
// than the way Rust normally would.
#[allow(non_camel_case_types)]
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum dgaard_action {
    /// The call failed. Inspect `dgaard_last_error`. Never produced by a
    /// successful classification, so it can never be confused with a verdict.
    DGAARD_ACTION_ERROR = -1,
    /// Forward the query to the configured upstream resolver.
    DGAARD_ACTION_PROXY_UPSTREAM = 0,
    /// Explicitly allowed (whitelist hit); forward it.
    DGAARD_ACTION_ALLOW = 1,
    /// Blocked. `dgaard_verdict_block_reason` says why.
    DGAARD_ACTION_BLOCK = 2,
    /// Discard the query without answering.
    DGAARD_ACTION_DROP = 3,
    /// Answer from the local cache. `dgaard_verdict_address` holds the IP.
    DGAARD_ACTION_LOCAL_RESOLVE = 4,
    /// Answer with an internal landing page. `dgaard_verdict_address` holds the IP.
    DGAARD_ACTION_INTERNAL_REDIRECT = 5,
    /// Answer immediately from the hot cache. `dgaard_verdict_address` holds the IP.
    DGAARD_ACTION_RESPOND = 6,
    /// Redirect to a local landing page. `dgaard_verdict_address` holds the IP.
    DGAARD_ACTION_REDIRECT = 7,
    /// Matched an inline config override; all filters were bypassed.
    /// `dgaard_verdict_address` holds the IP.
    DGAARD_ACTION_OVERRIDE = 8,
}

/// Which heuristic produced a block or a score contribution.
#[allow(non_camel_case_types)]
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum dgaard_reason {
    /// The call failed. Inspect `dgaard_last_error`.
    DGAARD_REASON_ERROR = -1,
    /// No reason — the verdict was not a block, or the index was out of range.
    DGAARD_REASON_NONE = 0,
    /// Hit a static blacklist.
    ///
    /// Text payload: a label for the stage that matched. The engine does not
    /// currently thread the source filename through to the verdict, so this
    /// is the literal `"blocklist"` rather than, say, `"oisd.txt"`. Treat it
    /// as a coarse origin tag, not as a list identifier.
    DGAARD_REASON_STATIC_BLACKLIST = 1,
    /// Hit an ABP-style or wildcard rule.
    ///
    /// Text payload: a stage label, with the same caveat as
    /// `DGAARD_REASON_STATIC_BLACKLIST` — the matched pattern itself is not
    /// carried out of the engine.
    DGAARD_REASON_ABP_RULE = 2,
    /// High Shannon entropy. Number payload: the entropy, in bits per character.
    DGAARD_REASON_HIGH_ENTROPY = 3,
    /// Repetitive or counter-padded label. Number payload: the label length.
    DGAARD_REASON_LOW_ENTROPY = 4,
    /// Failed consonant-ratio or n-gram analysis.
    DGAARD_REASON_LEXICAL_ANALYSIS = 5,
    /// Parental-control keyword hit. Text payload: the keyword.
    DGAARD_REASON_BANNED_KEYWORD = 6,
    /// Failed a structural check (depth, length, …).
    DGAARD_REASON_INVALID_STRUCTURE = 7,
    /// Suspicious IDN or Punycode homograph.
    DGAARD_REASON_SUSPICIOUS_IDN = 8,
    /// Listed as a newly registered domain.
    DGAARD_REASON_NRD_LIST = 9,
    /// Cumulative suspicion score crossed the blocking threshold.
    DGAARD_REASON_SUSPICIOUS = 10,
    /// The TLD is excluded by configuration.
    DGAARD_REASON_TLD_EXCLUDED = 11,
    /// A CNAME in the chain is blacklisted (cloaking).
    DGAARD_REASON_CNAME_CLOAKING = 12,
    /// Query type forbidden by policy. Number payload: the RFC 1035 type code.
    DGAARD_REASON_FORBIDDEN_QTYPE = 13,
    /// Upstream answer maps a public name to a private address.
    DGAARD_REASON_DNS_REBINDING = 14,
    /// Abnormally low response TTL. Number payload: the TTL, in seconds.
    DGAARD_REASON_LOW_TTL = 15,
    /// Resolves into a blocked ASN range.
    DGAARD_REASON_ASN_BLOCKED = 16,
    /// Resolves into a suspicious country. Text payload: the ISO 3166-1
    /// alpha-2 code.
    DGAARD_REASON_GEOIP_SUSPICIOUS = 17,
    /// Special-use or internal TLD that must not be forwarded (RFC 6761/6762).
    DGAARD_REASON_SPECIAL_USE_DOMAIN = 18,
    /// Reverse lookup for a private address range.
    DGAARD_REASON_PTR_LEAK = 19,
    /// DNS CHAOS-class query.
    DGAARD_REASON_CHAOS_CLASS = 20,
    /// Hit a user-defined custom flag list. Number payload: the bit index (16–31).
    DGAARD_REASON_CUSTOM_FLAG = 21,
}

/// One reason, flattened into the three things C can consume: a tag, an
/// optional number and an optional string.
#[derive(Debug, Clone)]
pub(crate) struct FlatReason {
    pub(crate) tag: dgaard_reason,
    /// NaN when the reason carries no numeric payload.
    pub(crate) number: f64,
    pub(crate) text: Option<String>,
}

impl FlatReason {
    fn bare(tag: dgaard_reason) -> Self {
        Self {
            tag,
            number: f64::NAN,
            text: None,
        }
    }

    fn with_number(tag: dgaard_reason, number: f64) -> Self {
        Self {
            tag,
            number,
            text: None,
        }
    }

    fn with_text(tag: dgaard_reason, text: &str) -> Self {
        Self {
            tag,
            number: f64::NAN,
            text: Some(text.to_owned()),
        }
    }

    /// Project an engine reason onto the C representation.
    ///
    /// Every numeric payload the engine carries (`u8`, `u16`, `u32`, `usize`
    /// label lengths, `f32` entropy) is exactly representable in an `f64`, so
    /// the single `number` channel loses nothing.
    pub(crate) fn from_reason(reason: &BlockReason) -> Self {
        use dgaard_reason::*;

        match reason {
            BlockReason::StaticBlacklist(source) => {
                Self::with_text(DGAARD_REASON_STATIC_BLACKLIST, source)
            }
            BlockReason::AbpRule(pattern) => Self::with_text(DGAARD_REASON_ABP_RULE, pattern),
            BlockReason::HighEntropy(entropy) => {
                Self::with_number(DGAARD_REASON_HIGH_ENTROPY, f64::from(*entropy))
            }
            BlockReason::LowEntropy(length) => {
                Self::with_number(DGAARD_REASON_LOW_ENTROPY, *length as f64)
            }
            BlockReason::LexicalAnalysis => Self::bare(DGAARD_REASON_LEXICAL_ANALYSIS),
            BlockReason::BannedKeyword(keyword) => {
                Self::with_text(DGAARD_REASON_BANNED_KEYWORD, keyword)
            }
            BlockReason::InvalidStructure => Self::bare(DGAARD_REASON_INVALID_STRUCTURE),
            BlockReason::SuspiciousIdn => Self::bare(DGAARD_REASON_SUSPICIOUS_IDN),
            BlockReason::NrdList => Self::bare(DGAARD_REASON_NRD_LIST),
            BlockReason::Suspicious => Self::bare(DGAARD_REASON_SUSPICIOUS),
            BlockReason::TldExcluded => Self::bare(DGAARD_REASON_TLD_EXCLUDED),
            BlockReason::CnameCloaking => Self::bare(DGAARD_REASON_CNAME_CLOAKING),
            BlockReason::ForbiddenQType(qtype) => {
                Self::with_number(DGAARD_REASON_FORBIDDEN_QTYPE, f64::from(*qtype))
            }
            BlockReason::DnsRebinding => Self::bare(DGAARD_REASON_DNS_REBINDING),
            BlockReason::LowTtl(ttl) => Self::with_number(DGAARD_REASON_LOW_TTL, f64::from(*ttl)),
            BlockReason::AsnBlocked => Self::bare(DGAARD_REASON_ASN_BLOCKED),
            BlockReason::GeoIpSuspicious(country) => {
                Self::with_text(DGAARD_REASON_GEOIP_SUSPICIOUS, country)
            }
            BlockReason::SpecialUseDomain => Self::bare(DGAARD_REASON_SPECIAL_USE_DOMAIN),
            BlockReason::PtrLeak => Self::bare(DGAARD_REASON_PTR_LEAK),
            BlockReason::ChaosClass => Self::bare(DGAARD_REASON_CHAOS_CLASS),
            BlockReason::CustomFlag(bit) => {
                Self::with_number(DGAARD_REASON_CUSTOM_FLAG, f64::from(*bit))
            }
        }
    }
}

/// Split an engine action into its C tag, the block reason it may carry and
/// the address it may carry.
pub(crate) fn flatten_action(
    action: &Action,
) -> (dgaard_action, Option<FlatReason>, Option<IpAddr>) {
    use dgaard_action::*;

    match action {
        Action::ProxyToUpstream => (DGAARD_ACTION_PROXY_UPSTREAM, None, None),
        Action::Allow => (DGAARD_ACTION_ALLOW, None, None),
        Action::Drop => (DGAARD_ACTION_DROP, None, None),
        Action::Block(reason) => (
            DGAARD_ACTION_BLOCK,
            Some(FlatReason::from_reason(reason)),
            None,
        ),
        Action::LocalResolve(address) => (DGAARD_ACTION_LOCAL_RESOLVE, None, Some(*address)),
        Action::InternalRedirect(address) => {
            (DGAARD_ACTION_INTERNAL_REDIRECT, None, Some(*address))
        }
        Action::Respond(address) => (DGAARD_ACTION_RESPOND, None, Some(*address)),
        Action::Redirect(address) => (DGAARD_ACTION_REDIRECT, None, Some(*address)),
        Action::Override(address) => (DGAARD_ACTION_OVERRIDE, None, Some(*address)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// One of every `BlockReason` variant. The match in `from_reason` is
    /// exhaustive, so adding a variant to the engine breaks the build here
    /// and forces a tag to be appended.
    fn every_reason() -> Vec<BlockReason> {
        vec![
            BlockReason::StaticBlacklist("oisd.txt".into()),
            BlockReason::AbpRule("||ads.example^".into()),
            BlockReason::HighEntropy(4.25),
            BlockReason::LowEntropy(19),
            BlockReason::LexicalAnalysis,
            BlockReason::BannedKeyword("casino".into()),
            BlockReason::InvalidStructure,
            BlockReason::SuspiciousIdn,
            BlockReason::NrdList,
            BlockReason::Suspicious,
            BlockReason::TldExcluded,
            BlockReason::CnameCloaking,
            BlockReason::ForbiddenQType(255),
            BlockReason::DnsRebinding,
            BlockReason::LowTtl(30),
            BlockReason::AsnBlocked,
            BlockReason::GeoIpSuspicious("RU".into()),
            BlockReason::SpecialUseDomain,
            BlockReason::PtrLeak,
            BlockReason::ChaosClass,
            BlockReason::CustomFlag(17),
        ]
    }

    #[test]
    fn every_reason_maps_to_a_distinct_non_none_tag() {
        let mut seen = Vec::new();
        for reason in every_reason() {
            let tag = FlatReason::from_reason(&reason).tag;
            assert_ne!(
                tag,
                dgaard_reason::DGAARD_REASON_NONE,
                "{reason:?} must not collapse onto NONE"
            );
            assert!(!seen.contains(&tag), "{reason:?} reuses tag {tag:?}");
            seen.push(tag);
        }
        assert_eq!(seen.len(), 21);
    }

    #[test]
    fn tag_values_are_the_published_abi() {
        // Pinned so a reordering of `BlockReason` cannot silently renumber the
        // ABI. Append new variants; never renumber existing ones.
        let tags: Vec<i32> = every_reason()
            .iter()
            .map(|reason| FlatReason::from_reason(reason).tag as i32)
            .collect();
        assert_eq!(tags, (1..=21).collect::<Vec<i32>>());
    }

    #[test]
    fn numeric_payloads_survive_the_f64_channel() {
        let entropy = FlatReason::from_reason(&BlockReason::HighEntropy(4.25));
        assert_eq!(entropy.number, 4.25);
        assert!(entropy.text.is_none());

        let ttl = FlatReason::from_reason(&BlockReason::LowTtl(u32::MAX));
        assert_eq!(ttl.number, f64::from(u32::MAX));

        let qtype = FlatReason::from_reason(&BlockReason::ForbiddenQType(255));
        assert_eq!(qtype.number, 255.0);

        let flag = FlatReason::from_reason(&BlockReason::CustomFlag(31));
        assert_eq!(flag.number, 31.0);

        let length = FlatReason::from_reason(&BlockReason::LowEntropy(19));
        assert_eq!(length.number, 19.0);
    }

    #[test]
    fn text_payloads_are_carried_verbatim() {
        let listed = FlatReason::from_reason(&BlockReason::StaticBlacklist("oisd.txt".into()));
        assert_eq!(listed.text.as_deref(), Some("oisd.txt"));
        assert!(listed.number.is_nan());

        let geo = FlatReason::from_reason(&BlockReason::GeoIpSuspicious("RU".into()));
        assert_eq!(geo.text.as_deref(), Some("RU"));
    }

    #[test]
    fn payload_free_reasons_report_nan_and_no_text() {
        let flat = FlatReason::from_reason(&BlockReason::PtrLeak);
        assert!(flat.number.is_nan());
        assert!(flat.text.is_none());
    }

    #[test]
    fn actions_split_into_tag_reason_and_address() {
        let address = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        let (tag, reason, carried) = flatten_action(&Action::ProxyToUpstream);
        assert_eq!(tag, dgaard_action::DGAARD_ACTION_PROXY_UPSTREAM);
        assert!(reason.is_none() && carried.is_none());

        let (tag, reason, carried) = flatten_action(&Action::Block(BlockReason::PtrLeak));
        assert_eq!(tag, dgaard_action::DGAARD_ACTION_BLOCK);
        assert_eq!(reason.unwrap().tag, dgaard_reason::DGAARD_REASON_PTR_LEAK);
        assert!(carried.is_none());

        let (tag, reason, carried) = flatten_action(&Action::Override(address));
        assert_eq!(tag, dgaard_action::DGAARD_ACTION_OVERRIDE);
        assert!(reason.is_none());
        assert_eq!(carried, Some(address));
    }

    #[test]
    fn every_action_maps_to_a_distinct_tag() {
        let address = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let actions = [
            Action::ProxyToUpstream,
            Action::Allow,
            Action::Block(BlockReason::NrdList),
            Action::Drop,
            Action::LocalResolve(address),
            Action::InternalRedirect(address),
            Action::Respond(address),
            Action::Redirect(address),
            Action::Override(address),
        ];

        let mut seen = Vec::new();
        for action in &actions {
            let (tag, _, _) = flatten_action(action);
            assert_ne!(
                tag,
                dgaard_action::DGAARD_ACTION_ERROR,
                "{action:?} collapsed onto ERROR"
            );
            assert!(!seen.contains(&tag), "{action:?} reuses tag {tag:?}");
            seen.push(tag);
        }
        assert_eq!(seen.len(), 9);
    }
}
