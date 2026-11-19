use dgaard_monitor_core::protocol::{StatAction, StatBlockReason, StatError};
use dgaard_monitor_core::util::custom_bit_label;

use crate::config::CountryDisplay;

// ── Country ───────────────────────────────────────────────────────────────────

/// Show the country hosting a domain: its alpha-2 code (`FR`) or flag emoji
/// (🇫🇷, a pair of regional indicator letters); empty when unknown.
pub fn format_country(country: Option<[u8; 2]>, display: CountryDisplay) -> String {
    let Some(code) = country else {
        return String::new();
    };
    match display {
        CountryDisplay::Code => code.iter().map(|&letter| char::from(letter)).collect(),
        // 🇦 is U+1F1E6; the protocol only lets uppercase ASCII letters through.
        CountryDisplay::Emoji => code
            .iter()
            .filter_map(|&letter| char::from_u32(0x1F1E6 + u32::from(letter - b'A')))
            .collect(),
    }
}

// ── Flag labels ───────────────────────────────────────────────────────────────

/// Number of `StatBlockReason` bits: 0–15 built in, 16–31 custom.
pub const REASON_BITS: usize = 32;

/// Short display names of the built-in `StatBlockReason` bits, by bit position.
const BUILT_IN_FLAGS: [&str; 16] = [
    "Blacklist",
    "AbpRule",
    "HighEntropy",
    "Lexical",
    "BannedKw",
    "InvalidStruct",
    "SuspIDN",
    "NRD",
    "TLD",
    "Suspicious",
    "CnameCloaking",
    "ForbidQtype",
    "DnsRebinding",
    "LowTTL",
    "AsnBlocked",
    "SuspGeoIP",
];

/// Short display name of one `StatBlockReason` bit, for every TUI table and
/// chart; custom bits (16–31) use the code configured in dgaard's
/// `[[security.custom_flags]]`.
pub fn flag_label(bit: usize) -> String {
    match BUILT_IN_FLAGS.get(bit) {
        Some(name) => name.to_string(),
        None => custom_bit_label(bit as u8),
    }
}

// ── Reason categories ─────────────────────────────────────────────────────────

/// What kind of check blocked a query: the `StatBlockReason` bits grouped by
/// detection stage, for the Block Reasons pie chart.
///
/// A query can carry bits of several categories; it counts once, in the
/// strongest one, in the order of `ALL`: hard rules first, score-based
/// signals last.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReasonCategory {
    /// Blacklist, ABP rule, newly registered domain, excluded TLD.
    Lists,
    /// Parental-control keyword, forbidden query type.
    Policy,
    /// Inspection of the upstream answer: CNAME cloaking, DNS rebinding, low
    /// TTL, blocked ASN, suspicious GeoIP country.
    Answer,
    /// Threat-intel lists from dgaard's `[[security.custom_flags]]` (bits 16–31).
    Custom,
    /// Entropy, lexical, structure, IDN and generic score signals.
    Heuristics,
    /// A blocking verdict that carried no reason bit.
    Unspecified,
}

impl ReasonCategory {
    /// Every category, strongest first; also the legend order.
    pub const ALL: [ReasonCategory; 6] = [
        ReasonCategory::Lists,
        ReasonCategory::Policy,
        ReasonCategory::Answer,
        ReasonCategory::Custom,
        ReasonCategory::Heuristics,
        ReasonCategory::Unspecified,
    ];

    /// Reason bits of each category but `Unspecified`.
    fn mask(self) -> u32 {
        match self {
            // STATIC_BLACKLIST, ABP_RULE, NRD_LIST, TLD_EXCLUDED
            Self::Lists => 1 << 0 | 1 << 1 | 1 << 7 | 1 << 8,
            // BANNED_KEYWORD, FORBIDDEN_QTYPE
            Self::Policy => 1 << 4 | 1 << 11,
            // CNAME_CLOAKING, DNS_REBINDING, LOW_TTL, ASN_BLOCKED, SUSPICIOUS_GEO_IP
            Self::Answer => 1 << 10 | 1 << 12 | 1 << 13 | 1 << 14 | 1 << 15,
            Self::Custom => 0xFFFF_0000,
            // HIGH_ENTROPY, LEXICAL_ANALYSIS, INVALID_STRUCTURE, SUSPICIOUS_IDN, SUSPICIOUS
            Self::Heuristics => 1 << 2 | 1 << 3 | 1 << 5 | 1 << 6 | 1 << 9,
            Self::Unspecified => 0,
        }
    }

    /// The category a blocking verdict with these reasons counts in.
    pub fn of(reasons: StatBlockReason) -> Self {
        Self::ALL
            .into_iter()
            .find(|category| reasons.bits() & category.mask() != 0)
            .unwrap_or(Self::Unspecified)
    }

    /// Position in `ALL`, to index per-category counters.
    pub fn index(self) -> usize {
        self as usize
    }

    /// Legend label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Lists => "Lists",
            Self::Policy => "Policy",
            Self::Answer => "Answer",
            Self::Custom => "Custom",
            Self::Heuristics => "Heuristics",
            Self::Unspecified => "Unspecified",
        }
    }
}

// ── Indicator symbols ─────────────────────────────────────────────────────────

pub const INDICATOR_ALLOWED: &str = "✔";
pub const INDICATOR_BLOCKED: &str = "✘";
pub const INDICATOR_SUSPICIOUS: &str = "⚠";
pub const INDICATOR_PROXIED: &str = "·";
/// SERVFAIL: the lookup failed, nothing was blocked.
pub const INDICATOR_ERROR: &str = "!";

// ── DomainColor ───────────────────────────────────────────────────────────────

/// Colour hint for the Domain column and the single-char indicator.
///
/// The renderer maps these to actual ratatui `Color` values; keeping them
/// as an enum here avoids a ratatui dependency in the data layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainColor {
    /// Green  — `Allowed`.
    Green,
    /// Red    — `Blocked` or `HighlySuspicious`.
    Red,
    /// Yellow — `Suspicious`.
    Yellow,
    /// Dim    — `Proxied` (pass-through, no verdict).
    Dim,
}

impl DomainColor {
    pub fn from_action(action: &StatAction) -> Self {
        match action {
            StatAction::Allowed | StatAction::AllowedWithOverride | StatAction::Cached => {
                Self::Green
            }
            StatAction::Proxied => Self::Dim,
            StatAction::Blocked(_)
            | StatAction::HighlySuspicious(_)
            | StatAction::Error(StatError::DnssecBogus) => Self::Red,
            // A failed lookup deserves attention without being a threat.
            StatAction::Suspicious(_) | StatAction::Error(StatError::Upstream) => Self::Yellow,
        }
    }

    /// The single-char indicator to display before the timestamp.
    pub fn indicator(self) -> &'static str {
        match self {
            Self::Green => INDICATOR_ALLOWED,
            Self::Red => INDICATOR_BLOCKED,
            Self::Yellow => INDICATOR_SUSPICIOUS,
            Self::Dim => INDICATOR_PROXIED,
        }
    }
}

#[cfg(test)]
mod tests {
    use dgaard_monitor_core::protocol::{StatAction, StatBlockReason};

    use super::*;

    // --- format_country ---

    #[test]
    fn test_format_country_code() {
        assert_eq!(format_country(Some(*b"FR"), CountryDisplay::Code), "FR");
    }

    #[test]
    fn test_format_country_emoji() {
        assert_eq!(format_country(Some(*b"FR"), CountryDisplay::Emoji), "🇫🇷");
        assert_eq!(format_country(Some(*b"US"), CountryDisplay::Emoji), "🇺🇸");
    }

    #[test]
    fn test_format_country_unknown_is_empty() {
        assert_eq!(format_country(None, CountryDisplay::Code), "");
        assert_eq!(format_country(None, CountryDisplay::Emoji), "");
    }

    #[test]
    fn test_format_country_fits_the_column() {
        // Two cells either way: the Queries column is sized for it.
        for display in [CountryDisplay::Code, CountryDisplay::Emoji] {
            let text = format_country(Some(*b"DE"), display);
            assert_eq!(ratatui::text::Span::raw(text).width(), 2, "{display:?}");
        }
    }

    // --- flag_label ---

    #[test]
    fn test_flag_label_built_in_bits() {
        assert_eq!(flag_label(0), "Blacklist");
        assert_eq!(flag_label(14), "AsnBlocked");
        assert_eq!(flag_label(15), "SuspGeoIP");
    }

    #[test]
    fn test_flag_label_custom_bits_use_engine_codes() {
        // No custom labels registered in unit tests: generic fallback.
        assert_eq!(flag_label(16), custom_bit_label(16));
        assert_eq!(flag_label(31), custom_bit_label(31));
    }

    #[test]
    fn test_flag_label_every_bit_non_empty() {
        for bit in 0..REASON_BITS {
            assert!(!flag_label(bit).is_empty(), "flag_label({bit}) is empty");
        }
    }

    // --- ReasonCategory ---

    fn category(bits: u32) -> ReasonCategory {
        ReasonCategory::of(StatBlockReason::from_bits_retain(bits))
    }

    #[test]
    fn test_category_masks_cover_every_bit_once() {
        let masks: Vec<u32> = ReasonCategory::ALL.iter().map(|cat| cat.mask()).collect();
        assert_eq!(masks.iter().fold(0, |all, mask| all | mask), u32::MAX);
        assert_eq!(masks.iter().map(|mask| mask.count_ones()).sum::<u32>(), 32);
    }

    #[test]
    fn test_category_of_single_bits() {
        assert_eq!(category(1 << 0), ReasonCategory::Lists);
        assert_eq!(category(1 << 7), ReasonCategory::Lists);
        assert_eq!(category(1 << 4), ReasonCategory::Policy);
        assert_eq!(category(1 << 11), ReasonCategory::Policy);
        assert_eq!(category(1 << 10), ReasonCategory::Answer);
        assert_eq!(category(1 << 15), ReasonCategory::Answer);
        assert_eq!(category(1 << 16), ReasonCategory::Custom);
        assert_eq!(category(1 << 31), ReasonCategory::Custom);
        assert_eq!(category(1 << 2), ReasonCategory::Heuristics);
        assert_eq!(category(1 << 9), ReasonCategory::Heuristics);
    }

    #[test]
    fn test_category_strongest_wins() {
        // Blacklist + high entropy: the list match decides.
        assert_eq!(category(1 << 0 | 1 << 2), ReasonCategory::Lists);
        // Custom threat intel + lexical: the intel list decides.
        assert_eq!(category(1 << 20 | 1 << 3), ReasonCategory::Custom);
        // Low TTL + forbidden qtype: policy before answer.
        assert_eq!(category(1 << 13 | 1 << 11), ReasonCategory::Policy);
    }

    #[test]
    fn test_category_without_bits_is_unspecified() {
        assert_eq!(category(0), ReasonCategory::Unspecified);
    }

    #[test]
    fn test_category_index_follows_all() {
        for (position, category) in ReasonCategory::ALL.into_iter().enumerate() {
            assert_eq!(category.index(), position);
            assert!(!category.label().is_empty());
        }
    }

    // --- DomainColor / indicator ---

    #[test]
    fn test_domain_color_allowed_is_green() {
        assert_eq!(
            DomainColor::from_action(&StatAction::Allowed),
            DomainColor::Green
        );
    }

    #[test]
    fn test_domain_color_proxied_is_dim() {
        assert_eq!(
            DomainColor::from_action(&StatAction::Proxied),
            DomainColor::Dim
        );
    }

    #[test]
    fn test_domain_color_blocked_is_red() {
        assert_eq!(
            DomainColor::from_action(&StatAction::Blocked(StatBlockReason::empty())),
            DomainColor::Red
        );
    }

    #[test]
    fn test_domain_color_highly_suspicious_is_red() {
        assert_eq!(
            DomainColor::from_action(&StatAction::HighlySuspicious(StatBlockReason::empty())),
            DomainColor::Red
        );
    }

    #[test]
    fn test_domain_color_suspicious_is_yellow() {
        assert_eq!(
            DomainColor::from_action(&StatAction::Suspicious(StatBlockReason::empty())),
            DomainColor::Yellow
        );
    }

    #[test]
    fn test_indicator_symbols() {
        assert_eq!(DomainColor::Green.indicator(), INDICATOR_ALLOWED);
        assert_eq!(DomainColor::Red.indicator(), INDICATOR_BLOCKED);
        assert_eq!(DomainColor::Yellow.indicator(), INDICATOR_SUSPICIOUS);
        assert_eq!(DomainColor::Dim.indicator(), INDICATOR_PROXIED);
    }
}
