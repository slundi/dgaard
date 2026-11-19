use dgaard_monitor_core::protocol::{StatAction, StatError};
use dgaard_monitor_core::util::custom_bit_label;

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
