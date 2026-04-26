// ── Indicator symbols ─────────────────────────────────────────────────────────

use crate::protocol::StatAction;

pub const INDICATOR_ALLOWED: &str = "✔";
pub const INDICATOR_BLOCKED: &str = "✘";
pub const INDICATOR_SUSPICIOUS: &str = "⚠";
pub const INDICATOR_PROXIED: &str = "·";

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
            StatAction::Allowed => Self::Green,
            StatAction::Proxied => Self::Dim,
            StatAction::Blocked(_) | StatAction::HighlySuspicious(_) => Self::Red,
            StatAction::Suspicious(_) => Self::Yellow,
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
    use crate::protocol::{StatAction, StatBlockReason};

    use super::*;

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
