//! Fine-grained IDN policy (`[security.idn] mode`).
//!
//! DNS carries internationalized labels as ASCII "A-labels" (`xn--` +
//! punycode, RFC 3492); a few clients send raw UTF-8. Both forms are judged:
//!
//! * `Strict` blocks every IDN label;
//! * `Smart` decodes each IDN label and allows it only when every letter
//!   belongs to a script of `allowed_scripts`, and the scripts it mixes are
//!   a combination UTS #39 calls *highly restrictive* (one script, or
//!   Latin + Han + Hiragana/Katakana, or Latin + Han + Hangul). Mixing Latin
//!   with Cyrillic or Greek look-alikes — the classic homograph — is refused
//!   even when both scripts are allowed.
//!
//! Plain ASCII labels are not IDNs and always pass. A malformed A-label is
//! refused: no legitimate registry publishes one. Punycode is decoded with
//! `idna`, already linked through hickory.

use crate::config::{IdnConfig, IdnMode};

/// Script of a code point, for the scripts IDN policies tell apart.
///
/// Block-level ranges, not the full Unicode `Script` property: precise
/// enough to separate the scripts registries allow in labels, without a
/// table dependency on embedded builds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Script {
    /// Digits, hyphen, combining marks: neutral, ignored by the policy.
    Common = 0,
    Latin,
    Greek,
    Cyrillic,
    Armenian,
    Hebrew,
    Arabic,
    Devanagari,
    Bengali,
    Thai,
    Georgian,
    Hangul,
    Hiragana,
    Katakana,
    Han,
    /// Any other script: never allowed.
    Other,
}

/// Configuration names of the scripts, as accepted in `allowed_scripts`.
const SCRIPT_NAMES: &[(&str, Script)] = &[
    ("Latin", Script::Latin),
    // Historical alias from the shipped config: accented Western European
    // letters are part of the Latin script.
    ("WesternEuropean", Script::Latin),
    ("Greek", Script::Greek),
    ("Cyrillic", Script::Cyrillic),
    ("Armenian", Script::Armenian),
    ("Hebrew", Script::Hebrew),
    ("Arabic", Script::Arabic),
    ("Devanagari", Script::Devanagari),
    ("Bengali", Script::Bengali),
    ("Thai", Script::Thai),
    ("Georgian", Script::Georgian),
    ("Hangul", Script::Hangul),
    ("Hiragana", Script::Hiragana),
    ("Katakana", Script::Katakana),
    ("Han", Script::Han),
];

impl Script {
    /// Parse a configuration name (case-insensitive).
    pub fn from_name(name: &str) -> Option<Self> {
        SCRIPT_NAMES
            .iter()
            .find(|(known, _)| known.eq_ignore_ascii_case(name))
            .map(|(_, script)| *script)
    }

    /// Every accepted configuration name, for error messages.
    pub fn names() -> impl Iterator<Item = &'static str> {
        SCRIPT_NAMES.iter().map(|(name, _)| *name)
    }

    fn bit(self) -> u16 {
        1 << (self as u8)
    }
}

/// Script of `c`.
pub fn script_of(c: char) -> Script {
    match u32::from(c) {
        0x30..=0x39 | 0x2D | 0x5F | 0xB7 | 0x300..=0x36F | 0x30FC => Script::Common,
        0x41..=0x5A | 0x61..=0x7A => Script::Latin,
        0xD7 | 0xF7 => Script::Common,
        0xC0..=0x24F | 0x250..=0x2AF | 0x1E00..=0x1EFF | 0x2C60..=0x2C7F | 0xA720..=0xA7FF => {
            Script::Latin
        }
        0x370..=0x3FF | 0x1F00..=0x1FFF => Script::Greek,
        0x400..=0x52F | 0x1C80..=0x1C8F | 0x2DE0..=0x2DFF | 0xA640..=0xA69F => Script::Cyrillic,
        0x530..=0x58F => Script::Armenian,
        0x590..=0x5FF => Script::Hebrew,
        0x600..=0x6FF | 0x750..=0x77F | 0x8A0..=0x8FF | 0xFB50..=0xFDFF | 0xFE70..=0xFEFF => {
            Script::Arabic
        }
        0x900..=0x97F => Script::Devanagari,
        0x980..=0x9FF => Script::Bengali,
        0xE00..=0xE7F => Script::Thai,
        0x10A0..=0x10FF | 0x2D00..=0x2D2F => Script::Georgian,
        0x1100..=0x11FF | 0x3130..=0x318F | 0xAC00..=0xD7AF => Script::Hangul,
        0x3040..=0x309F => Script::Hiragana,
        0x30A0..=0x30FF | 0x31F0..=0x31FF => Script::Katakana,
        0x3005..=0x3007
        | 0x3400..=0x4DBF
        | 0x4E00..=0x9FFF
        | 0xF900..=0xFAFF
        | 0x20000..=0x2FA1F => Script::Han,
        _ => Script::Other,
    }
}

/// Set of scripts as a bitmask (no allocation on the query path).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ScriptSet(u16);

impl ScriptSet {
    fn of(scripts: &[Script]) -> Self {
        Self(scripts.iter().fold(0, |bits, script| bits | script.bit()))
    }

    fn insert(&mut self, script: Script) {
        self.0 |= script.bit();
    }

    fn is_subset_of(self, other: Self) -> bool {
        self.0 & !other.0 == 0
    }
}

/// UTS #39 "highly restrictive": one script, or one of these mixes.
fn is_highly_restrictive(scripts: ScriptSet) -> bool {
    let japanese = ScriptSet::of(&[
        Script::Latin,
        Script::Han,
        Script::Hiragana,
        Script::Katakana,
    ]);
    let korean = ScriptSet::of(&[Script::Latin, Script::Han, Script::Hangul]);
    scripts.0.count_ones() <= 1 || scripts.is_subset_of(japanese) || scripts.is_subset_of(korean)
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

/// Unicode form of an IDN label: the decoded A-label, or the raw UTF-8
/// label. `None` for a plain ASCII label (not an IDN). `Some(None)` for a
/// malformed A-label, which no registry publishes.
fn idn_label(label: &str) -> Option<Option<String>> {
    if let Some(encoded) = label
        .get(..4)
        .filter(|prefix| prefix.eq_ignore_ascii_case("xn--"))
        .map(|_| &label[4..])
    {
        // A valid A-label decodes to a label with at least one non-ASCII
        // character (IDNA2008); anything else is malformed.
        return Some(
            idna::punycode::decode_to_string(encoded).filter(|decoded| !decoded.is_ascii()),
        );
    }
    (!label.is_ascii()).then(|| Some(label.to_owned()))
}

/// Smart-mode verdict for one Unicode label.
fn smart_label_allowed(label: &str, allowed: ScriptSet) -> bool {
    let mut scripts = ScriptSet::default();
    for c in label.chars() {
        match script_of(c) {
            Script::Common => {}
            Script::Other => return false,
            script => scripts.insert(script),
        }
    }
    scripts.is_subset_of(allowed) && is_highly_restrictive(scripts)
}

/// Scripts listed in `allowed_scripts`; unknown names are ignored here
/// (`Config::validate` rejects them at startup).
fn allowed_scripts(config: &IdnConfig) -> ScriptSet {
    let mut set = ScriptSet::default();
    for script in config
        .allowed_scripts
        .iter()
        .filter_map(|name| Script::from_name(name))
    {
        set.insert(script);
    }
    set
}

/// True when `idn.mode` refuses `domain`.
pub fn idn_policy_blocks(domain: &str, config: &IdnConfig) -> bool {
    match config.mode {
        IdnMode::Off => false,
        IdnMode::Strict => domain.split('.').any(|label| idn_label(label).is_some()),
        IdnMode::Smart => {
            let allowed = allowed_scripts(config);
            domain.split('.').any(|label| match idn_label(label) {
                None => false,
                Some(None) => true,
                Some(Some(unicode)) => !smart_label_allowed(&unicode, allowed),
            })
        }
    }
}

/// True when an IDN entry of a blacklist is sure to be blocked at query
/// time whatever its script, so the loader may drop it: `Strict` mode only.
/// In `Smart` mode an allowed-script IDN can still be explicitly listed.
pub fn idn_mode_blocks_every_idn(config: &IdnConfig) -> bool {
    config.mode == IdnMode::Strict
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a_label(unicode: &str) -> String {
        format!("xn--{}", idna::punycode::encode_str(unicode).unwrap())
    }

    fn smart(allowed: &[&str]) -> IdnConfig {
        IdnConfig {
            mode: IdnMode::Smart,
            allowed_scripts: allowed.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn strict() -> IdnConfig {
        IdnConfig {
            mode: IdnMode::Strict,
            ..IdnConfig::default()
        }
    }

    // ---- scripts ----

    #[test]
    fn script_of_samples() {
        assert_eq!(script_of('a'), Script::Latin);
        assert_eq!(script_of('é'), Script::Latin);
        assert_eq!(script_of('7'), Script::Common);
        assert_eq!(script_of('-'), Script::Common);
        assert_eq!(script_of('\u{301}'), Script::Common, "combining accent");
        assert_eq!(script_of('а'), Script::Cyrillic, "Cyrillic a");
        assert_eq!(script_of('ο'), Script::Greek, "Greek omicron");
        assert_eq!(script_of('日'), Script::Han);
        assert_eq!(script_of('ひ'), Script::Hiragana);
        assert_eq!(script_of('カ'), Script::Katakana);
        assert_eq!(script_of('한'), Script::Hangul);
        assert_eq!(script_of('ሀ'), Script::Other, "Ethiopic");
    }

    #[test]
    fn script_names_are_case_insensitive_with_alias() {
        assert_eq!(Script::from_name("latin"), Some(Script::Latin));
        assert_eq!(Script::from_name("WesternEuropean"), Some(Script::Latin));
        assert_eq!(Script::from_name("CYRILLIC"), Some(Script::Cyrillic));
        assert_eq!(Script::from_name("Klingon"), None);
        assert!(Script::names().any(|name| name == "Han"));
    }

    // ---- policy ----

    #[test]
    fn off_never_blocks() {
        let config = IdnConfig::default();
        assert!(!idn_policy_blocks(&a_label("пример"), &config));
    }

    #[test]
    fn strict_blocks_any_idn_label() {
        let config = strict();
        assert!(idn_policy_blocks(
            &format!("{}.fr", a_label("café")),
            &config
        ));
        assert!(idn_policy_blocks("café.fr", &config), "raw UTF-8 label");
        assert!(
            idn_policy_blocks("XN--CAF-DMA.fr", &config),
            "prefix is case-insensitive"
        );
        assert!(!idn_policy_blocks("cafe.fr", &config));
        assert!(
            !idn_policy_blocks("my-xn-site.com", &config),
            "xn- inside a label is not a prefix"
        );
    }

    #[test]
    fn smart_allows_listed_scripts() {
        let config = smart(&["Latin", "WesternEuropean"]);
        assert!(!idn_policy_blocks(
            &format!("{}.fr", a_label("café")),
            &config
        ));
        assert!(!idn_policy_blocks(
            &format!("{}.de", a_label("münchen-2024")),
            &config
        ));
        assert!(
            !idn_policy_blocks("example.com", &config),
            "ASCII is not an IDN"
        );
    }

    #[test]
    fn smart_blocks_scripts_outside_the_list() {
        let config = smart(&["Latin"]);
        assert!(idn_policy_blocks(
            &format!("{}.com", a_label("пример")),
            &config
        ));
        assert!(
            idn_policy_blocks(&format!("{}.com", a_label("ሀሁሂ")), &config),
            "Other script"
        );
        // Listed, then allowed.
        let config = smart(&["Latin", "Cyrillic"]);
        assert!(!idn_policy_blocks(
            &format!("{}.рф", a_label("пример")),
            &config
        ));
    }

    #[test]
    fn smart_blocks_mixed_script_homographs_even_when_both_are_allowed() {
        // "pаypal" with a Cyrillic "а".
        let config = smart(&["Latin", "Cyrillic", "Greek"]);
        assert!(idn_policy_blocks(
            &format!("{}.com", a_label("p\u{430}ypal")),
            &config
        ));
        assert!(idn_policy_blocks(
            &format!("{}.com", a_label("g\u{3BF}\u{3BF}gle")),
            &config
        ));
    }

    #[test]
    fn smart_allows_highly_restrictive_cjk_mixes() {
        let config = smart(&["Latin", "Han", "Hiragana", "Katakana", "Hangul"]);
        assert!(!idn_policy_blocks(
            &format!("{}.jp", a_label("東京すし")),
            &config
        ));
        assert!(!idn_policy_blocks(
            &format!("{}.jp", a_label("abcカタカナ")),
            &config
        ));
        assert!(!idn_policy_blocks(
            &format!("{}.kr", a_label("한국漢字")),
            &config
        ));
        // Hangul with Katakana is not one of the allowed mixes.
        assert!(idn_policy_blocks(
            &format!("{}.com", a_label("한국カ")),
            &config
        ));
    }

    #[test]
    fn smart_blocks_malformed_a_labels() {
        let config = smart(&["Latin"]);
        assert!(idn_policy_blocks("xn--ab$c.com", &config));
        // Decodes to plain ASCII: not a valid A-label.
        assert!(idn_policy_blocks("xn--abc-.com", &config));
        assert!(idn_policy_blocks("xn--.com", &config));
    }

    #[test]
    fn only_strict_makes_every_idn_blocked() {
        assert!(idn_mode_blocks_every_idn(&strict()));
        assert!(!idn_mode_blocks_every_idn(&smart(&["Latin"])));
        assert!(!idn_mode_blocks_every_idn(&IdnConfig::default()));
    }
}
