use std::collections::HashMap;

// Vowels for consonant ratio analysis (lowercase ASCII only)
const VOWELS: [u8; 5] = [b'a', b'e', b'i', b'o', b'u'];

/// Checks if a byte is a lowercase ASCII letter
#[inline]
fn is_lowercase_letter(b: u8) -> bool {
    b.is_ascii_lowercase()
}

/// Checks if a byte is a vowel (lowercase ASCII)
#[inline]
fn is_vowel(b: u8) -> bool {
    VOWELS.contains(&b)
}

/// Checks if a byte is a consonant (lowercase ASCII letter that is not a vowel)
#[inline]
fn is_consonant(b: u8) -> bool {
    is_lowercase_letter(b) && !is_vowel(b)
}

/// Finds the longest sequence of consecutive consonants in a string.
///
/// Normal English words rarely have more than 3-4 consecutive consonants.
/// DGA domains often have sequences of 5+ consonants due to random generation.
pub fn max_consonant_sequence(s: &str) -> usize {
    let bytes = s.as_bytes();
    let mut max_seq = 0usize;
    let mut current_seq = 0usize;

    for &b in bytes {
        if is_consonant(b) {
            current_seq += 1;
            if current_seq > max_seq {
                max_seq = current_seq;
            }
        } else {
            current_seq = 0;
        }
    }

    max_seq
}

/// Checks if a domain has suspicious consonant patterns.
///
/// This function combines both the consonant ratio and max sequence checks
/// to identify "unnatural" letter clustering typical of DGA domains.
///
/// # Arguments
/// * `s` - The domain string to analyze (should be lowercase)
/// * `ratio_threshold` - Maximum allowed consonant ratio (e.g., 0.8)
/// * `max_sequence_threshold` - Maximum allowed consecutive consonants (e.g., 4)
///
/// # Returns
/// `true` if the domain exceeds either threshold (suspicious)
pub fn is_consonant_suspicious(
    s: &str,
    ratio_threshold: f32,
    max_sequence_threshold: usize,
) -> bool {
    // Skip very short strings (not enough data to analyze)
    if s.len() < 4 {
        return false;
    }

    let ratio = calculate_consonant_ratio(s);
    if ratio > ratio_threshold {
        return true;
    }

    let max_seq = max_consonant_sequence(s);
    max_seq > max_sequence_threshold
}

/// Calculates the consonant ratio of a string.
///
/// Returns the ratio of consonants to total letters (0.0 to 1.0).
/// Non-letter characters (digits, hyphens, etc.) are ignored.
///
/// Normal English words have a consonant ratio around 0.6-0.7.
/// DGA domains often have ratios > 0.8 due to random character generation.
pub fn calculate_consonant_ratio(s: &str) -> f32 {
    let bytes = s.as_bytes();
    let mut consonants = 0u32;
    let mut letters = 0u32;

    for &b in bytes {
        if is_lowercase_letter(b) {
            letters += 1;
            if is_consonant(b) {
                consonants += 1;
            }
        }
    }

    if letters == 0 {
        return 0.0;
    }

    consonants as f32 / letters as f32
}

/// Calculates the Shannon Entropy of a string with full unicode support.
/// Higher values (typically > 3.5 to 4.5) indicate potential DGA.
pub fn calculate_entropy(s: &str) -> f32 {
    if s.is_empty() {
        return 0.0;
    }

    let mut frequencies = HashMap::with_capacity(36); // a-z + 0-9
    let len = s.len() as f32;

    // Count occurrences of each character
    for c in s.chars() {
        *frequencies.entry(c).or_insert(0) += 1;
    }

    // Shannon Formula: H = -sum(p_i * log2(p_i))
    let mut entropy = 0.0;
    for &count in frequencies.values() {
        let p = count as f32 / len;
        entropy -= p * p.log2();
    }

    entropy
}

/// Optimized version for OpenWrt (no HashMap allocation)
pub fn calculate_entropy_fast(s: &str) -> f32 {
    if s.is_empty() {
        return 0.0;
    }

    // Using a fixed-size array for ASCII chars to avoid Heap allocation
    let mut counts = [0u32; 256];
    let mut len = 0;

    for &byte in s.as_bytes() {
        counts[byte as usize] += 1;
        len += 1;
    }

    let mut entropy = 0.0;
    let len_f = len as f32;

    for &count in counts.iter() {
        if count > 0 {
            let p = count as f32 / len_f;
            entropy -= p * p.log2();
        }
    }

    entropy
}

// ---------------------------------------------------------------------------
// Low-entropy (repetitive / counter-padded) labels
// ---------------------------------------------------------------------------

/// Distinct-character ratio at or below which a label counts as repetitive.
/// A natural second-level domain of length L carries roughly L/3 distinct
/// characters or more, so 30% is already well outside normal.
const LOW_ENTROPY_DISTINCT_RATIO: f32 = 0.30;

/// Share of non-letter bytes (digits, hyphens) at or above which a repetitive
/// label counts as machine-padded. Legitimate SLDs are overwhelmingly `a-z`
/// with the occasional hyphen or digit.
const LOW_ENTROPY_NON_LETTER_RATIO: f32 = 0.50;

/// Length of a single-character run that no natural domain name reaches.
const LOW_ENTROPY_MAX_RUN: usize = 8;

/// Minimum length for the all-letter repetition rule. Below this, a label
/// built from a handful of letters is more likely a short generated slug than
/// a DGA seed.
const LOW_ENTROPY_ALPHA_MIN_LENGTH: usize = 16;

/// Maximum distinct letters for the all-letter repetition rule.
const LOW_ENTROPY_ALPHA_MAX_DISTINCT: usize = 4;

/// Length of the longest run of identical bytes in `s`.
///
/// Returns 0 for the empty string. Single pass, no allocation.
pub fn longest_run(s: &str) -> usize {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return 0;
    }

    let mut best = 1usize;
    let mut current = 1usize;
    for pair in bytes.windows(2) {
        if pair[0] == pair[1] {
            current += 1;
            if current > best {
                best = current;
            }
        } else {
            current = 1;
        }
    }

    best
}

/// Detects labels that are machine-generated through *too little* randomness.
///
/// [`calculate_entropy`] covers random-looking strings such as `a1b2c3d4e5f6`.
/// It is blind to the opposite shape — repetitive, digit-heavy or symbol-padded
/// noise such as `0000000000000000001`, `0-0-0-0-0-0-0-0`, `aaaaaaaaaaaaaaaa`
/// or `1234567890` — because a distribution skewed onto one character scores
/// *low*. Counter-padded and fixed-seed DGA families (Matsnu, Gozi, QakBot)
/// live in that blind spot.
///
/// A label is flagged when it is at least `min_length` bytes long and matches
/// one of:
///
/// 1. No letters at all (`1234567890`, `0-0-0-0-0-0-0-0`).
/// 2. A run of [`LOW_ENTROPY_MAX_RUN`] identical bytes or more
///    (`000000000shop`, `shop000000000`).
/// 3. Few distinct characters *and* mostly non-letters (`aaaa1111----`).
/// 4. A long all-letter label built from at most
///    [`LOW_ENTROPY_ALPHA_MAX_DISTINCT`] letters (`aaaabbbbccccdddd`).
///
/// Non-ASCII labels return `false`: the ratios below count bytes, which is
/// meaningless for multi-byte input. Those names are covered by the IDN
/// homograph check instead.
pub fn is_low_entropy_suspicious(label: &str, min_length: usize) -> bool {
    if label.len() < min_length || !label.is_ascii() {
        return false;
    }

    let mut seen = [false; 256];
    let mut distinct = 0usize;
    let mut letters = 0usize;

    for &byte in label.as_bytes() {
        if !seen[byte as usize] {
            seen[byte as usize] = true;
            distinct += 1;
        }
        if byte.is_ascii_alphabetic() {
            letters += 1;
        }
    }

    // 1. Pure non-letter label. Real SLDs carry letters.
    if letters == 0 {
        return true;
    }

    // 2. Long monotonic run — the signature of counter padding.
    if longest_run(label) >= LOW_ENTROPY_MAX_RUN {
        return true;
    }

    let length = label.len();
    if distinct as f32 / length as f32 > LOW_ENTROPY_DISTINCT_RATIO {
        return false;
    }

    // 3. Repetition plus digit/symbol domination.
    if (length - letters) as f32 / length as f32 >= LOW_ENTROPY_NON_LETTER_RATIO {
        return true;
    }

    // 4. Long all-letter label drawn from a handful of characters.
    letters == length
        && distinct <= LOW_ENTROPY_ALPHA_MAX_DISTINCT
        && length >= LOW_ENTROPY_ALPHA_MIN_LENGTH
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_empty_string_returns_zero() {
        assert_eq!(calculate_entropy(""), 0.0);
    }

    #[test]
    fn entropy_single_char_returns_zero() {
        assert_eq!(calculate_entropy("a"), 0.0);
    }

    #[test]
    fn entropy_repeated_char_returns_zero() {
        assert_eq!(calculate_entropy("aaaa"), 0.0);
    }

    #[test]
    fn entropy_two_chars_equal_distribution() {
        let e = calculate_entropy("ab");
        assert!((e - 1.0).abs() < 0.01);
    }

    #[test]
    fn entropy_increases_with_randomness() {
        let e1 = calculate_entropy("aabb");
        let e2 = calculate_entropy("abcd");
        assert!(e2 > e1);
    }

    #[test]
    fn entropy_normal_domain_below_threshold() {
        let e = calculate_entropy("google");
        assert!(e < 3.0, "google entropy: {}", e);

        let e = calculate_entropy("facebook");
        assert!(e < 3.5, "facebook entropy: {}", e);

        let e = calculate_entropy("example");
        assert!(e < 3.0, "example entropy: {}", e);
    }

    #[test]
    fn entropy_dga_domain_above_threshold() {
        let e = calculate_entropy("a1b2c3d4e5f6g7h8");
        assert!(e >= 4.0, "DGA-like entropy: {}", e);

        let e = calculate_entropy("a1b2c3d4e5f6g7h8i9j0k");
        assert!(e > 4.0, "random chars entropy: {}", e);
    }

    #[test]
    fn entropy_fast_empty_string_returns_zero() {
        assert_eq!(calculate_entropy_fast(""), 0.0);
    }

    #[test]
    fn entropy_fast_normal_domain_below_threshold() {
        let e = calculate_entropy_fast("google");
        assert!(e < 3.0, "google entropy: {}", e);
    }

    #[test]
    fn entropy_fast_dga_domain_above_threshold() {
        let e = calculate_entropy_fast("a1b2c3d4e5f6g7h8");
        assert!(e >= 4.0, "DGA-like entropy: {}", e);
    }

    #[test]
    fn is_consonant_suspicious_normal_domains_pass() {
        let normal_domains = ["google", "facebook", "amazon", "example", "cloudflare"];
        for domain in normal_domains {
            assert!(
                !is_consonant_suspicious(domain, 0.8, 4),
                "{} should not be suspicious",
                domain
            );
        }
    }

    #[test]
    fn is_consonant_suspicious_dga_domains_flagged() {
        let dga_domains = ["xvbrtzk", "bcdfghjk", "qwrtplkm"];
        for domain in dga_domains {
            assert!(
                is_consonant_suspicious(domain, 0.8, 4),
                "{} should be suspicious",
                domain
            );
        }
    }

    // -----------------------------------------------------------------------
    // Low-entropy detection (repetitive / counter-padded DGA families)
    // -----------------------------------------------------------------------

    /// The default `low_entropy_min_length`.
    const MIN: usize = 8;

    #[test]
    fn longest_run_counts_identical_bytes() {
        assert_eq!(longest_run(""), 0);
        assert_eq!(longest_run("a"), 1);
        assert_eq!(longest_run("abc"), 1);
        assert_eq!(longest_run("aabbbcc"), 3);
        assert_eq!(longest_run("000000000shop"), 9);
        assert_eq!(longest_run("shop000000000"), 9);
    }

    #[test]
    fn low_entropy_skips_labels_below_min_length() {
        assert!(!is_low_entropy_suspicious("", MIN));
        assert!(!is_low_entropy_suspicious("aaaa", MIN));
        assert!(!is_low_entropy_suspicious("0000", MIN));
        assert!(!is_low_entropy_suspicious("1234567", MIN));
    }

    #[test]
    fn low_entropy_flags_pure_non_letter_labels() {
        assert!(is_low_entropy_suspicious("0000000000000000001", MIN));
        assert!(is_low_entropy_suspicious("00000000000", MIN));
        assert!(is_low_entropy_suspicious("11111111111111", MIN));
        assert!(is_low_entropy_suspicious("1234567890", MIN));
        // The `0-0-0-0-…` and all-zero-UUID shapes seen in real traffic.
        assert!(is_low_entropy_suspicious(
            "0-0-0-0-0-0-0-0-0-0-0-0-0-10-0-0-0-0-0-0-0-0-0-0-0-0-0",
            MIN
        ));
        assert!(is_low_entropy_suspicious(
            "00000000-0000-0000-0000-000000000000",
            MIN
        ));
    }

    #[test]
    fn low_entropy_flags_long_single_character_runs() {
        // Counter padding on either side of a seed word.
        assert!(is_low_entropy_suspicious("000000000shop", MIN));
        assert!(is_low_entropy_suspicious("shop000000000", MIN));
        assert!(is_low_entropy_suspicious("aaaaaaaaaaaaaaaa", MIN));
    }

    #[test]
    fn low_entropy_flags_repetition_with_symbol_domination() {
        assert!(is_low_entropy_suspicious("aaaa1111----", MIN));
    }

    #[test]
    fn low_entropy_flags_long_all_letter_repetition() {
        assert!(is_low_entropy_suspicious("aaaabbbbccccdddd", MIN));
    }

    #[test]
    fn low_entropy_allows_short_all_letter_repetition() {
        // Below the 16-byte rule: could be a generated short slug.
        assert!(!is_low_entropy_suspicious("aaaabbbb", MIN));
        assert!(!is_low_entropy_suspicious("aabbccdd", MIN));
    }

    #[test]
    fn low_entropy_allows_normal_second_level_domains() {
        let legitimate = [
            "cloudflare",
            "microsoft",
            "wikipedia",
            "appsflyersdk",
            "wixstudio",
            "e-commerce-shop",
            "my-site-2024",
        ];
        for label in legitimate {
            assert!(
                !is_low_entropy_suspicious(label, MIN),
                "{} must not be flagged",
                label
            );
        }
    }

    #[test]
    fn low_entropy_leaves_high_entropy_labels_to_the_shannon_check() {
        // Diverse character sets are the other detector's job; flagging them
        // here would double-count the same domain.
        for label in ["a1b2c3d4e5", "abcd1234ef", "x9y8z7w6v5", "xvbrtzqk"] {
            assert!(
                !is_low_entropy_suspicious(label, MIN),
                "{} must not be flagged",
                label
            );
        }
    }

    #[test]
    fn low_entropy_ignores_non_ascii_labels() {
        // Byte ratios are meaningless on multi-byte input; the IDN check owns
        // these names.
        assert!(!is_low_entropy_suspicious("ééééééééééééééééé", MIN));
    }

    #[test]
    fn low_entropy_min_length_is_honoured() {
        assert!(!is_low_entropy_suspicious("12345678", 9));
        assert!(is_low_entropy_suspicious("12345678", 8));
    }
}
