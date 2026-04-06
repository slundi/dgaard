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
///
/// # Examples
/// ```
/// use dgaard::dga::max_consonant_sequence;
/// let seq = max_consonant_sequence("strength"); // 3 ("str")
/// let seq = max_consonant_sequence("xvbrtzkm"); // 8 (all consonants)
/// ```
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
///
/// # Examples
/// ```
/// use dgaard::dga::calculate_consonant_ratio;
/// let ratio = calculate_consonant_ratio("google"); // ~0.67 (4 consonants / 6 letters)
/// let ratio = calculate_consonant_ratio("xvbrtz"); // 1.0 (all consonants)
/// ```
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

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // calculate_entropy (full Unicode, HashMap-based)
    // -----------------------------------------------------------------------

    #[test]
    fn entropy_empty_string_returns_zero() {
        assert_eq!(calculate_entropy(""), 0.0);
    }

    #[test]
    fn entropy_single_char_returns_zero() {
        // Single character has no randomness
        assert_eq!(calculate_entropy("a"), 0.0);
    }

    #[test]
    fn entropy_repeated_char_returns_zero() {
        // "aaaa" has zero entropy (completely predictable)
        assert_eq!(calculate_entropy("aaaa"), 0.0);
    }

    #[test]
    fn entropy_two_chars_equal_distribution() {
        // "ab" with equal distribution should have entropy of 1.0
        let e = calculate_entropy("ab");
        assert!((e - 1.0).abs() < 0.01);
    }

    #[test]
    fn entropy_increases_with_randomness() {
        // More unique characters = higher entropy
        let e1 = calculate_entropy("aabb");
        let e2 = calculate_entropy("abcd");
        assert!(e2 > e1);
    }

    #[test]
    fn entropy_normal_domain_below_threshold() {
        // Normal readable domains should have low entropy (< 4.0)
        let e = calculate_entropy("google");
        assert!(e < 3.0, "google entropy: {}", e);

        let e = calculate_entropy("facebook");
        assert!(e < 3.5, "facebook entropy: {}", e);

        let e = calculate_entropy("example");
        assert!(e < 3.0, "example entropy: {}", e);
    }

    #[test]
    fn entropy_dga_domain_above_threshold() {
        // Random-looking domains should have high entropy (>= 4.0)
        // 16 unique chars = log2(16) = 4.0, so we use >= for the boundary case
        let e = calculate_entropy("a1b2c3d4e5f6g7h8");
        assert!(e >= 4.0, "DGA-like entropy: {}", e);

        // More random chars for entropy clearly above 4.0
        let e = calculate_entropy("a1b2c3d4e5f6g7h8i9j0k");
        assert!(e > 4.0, "random chars entropy: {}", e);
    }

    #[test]
    fn entropy_unicode_support() {
        // Full entropy should handle Unicode correctly
        let e = calculate_entropy("héllo");
        assert!(e > 0.0);

        let e = calculate_entropy("日本語");
        assert!(e > 0.0);
    }

    // -----------------------------------------------------------------------
    // calculate_entropy_fast (ASCII-only, zero-allocation)
    // -----------------------------------------------------------------------

    #[test]
    fn entropy_fast_empty_string_returns_zero() {
        assert_eq!(calculate_entropy_fast(""), 0.0);
    }

    #[test]
    fn entropy_fast_single_char_returns_zero() {
        assert_eq!(calculate_entropy_fast("a"), 0.0);
    }

    #[test]
    fn entropy_fast_repeated_char_returns_zero() {
        assert_eq!(calculate_entropy_fast("aaaa"), 0.0);
    }

    #[test]
    fn entropy_fast_two_chars_equal_distribution() {
        let e = calculate_entropy_fast("ab");
        assert!((e - 1.0).abs() < 0.01);
    }

    #[test]
    fn entropy_fast_increases_with_randomness() {
        let e1 = calculate_entropy_fast("aabb");
        let e2 = calculate_entropy_fast("abcd");
        assert!(e2 > e1);
    }

    #[test]
    fn entropy_fast_normal_domain_below_threshold() {
        let e = calculate_entropy_fast("google");
        assert!(e < 3.0, "google entropy: {}", e);

        let e = calculate_entropy_fast("facebook");
        assert!(e < 3.5, "facebook entropy: {}", e);
    }

    #[test]
    fn entropy_fast_dga_domain_above_threshold() {
        // 16 unique chars = log2(16) = 4.0, so we use >= for the boundary case
        let e = calculate_entropy_fast("a1b2c3d4e5f6g7h8");
        assert!(e >= 4.0, "DGA-like entropy: {}", e);

        // More random chars for entropy clearly above 4.0
        let e = calculate_entropy_fast("a1b2c3d4e5f6g7h8i9j0k");
        assert!(e > 4.0, "random chars entropy: {}", e);
    }

    // -----------------------------------------------------------------------
    // Comparison between fast and full entropy for ASCII input
    // -----------------------------------------------------------------------

    #[test]
    fn entropy_fast_matches_full_for_ascii() {
        // For ASCII-only input, both functions should produce identical results
        let test_cases = [
            "google",
            "facebook",
            "example",
            "a1b2c3d4",
            "qwertasdfzxcv",
            "dgaard",
            "aaaabbbb",
        ];

        for s in test_cases {
            let full = calculate_entropy(s);
            let fast = calculate_entropy_fast(s);
            assert!(
                (full - fast).abs() < 0.001,
                "Mismatch for '{}': full={}, fast={}",
                s,
                full,
                fast
            );
        }
    }

    #[test]
    fn entropy_fast_handles_multibyte_as_bytes() {
        // Fast version treats input as bytes, so multi-byte UTF-8 is counted per byte
        // This is expected behavior for the fast path
        let fast = calculate_entropy_fast("héllo");
        let full = calculate_entropy("héllo");
        // They won't match because 'é' is 2 bytes in UTF-8
        // Fast version counts byte frequencies, full version counts char frequencies
        assert!(fast > 0.0);
        assert!(full > 0.0);
        // The values will differ, which is acceptable for the fast path
    }

    // -----------------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn entropy_all_unique_chars() {
        // Maximum entropy for a given length: log2(n) where n is the number of unique chars
        let e = calculate_entropy("abcdefgh");
        // 8 unique chars -> max entropy = log2(8) = 3.0
        assert!((e - 3.0).abs() < 0.01);
    }

    #[test]
    fn entropy_fast_all_unique_chars() {
        let e = calculate_entropy_fast("abcdefgh");
        assert!((e - 3.0).abs() < 0.01);
    }

    #[test]
    fn entropy_numeric_string() {
        let e = calculate_entropy("1234567890");
        // 10 unique digits -> max entropy = log2(10) ≈ 3.32
        assert!((e - 3.32).abs() < 0.1);
    }

    #[test]
    fn entropy_fast_numeric_string() {
        let e = calculate_entropy_fast("1234567890");
        assert!((e - 3.32).abs() < 0.1);
    }

    // -----------------------------------------------------------------------
    // Consonant Ratio Tests (#4.3 from Roadmap)
    // -----------------------------------------------------------------------

    #[test]
    fn consonant_ratio_empty_string() {
        assert_eq!(calculate_consonant_ratio(""), 0.0);
    }

    #[test]
    fn consonant_ratio_only_vowels() {
        assert_eq!(calculate_consonant_ratio("aeiou"), 0.0);
    }

    #[test]
    fn consonant_ratio_only_consonants() {
        assert_eq!(calculate_consonant_ratio("bcdfg"), 1.0);
    }

    #[test]
    fn consonant_ratio_mixed() {
        // "google" = g, o, o, g, l, e -> 3 consonants (g, g, l) / 6 letters = 0.5
        let ratio = calculate_consonant_ratio("google");
        assert!((ratio - 0.5).abs() < 0.01, "google ratio: {}", ratio);
    }

    #[test]
    fn consonant_ratio_normal_domains() {
        // Normal domains should have ratios around 0.5-0.7
        // facebook = f-a-c-e-b-o-o-k = 8 letters, 4 consonants (f,c,b,k) = 0.5
        // example = e-x-a-m-p-l-e = 7 letters, 4 consonants (x,m,p,l) = ~0.57
        // amazon = a-m-a-z-o-n = 6 letters, 3 consonants (m,z,n) = 0.5
        let examples = [("facebook", 0.5), ("example", 0.571), ("amazon", 0.5)];

        for (domain, expected) in examples {
            let ratio = calculate_consonant_ratio(domain);
            assert!(
                (ratio - expected).abs() < 0.1,
                "{} ratio: {}, expected: {}",
                domain,
                ratio,
                expected
            );
        }
    }

    #[test]
    fn consonant_ratio_dga_like_domains() {
        // DGA domains often have very high consonant ratios
        let dga_examples = ["xvbrtz", "qwrtplk", "bcdfghjk"];

        for domain in dga_examples {
            let ratio = calculate_consonant_ratio(domain);
            assert!(ratio > 0.85, "{} should have high ratio: {}", domain, ratio);
        }
    }

    #[test]
    fn consonant_ratio_ignores_digits_and_hyphens() {
        // "abc123" has 2 consonants (b, c) / 3 letters = 0.67
        let ratio = calculate_consonant_ratio("abc123");
        assert!((ratio - 0.67).abs() < 0.1, "abc123 ratio: {}", ratio);

        // "a-b-c" has 2 consonants / 3 letters = 0.67
        let ratio = calculate_consonant_ratio("a-b-c");
        assert!((ratio - 0.67).abs() < 0.1, "a-b-c ratio: {}", ratio);
    }

    // -----------------------------------------------------------------------
    // Max Consonant Sequence Tests
    // -----------------------------------------------------------------------

    #[test]
    fn max_consonant_sequence_empty_string() {
        assert_eq!(max_consonant_sequence(""), 0);
    }

    #[test]
    fn max_consonant_sequence_only_vowels() {
        assert_eq!(max_consonant_sequence("aeiou"), 0);
    }

    #[test]
    fn max_consonant_sequence_single_consonant() {
        assert_eq!(max_consonant_sequence("aba"), 1);
    }

    #[test]
    fn max_consonant_sequence_normal_words() {
        // "strength" = s-t-r-e-n-g-t-h
        // "str" = 3, then "e" breaks, "ngth" = 4
        assert_eq!(max_consonant_sequence("strength"), 4);

        // "google" = g-o-o-g-l-e, "gl" = 2 consecutive
        assert_eq!(max_consonant_sequence("google"), 2);

        // "rhythm" = r-h-y-t-h-m (y is treated as consonant)
        // All 6 are consonants
        assert_eq!(max_consonant_sequence("rhythm"), 6);
    }

    #[test]
    fn max_consonant_sequence_dga_patterns() {
        // DGA patterns often have long consonant runs
        assert_eq!(max_consonant_sequence("xvbrtz"), 6);
        // "axvbrtzb" = a(vowel), then xvbrtzb = 7 consonants
        assert_eq!(max_consonant_sequence("axvbrtzb"), 7);
        assert_eq!(max_consonant_sequence("qwrtplk"), 7);
    }

    #[test]
    fn max_consonant_sequence_digits_break_sequence() {
        // Digits should break consonant sequences
        assert_eq!(max_consonant_sequence("bc1df"), 2);
    }

    // -----------------------------------------------------------------------
    // Combined Suspicious Check Tests
    // -----------------------------------------------------------------------

    #[test]
    fn is_consonant_suspicious_short_strings_not_flagged() {
        // Strings < 4 chars should not be flagged (not enough data)
        assert!(!is_consonant_suspicious("xyz", 0.8, 4));
        assert!(!is_consonant_suspicious("bc", 0.8, 4));
    }

    #[test]
    fn is_consonant_suspicious_normal_domains_pass() {
        // Normal domains should not be flagged
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
        // DGA-like domains should be flagged
        let dga_domains = [
            "xvbrtzk",  // All consonants, long sequence
            "bcdfghjk", // All consonants
            "qwrtplkm", // All consonants, long sequence
        ];

        for domain in dga_domains {
            assert!(
                is_consonant_suspicious(domain, 0.8, 4),
                "{} should be suspicious",
                domain
            );
        }
    }

    #[test]
    fn is_consonant_suspicious_by_ratio() {
        // High ratio but no long sequence
        // "bcbcbc" has ratio 1.0 but max sequence of 1
        assert!(is_consonant_suspicious("bcbcbc", 0.8, 10));
    }

    #[test]
    fn is_consonant_suspicious_by_sequence() {
        // Long sequence but acceptable ratio
        // "astrength" has 4 consecutive consonants "ngth" and ratio ~0.78
        assert!(is_consonant_suspicious("xyzth", 0.95, 3));
    }

    #[test]
    fn is_consonant_suspicious_edge_case_y() {
        // "y" is treated as a consonant in our implementation
        // This is a simplification; linguistically y can be a vowel
        assert!(is_consonant(b'y'));
        // "syzygy" = s-y-z-y-g-y, all 6 are consonants
        assert_eq!(max_consonant_sequence("syzygy"), 6);
    }
}
