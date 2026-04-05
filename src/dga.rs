use std::collections::HashMap;

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
}
