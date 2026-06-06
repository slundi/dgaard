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
}
