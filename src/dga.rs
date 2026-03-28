use std::collections::HashMap;

/// Calculates the Shannon Entropy of a string.
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
