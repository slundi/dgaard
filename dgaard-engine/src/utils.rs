/// Count the number of dots in a domain name.
/// This gives the subdomain depth (e.g., "example.com" → 1, "sub.example.com" → 2).
pub fn count_dots(domain: &str) -> u8 {
    domain.bytes().filter(|&b| b == b'.').count() as u8
}

/// Canonical form of a list entry: ASCII-lowercased, without trailing root dot.
/// Queries reach the matcher lowercased and dotless, so entries must match.
pub fn normalize_domain(domain: &str) -> String {
    domain.trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_count_dots() {
        assert_eq!(count_dots("tld"), 0);
        assert_eq!(count_dots("example.org"), 1);
        assert_eq!(count_dots("with.sub.domains.end"), 3);
    }

    #[test]
    fn test_normalize_domain() {
        assert_eq!(normalize_domain("Tracker.COM"), "tracker.com");
        assert_eq!(normalize_domain("example.com."), "example.com");
        assert_eq!(normalize_domain("already.ok"), "already.ok");
    }
}
