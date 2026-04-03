pub fn count_dots(domain: &str) -> u8 {
    domain.bytes().filter(|&b| b == b'.').count() as u8
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
}
