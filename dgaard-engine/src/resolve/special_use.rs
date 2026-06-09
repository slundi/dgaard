//! RFC 6761 special-use domain isolation.
//!
//! Checks whether a domain's TLD belongs to the set of names that must never
//! be forwarded to a public upstream resolver. These are either formally
//! reserved (RFC 6761, RFC 6762) or de-facto internal conventions.

use crate::config::Config;

/// Built-in TLDs that must never be forwarded to a public upstream resolver.
///
/// | TLD         | Spec      | Reason                                       |
/// |-------------|-----------|----------------------------------------------|
/// | `local`     | RFC 6762  | mDNS / Bonjour — multicast, not unicast DNS  |
/// | `localhost` | RFC 6761  | Loopback alias — always 127.0.0.1 / ::1      |
/// | `invalid`   | RFC 6761  | Guaranteed non-resolvable by design          |
/// | `test`      | RFC 6761  | Reserved for testing; no delegation exists   |
/// | `example`   | RFC 2606  | Reserved for documentation                   |
const BUILTIN_SPECIAL_USE_TLDS: &[&str] = &["local", "localhost", "invalid", "test", "example"];

/// Return `true` if `domain` has a TLD that must not be forwarded upstream.
///
/// Runs in O(k) time where k is the number of extra TLDs configured (the
/// built-in set is a fixed-size slice comparison). No heap allocation.
pub fn is_special_use_domain(domain: &str, config: &Config) -> bool {
    if !config.security.special_use.enabled {
        return false;
    }

    let tld = match domain.rsplit('.').next() {
        Some(t) if !t.is_empty() => t,
        _ => return false,
    };

    // Stack-allocate a lowercase copy — TLDs are short (≤ 63 bytes per RFC 1035).
    let mut buf = [0u8; 64];
    if tld.len() > buf.len() {
        return false;
    }
    let tld_lower = {
        let bytes = tld.as_bytes();
        buf[..bytes.len()].copy_from_slice(bytes);
        buf[..bytes.len()].make_ascii_lowercase();
        std::str::from_utf8(&buf[..bytes.len()]).unwrap_or(tld)
    };

    if BUILTIN_SPECIAL_USE_TLDS.contains(&tld_lower) {
        return true;
    }

    for extra in &config.security.special_use.extra_local_tlds {
        let extra_clean = extra.strip_prefix('.').unwrap_or(extra);
        if extra_clean.eq_ignore_ascii_case(tld_lower) {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn config_enabled() -> Config {
        Config::default() // special_use.enabled = true, no extras
    }

    fn config_disabled() -> Config {
        let mut c = Config::default();
        c.security.special_use.enabled = false;
        c
    }

    fn config_with_extras(extras: &[&str]) -> Config {
        let mut c = Config::default();
        c.security.special_use.extra_local_tlds = extras.iter().map(|s| s.to_string()).collect();
        c
    }

    // --- built-in RFC 6761 / RFC 6762 TLDs ---

    #[test]
    fn blocks_local() {
        assert!(is_special_use_domain("printer.local", &config_enabled()));
        assert!(is_special_use_domain("my-nas.local", &config_enabled()));
    }

    #[test]
    fn blocks_localhost() {
        assert!(is_special_use_domain("localhost", &config_enabled()));
        assert!(is_special_use_domain("db.localhost", &config_enabled()));
    }

    #[test]
    fn blocks_invalid() {
        assert!(is_special_use_domain("anything.invalid", &config_enabled()));
    }

    #[test]
    fn blocks_test() {
        assert!(is_special_use_domain("api.test", &config_enabled()));
        assert!(is_special_use_domain(
            "service.staging.test",
            &config_enabled()
        ));
    }

    #[test]
    fn blocks_example() {
        assert!(is_special_use_domain("www.example", &config_enabled()));
        assert!(is_special_use_domain("deep.sub.example", &config_enabled()));
    }

    // --- case insensitivity ---

    #[test]
    fn case_insensitive_tld_matching() {
        assert!(is_special_use_domain("printer.LOCAL", &config_enabled()));
        assert!(is_special_use_domain("host.Localhost", &config_enabled()));
        assert!(is_special_use_domain("x.INVALID", &config_enabled()));
    }

    // --- public TLDs must not be blocked ---

    #[test]
    fn does_not_block_public_tlds() {
        let c = config_enabled();
        assert!(!is_special_use_domain("example.com", &c));
        assert!(!is_special_use_domain("google.com", &c));
        assert!(!is_special_use_domain("sub.example.org", &c));
        assert!(!is_special_use_domain("api.internal.co.uk", &c));
    }

    // --- disabled config ---

    #[test]
    fn does_nothing_when_disabled() {
        assert!(!is_special_use_domain("printer.local", &config_disabled()));
        assert!(!is_special_use_domain("host.localhost", &config_disabled()));
        assert!(!is_special_use_domain("x.corp", &config_disabled()));
    }

    // --- extra TLDs ---

    #[test]
    fn blocks_extra_tld_with_dot_prefix() {
        let c = config_with_extras(&[".corp", ".lan"]);
        assert!(is_special_use_domain("dc1.corp", &c));
        assert!(is_special_use_domain("router.lan", &c));
    }

    #[test]
    fn blocks_extra_tld_without_dot_prefix() {
        let c = config_with_extras(&["internal", "home"]);
        assert!(is_special_use_domain("server.internal", &c));
        assert!(is_special_use_domain("nas.home", &c));
    }

    #[test]
    fn extra_tld_matching_is_case_insensitive() {
        let c = config_with_extras(&[".CORP"]);
        assert!(is_special_use_domain("dc1.corp", &c));
        assert!(is_special_use_domain("dc1.CORP", &c));
    }

    #[test]
    fn extra_tld_does_not_block_partial_match() {
        let c = config_with_extras(&[".corp"]);
        // "corporation.com" TLD is "com", not "corp"
        assert!(!is_special_use_domain("my.corporation.com", &c));
    }

    // --- edge cases ---

    #[test]
    fn empty_domain_does_not_panic() {
        assert!(!is_special_use_domain("", &config_enabled()));
    }

    #[test]
    fn single_label_local_is_blocked() {
        assert!(is_special_use_domain("local", &config_enabled()));
    }

    #[test]
    fn tld_longer_than_64_bytes_is_not_blocked() {
        let long_tld = "a".repeat(65);
        let domain = format!("host.{}", long_tld);
        assert!(!is_special_use_domain(&domain, &config_enabled()));
    }
}
