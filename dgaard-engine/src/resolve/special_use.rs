//! RFC 6761 special-use domain isolation.
//!
//! Checks whether a domain's TLD, or a reserved multi-label suffix such as
//! `home.arpa`, belongs to the set of names that must never be forwarded to
//! a public upstream resolver. These are either formally reserved (RFC 6761,
//! RFC 6762, RFC 8375) or de-facto internal conventions.

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
///
/// `local` can be released with `security.special_use.isolate_local =
/// false`, for networks whose unicast DNS serves a `.local` zone (Active
/// Directory domains often do).
const BUILTIN_SPECIAL_USE_TLDS: &[&str] = &["local", "localhost", "invalid", "test", "example"];

/// mDNS TLD, the one built-in entry `isolate_local` can release.
const MDNS_TLD: &str = "local";

/// Built-in multi-label suffixes that must never be forwarded upstream.
///
/// | Suffix      | Spec      | Reason                                       |
/// |-------------|-----------|----------------------------------------------|
/// | `home.arpa` | RFC 8375  | Home-network names, resolved locally only    |
const BUILTIN_SPECIAL_USE_SUFFIXES: &[&str] = &["home.arpa"];

/// `true` when `domain` is `suffix` or a name below it.
fn is_at_or_below(domain: &str, suffix: &str) -> bool {
    domain
        .strip_suffix(suffix)
        .is_some_and(|rest| rest.is_empty() || rest.ends_with('.'))
}

/// Return `true` if `domain` has a TLD that must not be forwarded upstream.
///
/// Runs in O(k) time where k is the number of extra TLDs configured (the
/// built-in set is a fixed-size slice comparison). No heap allocation.
pub fn is_special_use_domain(domain: &str, config: &Config) -> bool {
    let domain = super::normalize_domain(domain);
    let domain = domain.as_ref();
    let special_use = &config.security.special_use;
    if !special_use.enabled {
        return false;
    }

    if BUILTIN_SPECIAL_USE_SUFFIXES
        .iter()
        .any(|suffix| is_at_or_below(domain, suffix))
    {
        return true;
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

    // `isolate_local = false` releases only the built-in `local` entry; an
    // explicit `extra_local_tlds` entry still applies below.
    let released = tld_lower == MDNS_TLD && !special_use.isolate_local;
    if !released && BUILTIN_SPECIAL_USE_TLDS.contains(&tld_lower) {
        return true;
    }

    // Extra TLDs are validated lowercase & dotless at parse time; the
    // case-insensitive compare tolerates programmatically-built configs.
    for extra in &special_use.extra_local_tlds {
        if extra.eq_ignore_ascii_case(tld_lower) {
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

    // --- RFC 8375 home.arpa (review F16) ---

    #[test]
    fn blocks_home_arpa_and_names_below_it() {
        let c = config_enabled();
        assert!(is_special_use_domain("home.arpa", &c));
        assert!(is_special_use_domain("nas.home.arpa", &c));
        assert!(is_special_use_domain("printer.office.home.arpa", &c));
        assert!(is_special_use_domain("NAS.Home.Arpa.", &c));
    }

    #[test]
    fn home_arpa_match_respects_label_boundaries() {
        let c = config_enabled();
        // Other .arpa names (reverse DNS) are not special-use.
        assert!(!is_special_use_domain("1.168.192.in-addr.arpa", &c));
        assert!(!is_special_use_domain("myhome.arpa", &c));
        assert!(!is_special_use_domain("arpa", &c));
        assert!(!is_special_use_domain("home.arpa.example.com", &c));
    }

    #[test]
    fn home_arpa_follows_the_master_switch() {
        assert!(!is_special_use_domain("nas.home.arpa", &config_disabled()));
    }

    // --- .local opt-out (review F16) ---

    #[test]
    fn isolate_local_false_forwards_local_only() {
        let mut c = config_enabled();
        c.security.special_use.isolate_local = false;
        assert!(!is_special_use_domain("dc01.corp.local", &c));
        assert!(!is_special_use_domain("local", &c));
        // Every other special-use name stays isolated.
        assert!(is_special_use_domain("db.localhost", &c));
        assert!(is_special_use_domain("nas.home.arpa", &c));
        assert!(is_special_use_domain("x.invalid", &c));
    }

    #[test]
    fn isolate_local_false_still_honours_an_explicit_extra_tld() {
        // Listing `local` among the extras isolates it again.
        let mut c = config_with_extras(&["local"]);
        c.security.special_use.isolate_local = false;
        assert!(is_special_use_domain("printer.local", &c));
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

    // Extra TLDs reach this function already normalized (dotless) by the
    // config parser, so the tests configure them in canonical dotless form.

    #[test]
    fn blocks_configured_extra_tld() {
        let c = config_with_extras(&["corp", "lan"]);
        assert!(is_special_use_domain("dc1.corp", &c));
        assert!(is_special_use_domain("router.lan", &c));
    }

    #[test]
    fn extra_tld_matching_is_case_insensitive() {
        let c = config_with_extras(&["CORP"]);
        assert!(is_special_use_domain("dc1.corp", &c));
        assert!(is_special_use_domain("dc1.CORP", &c));
    }

    #[test]
    fn extra_tld_does_not_block_partial_match() {
        let c = config_with_extras(&["corp"]);
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
