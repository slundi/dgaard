//! Domain-structure helpers.
//!
//! The DGA heuristics work on the *registrable* label of a name — the one a
//! customer actually bought. Taking the second-to-last label gets that wrong
//! for every country-code registry that sells under a two-label suffix: the
//! registrable label of `news.bbc.co.uk` is `bbc`, not `co`.

use std::cmp::Ordering;

/// Two-label public suffixes, sorted for [`slice::binary_search_by`].
///
/// A *curated subset* of the Public Suffix List, not the whole thing. The full
/// list is ~10k entries and would have to be shipped as a file or compiled in,
/// neither of which fits a binary that targets OpenWrt; these cover the
/// country-code registries that show up in real resolver traffic. Everything
/// outside the list falls back to the last-two-labels rule, which is correct
/// for every single-label TLD (`.com`, `.dev`, `.fr`, …).
///
/// Invariants, enforced by `public_suffix_table_is_sorted_and_unique`: both
/// halves lowercase, non-empty, dot-free, and the table strictly increasing.
pub const PUBLIC_SUFFIX_2LABEL: &[(&str, &str)] = &[
    ("ac", "ae"),
    ("ac", "at"),
    ("ac", "bd"),
    ("ac", "cn"),
    ("ac", "cr"),
    ("ac", "cy"),
    ("ac", "id"),
    ("ac", "il"),
    ("ac", "in"),
    ("ac", "jp"),
    ("ac", "ke"),
    ("ac", "kr"),
    ("ac", "lk"),
    ("ac", "ma"),
    ("ac", "mw"),
    ("ac", "nz"),
    ("ac", "pa"),
    ("ac", "ru"),
    ("ac", "sz"),
    ("ac", "th"),
    ("ac", "tz"),
    ("ac", "ug"),
    ("ac", "uk"),
    ("ac", "za"),
    ("ac", "zm"),
    ("ac", "zw"),
    ("ad", "jp"),
    ("asn", "au"),
    ("biz", "pl"),
    ("biz", "tr"),
    ("chiba", "jp"),
    ("co", "ae"),
    ("co", "ag"),
    ("co", "at"),
    ("co", "bw"),
    ("co", "com"),
    ("co", "cr"),
    ("co", "id"),
    ("co", "il"),
    ("co", "in"),
    ("co", "jp"),
    ("co", "ke"),
    ("co", "kr"),
    ("co", "lc"),
    ("co", "ls"),
    ("co", "ma"),
    ("co", "mw"),
    ("co", "nz"),
    ("co", "sz"),
    ("co", "th"),
    ("co", "tt"),
    ("co", "tz"),
    ("co", "ua"),
    ("co", "ug"),
    ("co", "uk"),
    ("co", "vi"),
    ("co", "za"),
    ("co", "zm"),
    ("co", "zw"),
    ("com", "ag"),
    ("com", "ar"),
    ("com", "au"),
    ("com", "bb"),
    ("com", "bd"),
    ("com", "bo"),
    ("com", "br"),
    ("com", "bs"),
    ("com", "bz"),
    ("com", "cn"),
    ("com", "co"),
    ("com", "cu"),
    ("com", "cv"),
    ("com", "cy"),
    ("com", "dm"),
    ("com", "do"),
    ("com", "ec"),
    ("com", "eg"),
    ("com", "es"),
    ("com", "gd"),
    ("com", "gr"),
    ("com", "gt"),
    ("com", "hk"),
    ("com", "hn"),
    ("com", "hr"),
    ("com", "ht"),
    ("com", "jm"),
    ("com", "jo"),
    ("com", "kn"),
    ("com", "kw"),
    ("com", "ky"),
    ("com", "lb"),
    ("com", "lc"),
    ("com", "lk"),
    ("com", "mx"),
    ("com", "my"),
    ("com", "ng"),
    ("com", "ni"),
    ("com", "np"),
    ("com", "pa"),
    ("com", "pe"),
    ("com", "ph"),
    ("com", "pk"),
    ("com", "pl"),
    ("com", "pr"),
    ("com", "pt"),
    ("com", "py"),
    ("com", "qa"),
    ("com", "ru"),
    ("com", "sa"),
    ("com", "sg"),
    ("com", "sv"),
    ("com", "tr"),
    ("com", "tt"),
    ("com", "tw"),
    ("com", "ua"),
    ("com", "uy"),
    ("com", "vc"),
    ("com", "ve"),
    ("com", "vg"),
    ("com", "vi"),
    ("com", "vn"),
    ("ed", "cr"),
    ("ed", "jp"),
    ("edu", "ar"),
    ("edu", "au"),
    ("edu", "bb"),
    ("edu", "bd"),
    ("edu", "bo"),
    ("edu", "br"),
    ("edu", "bs"),
    ("edu", "bz"),
    ("edu", "cn"),
    ("edu", "co"),
    ("edu", "cu"),
    ("edu", "dm"),
    ("edu", "do"),
    ("edu", "ec"),
    ("edu", "eg"),
    ("edu", "es"),
    ("edu", "gr"),
    ("edu", "gt"),
    ("edu", "hk"),
    ("edu", "hn"),
    ("edu", "ht"),
    ("edu", "in"),
    ("edu", "jm"),
    ("edu", "jo"),
    ("edu", "kn"),
    ("edu", "kw"),
    ("edu", "ky"),
    ("edu", "lb"),
    ("edu", "lc"),
    ("edu", "lk"),
    ("edu", "mx"),
    ("edu", "my"),
    ("edu", "ng"),
    ("edu", "ni"),
    ("edu", "np"),
    ("edu", "pa"),
    ("edu", "pe"),
    ("edu", "ph"),
    ("edu", "pk"),
    ("edu", "pl"),
    ("edu", "pr"),
    ("edu", "pt"),
    ("edu", "py"),
    ("edu", "qa"),
    ("edu", "ru"),
    ("edu", "sa"),
    ("edu", "sg"),
    ("edu", "tr"),
    ("edu", "tt"),
    ("edu", "tw"),
    ("edu", "ua"),
    ("edu", "uy"),
    ("edu", "vc"),
    ("edu", "ve"),
    ("edu", "vn"),
    ("edu", "za"),
    ("fi", "cr"),
    ("fin", "ec"),
    ("firm", "in"),
    ("fukuoka", "jp"),
    ("geek", "nz"),
    ("gen", "in"),
    ("gen", "tr"),
    ("go", "cr"),
    ("go", "id"),
    ("go", "jp"),
    ("go", "ke"),
    ("go", "kr"),
    ("go", "th"),
    ("go", "tz"),
    ("go", "ug"),
    ("gob", "bo"),
    ("gob", "do"),
    ("gob", "ec"),
    ("gob", "es"),
    ("gob", "gt"),
    ("gob", "hn"),
    ("gob", "mx"),
    ("gob", "ni"),
    ("gob", "pa"),
    ("gob", "pe"),
    ("gob", "ve"),
    ("gov", "ae"),
    ("gov", "ar"),
    ("gov", "au"),
    ("gov", "bb"),
    ("gov", "bd"),
    ("gov", "br"),
    ("gov", "bs"),
    ("gov", "bz"),
    ("gov", "cn"),
    ("gov", "co"),
    ("gov", "cu"),
    ("gov", "cy"),
    ("gov", "dm"),
    ("gov", "do"),
    ("gov", "eg"),
    ("gov", "gr"),
    ("gov", "hk"),
    ("gov", "il"),
    ("gov", "in"),
    ("gov", "jm"),
    ("gov", "jo"),
    ("gov", "kn"),
    ("gov", "kw"),
    ("gov", "ky"),
    ("gov", "lb"),
    ("gov", "lc"),
    ("gov", "lk"),
    ("gov", "ma"),
    ("gov", "mw"),
    ("gov", "my"),
    ("gov", "ng"),
    ("gov", "np"),
    ("gov", "ph"),
    ("gov", "pk"),
    ("gov", "pl"),
    ("gov", "pr"),
    ("gov", "pt"),
    ("gov", "py"),
    ("gov", "qa"),
    ("gov", "ru"),
    ("gov", "sa"),
    ("gov", "sg"),
    ("gov", "tr"),
    ("gov", "tt"),
    ("gov", "tw"),
    ("gov", "ua"),
    ("gov", "uk"),
    ("gov", "vc"),
    ("gov", "vn"),
    ("gov", "za"),
    ("gov", "zm"),
    ("gov", "zw"),
    ("govt", "nz"),
    ("gr", "jp"),
    ("gub", "uy"),
    ("gv", "at"),
    ("hiroshima", "jp"),
    ("hokkaido", "jp"),
    ("id", "au"),
    ("idv", "hk"),
    ("idv", "tw"),
    ("in", "th"),
    ("in", "ua"),
    ("ind", "in"),
    ("info", "pl"),
    ("int", "ar"),
    ("int", "pt"),
    ("int", "ru"),
    ("isla", "pr"),
    ("k12", "il"),
    ("k12", "tr"),
    ("kiwi", "nz"),
    ("kobe", "jp"),
    ("kyoto", "jp"),
    ("lg", "jp"),
    ("ltd", "uk"),
    ("me", "uk"),
    ("med", "ec"),
    ("med", "sa"),
    ("mi", "th"),
    ("mil", "ae"),
    ("mil", "cn"),
    ("mil", "eg"),
    ("mil", "in"),
    ("mil", "jo"),
    ("mil", "kr"),
    ("mil", "ng"),
    ("mil", "qa"),
    ("mil", "tr"),
    ("mod", "uk"),
    ("muni", "il"),
    ("ne", "jp"),
    ("ne", "ke"),
    ("ne", "kr"),
    ("ne", "tz"),
    ("ne", "ug"),
    ("net", "ae"),
    ("net", "ag"),
    ("net", "ar"),
    ("net", "au"),
    ("net", "bb"),
    ("net", "bd"),
    ("net", "bo"),
    ("net", "br"),
    ("net", "bs"),
    ("net", "bz"),
    ("net", "cn"),
    ("net", "co"),
    ("net", "cu"),
    ("net", "cy"),
    ("net", "dm"),
    ("net", "do"),
    ("net", "ec"),
    ("net", "eg"),
    ("net", "gr"),
    ("net", "gt"),
    ("net", "hk"),
    ("net", "hn"),
    ("net", "ht"),
    ("net", "id"),
    ("net", "il"),
    ("net", "in"),
    ("net", "jm"),
    ("net", "jo"),
    ("net", "kn"),
    ("net", "kw"),
    ("net", "ky"),
    ("net", "lb"),
    ("net", "lc"),
    ("net", "lk"),
    ("net", "ma"),
    ("net", "mx"),
    ("net", "my"),
    ("net", "ng"),
    ("net", "ni"),
    ("net", "np"),
    ("net", "nz"),
    ("net", "pa"),
    ("net", "pe"),
    ("net", "ph"),
    ("net", "pk"),
    ("net", "pl"),
    ("net", "pr"),
    ("net", "pt"),
    ("net", "py"),
    ("net", "qa"),
    ("net", "ru"),
    ("net", "sa"),
    ("net", "sg"),
    ("net", "th"),
    ("net", "tr"),
    ("net", "tt"),
    ("net", "tw"),
    ("net", "ua"),
    ("net", "uk"),
    ("net", "uy"),
    ("net", "vc"),
    ("net", "ve"),
    ("net", "vi"),
    ("net", "vn"),
    ("net", "za"),
    ("nhs", "uk"),
    ("nom", "ag"),
    ("nom", "co"),
    ("nom", "es"),
    ("nom", "pe"),
    ("or", "at"),
    ("or", "cr"),
    ("or", "id"),
    ("or", "jp"),
    ("or", "ke"),
    ("or", "kr"),
    ("or", "th"),
    ("or", "tz"),
    ("or", "ug"),
    ("org", "ae"),
    ("org", "ag"),
    ("org", "ar"),
    ("org", "au"),
    ("org", "bb"),
    ("org", "bd"),
    ("org", "bo"),
    ("org", "br"),
    ("org", "bs"),
    ("org", "bw"),
    ("org", "bz"),
    ("org", "cn"),
    ("org", "co"),
    ("org", "cu"),
    ("org", "cy"),
    ("org", "dm"),
    ("org", "do"),
    ("org", "ec"),
    ("org", "eg"),
    ("org", "es"),
    ("org", "gr"),
    ("org", "gt"),
    ("org", "hk"),
    ("org", "hn"),
    ("org", "ht"),
    ("org", "il"),
    ("org", "in"),
    ("org", "jm"),
    ("org", "jo"),
    ("org", "kn"),
    ("org", "kw"),
    ("org", "ky"),
    ("org", "lb"),
    ("org", "lc"),
    ("org", "lk"),
    ("org", "ls"),
    ("org", "ma"),
    ("org", "mw"),
    ("org", "mx"),
    ("org", "my"),
    ("org", "ng"),
    ("org", "ni"),
    ("org", "np"),
    ("org", "nz"),
    ("org", "pa"),
    ("org", "pe"),
    ("org", "ph"),
    ("org", "pk"),
    ("org", "pl"),
    ("org", "pr"),
    ("org", "pt"),
    ("org", "py"),
    ("org", "qa"),
    ("org", "ru"),
    ("org", "sa"),
    ("org", "sg"),
    ("org", "sz"),
    ("org", "tr"),
    ("org", "tt"),
    ("org", "tw"),
    ("org", "ua"),
    ("org", "uk"),
    ("org", "uy"),
    ("org", "vc"),
    ("org", "ve"),
    ("org", "vi"),
    ("org", "vn"),
    ("org", "za"),
    ("org", "zm"),
    ("org", "zw"),
    ("osaka", "jp"),
    ("pe", "kr"),
    ("plc", "uk"),
    ("police", "uk"),
    ("pp", "ru"),
    ("pp", "ua"),
    ("press", "ma"),
    ("priv", "at"),
    ("pub", "sa"),
    ("publ", "pt"),
    ("re", "kr"),
    ("res", "in"),
    ("sa", "cr"),
    ("saitama", "jp"),
    ("sapporo", "jp"),
    ("sch", "ae"),
    ("sch", "id"),
    ("sch", "jo"),
    ("sch", "ng"),
    ("sch", "qa"),
    ("sch", "sa"),
    ("sch", "uk"),
    ("school", "nz"),
    ("sci", "eg"),
    ("sendai", "jp"),
    ("shizuoka", "jp"),
    ("tokyo", "jp"),
    ("waw", "pl"),
    ("web", "id"),
    ("web", "tr"),
    ("web", "ve"),
    ("web", "za"),
    ("yokohama", "jp"),
];

/// Compare a lowercase table entry against a probe of unknown case, without
/// allocating a lowercased copy of the probe.
fn cmp_ascii_lowercase(stored: &str, probe: &str) -> Ordering {
    let mut stored = stored.bytes();
    let mut probe = probe.bytes();

    loop {
        match (stored.next(), probe.next()) {
            (Some(left), Some(right)) => match left.cmp(&right.to_ascii_lowercase()) {
                Ordering::Equal => continue,
                ordering => return ordering,
            },
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
        }
    }
}

/// Is `<second>.<tld>` one of the known two-label public suffixes?
pub fn is_two_label_public_suffix(second: &str, tld: &str) -> bool {
    PUBLIC_SUFFIX_2LABEL
        .binary_search_by(|(entry_second, entry_tld)| {
            cmp_ascii_lowercase(entry_second, second)
                .then_with(|| cmp_ascii_lowercase(entry_tld, tld))
        })
        .is_ok()
}

/// The effective second-level domain: the registrable label of `domain`.
///
/// Borrows from `domain`; no allocation. A trailing root dot is accepted.
/// Returns `None` when there is no registrable label to analyse — a bare TLD
/// (`com`), a bare public suffix (`co.uk`), or a malformed name with an empty
/// label.
///
/// ```text
/// "google.com"        -> Some("google")
/// "sub.example.com"   -> Some("example")
/// "news.bbc.co.uk"    -> Some("bbc")
/// "foo.bar.tokyo.jp"  -> Some("bar")
/// "co.uk"             -> None
/// "com"               -> None
/// ```
pub fn effective_sld(domain: &str) -> Option<&str> {
    // At most three splits: the fourth piece is the unexamined remainder.
    let mut labels = domain.trim_end_matches('.').rsplitn(4, '.');

    let tld = labels.next()?;
    let second = labels.next()?;
    if tld.is_empty() || second.is_empty() {
        return None;
    }

    let third = labels.next().filter(|label| !label.is_empty());
    if is_two_label_public_suffix(second, tld) {
        // `None` here means the query *is* the public suffix.
        return third;
    }

    Some(second)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_suffix_table_is_sorted_and_unique() {
        for (second, tld) in PUBLIC_SUFFIX_2LABEL {
            assert!(!second.is_empty() && !tld.is_empty(), "{second}.{tld}");
            assert!(
                !second.contains('.') && !tld.contains('.'),
                "{second}.{tld}"
            );
            assert_eq!(
                (second.to_ascii_lowercase(), tld.to_ascii_lowercase()),
                (second.to_string(), tld.to_string()),
                "{second}.{tld} must be lowercase"
            );
        }

        for pair in PUBLIC_SUFFIX_2LABEL.windows(2) {
            assert!(
                pair[0] < pair[1],
                "table must be strictly increasing: {:?} then {:?}",
                pair[0],
                pair[1]
            );
        }
    }

    #[test]
    fn effective_sld_single_label_tld() {
        assert_eq!(effective_sld("google.com"), Some("google"));
        assert_eq!(effective_sld("sub.example.com"), Some("example"));
        assert_eq!(effective_sld("a.b.c.d.example.com"), Some("example"));
        assert_eq!(effective_sld("example.dev"), Some("example"));
    }

    #[test]
    fn effective_sld_two_label_public_suffix() {
        assert_eq!(effective_sld("bbc.co.uk"), Some("bbc"));
        assert_eq!(effective_sld("news.bbc.co.uk"), Some("bbc"));
        assert_eq!(effective_sld("foo.bar.tokyo.jp"), Some("bar"));
        assert_eq!(effective_sld("x.y.z.com.au"), Some("z"));
        assert_eq!(effective_sld("shop.com.br"), Some("shop"));
    }

    #[test]
    fn effective_sld_is_case_insensitive() {
        assert_eq!(effective_sld("News.BBC.CO.UK"), Some("BBC"));
        assert_eq!(effective_sld("Example.COM"), Some("Example"));
    }

    #[test]
    fn effective_sld_rejects_names_without_a_registrable_label() {
        assert_eq!(effective_sld(""), None);
        assert_eq!(effective_sld("com"), None);
        assert_eq!(effective_sld("co.uk"), None);
        assert_eq!(effective_sld("com.au"), None);
        assert_eq!(effective_sld("a..com"), None);
    }

    #[test]
    fn effective_sld_accepts_a_trailing_root_dot() {
        assert_eq!(effective_sld("google.com."), Some("google"));
        assert_eq!(effective_sld("news.bbc.co.uk."), Some("bbc"));
    }

    #[test]
    fn effective_sld_falls_back_for_unknown_two_label_suffixes() {
        // `zz` is not a registry we know; last-two-labels is the safe guess.
        assert_eq!(effective_sld("foo.example.zz"), Some("example"));
        // `co.fr` is not a public suffix: the registrable label really is `co`.
        assert_eq!(effective_sld("www.co.fr"), Some("co"));
    }

    #[test]
    fn two_label_public_suffix_lookup() {
        assert!(is_two_label_public_suffix("co", "uk"));
        assert!(is_two_label_public_suffix("CO", "UK"));
        assert!(is_two_label_public_suffix("com", "br"));
        assert!(!is_two_label_public_suffix("co", "fr"));
        assert!(!is_two_label_public_suffix("www", "com"));
        assert!(!is_two_label_public_suffix("", ""));
    }
}
