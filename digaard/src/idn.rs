//! Internationalized Domain Names — Unicode → A-label (Punycode).
//!
//! The DNS wire format only accepts ASCII labels; user input like `bücher.de`
//! must be converted to `xn--bcher-kva.de` before we encode the query. When
//! rendering results we hand back both the wire form and the Unicode form
//! so users can see what they actually asked for.

use idna::AsciiDenyList;

/// Encode a Unicode domain to its ASCII (A-label) form.
///
/// Returns `Ok(ascii)` on success. Idempotent for already-ASCII input.
/// Preserves a trailing `.` if the caller provided one.
pub fn to_ascii(name: &str) -> Result<String, String> {
    let (stripped, had_root) = match name.strip_suffix('.') {
        Some(s) => (s, true),
        None => (name, false),
    };

    let ascii = idna::domain_to_ascii_cow(stripped.as_bytes(), AsciiDenyList::URL)
        .map_err(|e| format!("idn error for '{name}': {e:?}"))?
        .into_owned();

    if had_root {
        Ok(format!("{ascii}."))
    } else {
        Ok(ascii)
    }
}

/// Decode an A-label (or already-Unicode) name back to its Unicode form.
///
/// Never fails: on any decoding error we return the input unchanged, since
/// this is a display-only helper.
pub fn to_unicode(name: &str) -> String {
    let (stripped, had_root) = match name.strip_suffix('.') {
        Some(s) => (s, true),
        None => (name, false),
    };

    let (uni, errors) = idna::domain_to_unicode(stripped);
    let s = if errors.is_ok() {
        uni
    } else {
        stripped.to_string()
    };
    if had_root { format!("{s}.") } else { s }
}

/// True if the label representation actually differs from its Unicode form
/// (i.e. contains any Punycode `xn--` labels).
pub fn is_idna(name: &str) -> bool {
    name.split('.')
        .any(|label| label.starts_with("xn--") || label.starts_with("XN--"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_roundtrip_is_noop() {
        assert_eq!(to_ascii("example.com").unwrap(), "example.com");
        assert_eq!(to_ascii("example.com.").unwrap(), "example.com.");
    }

    #[test]
    fn unicode_to_ascii() {
        assert_eq!(to_ascii("bücher.de").unwrap(), "xn--bcher-kva.de");
        assert_eq!(to_ascii("bücher.de.").unwrap(), "xn--bcher-kva.de.");
    }

    #[test]
    fn punycode_to_unicode() {
        assert_eq!(to_unicode("xn--bcher-kva.de"), "bücher.de");
        assert_eq!(to_unicode("xn--bcher-kva.de."), "bücher.de.");
    }

    #[test]
    fn is_idna_detects_punycode() {
        assert!(is_idna("xn--bcher-kva.de"));
        assert!(is_idna("mixed.xn--nxasmq6b.example"));
        assert!(!is_idna("example.com"));
    }
}
