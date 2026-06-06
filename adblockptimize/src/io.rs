use std::{
    fs::File,
    io::{BufReader, Read},
    path::Path,
};

use crate::{
    abp::parse_abp_line,
    error::ListError,
    model::{ListFormat, Rule},
    parser::{detect_format, parse_dnsmasq_line, parse_host_line, parse_plain_domain},
};

/// 2MB chunk size for reading large list files
const CHUNK_SIZE: usize = 2 * 1024 * 1024;

/// Load a list file by reading 2MB chunks at a time.
/// Detects format (hosts, dnsmasq, plain domain, ABP) and parses accordingly.
pub(crate) fn load_list_file(path: &str) -> std::io::Result<Vec<Rule>> {
    let path = Path::new(path);
    if !path.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("File not found: {}", path.display()),
        ));
    }

    let file = File::open(path)?;
    let file_size = file.metadata()?.len();

    let mut reader = BufReader::with_capacity(CHUNK_SIZE, file);
    let mut rules = Vec::new();
    let mut leftover = String::new();
    let mut bytes_read_total: u64 = 0;

    loop {
        let mut chunk = vec![0u8; CHUNK_SIZE];
        let bytes_read = reader.read(&mut chunk)?;

        if bytes_read == 0 {
            if !leftover.is_empty()
                && let Some(rule) = parse_line(&leftover)
            {
                rules.push(rule);
            }
            break;
        }

        bytes_read_total += bytes_read as u64;
        chunk.truncate(bytes_read);

        let chunk_str = String::from_utf8_lossy(&chunk);
        let combined = format!("{}{}", leftover, chunk_str);
        let last_newline = combined.rfind('\n');

        let (complete, new_leftover) = match last_newline {
            Some(idx) if bytes_read_total < file_size => {
                (&combined[..idx + 1], &combined[idx + 1..])
            }
            _ => (combined.as_str(), ""),
        };

        for line in complete.lines() {
            if let Some(rule) = parse_line(line) {
                rules.push(rule);
            }
        }

        leftover = new_leftover.to_string();
    }

    Ok(rules)
}

/// Load a list from raw content (e.g., downloaded from URL).
pub fn load_list_content(content: &str) -> Vec<Rule> {
    content.lines().filter_map(parse_line).collect()
}

/// Parse a single line into a `Rule`, returning `None` for blank lines, comments, and parse errors.
fn parse_line(line: &str) -> Option<Rule> {
    let trimmed = line.trim();

    // Skip empty lines and comments (hosts/dnsmasq use #, ABP uses !)
    if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('!') {
        return None;
    }

    // ABP browser-only rules (cosmetic CSS, element-hiding, scriptlets) — not DNS-filterable
    const BROWSER_MARKERS: &[&str] = &["##", "#@#", "#$#", "#%#", "#^#", "#?#"];
    if BROWSER_MARKERS.iter().any(|m| trimmed.contains(m)) {
        return Some(Rule::Browser(trimmed.to_string()));
    }

    let result: Result<Rule, ListError<'_>> = match detect_format(trimmed) {
        ListFormat::Hosts => parse_host_line(trimmed),
        ListFormat::Dnsmasq => parse_dnsmasq_line(trimmed),
        ListFormat::Plain => parse_plain_domain(trimmed),
        ListFormat::Abp => parse_abp_line(trimmed),
        ListFormat::Unknown => return None,
    };

    result.ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_temp(tag: &str, content: &str) -> String {
        let path = format!("/tmp/dgaard_abpopt_io_test_{tag}_{}", std::process::id());
        std::fs::write(&path, content).unwrap();
        path
    }

    // ── load_list_content ─────────────────────────────────────────────────────

    #[test]
    fn load_content_plain_domains() {
        let rules = load_list_content("example.com\ngoogle.com\n");
        assert_eq!(rules.len(), 2);
        assert!(rules.iter().all(|r| matches!(r, Rule::NetworkDomain(_))));
    }

    #[test]
    fn load_content_skips_comments_and_blanks() {
        let content = "# comment\nexample.com\n\n! abp comment\ngoogle.com\n";
        let rules = load_list_content(content);
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn load_content_abp_rules() {
        let content = "||ads.example.com^\n@@||safe.com^\n";
        let rules = load_list_content(content);
        assert_eq!(rules.len(), 2);
        assert!(matches!(&rules[0], Rule::NetworkDomain(d) if d == "ads.example.com"));
        assert!(matches!(&rules[1], Rule::Whitelist(d) if d == "safe.com"));
    }

    #[test]
    fn load_content_hosts_format() {
        let content = "0.0.0.0 tracker.com\n127.0.0.1 ads.net\n";
        let rules = load_list_content(content);
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn load_content_browser_rules_included() {
        let content = "example.com##.ad-banner\nexample.com#@#.sponsored\n";
        let rules = load_list_content(content);
        assert_eq!(rules.len(), 2);
        assert!(rules.iter().all(|r| r.is_browser()));
    }

    #[test]
    fn load_content_empty_string() {
        let rules = load_list_content("");
        assert!(rules.is_empty());
    }

    #[test]
    fn load_content_unknown_format_skipped() {
        // Lines with spaces that don't match any known format → Unknown → skipped
        let content = "some random line with spaces and/slashes\n";
        let rules = load_list_content(content);
        assert!(rules.is_empty(), "Unknown format lines should be skipped");
    }

    // ── load_list_file ────────────────────────────────────────────────────────

    #[test]
    fn load_list_file_not_found_returns_error() {
        let result = load_list_file("/nonexistent/path/file.txt");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn load_list_file_plain_domains() {
        let path = write_temp("plain", "example.com\ngoogle.com\nbad.org\n");
        let rules = load_list_file(&path).unwrap();
        assert_eq!(rules.len(), 3);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_list_file_mixed_formats() {
        let content =
            "# blocklist\n0.0.0.0 tracker.net\nexample.com\n||ads.evil.com^\n@@||safe.com^\n";
        let path = write_temp("mixed", content);
        let rules = load_list_file(&path).unwrap();
        assert_eq!(rules.len(), 4);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_list_file_empty_file() {
        let path = write_temp("empty", "");
        let rules = load_list_file(&path).unwrap();
        assert!(rules.is_empty());
        let _ = std::fs::remove_file(&path);
    }
}
