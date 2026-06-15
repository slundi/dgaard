use regex::Regex;
use std::{
    collections::HashMap,
    fs::File,
    io::{BufReader, Read as _},
    path::Path,
};

use crate::{
    filter::process_line,
    model::{DomainEntry, DomainEntryFlags},
};

/// 2MB chunk size for reading large list files
const CHUNK_SIZE: usize = 2 * 1024 * 1024;

/// Load a list file by reading 2MB chunks at a time.
/// Detects format (hosts, dnsmasq, plain domain, or ABP) and parses accordingly.
#[allow(clippy::too_many_arguments)]
pub fn load_list_file(
    path: &str,
    base_flags: DomainEntryFlags,
    seed: u64,
    fast_map: &mut HashMap<u64, (u8, Box<str>)>,
    hierarchical_list: &mut Vec<DomainEntry>,
    wildcard_patterns: &mut Vec<String>,
    regex_pool: &mut Vec<Regex>,
    host_index: &mut HashMap<u64, String>,
    browser_rules: &mut Vec<String>,
) -> std::io::Result<()> {
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
    let mut leftover = String::new();
    let mut bytes_read_total: u64 = 0;

    loop {
        let mut chunk = vec![0u8; CHUNK_SIZE];
        let bytes_read = reader.read(&mut chunk)?;

        if bytes_read == 0 {
            if !leftover.is_empty() {
                process_line(
                    &leftover,
                    base_flags,
                    seed,
                    fast_map,
                    hierarchical_list,
                    wildcard_patterns,
                    regex_pool,
                    host_index,
                    browser_rules,
                );
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
            process_line(
                line,
                base_flags,
                seed,
                fast_map,
                hierarchical_list,
                wildcard_patterns,
                regex_pool,
                host_index,
                browser_rules,
            );
        }

        leftover = new_leftover.to_string();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: u64 = 42;

    #[allow(clippy::type_complexity)]
    fn make_collections() -> (
        HashMap<u64, (u8, Box<str>)>,
        Vec<DomainEntry>,
        Vec<String>,
        Vec<Regex>,
        HashMap<u64, String>,
        Vec<String>,
    ) {
        (
            HashMap::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            HashMap::new(),
            Vec::new(),
        )
    }

    #[test]
    fn test_load_list_file_not_found() {
        let (mut fm, mut hl, mut wp, mut rp, mut hi, mut br) = make_collections();
        let result = load_list_file(
            "nonexistent_file.txt",
            DomainEntryFlags::NONE,
            SEED,
            &mut fm,
            &mut hl,
            &mut wp,
            &mut rp,
            &mut hi,
            &mut br,
        );
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::NotFound);
    }

    fn write_temp_list(tag: &str, content: &str) -> String {
        let path = format!("/tmp/dgaard_engine_io_test_{tag}_{}", std::process::id());
        std::fs::write(&path, content).expect("write temp file");
        path
    }

    #[test]
    fn test_load_plain_domain_list() {
        let path = write_temp_list("plain", "example.com\ngoogle.com\n# comment\n\nbad.com\n");
        let (mut fm, mut hl, mut wp, mut rp, mut hi, mut br) = make_collections();
        let result = load_list_file(
            &path,
            DomainEntryFlags::NONE,
            SEED,
            &mut fm,
            &mut hl,
            &mut wp,
            &mut rp,
            &mut hi,
            &mut br,
        );
        assert!(result.is_ok());
        // 3 valid domains (comment and blank line skipped)
        assert_eq!(fm.len(), 3, "expected 3 entries, got {}", fm.len());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_load_hosts_format_list() {
        let content = "0.0.0.0 example.com\n0.0.0.0 ads.evil.com\n127.0.0.1 tracker.net\n";
        let path = write_temp_list("hosts", content);
        let (mut fm, mut hl, mut wp, mut rp, mut hi, mut br) = make_collections();
        let result = load_list_file(
            &path,
            DomainEntryFlags::NONE,
            SEED,
            &mut fm,
            &mut hl,
            &mut wp,
            &mut rp,
            &mut hi,
            &mut br,
        );
        assert!(result.is_ok());
        assert_eq!(fm.len(), 3);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_load_whitelist_file() {
        let path = write_temp_list("whitelist", "safe.com\nallowed.org\n");
        let (mut fm, mut hl, mut wp, mut rp, mut hi, mut br) = make_collections();
        let result = load_list_file(
            &path,
            DomainEntryFlags::WHITELIST,
            SEED,
            &mut fm,
            &mut hl,
            &mut wp,
            &mut rp,
            &mut hi,
            &mut br,
        );
        assert!(result.is_ok());
        // Whitelist entries are in the hierarchical list
        assert!(!hl.is_empty());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_load_abp_format_list() {
        let content = "||ads.example.com^\n||tracker.net^\n@@||safe.com^\n";
        let path = write_temp_list("abp", content);
        let (mut fm, mut hl, mut wp, mut rp, mut hi, mut br) = make_collections();
        let result = load_list_file(
            &path,
            DomainEntryFlags::NONE,
            SEED,
            &mut fm,
            &mut hl,
            &mut wp,
            &mut rp,
            &mut hi,
            &mut br,
        );
        assert!(result.is_ok());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_load_empty_file() {
        let path = write_temp_list("empty", "");
        let (mut fm, mut hl, mut wp, mut rp, mut hi, mut br) = make_collections();
        let result = load_list_file(
            &path,
            DomainEntryFlags::NONE,
            SEED,
            &mut fm,
            &mut hl,
            &mut wp,
            &mut rp,
            &mut hi,
            &mut br,
        );
        assert!(result.is_ok());
        assert!(fm.is_empty());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_load_comments_only_file() {
        let content = "# This is a comment\n! ABP comment\n# Another comment\n";
        let path = write_temp_list("comments", content);
        let (mut fm, mut hl, mut wp, mut rp, mut hi, mut br) = make_collections();
        let result = load_list_file(
            &path,
            DomainEntryFlags::NONE,
            SEED,
            &mut fm,
            &mut hl,
            &mut wp,
            &mut rp,
            &mut hi,
            &mut br,
        );
        assert!(result.is_ok());
        assert!(
            fm.is_empty(),
            "comments-only file should produce no entries"
        );
        let _ = std::fs::remove_file(&path);
    }
}
