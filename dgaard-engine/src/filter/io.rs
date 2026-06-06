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
    fast_map: &mut HashMap<u64, u8>,
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

    fn make_collections() -> (
        HashMap<u64, u8>,
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
}
