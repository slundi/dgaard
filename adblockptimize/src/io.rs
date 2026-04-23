use std::{
    fs::File,
    io::{BufReader, Read},
    path::Path,
};

use crate::{
    abp::parse_abp_line,
    error::ListError,
    model::ListFormat,
    parser::{detect_format, parse_dnsmasq_line, parse_host_line, parse_plain_domain},
};

/// 2MB chunk size for reading large list files
const CHUNK_SIZE: usize = 2 * 1024 * 1024;

/// Load a list file by reading 2MB chunks at a time.
/// Detects format (hosts, dnsmasq, or plain domain) and parses accordingly.
#[allow(clippy::too_many_arguments)]
pub(crate) fn load_list_file(
    path: &str,
    network_rules: &mut Vec<(String, u8)>,
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

    // Use BufReader with 2MB buffer
    let mut reader = BufReader::with_capacity(CHUNK_SIZE, file);
    let mut leftover = String::new();
    let mut bytes_read_total: u64 = 0;

    loop {
        let mut chunk = vec![0u8; CHUNK_SIZE];
        let bytes_read = reader.read(&mut chunk)?;

        if bytes_read == 0 {
            // Process any remaining leftover
            if !leftover.is_empty() {
                process_line(&leftover, network_rules, browser_rules);
            }
            break;
        }

        bytes_read_total += bytes_read as u64;
        chunk.truncate(bytes_read);

        // Convert chunk to string (lossy to handle any invalid UTF-8)
        let chunk_str = String::from_utf8_lossy(&chunk);

        // Combine with leftover from previous chunk
        let combined = format!("{}{}", leftover, chunk_str);

        // Find the last newline to split complete lines from partial
        let last_newline = combined.rfind('\n');

        let (complete, new_leftover) = match last_newline {
            Some(idx) if bytes_read_total < file_size => {
                // More data to come, save incomplete line
                (&combined[..idx + 1], &combined[idx + 1..])
            }
            _ => {
                // Last chunk or no newline found, process everything
                (combined.as_str(), "")
            }
        };

        // Process complete lines
        for line in complete.lines() {
            process_line(line, network_rules, browser_rules);
        }

        leftover = new_leftover.to_string();
    }

    Ok(())
}

/// Load a list from raw content (e.g., downloaded from URL).
pub fn load_list_content(
    content: &str,
    network_rules: &mut Vec<(String, u8)>,
    browser_rules: &mut Vec<String>,
) {
    for line in content.lines() {
        process_line(line, network_rules, browser_rules);
    }
}

/// Process a single line using the appropriate parser based on detected format.
#[allow(clippy::too_many_arguments)]
fn process_line(
    line: &str,
    network_rules: &mut Vec<(String, u8)>,
    browser_rules: &mut Vec<String>,
) {
    // Use parse_line wrapper for common logic (trim, skip comments)
    let result: Result<(String, u8), ListError<'_>> =
        parse_line(line, |trimmed| match detect_format(trimmed) {
            ListFormat::Hosts => parse_host_line(trimmed),
            ListFormat::Dnsmasq => parse_dnsmasq_line(trimmed),
            ListFormat::Plain => parse_plain_domain(trimmed),
            ListFormat::Abp => parse_abp_line(trimmed),
            ListFormat::Unknown => Err(ListError::ParseError(
                std::io::Error::new(std::io::ErrorKind::InvalidData, "Unknown format"),
                trimmed,
                "unknown",
            )),
        });

    match result {
        Ok(entry) => {
            if entry.1 > 0 {
                browser_rules.push(entry.0);
            } else {
                network_rules.push(entry);
            }
        }
        Err(ListError::Skip) => {
            // Empty line or comment, silently skip
        }
        Err(ListError::BrowserRule(rule)) => {
            // Cosmetic/scriptlet ABP rule — not a DNS filter, collect for browser export
            browser_rules.push(rule.to_string());
        }
        Err(_) => {
            // Parse error, silently skip (could log in debug mode)
        }
    }
}

pub fn parse_line<'a, F>(line: &'a str, parser: F) -> Result<(String, u8), ListError<'a>>
where
    F: Fn(&'a str) -> Result<(String, u8), ListError<'a>>,
{
    // common logic like trimming and ignoring comments
    let trimmed = line.trim();
    // Skip empty lines, hosts/dnsmasq comments (#), and ABP comments (!)
    if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('!') {
        return Err(ListError::Skip);
    }
    // Identify ABP browser-only rules (cosmetic, element-hiding, scriptlet).
    // These are not applicable to DNS filtering but are useful for browser extensions.
    const BROWSER_MARKERS: &[&str] = &["##", "#@#", "#$#", "#%#", "#^#", "#?#"];
    if BROWSER_MARKERS.iter().any(|m| trimmed.contains(m)) {
        return Err(ListError::BrowserRule(trimmed));
    }

    parser(trimmed)
}
