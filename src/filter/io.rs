use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use regex::Regex;
use std::{
    collections::HashMap,
    fs::File,
    io::{BufReader, Read as _},
    path::Path,
};
use url::Url;

use crate::{
    filter::{HttpsClient, load_list_content, process_line},
    model::{DomainEntry, DomainEntryFlags},
    updater::{Resource, validate_input},
};

/// 2MB chunk size for reading large list files
const CHUNK_SIZE: usize = 2 * 1024 * 1024;

/// Load a list file by reading 2MB chunks at a time.
/// Detects format (hosts, dnsmasq, or plain domain) and parses accordingly.
pub(crate) fn load_list_file(
    path: &str,
    base_flags: DomainEntryFlags,
    fast_map: &mut HashMap<u64, u8>,
    hierarchical_list: &mut Vec<DomainEntry>,
    wildcard_patterns: &mut Vec<String>,
    regex_pool: &mut Vec<Regex>,
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
                process_line(
                    &leftover,
                    base_flags,
                    fast_map,
                    hierarchical_list,
                    wildcard_patterns,
                    regex_pool,
                );
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
            process_line(
                line,
                base_flags,
                fast_map,
                hierarchical_list,
                wildcard_patterns,
                regex_pool,
            );
        }

        leftover = new_leftover.to_string();
    }

    Ok(())
}

/// Create an HTTPS client with rustls for downloading lists.
pub(crate) fn build_https_client() -> HttpsClient {
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .build();
    Client::builder(TokioExecutor::new()).build(https)
}

/// Download a list from a URL using the provided HTTP client.
async fn download_list(
    client: &HttpsClient,
    url: &Url,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let uri: hyper::Uri = url.as_str().parse()?;
    let req = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri(&uri)
        .header("User-Agent", "dgaard/0.1")
        .body(Empty::<Bytes>::new())?;

    let res = client.request(req).await?;
    let status = res.status();
    if !status.is_success() {
        return Err(format!("HTTP error: {}", status).into());
    }

    let body = res.collect().await?.to_bytes();
    Ok(String::from_utf8_lossy(&body).into_owned())
}

/// Load a source (file path or URL) into the filter collections.
pub(crate) async fn load_source(
    source: &str,
    base_flags: DomainEntryFlags,
    client: &HttpsClient,
    fast_map: &mut HashMap<u64, u8>,
    hierarchical_list: &mut Vec<DomainEntry>,
    wildcard_patterns: &mut Vec<String>,
    regex_pool: &mut Vec<Regex>,
) {
    match validate_input(source) {
        Ok(Resource::HttpUrl(url)) => match download_list(client, &url).await {
            Ok(content) => {
                println!("Downloaded {} ({} bytes)", source, content.len());
                load_list_content(
                    &content,
                    base_flags,
                    fast_map,
                    hierarchical_list,
                    wildcard_patterns,
                    regex_pool,
                );
            }
            Err(e) => eprintln!("Warning: Failed to download {}: {}", source, e),
        },
        Ok(Resource::FilePath(_)) => {
            if let Err(e) = load_list_file(
                source,
                base_flags,
                fast_map,
                hierarchical_list,
                wildcard_patterns,
                regex_pool,
            ) {
                eprintln!("Warning: Failed to load {}: {}", source, e);
            }
        }
        Err(e) => eprintln!("Warning: Invalid source {}: {}", source, e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{filter::tests::init_seed, model::DomainEntryFlags};

    // --- Tests for load_list_file ---

    #[test]
    fn test_load_list_file_hosts() {
        init_seed();
        let mut fast_map = HashMap::new();
        let mut hierarchical_list = Vec::new();
        let mut wildcard_patterns = Vec::new();
        let mut regex_pool = Vec::new();

        let result = load_list_file(
            "tests/list_host.txt",
            DomainEntryFlags::NONE,
            &mut fast_map,
            &mut hierarchical_list,
            &mut wildcard_patterns,
            &mut regex_pool,
        );

        assert!(result.is_ok(), "Failed to load hosts file: {:?}", result);
        // The test file has 78 entries (excluding comments and empty lines)
        assert!(
            fast_map.len() >= 70,
            "Expected at least 70 entries, got {}",
            fast_map.len()
        );
        assert_eq!(fast_map.len(), hierarchical_list.len());
    }

    #[test]
    fn test_load_list_file_dnsmasq() {
        init_seed();
        let mut fast_map = HashMap::new();
        let mut hierarchical_list = Vec::new();
        let mut wildcard_patterns = Vec::new();
        let mut regex_pool = Vec::new();

        let result = load_list_file(
            "tests/list_dnsmasq.txt",
            DomainEntryFlags::NONE,
            &mut fast_map,
            &mut hierarchical_list,
            &mut wildcard_patterns,
            &mut regex_pool,
        );

        assert!(result.is_ok(), "Failed to load dnsmasq file: {:?}", result);
        assert!(
            fast_map.len() >= 70,
            "Expected at least 70 entries, got {}",
            fast_map.len()
        );
        assert_eq!(fast_map.len(), hierarchical_list.len());
    }

    #[test]
    fn test_load_list_file_not_found() {
        init_seed();
        let mut fast_map = HashMap::new();
        let mut hierarchical_list = Vec::new();
        let mut wildcard_patterns = Vec::new();
        let mut regex_pool = Vec::new();

        let result = load_list_file(
            "nonexistent_file.txt",
            DomainEntryFlags::NONE,
            &mut fast_map,
            &mut hierarchical_list,
            &mut wildcard_patterns,
            &mut regex_pool,
        );

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn test_load_list_file_with_whitelist_flag() {
        init_seed();
        let mut fast_map = HashMap::new();
        let mut hierarchical_list = Vec::new();
        let mut wildcard_patterns = Vec::new();
        let mut regex_pool = Vec::new();

        let result = load_list_file(
            "tests/list_host.txt",
            DomainEntryFlags::WHITELIST,
            &mut fast_map,
            &mut hierarchical_list,
            &mut wildcard_patterns,
            &mut regex_pool,
        );

        assert!(result.is_ok());
        // All entries should have WHITELIST flag
        for entry in &hierarchical_list {
            assert!(
                entry.flags.contains(DomainEntryFlags::WHITELIST),
                "Entry should have WHITELIST flag"
            );
        }
    }

    #[test]
    fn test_load_list_file_abp() {
        init_seed();
        let mut fast_map = HashMap::new();
        let mut hierarchical_list = Vec::new();
        let mut wildcard_patterns = Vec::new();
        let mut regex_pool = Vec::new();

        let result = load_list_file(
            "tests/list_abp.txt",
            DomainEntryFlags::NONE,
            &mut fast_map,
            &mut hierarchical_list,
            &mut wildcard_patterns,
            &mut regex_pool,
        );

        assert!(result.is_ok(), "Failed to load ABP file: {:?}", result);
        // The test file has 78 entries (excluding comments)
        assert!(
            fast_map.len() >= 70,
            "Expected at least 70 entries, got {}",
            fast_map.len()
        );
        assert_eq!(fast_map.len(), hierarchical_list.len());

        // Verify domains are hashed correctly (not including || and ^)
        let expected_hash = twox_hash::XxHash64::oneshot(42, "samsungads.com".as_bytes());
        assert!(
            fast_map.contains_key(&expected_hash),
            "Should contain hash for samsungads.com"
        );
    }
}
