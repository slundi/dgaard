mod abp;
mod cli;
mod error;
mod formatter;
mod http;
mod io;
mod model;
mod parser;

use std::path::Path;

use url::Url;

use crate::{
    error::ResourceError,
    formatter::format_rule,
    http::{HttpsClient, build_https_client, download_list},
    io::{load_list_content, load_list_file},
    model::{DnsTarget, Resource, Rule},
};

pub fn validate_input(input: &str) -> Result<Resource, ResourceError> {
    // 1. Try to parse as a URL
    if let Ok(parsed_url) = Url::parse(input) {
        if parsed_url.scheme() == "http" || parsed_url.scheme() == "https" {
            return Ok(Resource::HttpUrl(parsed_url));
        } else {
            eprintln!("Invalid protocol URL: {}", input);
            return Err(ResourceError::NonHttpScheme);
        }
    }

    // 2. Try to treat as a file path
    let path = Path::new(input);
    if path.exists() {
        return Ok(Resource::FilePath(path.to_path_buf()));
    }

    if input.contains('/') || input.contains('\\') {
        eprintln!("Invalid file path: {}", input);
        return Err(ResourceError::InvalidFilePath(input.to_string()));
    }

    if input.starts_with("http") {
        eprintln!("Invalid URL: {}", input);
        return Err(ResourceError::InvalidUrl(Url::parse(input).unwrap_err()));
    }

    Err(ResourceError::UnknownResource)
}

/// Load a source (file path or URL) and return its parsed rules.
pub async fn load_source(source: &str, client: &HttpsClient) -> Vec<Rule> {
    match validate_input(source) {
        Ok(Resource::HttpUrl(url)) => match download_list(client, &url).await {
            Ok(content) => {
                println!("Downloaded {} ({} bytes)", source, content.len());
                load_list_content(&content)
            }
            Err(e) => {
                eprintln!("Warning: Failed to download {}: {}", source, e);
                vec![]
            }
        },
        Ok(Resource::FilePath(_)) => match load_list_file(source) {
            Ok(rules) => rules,
            Err(e) => {
                eprintln!("Warning: Failed to load {}: {}", source, e);
                vec![]
            }
        },
        Err(e) => {
            eprintln!("Warning: Invalid source {}: {}", source, e);
            vec![]
        }
    }
}

#[tokio::main]
async fn main() {
    let opts = cli::parse();
    let client = build_https_client();

    let mut handles: tokio::task::JoinSet<Vec<Rule>> = tokio::task::JoinSet::new();
    for list in opts.paths {
        let client = client.clone();
        handles.spawn(async move { load_source(&list, &client).await });
    }

    let mut all_rules: Vec<Rule> = Vec::new();
    while let Some(result) = handles.join_next().await {
        all_rules.extend(result.expect("task panicked"));
    }

    // Split into network / browser / whitelist, deduplicate, sort
    let mut network: Vec<&Rule> = all_rules.iter().filter(|r| r.is_network()).collect();
    let mut browser: Vec<&Rule> = all_rules.iter().filter(|r| r.is_browser()).collect();
    let whitelists: Vec<&Rule> = all_rules.iter().filter(|r| r.is_whitelist()).collect();

    network.sort_by_key(|r| r.value());
    network.dedup_by_key(|r| r.value());

    browser.sort_by_key(|r| r.value());
    browser.dedup_by_key(|r| r.value());

    let target = opts.target.unwrap_or(DnsTarget::Plain);

    // Network output
    if !opts.no_network {
        let mut lines: Vec<String> = network
            .iter()
            .filter_map(|r| format_rule(r, target))
            .collect();

        // For AdGuard, include whitelists in the network file (unless a separate
        // whitelist file was requested).
        if matches!(target, DnsTarget::AdGuard) && opts.whitelist_file.is_none() {
            lines.extend(whitelists.iter().filter_map(|r| format_rule(r, target)));
        }

        write_lines(&opts.network_file, &lines);
    }

    // Explicit whitelist file
    if let Some(ref path) = opts.whitelist_file {
        let lines: Vec<String> = whitelists
            .iter()
            .filter_map(|r| format_rule(r, target))
            .collect();
        if let Err(e) = std::fs::write(path, lines.join("\n")) {
            eprintln!("Error writing whitelist file {}: {e}", path.display());
        }
    }

    // Browser output
    if !opts.no_browser {
        let lines: Vec<String> = browser.iter().map(|r| r.value().to_string()).collect();
        write_lines(&opts.browser_file, &lines);
    }
}

/// Write lines to a file, or print them to stdout if no path is given.
fn write_lines(path: &Option<std::path::PathBuf>, lines: &[String]) {
    match path {
        Some(p) => {
            if let Err(e) = std::fs::write(p, lines.join("\n")) {
                eprintln!("Error writing {}: {e}", p.display());
            }
        }
        None => {
            for line in lines {
                println!("{line}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{error::ResourceError, http::build_https_client, model::Resource};

    #[test]
    fn validate_input_rejects_unknown_resource() {
        assert!(matches!(
            validate_input("notafileorurl"),
            Err(ResourceError::UnknownResource)
        ));
    }

    #[test]
    fn validate_input_rejects_non_http_scheme() {
        assert!(matches!(
            validate_input("ftp://example.com/list.txt"),
            Err(ResourceError::NonHttpScheme)
        ));
    }

    #[test]
    fn validate_input_accepts_https_url() {
        assert!(matches!(
            validate_input("https://example.com/list.txt"),
            Ok(Resource::HttpUrl(_))
        ));
    }

    #[test]
    fn validate_input_accepts_existing_file() {
        assert!(matches!(
            validate_input("/etc/hostname"),
            Ok(Resource::FilePath(_))
        ));
    }

    #[tokio::test]
    async fn load_source_returns_empty_for_invalid_source() {
        let client = build_https_client();
        let rules = load_source("notexistentfile", &client).await;
        assert!(rules.is_empty());
    }
}
