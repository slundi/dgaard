mod abp;
mod cli;
mod error;
mod http;
mod io;
mod model;
mod parser;

use std::path::Path;

use url::Url;

use crate::{
    error::ResourceError,
    http::{HttpsClient, build_https_client, download_list},
    io::{load_list_content, load_list_file},
    model::{Resource, Rule},
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

    let mut all_rules: Vec<Rule> = Vec::new();
    for list in opts.paths {
        all_rules.extend(load_source(&list, &client).await);
    }

    // Split into network vs browser, deduplicate, sort
    let mut network: Vec<&Rule> = all_rules.iter().filter(|r| r.is_network()).collect();
    let mut browser: Vec<&Rule> = all_rules.iter().filter(|r| r.is_browser()).collect();

    network.sort_by_key(|r| r.value());
    network.dedup_by_key(|r| r.value());

    browser.sort_by_key(|r| r.value());
    browser.dedup_by_key(|r| r.value());

    // TODO: write network and browser output files according to opts
    println!("Network rules: {}", network.len());
    println!("Browser rules: {}", browser.len());
}
