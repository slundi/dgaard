mod cli;
mod error;
mod http;
mod io;
mod model;

use std::path::Path;

use rayon::prelude::*;
use url::Url;

use crate::{
    error::ResourceError,
    http::{HttpsClient, build_https_client, download_list},
    model::Resource,
};

const WILDCARD_RULE: u8 = 0b00000001;
const REGEX_RULE: u8 = 0b00000010;

pub fn validate_input(input: &str) -> Result<Resource, ResourceError> {
    // 1. Try to parse as a URL
    if let Ok(parsed_url) = Url::parse(input) {
        // Check if it's specifically HTTP or HTTPS
        if parsed_url.scheme() == "http" || parsed_url.scheme() == "https" {
            return Ok(Resource::HttpUrl(parsed_url));
        } else {
            // It's a valid URL format (like ftp://), but we don't support the scheme
            eprintln!("Invalid protocol URL: {}", input);
            return Err(ResourceError::NonHttpScheme);
        }
    }

    // 2. Try to treat as a File Path
    // We check if the path exists to distinguish it from just "random text"
    let path = Path::new(input);
    if path.exists() {
        return Ok(Resource::FilePath(path.to_path_buf()));
    }

    // Explicitly catch cases that look like paths but don't exist
    // This uses a simple heuristic: if it contains a slash or backslash
    if input.contains('/') || input.contains('\\') {
        eprintln!("Invalid file path: {}", input);
        return Err(ResourceError::InvalidFilePath(input.to_string()));
    }

    // 3. If it looks like a URL (starts with http) but failed parsing
    if input.starts_with("http") {
        eprintln!("Invalid URL: {}", input);
        return Err(ResourceError::InvalidUrl(Url::parse(input).unwrap_err()));
    }

    Err(ResourceError::UnknownResource)
}

/// Load a source (file path or URL) into the filter collections.
pub async fn load_source(
    source: &str,
    client: &HttpsClient,
    network_rules: &mut Vec<(String, u8)>,
    browser_rules: &mut Vec<String>,
) {
    match validate_input(source) {
        Ok(Resource::HttpUrl(url)) => match download_list(client, &url).await {
            Ok(content) => {
                println!("Downloaded {} ({} bytes)", source, content.len());
                // load_list_content(
                //     &content,
                //     network_rules,
                //     browser_rules,
                // );
            }
            Err(e) => eprintln!("Warning: Failed to download {}: {}", source, e),
        },
        Ok(Resource::FilePath(_)) => {
            // if let Err(e) = load_list_file(
            //     source,
            //     network_rules,
            //     browser_rules,
            // ) {
            //     eprintln!("Warning: Failed to load {}: {}", source, e);
            // }
        }
        Err(e) => eprintln!("Warning: Invalid source {}: {}", source, e),
    }
}

#[tokio::main]
async fn main() {
    let opts = cli::parse();
    let client = build_https_client();
    // process lists in parralel
    opts.paths.par_iter().for_each(|list| {
        let mut network: Vec<(String, u8)> = Vec::new();
        let mut browser: Vec<String> = Vec::new(); // only ABP rules
        load_source(list, &client, &mut network, &mut browser);
    });

    // gather result, deduplicate, sort
}
