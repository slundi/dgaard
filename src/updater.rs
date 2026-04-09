use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use thiserror::Error;
use url::Url;

use crate::{CONFIG, filter::reload_lists};

#[derive(Error, Debug)]
pub enum ResourceError {
    #[error("Invalid URL format: {0}")]
    InvalidUrl(#[from] url::ParseError),

    #[error("Not a valid HTTP/HTTPS scheme")]
    NonHttpScheme,

    #[error("File path does not exist or is inaccessible: {0}")]
    InvalidFilePath(String),

    #[error("Input matches neither a valid HTTP URL nor an existing file path")]
    UnknownResource,
}

#[derive(Debug, PartialEq)]
pub enum Resource {
    HttpUrl(Url),
    FilePath(PathBuf),
}

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

pub async fn spawn_update_task() {
    let hours = CONFIG.load().sources.update_interval_hours;
    let interval = Duration::from_hours(hours.into());

    tokio::spawn(async move {
        loop {
            // 1. Wait for the next update cycle
            tokio::time::sleep(interval).await;

            println!("Starting scheduled rule update...");

            // 2. Download and Parse
            reload_lists().await;
        }
    });
}

#[cfg(test)]
mod tests {
    use std::{fs::File, io::Write};

    use super::*;

    #[test]
    fn validate_url() {
        assert!(
            validate_input("https://google.com").unwrap()
                == Resource::HttpUrl(Url::parse("https://google.com").unwrap())
        );
    }

    #[test]
    fn validate_path() {
        let mut file = File::create("/tmp/foo.txt").unwrap();
        file.write_all(b"Hello, world!").unwrap();
        assert!(
            validate_input("/tmp/foo.txt").unwrap()
                == Resource::FilePath(PathBuf::from("/tmp/foo.txt"))
        );

        assert!(
            validate_input("README.md").unwrap() == Resource::FilePath(PathBuf::from("README.md"))
        );

        assert!(
            validate_input("../dgaard/README.md").unwrap()
                == Resource::FilePath(PathBuf::from("../dgaard/README.md"))
        );

        assert!(validate_input("not_a_valid_resource").is_err())
    }
}
