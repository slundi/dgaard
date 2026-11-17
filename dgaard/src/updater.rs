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
    if input.is_empty() {
        return Err(ResourceError::UnknownResource);
    }

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

    // 3. If it looks like a URL (starts with http) but failed parsing
    if input.starts_with("http") {
        eprintln!("Invalid URL: {}", input);
        return Err(ResourceError::InvalidUrl(Url::parse(input).unwrap_err()));
    }

    // 4. Anything else that didn't parse as a URL and doesn't exist on disk
    // is treated as a missing file path. The previous heuristic ("requires
    // a slash") silently misclassified bare filenames like "blocklist.txt"
    // as UnknownResource, which was confusing for operators.
    eprintln!("Invalid file path: {}", input);
    Err(ResourceError::InvalidFilePath(input.to_string()))
}

/// Delay before the next scheduled reload: `update_interval_hours`
/// normally, `retry_delay_mins` after a degraded reload (a list served from
/// its last valid copy, missing, or a timeout), so a list missed at boot or
/// during an outage comes back without waiting a full interval. `None`
/// disables scheduled updates.
pub fn next_update_delay(interval_hours: u32, retry_mins: u32, degraded: bool) -> Option<Duration> {
    if interval_hours == 0 {
        return None;
    }
    let interval = Duration::from_hours(interval_hours.into());
    if degraded && retry_mins > 0 {
        Some(Duration::from_mins(retry_mins.into()).min(interval))
    } else {
        Some(interval)
    }
}

/// Run scheduled list updates. `degraded` is the state of the reload that
/// just happened (startup), deciding the first delay.
pub async fn spawn_update_task(mut degraded: bool) {
    tokio::spawn(async move {
        loop {
            // Re-read on every iteration so a SIGHUP config reload takes effect
            // without restarting the process.
            let delay = {
                let sources = &CONFIG.load().sources;
                next_update_delay(
                    sources.update_interval_hours,
                    sources.retry_delay_mins,
                    degraded,
                )
            };
            let Some(delay) = delay else {
                return;
            };
            tokio::time::sleep(delay).await;

            println!("Starting scheduled rule update...");
            degraded = reload_lists().await.is_degraded();
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
            validate_input("../README.md").unwrap()
                == Resource::FilePath(PathBuf::from("../README.md"))
        );

        assert!(
            validate_input("../dgaard/Cargo.toml").unwrap()
                == Resource::FilePath(PathBuf::from("../dgaard/Cargo.toml"))
        );

        assert!(validate_input("not_a_valid_resource").is_err())
    }

    #[test]
    fn bare_filename_that_does_not_exist_is_invalid_file_path() {
        // Regression: a bare filename like `blocklist.txt` with no slash used to
        // be silently classified as UnknownResource, which made config errors
        // confusing to debug.
        match validate_input("definitely-not-a-real-file-blocklist.txt") {
            Err(ResourceError::InvalidFilePath(s)) => {
                assert_eq!(s, "definitely-not-a-real-file-blocklist.txt");
            }
            other => panic!("expected InvalidFilePath, got {other:?}"),
        }
    }

    #[test]
    fn next_update_delay_uses_the_interval_when_healthy() {
        assert_eq!(
            next_update_delay(24, 30, false),
            Some(Duration::from_hours(24))
        );
    }

    #[test]
    fn next_update_delay_retries_early_when_degraded() {
        assert_eq!(
            next_update_delay(24, 30, true),
            Some(Duration::from_mins(30))
        );
        // Never later than the regular interval.
        assert_eq!(
            next_update_delay(1, 90, true),
            Some(Duration::from_hours(1))
        );
        // retry_delay_mins = 0 disables early retries.
        assert_eq!(
            next_update_delay(24, 0, true),
            Some(Duration::from_hours(24))
        );
    }

    #[test]
    fn next_update_delay_disabled_without_interval() {
        assert_eq!(next_update_delay(0, 30, true), None);
    }

    #[test]
    fn empty_input_returns_unknown_resource() {
        assert!(matches!(
            validate_input(""),
            Err(ResourceError::UnknownResource)
        ));
    }
}
