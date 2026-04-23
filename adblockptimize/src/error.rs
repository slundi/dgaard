use hickory_resolver::proto::ProtoError;
use thiserror::Error;

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

#[derive(Error, Debug)]
pub enum ListError<'a> {
    #[error("Invalid domain {1}: {0}")]
    InvalidDomain(#[source] ProtoError, &'a str),
    #[error("Failed to parse line: {1}, format: {2}. Internal error: {0}")]
    ParseError(#[source] std::io::Error, &'a str, &'a str),
    #[error("Line skipped (empty or comment)")]
    Skip,
    #[error("Browser-only rule (cosmetic/scriptlet): {0}")]
    BrowserRule(&'a str),
}
