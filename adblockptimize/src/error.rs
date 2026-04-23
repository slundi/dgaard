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
