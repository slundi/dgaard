use hickory_proto::serialize::binary::DecodeError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid name: {0}")]
    InvalidName(String),

    #[error("transport error: {0}")]
    Transport(String),

    #[error("DNS encode error: {0}")]
    Encode(#[from] hickory_proto::ProtoError),

    #[error("DNS decode error: {0}")]
    Decode(#[from] DecodeError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("timeout waiting for response")]
    Timeout,

    #[error("response truncated (TC bit set); retry with --tcp")]
    Truncated,
}

pub type Result<T> = std::result::Result<T, Error>;
