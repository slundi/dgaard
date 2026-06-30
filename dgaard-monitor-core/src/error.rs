use thiserror::Error;

#[derive(Debug, Error)]
pub enum MonitorError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid index: {0}")]
    InvalidIndex(String),

    #[error("Invalid message: {0}")]
    InvalidMessage(String),

    #[error("Socket error: {0}")]
    SocketError(String),
}
