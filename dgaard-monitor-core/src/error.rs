use thiserror::Error;

#[derive(Debug, Error)]
pub enum MonitorError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid index: {0}")]
    InvalidIndex(String),

    #[error("Invalid message: {0}")]
    InvalidMessage(String),

    /// A complete frame this monitor does not understand (e.g. an event
    /// action added by a newer dgaard). The stream is still in sync: skip it.
    #[error("Unsupported frame: {0}")]
    UnsupportedFrame(String),

    #[error("Socket error: {0}")]
    SocketError(String),
}
