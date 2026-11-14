//! Domain services shared by every front-end (REST API, MCP, web UI).
//!
//! Front-ends only translate their transport input into the request types
//! defined here and map [`ServiceError`] back to their own error shape.
//! Filtering, persistence fallback and detection logic live here only, so
//! the surfaces cannot drift apart.

pub mod beaconing;
pub mod events;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("invalid IP address: {0}")]
    InvalidIp(String),

    #[error(
        "invalid action '{0}': must be one of: allowed, blocked, suspicious, highlysuspicious, proxied"
    )]
    InvalidAction(String),

    #[error("persistence not configured")]
    PersistenceUnavailable,

    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("task error: {0}")]
    Task(#[from] tokio::task::JoinError),
}
