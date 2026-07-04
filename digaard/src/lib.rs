//! digaard — a modern DNS lookup CLI. Library surface exposed for integration tests.

pub mod cli;
pub mod config;
pub mod dnssec;
pub mod error;
pub mod geoip;
pub mod idn;
pub mod output;
pub mod prepass;
pub mod query;
pub mod stats;
pub mod transport;
