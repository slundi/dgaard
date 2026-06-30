//! Core types and primitives for the dgaard monitor daemon.
//!
//! This crate contains protocol/state/storage/io that all frontends
//! (TUI, REST/WS/MCP, NATS) depend on, with zero HTTP, UI, or sink
//! concerns of its own.

pub mod config;
pub mod db;
pub mod error;
pub mod forwarding;
pub mod io;
pub mod protocol;
pub mod state;
pub mod util;
