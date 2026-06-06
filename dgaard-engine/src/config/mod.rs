//! Configuration module for the dgaard filtering engine.
//!
//! This module provides:
//! - [`Config`]: The complete runtime configuration
//! - [`ConfigError`]: Error types for parsing and loading

mod model;
mod parser;

pub use model::*;
#[allow(unused_imports)]
pub use parser::ConfigError;
