//! dgaard-engine — embeddable domain filtering and scoring library.
//!
//! This crate provides the core DNS filtering engine used by `dgaard`.
//! It can be embedded into any consumer (DNS proxy, MTA, HTTP service, etc.)
//! without pulling in async runtimes or networking dependencies.
//!
//! # Quick start
//!
//! ```rust,no_run
//! use dgaard_engine::{Config, FilterEngine, resolve_with_score};
//!
//! let config = Config::default();
//! let seed = 42u64;
//! let filter = FilterEngine::build_from_files(&config, seed);
//! let result = resolve_with_score("example.com", &filter, &config);
//! println!("{:?}", result.action);
//! ```

pub mod config;
pub mod dga;
pub mod filter;
pub mod model;
pub mod resolve;
pub mod utils;

// Top-level re-exports for ergonomic use
pub use config::Config;
pub use filter::engine::FilterEngine;
pub use model::{Action, BlockReason, InspectedAnswer, SuspicionScore};
pub use resolve::{ResolveResult, resolve_with_score};
