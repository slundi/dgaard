pub mod config;
pub mod error;
pub mod routes;
pub mod state;

/// Hash seed used for all domain fingerprinting within this service.
pub const HASH_SEED: u64 = 42;
