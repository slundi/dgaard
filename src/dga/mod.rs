//! DGA (Domain Generation Algorithm) detection module.
//!
//! This module provides heuristics for detecting algorithmically generated
//! domain names used by malware for C2 communication.
//!
//! Features:
//! - Shannon entropy calculation
//! - Consonant ratio and clustering detection
//! - N-gram language model analysis (embedded and external)

pub mod entropy;
pub mod lexical;
pub mod ngram;
