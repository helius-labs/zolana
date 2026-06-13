//! Forester for shielded-pool nullifier-tree maintenance.
//!
//! Proof generation lives in `prover/client`; this crate handles the on-chain
//! submission path only.

pub type Result<T> = anyhow::Result<T>;

pub mod cli;
pub mod config;
pub mod errors;
pub mod forest;
pub mod logging;
pub mod utils;

pub use forest::{batch_update_nullifier_tree_once, ForestError, ForestParams};
