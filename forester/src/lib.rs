//! Forester for the shielded-pool address sub-tree. Submits a single
//! `forest_address_tree` transaction against the registry given a pre-built
//! Groth16 proof.
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

pub use forest::{forest_address_tree_once, ForestError, ForestParams};
