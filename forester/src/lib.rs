//! Forester for shielded-pool nullifier-tree maintenance.
//!
//! Proof generation lives in `prover/client`; this crate handles the on-chain
//! submission path only.

pub mod cli;
pub mod forest;
pub mod info;
pub mod logging;
pub mod photon;
pub mod run;

pub use forest::{batch_update_nullifier_tree_once, ForestError, ForestParams};
