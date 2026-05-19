//! Event types emitted by the shielded-pool program.
//!
//! These events let indexers reconstruct tree state from transaction logs
//! without having to read the full ~1.16 MB pool-tree account. The program
//! does not emit them yet — that wiring lands together with the indexer/RPC
//! work in a follow-up.

pub mod event;
pub use event::*;
