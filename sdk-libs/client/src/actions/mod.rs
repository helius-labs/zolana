//! Build-and-send actions for shielded-pool operations over [`Rpc`].
//!
//! [`Rpc`]: crate::rpc::Rpc

pub mod proofless_shield;

pub use proofless_shield::proofless_shield;
