//! Build-and-send actions for shielded-pool operations, layered over the [`Rpc`]
//! trait so clients (the CLI, integrations) can perform an operation in a single
//! call. Mirrors light-protocol's `token-client` actions, but synchronous — the
//! SPP client rail is blocking, so there is no `.await`.
//!
//! [`Rpc`]: crate::rpc::Rpc

pub mod proofless_shield;

pub use proofless_shield::proofless_shield;
