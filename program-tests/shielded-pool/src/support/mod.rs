//! Shared shielded-pool test fixtures and backend helpers.
//!
//! - [`runtime`]: LiteSVM setup and account sizing.
//! - [`fixtures`]: initialized pool environments and builders.
//! - [`transact`]: transact fixtures and tree helpers.
//! - [`localnet`]: Solana RPC and indexing helpers.
//! - [`mollusk`]: Mollusk snapshot fixtures.
//! - [`forester`]: local-validator nullifier-tree driver.

pub mod fixtures;
pub mod mollusk;
pub mod runtime;
pub mod transact;

#[cfg(feature = "localnet")]
pub mod forester;
#[cfg(feature = "localnet")]
pub mod localnet;
