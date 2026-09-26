//! # zolana-program
//!
//! SPP SDK for Solana programs. Everything here is `no_std` and builds for the
//! SBF target, so a program that consumes SPP transactions through CPI can
//! build the shielded-pool instruction and recompute the values the proof
//! derives instead of trusting instruction data.
//!
//! What belongs here: the shielded-pool instruction builders in
//! [`instruction`], and derivations shared between an SPP proof and the
//! program that verifies its effects, such as the blinding seed derivations in
//! [`derivation`], the `external_data_hash` assembly in [`external_data`] and
//! the `private_tx_hash` in [`private_tx`]. `zolana-transaction` delegates to
//! this crate so the math has one implementation for clients and programs
//! alike.
//!
//! Two features serve pinocchio programs. `cpi` adds `cpi`, the transact CPI.
//! `compression` adds `compression`, program state kept as SPP UTXOs, on top
//! of it.
//!
//! The builders for protocol operations (protocol and fee authority
//! administration, tree creation, ring activation, and the forester's
//! nullifier tree maintenance) sit behind the non-default `protocol` feature.
//!
//! What does not belong here: anything that needs randomness, signing, or
//! encryption. Those stay in the host-only SDK crates (`zolana-keypair`,
//! `zolana-transaction`), which pull dependencies that do not build for SBF.

#![no_std]

extern crate alloc;

#[cfg(feature = "compression")]
pub mod compression;
#[cfg(feature = "cpi")]
pub mod cpi;
pub mod derivation;
pub mod external_data;
pub mod instruction;
pub mod private_tx;

pub use derivation::{
    derive_output_blinding_seed, derive_private_tx_blinding, derive_transact_output_blinding,
    DOMAIN_PRIVATE_TX_BLINDING_V1, DOMAIN_TRANSACT_OUTPUT_BLINDING_SEED_V1,
    DOMAIN_TRANSACT_OUTPUT_BLINDING_V1,
};
pub use external_data::{
    ExternalDataHashError, SettlementAccounts, TransactExternalData, TransactInputs,
};
pub use private_tx::PrivateTxHash;
