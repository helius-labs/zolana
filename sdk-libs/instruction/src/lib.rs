//! # spr-instruction
//!
//! SPP instructions for Solana programs. Everything here is `no_std` and
//! builds for the SBF target, so a program that consumes SPP transactions
//! through CPI can build the shielded-pool instruction and recompute the values
//! the proof derives instead of trusting instruction data. `spr-program`
//! re-exports this crate.
//!
//! What belongs here: the shielded-pool instruction builders in
//! [`instruction`], and derivations shared between an SPP proof and the
//! program that verifies its effects, such as the blinding seed derivations in
//! [`derivation`], the `external_data_hash` assembly in [`external_data`], the
//! `private_tx_hash` in [`private_tx`] and the transaction hash that binds a
//! ZK program's proof to its public transfers in [`public_transfer`].
//! `spr-transaction` delegates to this crate so the math has one
//! implementation for clients and programs alike.
//!
//! The `cpi` feature adds `cpi`, the transact CPI for pinocchio programs.
//!
//! Protocol authority and maintenance builders live in `spr-protocol-instructions`.
//!
//! What does not belong here: anything that needs randomness, signing, or
//! encryption. Those stay in the host-only SDK crates (`spr-keypair`,
//! `spr-transaction`), which pull dependencies that do not build for SBF.

#![no_std]

extern crate alloc;

#[cfg(feature = "cpi")]
pub mod cpi;
pub mod derivation;
pub mod external_data;
pub mod instruction;
pub mod private_tx;
pub mod public_transfer;

pub use derivation::{
    derive_output_blinding_seed, derive_private_tx_blinding, derive_transact_output_blinding,
    DOMAIN_PRIVATE_TX_BLINDING_V1, DOMAIN_TRANSACT_OUTPUT_BLINDING_SEED_V1,
    DOMAIN_TRANSACT_OUTPUT_BLINDING_V1,
};
pub use external_data::{
    ExternalDataHashError, SettlementAccounts, TransactExternalData, TransactInputs,
};
pub use private_tx::PrivateTxHash;
pub use public_transfer::{transaction_hash, PublicTransfer};

/// Default tree id an address is derived under: the tree a new address is
/// created in when the caller does not pick one.
pub const ADDRESS_TREE_ID: u16 = 0;
