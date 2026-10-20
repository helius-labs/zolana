//! # zolana-program
//!
//! SPP SDK for Solana programs. Everything here is `no_std` and builds for the
//! SBF target, so a program that consumes SPP transactions through CPI can
//! build the shielded-pool instruction and recompute the values the proof
//! derives instead of trusting instruction data.
//!
//! The shielded-pool instruction builders ([`instruction`]) and the
//! derivations shared between an SPP proof and the program that verifies its
//! effects ([`derivation`], [`external_data`], [`private_tx`]) live in
//! `zolana-instruction` and are re-exported here under the same paths.
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
pub use zolana_instruction::cpi;
pub use zolana_instruction::{
    derivation, derive_output_blinding_seed, derive_private_tx_blinding,
    derive_transact_output_blinding, external_data, instruction, private_tx, ExternalDataHashError,
    PrivateTxHash, SettlementAccounts, TransactExternalData, TransactInputs, ADDRESS_TREE_ID,
    DOMAIN_PRIVATE_TX_BLINDING_V1, DOMAIN_TRANSACT_OUTPUT_BLINDING_SEED_V1,
    DOMAIN_TRANSACT_OUTPUT_BLINDING_V1,
};
