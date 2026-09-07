//! # zolana-program
//!
//! SPP protocol math for Solana programs. Everything here is `no_std`, depends
//! only on `zolana-hasher`, and builds for the SBF target, so a program that
//! consumes SPP transactions through CPI can recompute the values the proof
//! derives instead of trusting instruction data.
//!
//! What belongs here: derivations shared between an SPP proof and the program
//! that verifies its effects, such as the transaction-secret derivations in
//! [`derivation`]. `zolana-transaction` delegates to this crate so the math has
//! one implementation for clients and programs alike.
//!
//! What does not belong here: anything that needs randomness, signing, or
//! encryption. Those stay in the host-only SDK crates (`zolana-keypair`,
//! `zolana-transaction`), which pull dependencies that do not build for SBF.

#![no_std]

pub mod derivation;

pub use derivation::{
    derive_output_blinding_seed, derive_private_tx_blinding, derive_transact_output_blinding,
    DOMAIN_PRIVATE_TX_BLINDING_V1, DOMAIN_TRANSACT_OUTPUT_BLINDING_SEED_V1,
    DOMAIN_TRANSACT_OUTPUT_BLINDING_V1,
};
