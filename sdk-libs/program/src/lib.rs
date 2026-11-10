//! The SDK for Solana programs built on the shielded pool (SPP): its
//! instruction builders, compressed accounts, and ZK programs with their
//! circuits, proofs and transaction client.
//!
//! **Not for production.** This crate is not audited. Keys from
//! `zolana zk compile --test`, or from any other single-party setup, are
//! insecure: whoever knows the setup's randomness, such as the fixed public
//! seed `--test` uses, can forge proofs. A program that holds real funds needs
//! keys from a trusted setup ceremony, its own verifying keys and an audit.

#![cfg_attr(not(any(feature = "circuit", feature = "shielded-pda")), no_std)]

extern crate alloc;

#[cfg(feature = "cpi")]
pub use spr_instruction::cpi;
pub use spr_instruction::{
    derivation, derive_output_blinding_seed, derive_private_tx_blinding,
    derive_transact_output_blinding, external_data, instruction, private_tx, public_transfer,
    transaction_hash, ExternalDataHashError, PrivateTxHash, PublicTransfer, SettlementAccounts,
    TransactExternalData, TransactInputs, ADDRESS_TREE_ID, DOMAIN_PRIVATE_TX_BLINDING_V1,
    DOMAIN_TRANSACT_OUTPUT_BLINDING_SEED_V1, DOMAIN_TRANSACT_OUTPUT_BLINDING_V1,
};

mod compressed_proof;

/// The most inputs one Poseidon hash takes. A program's public fields plus the
/// transaction hash fold into one such hash, and so does every public array.
/// `spr-macros` repeats this bound in its derive checks.
pub const MAX_POSEIDON_INPUTS: usize = 12;
pub use compressed_proof::CompressedProof;
pub mod hasher;

#[cfg(feature = "circuit")]
pub mod circuit;
#[cfg(feature = "compression")]
pub mod program;
#[cfg(feature = "verifier")]
pub mod verifier;
#[cfg(feature = "circuit")]
pub use spr_circuit::protocol::TxContext;
#[cfg(feature = "circuit")]
pub use spr_circuit::{
    checked, input, poseidon, require, require_eq, xark, ArrayVec, Asset, CircuitError,
    CircuitErrorKind, EncryptionCodec, Field, PaddedInput, ShieldedAddress, SigningPubkey,
    UtxoOwner,
};
#[cfg(all(feature = "circuit", not(xark)))]
pub use spr_circuit::{from_bytes, from_decimal, to_bytes};
#[cfg(feature = "circuit")]
pub use spr_macros::{ClientInputs, PublicInputs, UtxoState, ZkProgram};

#[cfg(all(feature = "shielded-pda", not(xark), not(xark_client)))]
mod shielded_pda;
#[cfg(all(feature = "shielded-pda", not(xark), not(xark_client)))]
pub use shielded_pda::ShieldedPda;
#[cfg(all(feature = "client", not(xark), not(xark_client)))]
mod client;
#[cfg(all(feature = "client", not(xark), not(xark_client)))]
pub use client::{
    ClientError, ClientInputs, DataUtxo, InputRecords, ProgramOwner, ProgramProofInputs,
    ProgramTransaction, TransactionOptions,
};
#[cfg(all(feature = "client", not(xark), not(xark_client)))]
pub mod proof;
#[cfg(all(feature = "wasm", not(xark), not(xark_client)))]
pub mod wasm;

#[cfg(all(feature = "build", not(xark), not(xark_client)))]
pub mod build;

#[cfg(all(feature = "build", not(xark), not(xark_client)))]
#[macro_export]
macro_rules! __zk_export { ($($item:item)*) => { $($item)* }; }
#[cfg(not(all(feature = "build", not(xark), not(xark_client))))]
#[macro_export]
macro_rules! __zk_export {
    ($($item:item)*) => {};
}

#[cfg(feature = "circuit")]
#[doc(hidden)]
pub mod __private {
    pub use alloc::{vec, vec::Vec};
    pub use borsh;
    #[cfg(all(feature = "client", not(xark), not(xark_client)))]
    pub use solana_address::Address;
    #[cfg(all(feature = "client", not(xark), not(xark_client)))]
    pub use spr_keypair::ShieldedAddress as NativeShieldedAddress;
    #[cfg(all(feature = "client", not(xark), not(xark_client)))]
    pub use spr_transaction::{Mint, WalletUtxo};
    #[cfg(all(feature = "wasm", not(xark), not(xark_client)))]
    pub use {
        serde,
        spr_circuit::field_serde,
        spr_keypair::serde_helpers::bytes,
        tsify::{self, Ts},
        wasm_bindgen,
    };
}

#[cfg(all(feature = "client", not(xark), not(xark_client)))]
#[macro_export]
macro_rules! __zk_client { ($($item:item)*) => { $($item)* }; }
#[cfg(not(all(feature = "client", not(xark), not(xark_client))))]
#[macro_export]
macro_rules! __zk_client {
    ($($item:item)*) => {};
}

#[cfg(all(feature = "wasm", not(xark), not(xark_client)))]
#[macro_export]
macro_rules! __zk_wasm { ($($item:item)*) => { $($item)* }; }
#[cfg(not(all(feature = "wasm", not(xark), not(xark_client))))]
#[macro_export]
macro_rules! __zk_wasm {
    ($($item:item)*) => {};
}
