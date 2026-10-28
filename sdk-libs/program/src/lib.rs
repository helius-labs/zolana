#![cfg_attr(not(feature = "circuit"), no_std)]

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
pub use compressed_proof::CompressedProof;
pub mod hasher;

#[cfg(feature = "compression")]
pub mod program;
#[cfg(feature = "verifier")]
pub mod verifier;
#[cfg(feature = "circuit")]
pub mod circuit;
#[cfg(feature = "circuit")]
pub use spr_circuit::{EncryptionCodec, input, xark, poseidon, require, require_eq, CircuitError, CircuitErrorKind, Field, ArrayVec, PaddedInput, ShieldedAddress, SigningPubkey, UtxoOwner};
#[cfg(all(feature = "circuit", not(xark)))]
pub use spr_circuit::{from_bytes, to_bytes, from_decimal};
#[cfg(feature = "circuit")]
pub use spr_circuit::protocol::TxContext;
#[cfg(feature = "circuit")]
pub use spr_macros::{ZkProgram, UtxoState, PublicInputs, ClientInputs};

#[cfg(all(feature = "client", not(xark), not(xark_client)))]
mod client;
#[cfg(all(feature = "client", not(xark), not(xark_client)))]
pub use client::{DataUtxo, ClientError, InputRecords, ProgramProofInputs, ProgramTransaction, ProgramOwner, TransactionOptions, ClientInputs};
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
macro_rules! __zk_export { ($($item:item)*) => {}; }

#[cfg(all(feature = "build", not(xark), not(xark_client)))]
pub use build::SetupKind;

#[cfg(feature = "circuit")]
#[doc(hidden)]
pub mod __private {
    pub use alloc::{string::String, vec, vec::Vec};
    pub use borsh;
    #[cfg(all(feature = "client", not(xark), not(xark_client)))]
    pub use spr_keypair::ShieldedAddress as NativeShieldedAddress;
    #[cfg(all(feature = "client", not(xark), not(xark_client)))]
    pub use spr_transaction::WalletUtxo;
    #[cfg(all(feature = "client", not(xark), not(xark_client)))]
    pub use solana_address::Address;
    #[cfg(all(feature = "client", not(xark), not(xark_client)))]
    pub use crate::client::transaction::fail as client_error;
    #[cfg(all(feature = "wasm", not(xark), not(xark_client)))]
    pub use wasm_bindgen;
    #[cfg(all(feature = "wasm", not(xark), not(xark_client)))]
    pub use tsify::Ts;
}

#[cfg(all(feature = "client", not(xark), not(xark_client)))]
#[macro_export]
macro_rules! __zk_client { ($($item:item)*) => { $($item)* }; }
#[cfg(not(all(feature = "client", not(xark), not(xark_client))))]
#[macro_export]
macro_rules! __zk_client { ($($item:item)*) => {}; }

#[cfg(all(feature = "wasm", not(xark), not(xark_client)))]
#[macro_export]
macro_rules! __zk_wasm { ($($item:item)*) => { $($item)* }; }
#[cfg(not(all(feature = "wasm", not(xark), not(xark_client))))]
#[macro_export]
macro_rules! __zk_wasm { ($($item:item)*) => {}; }
