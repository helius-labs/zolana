#![cfg_attr(not(feature = "circuit"), no_std)]

extern crate alloc;

#[cfg(feature = "cpi")]
pub use zolana_instruction::cpi;
pub use zolana_instruction::{
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
pub use zolana_circuit::{EncryptionCodec, input, xark, poseidon, require, require_eq, CircuitError, CircuitErrorKind, Field, ArrayVec, PaddedInput, ShieldedAddress, SigningPubkey, UtxoOwner};
#[cfg(all(feature = "circuit", not(xark)))]
pub use zolana_circuit::{from_bytes, to_bytes};
#[cfg(feature = "circuit")]
pub use zolana_circuit::protocol::TxContext;
#[cfg(feature = "circuit")]
pub use zolana_macros::{ZkProgram, UtxoState, PublicInputs};

#[cfg(all(feature = "client", not(xark), not(xark_client)))]
mod client;
#[cfg(all(feature = "client", not(xark), not(xark_client)))]
pub use client::{DataUtxo, ClientError, InputRecords, ProgramProofInputs, ProgramTransaction, ProgramOwner};
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

#[cfg(feature = "circuit")]
#[doc(hidden)]
pub mod __private {
    pub use borsh;
    #[cfg(all(feature = "wasm", not(xark), not(xark_client)))]
    pub use wasm_bindgen;
}

#[cfg(all(feature = "wasm", not(xark), not(xark_client)))]
#[macro_export]
macro_rules! __zk_wasm { ($($item:item)*) => { $($item)* }; }
#[cfg(not(all(feature = "wasm", not(xark), not(xark_client))))]
#[macro_export]
macro_rules! __zk_wasm { ($($item:item)*) => {}; }
