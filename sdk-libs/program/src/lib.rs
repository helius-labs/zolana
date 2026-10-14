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

#[cfg(feature = "circuit")]
#[doc(hidden)]
pub mod __private;
#[cfg(feature = "circuit")]
pub mod circuit;
#[cfg(feature = "circuit")]
mod client;
mod compressed_proof;
#[cfg(feature = "compression")]
pub mod compression;
#[cfg(feature = "circuit")]
pub mod conversion;
#[cfg(feature = "circuit")]
mod error;
#[cfg(feature = "circuit")]
pub mod hasher;
#[cfg(feature = "circuit")]
mod prover;
#[cfg(feature = "test-support")]
pub mod testing;
#[cfg(feature = "verifier")]
pub mod verifier;
#[cfg(feature = "circuit")]
mod verifier_glue;
#[cfg(feature = "wasm")]
pub mod wasm;

#[cfg(feature = "circuit")]
pub use client::{
    Bytes, DataUtxo, Owner, ProgramOwner, PublicField, PublicFieldKind, PublicInputLayout,
    TxContext,
};
#[cfg(feature = "client")]
pub use client::{ProgramTransaction, ZkCircuit, ZkProgram};
pub use compressed_proof::CompressedProof;
#[cfg(feature = "circuit")]
pub use error::{
    CircuitError, CircuitErrorKind, ClientError, ClientErrorKind, ProverError, ProverErrorKind,
    SlotKind, SourceLocation,
};
#[cfg(feature = "setup")]
pub use prover::R1cs;
#[cfg(feature = "client")]
pub use prover::{Groth16Keys, Proof, ProvingKey, SolanaVerifyingKey, VerifyingKey};
#[cfg(feature = "client")]
pub use prover::{Groth16Prover, ProofInputs, ProofResult, SolanaProof};
#[cfg(feature = "setup")]
pub use prover::{SetupKind, VerifyingKeyExport};
