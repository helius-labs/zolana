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
#[cfg(feature = "compression")]
pub mod compression;
#[cfg(feature = "circuit")]
pub mod conversion;
#[cfg(feature = "circuit")]
mod error;
#[cfg(feature = "circuit")]
pub mod hasher;
#[cfg(feature = "test-support")]
pub mod testing;
#[cfg(feature = "verifier")]
pub mod verifier;
// Build-time codegen: only the r1cs export hook and its tests render verifiers.
#[cfg(feature = "setup")]
mod verifier_codegen;
#[cfg(feature = "wasm")]
pub mod wasm;

#[cfg(feature = "circuit")]
pub use client::{
    Bytes, DataUtxo, Owner, ProgramOwner, PublicField, PublicFieldKind, PublicHashField,
    PublicInputLayout, TxContext,
};
#[cfg(feature = "client")]
pub use client::{ProgramTransaction, ZkCircuit, ZkProgram};
#[cfg(feature = "circuit")]
pub use error::{ClientError, ClientErrorKind, ProtocolCircuitErrorKind, SlotKind};
#[cfg(feature = "circuit")]
pub use zolana_keypair::circuit::OwnerCircuitErrorKind;
#[cfg(feature = "circuit")]
pub use zolana_macros::ZkProgram;
// The gates of the ZkCircuit derive, on the zk DSL's features, which this
// crate's features forward.
#[cfg(feature = "circuit")]
#[doc(hidden)]
pub use zolana_zk_dsl::{__zk_circuit_r1cs, __zk_circuit_wasm, __zk_circuit_wasm_prover};
// The derive alone; with `client`, `zolana_zk_dsl::ZkCircuit` brings the
// derive and the trait of the same name.
#[cfg(feature = "circuit")]
pub use zolana_transaction::circuit::UtxoCircuitErrorKind;
#[cfg(feature = "build")]
pub use zolana_zk_dsl::build;
#[cfg(all(feature = "circuit", not(feature = "client")))]
pub use zolana_zk_dsl::circuit::ZkCircuit;
pub use zolana_zk_dsl::CompressedProof;
#[cfg(feature = "setup")]
pub use zolana_zk_dsl::R1cs;
#[cfg(feature = "circuit")]
pub use zolana_zk_dsl::{
    CircuitError, CircuitErrorKind, ProtocolError, ProtocolErrorKind, ProverError, ProverErrorKind,
    SourceLocation,
};
#[cfg(feature = "client")]
pub use zolana_zk_dsl::{Groth16Keys, Proof, ProvingKey, SolanaVerifyingKey, VerifyingKey};
#[cfg(feature = "client")]
pub use zolana_zk_dsl::{Groth16Prover, ProofInputs, ProofResult, SolanaProof};
#[cfg(feature = "setup")]
pub use zolana_zk_dsl::{SetupKind, VerifyingKeyExport};
