#![cfg_attr(not(feature = "circuit"), no_std)]

extern crate alloc;

pub use zolana_instruction::*;

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
#[cfg(feature = "client")]
pub mod testing;
#[cfg(feature = "wasm")]
pub mod wasm;

#[cfg(feature = "circuit")]
pub use client::{Bytes, DataUtxo, Owner, ProgramOwner, TxContext};
#[cfg(feature = "client")]
pub use client::{ProgramTransaction, ZkCircuit, ZkProgram};
pub use compressed_proof::CompressedProof;
#[cfg(feature = "circuit")]
pub use error::{
    CircuitError, CircuitErrorKind, ClientError, ClientErrorKind, ProverError, ProverErrorKind,
    SlotKind, SourceLocation,
};
#[cfg(all(feature = "client", feature = "setup"))]
pub use prover::R1cs;
#[cfg(any(feature = "client", feature = "setup"))]
pub use prover::{Groth16Keys, Proof, ProvingKey, SolanaVerifyingKey, VerifyingKey};
#[cfg(feature = "client")]
pub use prover::{Groth16Prover, ProofInputs, ProofResult, SolanaProof};
#[cfg(feature = "setup")]
pub use prover::{SetupKind, VerifyingKeyExport};
