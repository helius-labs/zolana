//! Circuit DSL over BN254 for Groth16 proofs verified on Solana: circuit types
//! and operations, proof input conversion, errors, and the arkworks prover.
//! Nothing here knows the zolana protocol; `zolana-program` builds on it.
//!
//! Derives generate paths under `::zolana_program`. A crate that uses the DSL
//! without `zolana-program` names this crate so in its root:
//! `extern crate zolana_zk_dsl as zolana_program;`.

#![cfg_attr(not(feature = "circuit"), no_std)]

#[cfg(feature = "circuit")]
extern crate self as zolana_program;

#[cfg(feature = "circuit")]
#[doc(hidden)]
pub mod __private;
#[cfg(feature = "build")]
pub mod build;
#[cfg(feature = "circuit")]
pub mod circuit;
#[cfg(feature = "circuit")]
mod client;
mod compressed_proof;
#[cfg(feature = "circuit")]
pub mod conversion;
#[cfg(feature = "circuit")]
mod error;
#[cfg(feature = "wasm")]
#[doc(hidden)]
pub mod js_error;
#[cfg(feature = "circuit")]
#[doc(hidden)]
pub mod prover;
#[cfg(feature = "circuit")]
pub mod r1cs_hook;
#[cfg(feature = "test-support")]
pub mod testing;
#[cfg(feature = "verifier")]
pub mod verifier;
#[cfg(feature = "wasm")]
pub mod wasm;

#[cfg(feature = "client")]
pub use client::ZkCircuit;
#[cfg(feature = "circuit")]
pub use client::{Bytes, PublicField, PublicFieldKind, PublicHashField, PublicInputLayout};
pub use compressed_proof::CompressedProof;
#[cfg(feature = "circuit")]
pub use error::{
    CircuitError, CircuitErrorKind, ProtocolError, ProtocolErrorKind, ProverError, ProverErrorKind,
    SourceLocation,
};
#[cfg(feature = "setup")]
pub use prover::R1cs;
#[cfg(feature = "client")]
pub use prover::{Groth16Keys, Proof, ProvingKey, SolanaVerifyingKey, VerifyingKey};
#[cfg(feature = "client")]
pub use prover::{Groth16Prover, ProofInputs, ProofResult, SolanaProof};
#[cfg(feature = "setup")]
pub use prover::{SetupKind, VerifyingKeyExport};
#[cfg(feature = "circuit")]
#[doc(hidden)]
pub use zolana_zk_macros::ErrorName;
// The derive; the trait of the same name comes from `client`.
#[cfg(feature = "circuit")]
pub use zolana_zk_macros::ZkCircuit;
