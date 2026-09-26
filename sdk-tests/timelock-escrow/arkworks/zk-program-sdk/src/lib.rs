pub mod circuit;
mod circuit_lib;
mod client;
pub mod conversion;
mod error;
pub mod hasher;
pub mod program;
mod prover;
#[cfg(feature = "wasm")]
pub mod wasm;

pub use client::{Bytes, Owner, ProgramOwner, TxContext};
#[cfg(feature = "client")]
pub use client::{ProgramTransaction, ZkProgram};
pub use error::RelationError;
#[cfg(feature = "client")]
pub use prover::{CompressedProof, Groth16Prover, ProofInputs, ProofResult, SolanaProof};
#[cfg(any(feature = "client", feature = "setup"))]
pub use prover::{Groth16Keys, Proof, ProvingKey, SolanaVerifyingKey, VerifyingKey};
#[cfg(feature = "setup")]
pub use prover::{SetupKind, VerifyingKeyExport};
pub use zk_program_sdk_macros::circuit;
