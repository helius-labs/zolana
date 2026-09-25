pub mod circuit;
mod circuit_lib;
mod client;
pub mod conversion;
mod error;
pub mod program;
mod prover;

#[cfg(feature = "client")]
pub use client::ZkProgram;
pub use client::{Bytes, Owner, TxContext};
pub use error::RelationError;
#[cfg(feature = "setup")]
pub use prover::VerifyingKeyExport;
#[cfg(feature = "client")]
pub use prover::{CompressedProof, Groth16Prover, ProofResult, SolanaProof};
#[cfg(any(feature = "client", feature = "setup"))]
pub use prover::{Groth16Keys, Proof, ProvingKey, SolanaVerifyingKey, VerifyingKey};
