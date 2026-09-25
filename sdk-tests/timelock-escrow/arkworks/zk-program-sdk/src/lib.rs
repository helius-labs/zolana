pub mod circuit;
mod circuit_lib;
mod client;
pub mod conversion;
mod error;
mod prover;

pub use ark_std::rand;
pub use client::TxContext;
#[cfg(feature = "client")]
pub use client::ZkProgram;
pub use error::RelationError;
pub use prover::ArkworksCircuit;
#[cfg(feature = "setup")]
pub use prover::VerifyingKeyExport;
#[cfg(feature = "client")]
pub use prover::{CompressedProof, SolanaProof};
#[cfg(any(feature = "client", feature = "setup"))]
pub use prover::{Groth16Keys, Proof, ProvingKey, SolanaVerifyingKey, VerifyingKey};
