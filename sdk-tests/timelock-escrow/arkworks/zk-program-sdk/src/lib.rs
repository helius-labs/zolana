pub mod circuit;
mod circuit_lib;
mod client;
pub mod conversion;
mod error;
pub mod program;
mod prover;

pub use ark_std::rand;
#[cfg(feature = "client")]
pub use client::ZkProgram;
pub use client::{Bytes, Owner, TxContext};
pub use error::RelationError;
pub use prover::ArkworksCircuit;
#[cfg(feature = "setup")]
pub use prover::VerifyingKeyExport;
#[cfg(feature = "client")]
pub use prover::{CompressedProof, SolanaProof};
#[cfg(any(feature = "client", feature = "setup"))]
pub use prover::{Groth16Keys, Proof, ProvingKey, SolanaVerifyingKey, VerifyingKey};
