#[cfg(any(feature = "client", feature = "setup"))]
mod groth16;
#[cfg(feature = "client")]
mod synthesis;

#[cfg(feature = "setup")]
pub use groth16::VerifyingKeyExport;
#[cfg(feature = "client")]
pub use groth16::{CompressedProof, Groth16Prover, ProofResult, SolanaProof};
#[cfg(any(feature = "client", feature = "setup"))]
pub use groth16::{Groth16Keys, Proof, ProvingKey, SolanaVerifyingKey, VerifyingKey};
#[cfg(feature = "client")]
pub(crate) use synthesis::ArkworksCircuit;
