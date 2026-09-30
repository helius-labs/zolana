#[cfg(any(feature = "client", feature = "setup"))]
mod groth16;
#[cfg(feature = "client")]
mod proof;
#[cfg(feature = "client")]
mod proof_inputs;
#[cfg(all(feature = "client", feature = "setup"))]
mod r1cs;
#[cfg(feature = "client")]
mod reduction;
#[cfg(feature = "client")]
mod snarkjs;
#[cfg(feature = "client")]
mod synthesis;
#[cfg(feature = "client")]
mod zkey;

#[cfg(any(feature = "client", feature = "setup"))]
pub use groth16::{Groth16Keys, Proof, ProvingKey, SolanaVerifyingKey, VerifyingKey};
#[cfg(feature = "client")]
pub use groth16::{Groth16Prover, ProofResult, SolanaProof};
#[cfg(feature = "setup")]
pub use groth16::{SetupKind, VerifyingKeyExport};
#[cfg(feature = "client")]
pub use proof_inputs::ProofInputs;
#[cfg(all(feature = "client", feature = "setup"))]
pub use r1cs::R1cs;
#[cfg(feature = "client")]
pub(crate) use synthesis::{ArkworksCircuit, Statement};
