#[cfg(feature = "client")]
mod groth16;
#[cfg(feature = "client")]
mod proof;
#[cfg(feature = "client")]
mod proof_inputs;
#[cfg(feature = "setup")]
mod r1cs;
#[cfg(feature = "client")]
mod reduction;
#[cfg(feature = "client")]
mod snarkjs;
#[cfg(feature = "client")]
mod synthesis;
#[cfg(feature = "client")]
mod zkey;

#[cfg(feature = "wasm-verify")]
pub(crate) use groth16::verify_groth16;
#[cfg(feature = "client")]
pub use groth16::{Groth16Keys, Proof, ProvingKey, SolanaVerifyingKey, VerifyingKey};
#[cfg(feature = "client")]
pub use groth16::{Groth16Prover, ProofResult, SolanaProof, MAX_PUBLIC_INPUTS};
#[cfg(feature = "setup")]
pub use groth16::{SetupKind, VerifyingKeyExport};
#[cfg(feature = "client")]
pub use proof_inputs::ProofInputs;
#[cfg(feature = "setup")]
pub use r1cs::R1cs;
#[cfg(feature = "client")]
#[doc(hidden)]
pub use synthesis::ArkworksCircuit;
