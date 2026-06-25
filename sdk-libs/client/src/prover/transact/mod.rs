pub mod eddsa;
pub mod p256_and_eddsa;
pub mod witness;

pub use eddsa::{TransferProofResult, TransferProver};
pub use p256_and_eddsa::{
    P256Owner, PublicAmounts, TransferP256ProofResult, TransferP256Prover, TransferSpendInput,
};
pub use witness::{assemble, into_prover, AssembledTransfer, CircuitType, ProverInputs, SpendProof};
