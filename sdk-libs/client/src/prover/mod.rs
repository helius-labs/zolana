mod client;
mod inputs;
mod json;
mod proof;

pub use client::{spawn_prover, ProverClient, PROVE_PATH, SERVER_ADDRESS};
pub use inputs::{TransferEddsaInputs, TransferInput, TransferInputs, TransferOutput, UtxoInputs};
pub use proof::{Commitments, CompressedCommitments, Proof, ProofCompressed};
