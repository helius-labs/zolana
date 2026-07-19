pub mod escrow;
pub mod escrow_terms;
pub mod ffi;
pub mod proof;
mod utxo;
pub mod withdraw;

use num_bigint::BigUint;

pub use escrow::EscrowProofInputs;
pub use escrow_terms::EscrowTermsProofInput;
pub use ffi::{preload, prove, setup, CircuitId, WitnessMap};
pub use proof::{ProofError, TimelockProof};
pub use withdraw::WithdrawProofInputs;
pub use zolana_transaction::ProofInputUtxo;

pub fn bytes_to_decimal_string(bytes: &[u8; 32]) -> String {
    BigUint::from_bytes_be(bytes).to_string()
}
