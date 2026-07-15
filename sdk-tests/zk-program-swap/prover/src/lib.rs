pub mod cancel;
pub mod ffi;
pub mod make;
pub mod order_terms;
pub mod proof;
pub mod take;
pub mod take_verifiable_encryption;
mod utxo;

use num_bigint::BigUint;

pub use cancel::CancelProofInputs;
pub use ffi::{preload, prove, setup, CircuitId, WitnessMap};
pub use make::MakeProofInputs;
pub use order_terms::{OrderTermsProofInput, TAKE_MODE_DERIVED, TAKE_MODE_VERIFIABLE};
pub use proof::{OrderProof, ProofError};
pub use take::{TakeProofInputs, DESTINATION_BLINDING_DOMAIN};
pub use take_verifiable_encryption::{TakeVerifiableEncryptionProofInputs, TAKE_ENC_KDF_DOMAIN};
pub use zolana_transaction::ProofInputUtxo;

pub fn bytes_to_decimal_string(bytes: &[u8; 32]) -> String {
    BigUint::from_bytes_be(bytes).to_string()
}
