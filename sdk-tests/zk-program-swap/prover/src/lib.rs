pub mod cancel;
pub mod create;
pub mod ffi;
pub mod fill;
pub mod fill_verifiable_encryption;
pub mod order_terms;
pub mod proof;
pub mod utxo;

use num_bigint::BigUint;

pub use cancel::CancelProofInputs;
pub use create::CreateProofInputs;
pub use ffi::{preload, prove, setup, CircuitId, WitnessMap};
pub use fill::{FillProofInputs, DESTINATION_BLINDING_DOMAIN};
pub use fill_verifiable_encryption::{FillVerifiableEncryptionProofInputs, FILL_ENC_KDF_DOMAIN};
pub use order_terms::{OrderTermsFieldElements, FILL_MODE_DERIVED, FILL_MODE_VERIFIABLE};
pub use proof::{OrderProof, ProofError};
pub use utxo::UtxoFieldElements;

pub fn bytes_to_decimal_string(bytes: &[u8; 32]) -> String {
    BigUint::from_bytes_be(bytes).to_string()
}
