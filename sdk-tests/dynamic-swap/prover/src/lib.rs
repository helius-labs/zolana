pub mod escrow_cancel;
pub mod escrow_open;
pub mod escrow_settle;
pub mod ffi;
pub mod proof;
mod utxo;

use num_bigint::BigUint;

pub use escrow_cancel::EscrowCancelProofInputs;
pub use escrow_open::EscrowOpenProofInputs;
pub use escrow_settle::{
    EscrowSettleProofInputs, CANCEL_REFUND_BLINDING_DOMAIN, FUNDER_CHANGE_BLINDING_DOMAIN,
    FUNDER_RECEIPT_BLINDING_DOMAIN, RECIPIENT_BLINDING_DOMAIN,
};
pub use ffi::{preload, prove, setup, CircuitId, WitnessMap};
pub use proof::{OrderProof, ProofError};
pub use zolana_transaction::ProofInputUtxo;

pub fn bytes_to_decimal_string(bytes: &[u8; 32]) -> String {
    BigUint::from_bytes_be(bytes).to_string()
}
