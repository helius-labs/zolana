pub mod blinding;
pub mod escrow_cancel;
pub mod escrow_open;
pub mod ffi;
pub mod pool_rebalance;
pub mod pool_settle;
pub mod pool_withdraw;
pub mod proof;
mod utxo;

use num_bigint::BigUint;

pub use blinding::{CANCEL_REFUND_BLINDING_DOMAIN, RECIPIENT_BLINDING_DOMAIN};
pub use escrow_cancel::EscrowCancelProofInputs;
pub use escrow_open::EscrowOpenProofInputs;
pub use ffi::{preload, prove, setup, CircuitId, WitnessMap};
pub use pool_rebalance::{PoolRebalanceProofInputs, REBALANCE_INPUT_SLOTS, REBALANCE_OUTPUT_SLOTS};
pub use pool_settle::PoolSettleProofInputs;
pub use pool_withdraw::PoolWithdrawProofInputs;
pub use proof::{OrderProof, ProofError};
pub use zolana_transaction::ProofInputUtxo;

pub fn bytes_to_decimal_string(bytes: &[u8; 32]) -> String {
    BigUint::from_bytes_be(bytes).to_string()
}
