use num_bigint::BigUint;

use crate::proof_types::transfer_common::{TransferInput, TransferOutput};

/// Flat, pre-computed witness for the P256-capable spp_transaction circuit.
/// Mirrors prover/server/prover/transfer/params.go TransferParameters. The input
/// and output counts are derived from `inputs`/`outputs` at serialization time.
#[derive(Debug, Clone)]
pub struct TransferInputs {
    pub inputs: Vec<TransferInput>,
    pub outputs: Vec<TransferOutput>,
    pub external_data_hash: BigUint,
    pub p256_pub_x: BigUint,
    pub p256_pub_y: BigUint,
    pub p256_sig_r: BigUint,
    pub p256_sig_s: BigUint,
    pub private_tx_hash: BigUint,
    pub p256_message_hash: BigUint,
    pub public_sol_amount: BigUint,
    pub public_spl_amount: BigUint,
    pub public_spl_asset_pubkey: BigUint,
    pub program_id_hashchain: BigUint,
    pub payer_pubkey_hash: BigUint,
    pub data_hash: BigUint,
    pub zone_data_hash: BigUint,
    pub public_input_hash: BigUint,
}
