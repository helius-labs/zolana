use num_bigint::BigUint;

use crate::proof_types::transfer_common::{TransferInput, TransferOutput};

/// Flat, pre-computed witness for the Solana-only spp_transaction circuit. This
/// rail has no P256 gadget, so there is no P256 pubkey/signature/message-hash.
/// Mirrors prover/server/prover/transfer_eddsa_only/params.go TransferParameters.
/// The input and output counts are derived from `inputs`/`outputs` at
/// serialization time.
#[derive(Debug, Clone)]
pub struct TransferEddsaInputs {
    pub inputs: Vec<TransferInput>,
    pub outputs: Vec<TransferOutput>,
    pub external_data_hash: BigUint,
    pub private_tx_hash: BigUint,
    pub public_sol_amount: BigUint,
    pub public_spl_amount: BigUint,
    pub public_spl_asset_pubkey: BigUint,
    pub program_id_hashchain: BigUint,
    pub payer_pubkey_hash: BigUint,
    pub data_hash: BigUint,
    pub zone_data_hash: BigUint,
    pub public_input_hash: BigUint,
}
