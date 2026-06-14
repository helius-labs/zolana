use num_bigint::BigUint;

/// UTXO commitment fields, pre-computed by the caller. Mirrors the circuit's
/// UtxoCircuitFields (prover/server/circuits/spp_transaction/utxo.go).
#[derive(Debug, Clone)]
pub struct UtxoInputs {
    pub domain: BigUint,
    pub owner: BigUint,
    pub asset: BigUint,
    pub amount: BigUint,
    pub blinding: BigUint,
    pub data_hash: BigUint,
    pub zone_data_hash: BigUint,
    pub zone_program_id: BigUint,
}

/// One spend input. Mirrors txcircuit.Input.
#[derive(Debug, Clone)]
pub struct TransferInput {
    pub utxo: UtxoInputs,
    pub is_dummy: BigUint,
    pub state_path_elements: Vec<BigUint>,
    pub state_path_index: BigUint,
    pub nullifier_low_value: BigUint,
    pub nullifier_next_value: BigUint,
    pub nullifier_low_path_elements: Vec<BigUint>,
    pub nullifier_low_path_index: BigUint,
    pub utxo_tree_root: BigUint,
    pub nullifier_tree_root: BigUint,
    pub nullifier: BigUint,
    pub solana_owner_pk_hash: BigUint,
    pub nullifier_secret: BigUint,
}

/// One output. Mirrors txcircuit.Output.
#[derive(Debug, Clone)]
pub struct TransferOutput {
    pub utxo: UtxoInputs,
    pub is_dummy: BigUint,
    pub hash: BigUint,
}

/// Flat, pre-computed witness for the P256-capable spp_transaction circuit.
/// Mirrors prover/server/prover/transfer/params.go TransferParameters.
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

/// Flat, pre-computed witness for the Solana-only spp_transaction circuit. This
/// rail has no P256 gadget, so there is no P256 pubkey/signature/message-hash.
/// Mirrors prover/server/prover/transfer_eddsa_only/params.go TransferParameters.
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
