use num_bigint::BigUint;

/// UTXO commitment fields, pre-computed by the caller. Mirrors the circuit's
/// UtxoCircuitFields (see prover/server/circuits/spp_transaction/utxo.go).
/// Shared by both transfer rails (P256 and Solana-only).
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

/// One spend input. Every value is computed client-side; the prover only assigns
/// them onto circuit signals. Mirrors txcircuit.Input.
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
