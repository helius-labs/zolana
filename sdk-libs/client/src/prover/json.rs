use num_bigint::BigUint;
use serde::Serialize;

use crate::prover::inputs::{
    TransferInput, TransferInputs, TransferOutput, TransferP256Inputs, UtxoInputs,
};

fn big_uint_to_string(value: &BigUint) -> String {
    format!("0x{}", value.to_str_radix(16))
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct UtxoParamsJson {
    #[serde(rename = "domain")]
    pub domain: String,
    #[serde(rename = "owner")]
    pub owner: String,
    #[serde(rename = "asset")]
    pub asset: String,
    #[serde(rename = "amount")]
    pub amount: String,
    #[serde(rename = "blinding")]
    pub blinding: String,
    #[serde(rename = "dataHash")]
    pub data_hash: String,
    #[serde(rename = "zoneDataHash")]
    pub zone_data_hash: String,
    #[serde(rename = "zoneProgramId")]
    pub zone_program_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct InputParamsJson {
    #[serde(rename = "utxo")]
    pub utxo: UtxoParamsJson,
    #[serde(rename = "isDummy")]
    pub is_dummy: String,
    #[serde(rename = "statePathElements")]
    pub state_path_elements: Vec<String>,
    #[serde(rename = "statePathIndex")]
    pub state_path_index: String,
    #[serde(rename = "nullifierLowValue")]
    pub nullifier_low_value: String,
    #[serde(rename = "nullifierNextValue")]
    pub nullifier_next_value: String,
    #[serde(rename = "nullifierLowPathElements")]
    pub nullifier_low_path_elements: Vec<String>,
    #[serde(rename = "nullifierLowPathIndex")]
    pub nullifier_low_path_index: String,
    #[serde(rename = "utxoTreeRoot")]
    pub utxo_tree_root: String,
    #[serde(rename = "nullifierTreeRoot")]
    pub nullifier_tree_root: String,
    #[serde(rename = "nullifier")]
    pub nullifier: String,
    #[serde(rename = "solanaOwnerPkHash")]
    pub solana_owner_pk_hash: String,
    #[serde(rename = "nullifierSecret")]
    pub nullifier_secret: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct OutputParamsJson {
    #[serde(rename = "utxo")]
    pub utxo: UtxoParamsJson,
    #[serde(rename = "isDummy")]
    pub is_dummy: String,
    #[serde(rename = "hash")]
    pub hash: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct TransferP256InputsJson {
    #[serde(rename = "circuitType")]
    pub circuit_type: String,
    #[serde(rename = "nInputs")]
    pub n_inputs: usize,
    #[serde(rename = "nOutputs")]
    pub n_outputs: usize,
    #[serde(rename = "inputs")]
    pub inputs: Vec<InputParamsJson>,
    #[serde(rename = "outputs")]
    pub outputs: Vec<OutputParamsJson>,
    #[serde(rename = "externalDataHash")]
    pub external_data_hash: String,
    #[serde(rename = "p256PubX")]
    pub p256_pub_x: String,
    #[serde(rename = "p256PubY")]
    pub p256_pub_y: String,
    #[serde(rename = "p256SigR")]
    pub p256_sig_r: String,
    #[serde(rename = "p256SigS")]
    pub p256_sig_s: String,
    #[serde(rename = "privateTxHash")]
    pub private_tx_hash: String,
    #[serde(rename = "p256MessageHash")]
    pub p256_message_hash: String,
    #[serde(rename = "publicSolAmount")]
    pub public_sol_amount: String,
    #[serde(rename = "publicSplAmount")]
    pub public_spl_amount: String,
    #[serde(rename = "publicSplAssetPubkey")]
    pub public_spl_asset_pubkey: String,
    #[serde(rename = "programIdHashchain")]
    pub program_id_hashchain: String,
    #[serde(rename = "payerPubkeyHash")]
    pub payer_pubkey_hash: String,
    #[serde(rename = "dataHash")]
    pub data_hash: String,
    #[serde(rename = "zoneDataHash")]
    pub zone_data_hash: String,
    #[serde(rename = "publicInputHash")]
    pub public_input_hash: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct TransferInputsJson {
    #[serde(rename = "circuitType")]
    pub circuit_type: String,
    #[serde(rename = "nInputs")]
    pub n_inputs: usize,
    #[serde(rename = "nOutputs")]
    pub n_outputs: usize,
    #[serde(rename = "inputs")]
    pub inputs: Vec<InputParamsJson>,
    #[serde(rename = "outputs")]
    pub outputs: Vec<OutputParamsJson>,
    #[serde(rename = "externalDataHash")]
    pub external_data_hash: String,
    #[serde(rename = "privateTxHash")]
    pub private_tx_hash: String,
    #[serde(rename = "publicSolAmount")]
    pub public_sol_amount: String,
    #[serde(rename = "publicSplAmount")]
    pub public_spl_amount: String,
    #[serde(rename = "publicSplAssetPubkey")]
    pub public_spl_asset_pubkey: String,
    #[serde(rename = "programIdHashchain")]
    pub program_id_hashchain: String,
    #[serde(rename = "payerPubkeyHash")]
    pub payer_pubkey_hash: String,
    #[serde(rename = "dataHash")]
    pub data_hash: String,
    #[serde(rename = "zoneDataHash")]
    pub zone_data_hash: String,
    #[serde(rename = "publicInputHash")]
    pub public_input_hash: String,
}

fn utxo_to_json(utxo: &UtxoInputs) -> UtxoParamsJson {
    UtxoParamsJson {
        domain: big_uint_to_string(&utxo.domain),
        owner: big_uint_to_string(&utxo.owner),
        asset: big_uint_to_string(&utxo.asset),
        amount: big_uint_to_string(&utxo.amount),
        blinding: big_uint_to_string(&utxo.blinding),
        data_hash: big_uint_to_string(&utxo.data_hash),
        zone_data_hash: big_uint_to_string(&utxo.zone_data_hash),
        zone_program_id: big_uint_to_string(&utxo.zone_program_id),
    }
}

fn input_to_json(input: &TransferInput) -> InputParamsJson {
    InputParamsJson {
        utxo: utxo_to_json(&input.utxo),
        is_dummy: big_uint_to_string(&input.is_dummy),
        state_path_elements: input
            .state_path_elements
            .iter()
            .map(big_uint_to_string)
            .collect(),
        state_path_index: big_uint_to_string(&input.state_path_index),
        nullifier_low_value: big_uint_to_string(&input.nullifier_low_value),
        nullifier_next_value: big_uint_to_string(&input.nullifier_next_value),
        nullifier_low_path_elements: input
            .nullifier_low_path_elements
            .iter()
            .map(big_uint_to_string)
            .collect(),
        nullifier_low_path_index: big_uint_to_string(&input.nullifier_low_path_index),
        utxo_tree_root: big_uint_to_string(&input.utxo_tree_root),
        nullifier_tree_root: big_uint_to_string(&input.nullifier_tree_root),
        nullifier: big_uint_to_string(&input.nullifier),
        solana_owner_pk_hash: big_uint_to_string(&input.solana_owner_pk_hash),
        nullifier_secret: big_uint_to_string(&input.nullifier_secret),
    }
}

fn output_to_json(output: &TransferOutput) -> OutputParamsJson {
    OutputParamsJson {
        utxo: utxo_to_json(&output.utxo),
        is_dummy: big_uint_to_string(&output.is_dummy),
        hash: big_uint_to_string(&output.hash),
    }
}

/// Serialize the P256 transfer witness to the prover server's JSON request body.
pub(crate) fn to_json_p256(inputs: &TransferP256Inputs) -> String {
    let json = TransferP256InputsJson {
        circuit_type: "transfer-p256".to_string(),
        n_inputs: inputs.inputs.len(),
        n_outputs: inputs.outputs.len(),
        inputs: inputs.inputs.iter().map(input_to_json).collect(),
        outputs: inputs.outputs.iter().map(output_to_json).collect(),
        external_data_hash: big_uint_to_string(&inputs.external_data_hash),
        p256_pub_x: big_uint_to_string(&inputs.p256_pub_x),
        p256_pub_y: big_uint_to_string(&inputs.p256_pub_y),
        p256_sig_r: big_uint_to_string(&inputs.p256_sig_r),
        p256_sig_s: big_uint_to_string(&inputs.p256_sig_s),
        private_tx_hash: big_uint_to_string(&inputs.private_tx_hash),
        p256_message_hash: big_uint_to_string(&inputs.p256_message_hash),
        public_sol_amount: big_uint_to_string(&inputs.public_sol_amount),
        public_spl_amount: big_uint_to_string(&inputs.public_spl_amount),
        public_spl_asset_pubkey: big_uint_to_string(&inputs.public_spl_asset_pubkey),
        program_id_hashchain: big_uint_to_string(&inputs.program_id_hashchain),
        payer_pubkey_hash: big_uint_to_string(&inputs.payer_pubkey_hash),
        data_hash: big_uint_to_string(&inputs.data_hash),
        zone_data_hash: big_uint_to_string(&inputs.zone_data_hash),
        public_input_hash: big_uint_to_string(&inputs.public_input_hash),
    };
    serde_json::to_string(&json).expect("JSON serialization failed for valid struct")
}

/// Serialize the Solana-only transfer witness to the prover server's JSON request body.
pub(crate) fn to_json(inputs: &TransferInputs) -> String {
    let json = TransferInputsJson {
        circuit_type: "transfer".to_string(),
        n_inputs: inputs.inputs.len(),
        n_outputs: inputs.outputs.len(),
        inputs: inputs.inputs.iter().map(input_to_json).collect(),
        outputs: inputs.outputs.iter().map(output_to_json).collect(),
        external_data_hash: big_uint_to_string(&inputs.external_data_hash),
        private_tx_hash: big_uint_to_string(&inputs.private_tx_hash),
        public_sol_amount: big_uint_to_string(&inputs.public_sol_amount),
        public_spl_amount: big_uint_to_string(&inputs.public_spl_amount),
        public_spl_asset_pubkey: big_uint_to_string(&inputs.public_spl_asset_pubkey),
        program_id_hashchain: big_uint_to_string(&inputs.program_id_hashchain),
        payer_pubkey_hash: big_uint_to_string(&inputs.payer_pubkey_hash),
        data_hash: big_uint_to_string(&inputs.data_hash),
        zone_data_hash: big_uint_to_string(&inputs.zone_data_hash),
        public_input_hash: big_uint_to_string(&inputs.public_input_hash),
    };
    serde_json::to_string(&json).expect("JSON serialization failed for valid struct")
}
