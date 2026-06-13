use serde::Serialize;

use crate::{
    helpers::big_uint_to_string,
    proof_types::transfer_common::{TransferInput, TransferOutput, UtxoInputs},
};

#[derive(Debug, Clone, Serialize)]
pub struct UtxoParamsJson {
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
pub struct InputParamsJson {
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
pub struct OutputParamsJson {
    #[serde(rename = "utxo")]
    pub utxo: UtxoParamsJson,
    #[serde(rename = "isDummy")]
    pub is_dummy: String,
    #[serde(rename = "hash")]
    pub hash: String,
}

pub fn utxo_to_json(utxo: &UtxoInputs) -> UtxoParamsJson {
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

pub fn input_to_json(input: &TransferInput) -> InputParamsJson {
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

pub fn output_to_json(output: &TransferOutput) -> OutputParamsJson {
    OutputParamsJson {
        utxo: utxo_to_json(&output.utxo),
        is_dummy: big_uint_to_string(&output.is_dummy),
        hash: big_uint_to_string(&output.hash),
    }
}
