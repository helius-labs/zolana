use serde::Serialize;

use crate::{
    helpers::{big_uint_to_string, create_json_from_struct},
    proof_types::{
        circuit_type::CircuitType,
        transfer_common::{input_to_json, output_to_json, InputParamsJson, OutputParamsJson},
        transfer_eddsa::TransferEddsaInputs,
    },
};

#[derive(Debug, Clone, Serialize)]
pub struct TransferEddsaInputsJson {
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

impl TransferEddsaInputsJson {
    pub fn from_inputs(inputs: &TransferEddsaInputs) -> Self {
        Self {
            circuit_type: CircuitType::TransferEddsa.to_string(),
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
        }
    }

    #[allow(clippy::inherent_to_string)]
    pub fn to_string(&self) -> String {
        create_json_from_struct(&self)
    }
}

pub fn to_json(inputs: &TransferEddsaInputs) -> String {
    TransferEddsaInputsJson::from_inputs(inputs).to_string()
}
