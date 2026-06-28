use num_bigint::BigUint;
use serde::Serialize;

use crate::prover::inputs::{
    BatchAddressAppendInputs, MergeInputs, TransferInput, TransferInputs, TransferOutput,
    TransferP256Inputs, UtxoInputs,
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
    #[serde(rename = "programId")]
    pub program_id: String,
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
    #[serde(rename = "ownerPkHash")]
    pub owner_pk_hash: String,
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
    #[serde(rename = "ownerPkHash")]
    pub owner_pk_hash: String,
    #[serde(rename = "nullifierPk")]
    pub nullifier_pk: String,
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
    #[serde(rename = "p256MessageHashLow")]
    pub p256_message_hash_low: String,
    #[serde(rename = "p256MessageHashHigh")]
    pub p256_message_hash_high: String,
    #[serde(rename = "publicSolAmount")]
    pub public_sol_amount: String,
    #[serde(rename = "publicSplAmount")]
    pub public_spl_amount: String,
    #[serde(rename = "publicSplAssetPubkey")]
    pub public_spl_asset_pubkey: String,
    #[serde(rename = "programId")]
    pub program_id: String,
    #[serde(rename = "zoneProgramId")]
    pub zone_program_id: String,
    #[serde(rename = "payerPubkeyHash")]
    pub payer_pubkey_hash: String,
    #[serde(rename = "p256SigningPkField")]
    pub p256_signing_pk_field: String,
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
    #[serde(rename = "programId")]
    pub program_id: String,
    #[serde(rename = "zoneProgramId")]
    pub zone_program_id: String,
    #[serde(rename = "payerPubkeyHash")]
    pub payer_pubkey_hash: String,
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
        program_id: big_uint_to_string(&utxo.program_id),
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
        owner_pk_hash: big_uint_to_string(&input.owner_pk_hash),
        nullifier_secret: big_uint_to_string(&input.nullifier_secret),
    }
}

fn output_to_json(output: &TransferOutput) -> OutputParamsJson {
    OutputParamsJson {
        utxo: utxo_to_json(&output.utxo),
        is_dummy: big_uint_to_string(&output.is_dummy),
        hash: big_uint_to_string(&output.hash),
        owner_pk_hash: big_uint_to_string(&output.owner_pk_hash),
        nullifier_pk: big_uint_to_string(&output.nullifier_pk),
    }
}

/// Serialize a P256 transfer witness under the given circuit type. The confidential
/// and zone variants share the witness shape and differ only by the circuit type.
fn transfer_p256_inputs_json(inputs: &TransferP256Inputs, circuit_type: &str) -> String {
    let json = TransferP256InputsJson {
        circuit_type: circuit_type.to_string(),
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
        p256_message_hash_low: big_uint_to_string(&inputs.p256_message_hash_low),
        p256_message_hash_high: big_uint_to_string(&inputs.p256_message_hash_high),
        public_sol_amount: big_uint_to_string(&inputs.public_sol_amount),
        public_spl_amount: big_uint_to_string(&inputs.public_spl_amount),
        public_spl_asset_pubkey: big_uint_to_string(&inputs.public_spl_asset_pubkey),
        program_id: big_uint_to_string(&inputs.program_id),
        zone_program_id: big_uint_to_string(&inputs.zone_program_id),
        payer_pubkey_hash: big_uint_to_string(&inputs.payer_pubkey_hash),
        p256_signing_pk_field: big_uint_to_string(&inputs.p256_signing_pk_field),
        public_input_hash: big_uint_to_string(&inputs.public_input_hash),
    };
    serde_json::to_string(&json).expect("JSON serialization failed for valid struct")
}

/// Serialize the P256 confidential transfer witness.
pub(crate) fn to_json_p256(inputs: &TransferP256Inputs) -> String {
    transfer_p256_inputs_json(inputs, "transfer-p256-confidential")
}

/// Serialize the P256 anonymous policy-zone transfer witness.
pub(crate) fn to_json_p256_zone(inputs: &TransferP256Inputs) -> String {
    transfer_p256_inputs_json(inputs, "transfer-p256-zone")
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct MergeParametersJson {
    #[serde(rename = "circuitType")]
    pub circuit_type: String,
    // Reuses the transfer input/output JSON. The merge circuit ignores the
    // transfer-only per-input `ownerPkHash`/`nullifierSecret` and output
    // `isDummy` (Go drops unknown keys), so no merge-specific shape is needed.
    #[serde(rename = "inputs")]
    pub inputs: Vec<InputParamsJson>,
    #[serde(rename = "output")]
    pub output: OutputParamsJson,
    #[serde(rename = "p256PubX")]
    pub p256_pub_x: String,
    #[serde(rename = "p256PubY")]
    pub p256_pub_y: String,
    #[serde(rename = "ownerPkHash")]
    pub owner_pk_hash: String,
    #[serde(rename = "userNullifierPk")]
    pub user_nullifier_pk: String,
    #[serde(rename = "userNullifierSecret")]
    pub user_nullifier_secret: String,
    #[serde(rename = "txViewingSk")]
    pub tx_viewing_sk: String,
    #[serde(rename = "userViewingPubkey")]
    pub user_viewing_pubkey: Vec<String>,
    #[serde(rename = "externalDataHash")]
    pub external_data_hash: String,
    #[serde(rename = "privateTxHash")]
    pub private_tx_hash: String,
    #[serde(rename = "publicInputHash")]
    pub public_input_hash: String,
    /// Top-level zone program pk_field; `0x0` for the default merge,
    /// the zone's pk_field for merge-zone (the circuit's top-level public input).
    #[serde(rename = "zoneProgramId")]
    pub zone_program_id: String,
}

/// Serialize a merge witness under the given circuit type. The default merge and
/// merge-zone share the witness shape and differ only by the circuit type and the
/// `zoneProgramId` value (`0` for default merge).
fn merge_params_json(inputs: &MergeInputs, circuit_type: &str) -> String {
    let json = MergeParametersJson {
        circuit_type: circuit_type.to_string(),
        inputs: inputs.inputs.iter().map(input_to_json).collect(),
        output: output_to_json(&inputs.output),
        p256_pub_x: big_uint_to_string(&inputs.p256_pub_x),
        p256_pub_y: big_uint_to_string(&inputs.p256_pub_y),
        owner_pk_hash: big_uint_to_string(&inputs.owner_pk_hash),
        user_nullifier_pk: big_uint_to_string(&inputs.user_nullifier_pk),
        user_nullifier_secret: big_uint_to_string(&inputs.user_nullifier_secret),
        tx_viewing_sk: big_uint_to_string(&inputs.tx_viewing_sk),
        user_viewing_pubkey: inputs
            .user_viewing_pubkey
            .iter()
            .map(big_uint_to_string)
            .collect(),
        external_data_hash: big_uint_to_string(&inputs.external_data_hash),
        private_tx_hash: big_uint_to_string(&inputs.private_tx_hash),
        public_input_hash: big_uint_to_string(&inputs.public_input_hash),
        zone_program_id: big_uint_to_string(&inputs.zone_program_id),
    };
    serde_json::to_string(&json).expect("JSON serialization failed for valid struct")
}

/// Serialize the default merge witness to the prover server's JSON request body.
pub(crate) fn to_json_merge(inputs: &MergeInputs) -> String {
    merge_params_json(inputs, "merge")
}

/// Serialize the policy-zone merge witness; the prover server routes `"merge-zone"`
/// to the merge-zone circuit and reads the top-level `zoneProgramId`.
pub(crate) fn to_json_merge_zone(inputs: &MergeInputs) -> String {
    merge_params_json(inputs, "merge-zone")
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct BatchAddressAppendParametersJson {
    #[serde(rename = "circuitType")]
    pub circuit_type: String,
    #[serde(rename = "stateTreeHeight")]
    pub state_tree_height: u32,
    #[serde(rename = "publicInputHash")]
    pub public_input_hash: String,
    #[serde(rename = "oldRoot")]
    pub old_root: String,
    #[serde(rename = "newRoot")]
    pub new_root: String,
    #[serde(rename = "hashchainHash")]
    pub hashchain_hash: String,
    #[serde(rename = "startIndex")]
    pub start_index: u64,
    #[serde(rename = "lowElementValues")]
    pub low_element_values: Vec<String>,
    #[serde(rename = "lowElementIndices")]
    pub low_element_indices: Vec<String>,
    #[serde(rename = "lowElementNextValues")]
    pub low_element_next_values: Vec<String>,
    #[serde(rename = "newElementValues")]
    pub new_element_values: Vec<String>,
    #[serde(rename = "lowElementProofs")]
    pub low_element_proofs: Vec<Vec<String>>,
    #[serde(rename = "newElementProofs")]
    pub new_element_proofs: Vec<Vec<String>>,
    #[serde(rename = "treeHeight")]
    pub tree_height: u32,
    #[serde(rename = "batchSize")]
    pub batch_size: u32,
}

/// Serialize a batch address-append witness to the prover server's JSON request
/// body. This circuit is used by the nullifier-tree forester path.
pub(crate) fn to_json_batch_address_append(inputs: &BatchAddressAppendInputs) -> String {
    let strings = |values: &[BigUint]| values.iter().map(big_uint_to_string).collect();
    let proof_strings = |proofs: &[Vec<BigUint>]| {
        proofs
            .iter()
            .map(|proof| proof.iter().map(big_uint_to_string).collect())
            .collect()
    };
    let json = BatchAddressAppendParametersJson {
        circuit_type: "address-append".to_string(),
        state_tree_height: 0,
        public_input_hash: big_uint_to_string(&inputs.public_input_hash),
        old_root: big_uint_to_string(&inputs.old_root),
        new_root: big_uint_to_string(&inputs.new_root),
        hashchain_hash: big_uint_to_string(&inputs.hashchain_hash),
        start_index: inputs.start_index,
        low_element_values: strings(&inputs.low_element_values),
        low_element_indices: strings(&inputs.low_element_indices),
        low_element_next_values: strings(&inputs.low_element_next_values),
        new_element_values: strings(&inputs.new_element_values),
        low_element_proofs: proof_strings(&inputs.low_element_proofs),
        new_element_proofs: proof_strings(&inputs.new_element_proofs),
        tree_height: inputs.tree_height,
        batch_size: inputs.batch_size,
    };
    serde_json::to_string(&json).expect("JSON serialization failed for valid struct")
}

/// Serialize a Solana-only transfer witness to the prover server's JSON request
/// body under the given `circuit_type`. The eddsa transfer and zone-authority
/// variants share the witness shape and differ only by the circuit type.
fn transfer_inputs_json(inputs: &TransferInputs, circuit_type: &str) -> String {
    let json = TransferInputsJson {
        circuit_type: circuit_type.to_string(),
        n_inputs: inputs.inputs.len(),
        n_outputs: inputs.outputs.len(),
        inputs: inputs.inputs.iter().map(input_to_json).collect(),
        outputs: inputs.outputs.iter().map(output_to_json).collect(),
        external_data_hash: big_uint_to_string(&inputs.external_data_hash),
        private_tx_hash: big_uint_to_string(&inputs.private_tx_hash),
        public_sol_amount: big_uint_to_string(&inputs.public_sol_amount),
        public_spl_amount: big_uint_to_string(&inputs.public_spl_amount),
        public_spl_asset_pubkey: big_uint_to_string(&inputs.public_spl_asset_pubkey),
        program_id: big_uint_to_string(&inputs.program_id),
        zone_program_id: big_uint_to_string(&inputs.zone_program_id),
        payer_pubkey_hash: big_uint_to_string(&inputs.payer_pubkey_hash),
        public_input_hash: big_uint_to_string(&inputs.public_input_hash),
    };
    serde_json::to_string(&json).expect("JSON serialization failed for valid struct")
}

/// Serialize the Solana-only confidential transfer witness to the prover server's
/// JSON request body.
pub(crate) fn to_json(inputs: &TransferInputs) -> String {
    transfer_inputs_json(inputs, "transfer-confidential")
}

/// Serialize the zone-authority witness to the prover server's JSON request body.
/// Shares the Solana-only witness shape with [`to_json`]; only the circuit type and
/// the embedded `public_input_hash` differ.
pub(crate) fn to_json_zone_authority(inputs: &TransferInputs) -> String {
    transfer_inputs_json(inputs, "transfer-zone-authority")
}

/// Serialize the eddsa anonymous policy-zone transfer witness.
pub(crate) fn to_json_zone(inputs: &TransferInputs) -> String {
    transfer_inputs_json(inputs, "transfer-zone")
}

#[cfg(test)]
mod merge_tests {
    use super::*;
    use crate::rpc::{NULLIFIER_TREE_HEIGHT, STATE_TREE_HEIGHT};

    fn sample_utxo() -> UtxoInputs {
        UtxoInputs {
            domain: BigUint::from(1u8),
            owner: BigUint::from(2u8),
            asset: BigUint::from(1u8),
            amount: BigUint::from(5u8),
            blinding: BigUint::from(7u8),
            data_hash: BigUint::ZERO,
            program_id: BigUint::ZERO,
            zone_data_hash: BigUint::ZERO,
            zone_program_id: BigUint::ZERO,
        }
    }

    // Guards the wire-format field names against the Go server
    // (prover/server/prover/merge/marshal.go): a serde-rename typo would break
    // the request silently. Asserts circuitType and the full key set.
    #[test]
    fn to_json_merge_shape() {
        let input = TransferInput {
            utxo: sample_utxo(),
            is_dummy: BigUint::ZERO,
            state_path_elements: vec![BigUint::ZERO; STATE_TREE_HEIGHT],
            state_path_index: BigUint::ZERO,
            nullifier_low_value: BigUint::ZERO,
            nullifier_next_value: BigUint::ZERO,
            nullifier_low_path_elements: vec![BigUint::ZERO; NULLIFIER_TREE_HEIGHT],
            nullifier_low_path_index: BigUint::ZERO,
            utxo_tree_root: BigUint::from(11u8),
            nullifier_tree_root: BigUint::from(13u8),
            nullifier: BigUint::from(99u8),
            owner_pk_hash: BigUint::ZERO,
            nullifier_secret: BigUint::from(4u8),
        };
        let inputs = MergeInputs {
            inputs: vec![input; 8],
            output: TransferOutput {
                utxo: sample_utxo(),
                is_dummy: BigUint::ZERO,
                hash: BigUint::from(0xABCu32),
                owner_pk_hash: BigUint::ZERO,
                nullifier_pk: BigUint::ZERO,
            },
            p256_pub_x: BigUint::from(1u8),
            p256_pub_y: BigUint::from(2u8),
            owner_pk_hash: BigUint::ZERO,
            user_nullifier_pk: BigUint::from(3u8),
            user_nullifier_secret: BigUint::from(4u8),
            tx_viewing_sk: BigUint::from(5u8),
            user_viewing_pubkey: (0..65u32).map(BigUint::from).collect(),
            external_data_hash: BigUint::from(6u8),
            private_tx_hash: BigUint::from(7u8),
            public_input_hash: BigUint::from(8u8),
            zone_program_id: BigUint::ZERO,
        };

        let value: serde_json::Value = serde_json::from_str(&to_json_merge(&inputs)).unwrap();
        assert_eq!(value["circuitType"], "merge");
        for key in [
            "inputs",
            "output",
            "p256PubX",
            "p256PubY",
            "ownerPkHash",
            "userNullifierPk",
            "userNullifierSecret",
            "txViewingSk",
            "userViewingPubkey",
            "externalDataHash",
            "privateTxHash",
            "publicInputHash",
        ] {
            assert!(!value[key].is_null(), "missing top-level key {key}");
        }
        assert_eq!(value["inputs"].as_array().unwrap().len(), 8);
        assert_eq!(value["userViewingPubkey"].as_array().unwrap().len(), 65);
        let in0 = &value["inputs"][0];
        for key in [
            "utxo",
            "isDummy",
            "statePathElements",
            "nullifierTreeRoot",
            "nullifier",
        ] {
            assert!(!in0[key].is_null(), "missing input key {key}");
        }
        // Inputs reuse the transfer JSON; the merge circuit ignores these
        // transfer-only fields server-side.
        assert!(!in0["ownerPkHash"].is_null());
        assert!(!in0["nullifierSecret"].is_null());
        assert_eq!(value["output"]["hash"], "0xabc");
    }

    // Guards the zone-authority request against the Go server: it must carry the
    // "transfer-zone-authority" circuit type and the Solana-only transfer key set
    // (no P256 fields).
    #[test]
    fn to_json_zone_authority_shape() {
        let input = TransferInput {
            utxo: sample_utxo(),
            is_dummy: BigUint::ZERO,
            state_path_elements: vec![BigUint::ZERO; STATE_TREE_HEIGHT],
            state_path_index: BigUint::ZERO,
            nullifier_low_value: BigUint::ZERO,
            nullifier_next_value: BigUint::ZERO,
            nullifier_low_path_elements: vec![BigUint::ZERO; NULLIFIER_TREE_HEIGHT],
            nullifier_low_path_index: BigUint::ZERO,
            utxo_tree_root: BigUint::from(11u8),
            nullifier_tree_root: BigUint::from(13u8),
            nullifier: BigUint::from(99u8),
            owner_pk_hash: BigUint::from(7u8),
            nullifier_secret: BigUint::from(4u8),
        };
        let inputs = TransferInputs {
            inputs: vec![input],
            outputs: vec![TransferOutput {
                utxo: sample_utxo(),
                is_dummy: BigUint::ZERO,
                hash: BigUint::from(0xABCu32),
                owner_pk_hash: BigUint::ZERO,
                nullifier_pk: BigUint::ZERO,
            }],
            external_data_hash: BigUint::from(6u8),
            private_tx_hash: BigUint::from(7u8),
            public_sol_amount: BigUint::ZERO,
            public_spl_amount: BigUint::ZERO,
            public_spl_asset_pubkey: BigUint::ZERO,
            program_id: BigUint::ZERO,
            zone_program_id: BigUint::from(0x55u8),
            payer_pubkey_hash: BigUint::from(8u8),
            public_input_hash: BigUint::from(9u8),
        };

        let value: serde_json::Value =
            serde_json::from_str(&to_json_zone_authority(&inputs)).unwrap();
        assert_eq!(value["circuitType"], "transfer-zone-authority");
        for key in [
            "nInputs",
            "nOutputs",
            "inputs",
            "outputs",
            "externalDataHash",
            "privateTxHash",
            "publicSolAmount",
            "publicSplAmount",
            "publicSplAssetPubkey",
            "programId",
            "zoneProgramId",
            "payerPubkeyHash",
            "publicInputHash",
        ] {
            assert!(!value[key].is_null(), "missing top-level key {key}");
        }
        // Solana-only rail: no P256 fields on the request.
        assert!(value.get("p256PubX").is_none());
        assert_eq!(value["zoneProgramId"], "0x55");
        assert_eq!(value["nInputs"], 1);
    }

    #[test]
    fn to_json_batch_address_append_shape() {
        let inputs = BatchAddressAppendInputs {
            public_input_hash: BigUint::from(1u8),
            old_root: BigUint::from(2u8),
            new_root: BigUint::from(3u8),
            hashchain_hash: BigUint::from(4u8),
            start_index: 5,
            low_element_values: vec![BigUint::from(6u8), BigUint::from(7u8)],
            low_element_indices: vec![BigUint::from(8u8), BigUint::from(9u8)],
            low_element_next_values: vec![BigUint::from(10u8), BigUint::from(11u8)],
            new_element_values: vec![BigUint::from(12u8), BigUint::from(13u8)],
            low_element_proofs: vec![
                vec![BigUint::from(14u8), BigUint::from(15u8)],
                vec![BigUint::from(16u8), BigUint::from(17u8)],
            ],
            new_element_proofs: vec![
                vec![BigUint::from(18u8), BigUint::from(19u8)],
                vec![BigUint::from(20u8), BigUint::from(21u8)],
            ],
            tree_height: 40,
            batch_size: 2,
        };

        let value: serde_json::Value =
            serde_json::from_str(&to_json_batch_address_append(&inputs)).unwrap();
        assert_eq!(value["circuitType"], "address-append");
        assert_eq!(value["stateTreeHeight"], 0);
        assert_eq!(value["publicInputHash"], "0x1");
        assert_eq!(value["oldRoot"], "0x2");
        assert_eq!(value["newRoot"], "0x3");
        assert_eq!(value["hashchainHash"], "0x4");
        assert_eq!(value["startIndex"], 5);
        assert_eq!(value["treeHeight"], 40);
        assert_eq!(value["batchSize"], 2);
        assert_eq!(value["lowElementValues"], serde_json::json!(["0x6", "0x7"]));
        assert_eq!(
            value["lowElementProofs"],
            serde_json::json!([["0xe", "0xf"], ["0x10", "0x11"]])
        );
        assert_eq!(
            value["newElementProofs"],
            serde_json::json!([["0x12", "0x13"], ["0x14", "0x15"]])
        );
    }
}
