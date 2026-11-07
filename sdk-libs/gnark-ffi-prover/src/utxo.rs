use spr_client::ProofInputUtxo;

use crate::decimal;

/// The reflected field names of the circuit's `gnarksdk.Utxo` field, in its
/// declaration order.
const UTXO_FIELDS: [&str; 9] = [
    "Domain",
    "Owner",
    "Asset",
    "Amount",
    "Blinding",
    "DataHash",
    "RingDataHash",
    "RingProgramID",
    "TreeID",
];

/// Encodes one UTXO as proof input entries for a Go circuit, one
/// `{prefix}_{field}` key per circuit field.
pub fn utxo_proof_inputs(utxo: &ProofInputUtxo, prefix: &str) -> Vec<(String, Vec<String>)> {
    let values: [&[u8; 32]; 9] = [
        &utxo.domain,
        &utxo.owner_hash,
        &utxo.asset,
        &utxo.amount,
        &utxo.blinding,
        &utxo.data_hash,
        &utxo.ring_data_hash,
        &utxo.ring_program_id,
        &utxo.tree_id,
    ];
    UTXO_FIELDS
        .iter()
        .zip(values)
        .map(|(field, value)| (format!("{prefix}_{field}"), vec![decimal(value)]))
        .collect()
}

/// The key set an encoder must produce for one UTXO prefix.
pub fn utxo_proof_input_keys(prefix: &str) -> Vec<String> {
    UTXO_FIELDS
        .iter()
        .map(|field| format!("{prefix}_{field}"))
        .collect()
}
