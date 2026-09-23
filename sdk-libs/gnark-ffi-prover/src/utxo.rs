use zolana_client::ProofInputUtxo;

use crate::decimal;

/// Encodes one UTXO as witness entries for a Go circuit.
///
/// The nine `{prefix}_{field}` keys are the reflected field names of the
/// circuit's `gnarksdk.Utxo` field, in its declaration order.
pub fn utxo_witness_entries(utxo: &ProofInputUtxo, prefix: &str) -> Vec<(String, Vec<String>)> {
    let fields: [(&str, &[u8; 32]); 9] = [
        ("Domain", &utxo.domain),
        ("Owner", &utxo.owner_hash),
        ("Asset", &utxo.asset),
        ("Amount", &utxo.amount),
        ("Blinding", &utxo.blinding),
        ("DataHash", &utxo.data_hash),
        ("RingDataHash", &utxo.ring_data_hash),
        ("RingProgramID", &utxo.ring_program_id),
        ("TreeID", &utxo.tree_id),
    ];
    fields
        .iter()
        .map(|(suffix, value)| (format!("{prefix}_{suffix}"), vec![decimal(value)]))
        .collect()
}

/// The witness keys one UTXO prefix must produce, spelled out from the Go
/// `gnarksdk.Utxo` field names. Exact-key-set tests compare an encoder's
/// output against this, so it is written by hand rather than derived from
/// [`utxo_witness_entries`].
pub fn expected_utxo_witness_keys(prefix: &str) -> Vec<String> {
    [
        "Domain",
        "Owner",
        "Asset",
        "Amount",
        "Blinding",
        "DataHash",
        "RingDataHash",
        "RingProgramID",
        "TreeID",
    ]
    .iter()
    .map(|suffix| format!("{prefix}_{suffix}"))
    .collect()
}
