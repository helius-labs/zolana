use zolana_client::ProofInputUtxo;

use crate::decimal;

/// Encodes one UTXO as witness entries for a Go circuit.
///
/// The eight `{prefix}_{field}` keys are the reflected field names of the
/// embedded `spp.UtxoCircuitFields` struct. The tree id is a sibling
/// `frontend.Variable` named `<prefix>TreeID` next to that struct, not a member
/// of it, so its key carries no separating underscore.
pub fn utxo_witness_entries(utxo: &ProofInputUtxo, prefix: &str) -> Vec<(String, Vec<String>)> {
    let fields: [(&str, &[u8; 32]); 8] = [
        ("Domain", &utxo.domain),
        ("Owner", &utxo.owner_hash),
        ("Asset", &utxo.asset),
        ("Amount", &utxo.amount),
        ("Blinding", &utxo.blinding),
        ("DataHash", &utxo.data_hash),
        ("RingDataHash", &utxo.ring_data_hash),
        ("RingProgramID", &utxo.ring_program_id),
    ];
    fields
        .iter()
        .map(|(suffix, value)| (format!("{prefix}_{suffix}"), vec![decimal(value)]))
        .chain(std::iter::once((
            format!("{prefix}TreeID"),
            vec![decimal(&utxo.tree_id)],
        )))
        .collect()
}

/// The witness keys one UTXO prefix must produce, spelled out from the Go
/// `spp.UtxoCircuitFields` field names plus the sibling `<prefix>TreeID`.
/// Exact-key-set tests compare an encoder's output against this, so it is
/// written by hand rather than derived from [`utxo_witness_entries`].
pub fn expected_utxo_witness_keys(prefix: &str) -> Vec<String> {
    let mut keys: Vec<String> = [
        "Domain",
        "Owner",
        "Asset",
        "Amount",
        "Blinding",
        "DataHash",
        "RingDataHash",
        "RingProgramID",
    ]
    .iter()
    .map(|suffix| format!("{prefix}_{suffix}"))
    .collect();
    keys.push(format!("{prefix}TreeID"));
    keys
}
