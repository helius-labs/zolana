use zolana_transaction::ProofInputUtxo;

use crate::bytes_to_decimal_string;

/// Encodes one UTXO as witness entries for the Go circuit.
///
/// The eight `{prefix}_{field}` keys are the reflected field names of the
/// embedded `spp.UtxoCircuitFields` struct. The tree id is a sibling
/// `frontend.Variable` named `<prefix>TreeID` next to that struct, not a member
/// of it, so its key carries no separating underscore.
pub(crate) fn utxo_witness_entries(
    utxo: &ProofInputUtxo,
    prefix: &str,
) -> Vec<(String, Vec<String>)> {
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
        .map(|(suffix, value)| {
            (
                format!("{prefix}_{suffix}"),
                vec![bytes_to_decimal_string(value)],
            )
        })
        .chain(std::iter::once((
            format!("{prefix}TreeID"),
            vec![bytes_to_decimal_string(&utxo.tree_id)],
        )))
        .collect()
}

/// The witness keys one UTXO prefix must produce, spelled out from the Go
/// `spp.UtxoCircuitFields` field names plus the sibling `<prefix>TreeID`. The
/// exact-key-set tests compare the encoder's output against this, so it must be
/// written by hand rather than derived from [`utxo_witness_entries`].
#[cfg(test)]
pub(crate) fn expected_utxo_witness_keys(prefix: &str) -> Vec<String> {
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
