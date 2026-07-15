use zolana_transaction::ProofInputUtxo;

use crate::bytes_to_decimal_string;

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
        ("ZoneDataHash", &utxo.zone_data_hash),
        ("ZoneProgramID", &utxo.zone_program_id),
    ];
    fields
        .iter()
        .map(|(suffix, value)| {
            (
                format!("{prefix}_{suffix}"),
                vec![bytes_to_decimal_string(value)],
            )
        })
        .collect()
}
