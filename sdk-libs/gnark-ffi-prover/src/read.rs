use zolana_client::{MerkleProof, NonInclusionProof};

use crate::decimal;

/// Encodes the proof that a UTXO is unspent as proof input entries for a Go
/// circuit: `merkle_proof` of its hash in the state tree and `non_inclusion`
/// of its nullifier in the nullifier tree.
///
/// The six `{prefix}_{field}` keys are the reflected field names of the
/// circuit's `gnarksdk.UtxoRead` field, in its declaration order. The leaves
/// and roots are the circuit's to place, usually as public inputs.
pub fn utxo_read_proof_inputs(
    merkle_proof: &MerkleProof,
    non_inclusion: &NonInclusionProof,
    prefix: &str,
) -> Vec<(String, Vec<String>)> {
    let fields: [(&str, Vec<String>); 6] = [
        (
            "StatePathElements",
            merkle_proof.path.iter().map(decimal).collect(),
        ),
        ("StatePathIndex", vec![merkle_proof.leaf_index.to_string()]),
        (
            "NullifierLowValue",
            vec![decimal(&non_inclusion.low_element)],
        ),
        (
            "NullifierNextValue",
            vec![decimal(&non_inclusion.high_element)],
        ),
        (
            "NullifierLowPathElements",
            non_inclusion.path.iter().map(decimal).collect(),
        ),
        (
            "NullifierLowPathIndex",
            vec![non_inclusion.low_element_index.to_string()],
        ),
    ];
    fields
        .into_iter()
        .map(|(suffix, values)| (format!("{prefix}_{suffix}"), values))
        .collect()
}
