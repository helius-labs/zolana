use serde::Serialize;

use crate::prover::{
    json::{hex64, proof_json, ProofJson},
    proof::Proof,
};

/// One proved append, with the span it advanced. The prover recomputes the
/// append's public input from these four fields, so a mislabelled span fails to
/// prove rather than folding silently.
#[derive(Debug, Clone)]
pub struct FoldAppend {
    pub proof: Proof,
    pub old_root: [u8; 32],
    pub new_root: [u8; 32],
    pub hashchain_hash: [u8; 32],
    pub start_index: u64,
}

/// Inputs for one fold proof request. The run must already be consecutive. A
/// gap fails inside the circuit.
#[derive(Debug, Clone)]
pub struct NullifierFoldInputs {
    pub tree_height: u32,
    pub batch_size: u32,
    pub appends: Vec<FoldAppend>,
}

#[derive(Debug, Serialize)]
struct AppendJson {
    proof: ProofJson,
    #[serde(rename = "oldRoot")]
    old_root: String,
    #[serde(rename = "newRoot")]
    new_root: String,
    #[serde(rename = "hashchainHash")]
    hashchain_hash: String,
    #[serde(rename = "startIndex")]
    start_index: String,
}

#[derive(Debug, Serialize)]
struct FoldParamsJson {
    #[serde(rename = "circuitType")]
    circuit_type: &'static str,
    #[serde(rename = "treeHeight")]
    tree_height: u32,
    #[serde(rename = "batchSize")]
    batch_size: u32,
    appends: Vec<AppendJson>,
}

pub(crate) fn to_json_nullifier_fold(inputs: &NullifierFoldInputs) -> String {
    let params = FoldParamsJson {
        circuit_type: "nullifier-fold",
        tree_height: inputs.tree_height,
        batch_size: inputs.batch_size,
        appends: inputs
            .appends
            .iter()
            .map(|append| {
                let mut start_index = [0u8; 32];
                start_index[24..].copy_from_slice(&append.start_index.to_be_bytes());
                AppendJson {
                    proof: proof_json(&append.proof),
                    old_root: hex64(&append.old_root),
                    new_root: hex64(&append.new_root),
                    hashchain_hash: hex64(&append.hashchain_hash),
                    start_index: hex64(&start_index),
                }
            })
            .collect(),
    };
    serde_json::to_string(&params).expect("fold request serialization is infallible")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The prover derives each append's public input from the span, so
    /// `startIndex` must be the same right-aligned field element the append
    /// circuit hashed. A left-aligned or decimal encoding would produce a
    /// different public input and fail to prove.
    #[test]
    fn start_index_is_a_right_aligned_field_element() {
        let inputs = NullifierFoldInputs {
            tree_height: 40,
            batch_size: 10,
            appends: vec![FoldAppend {
                proof: Proof {
                    a: [0u8; 64],
                    b: [0u8; 128],
                    c: [0u8; 64],
                    commitment: None,
                },
                old_root: [1u8; 32],
                new_root: [2u8; 32],
                hashchain_hash: [3u8; 32],
                start_index: 10,
            }],
        };
        let json = to_json_nullifier_fold(&inputs);
        assert!(
            json.contains("\"startIndex\":\"0x000000000000000000000000000000000000000000000000000000000000000a\""),
            "start index encoding changed: {json}"
        );
    }
}
