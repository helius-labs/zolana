use zolana_client::{MerkleContext, MerkleProof, NonInclusionProof};
use zolana_gnark_ffi_prover::utxo_read_proof_inputs;

fn value(n: u8) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[31] = n;
    bytes
}

fn proofs() -> (MerkleProof, NonInclusionProof) {
    let merkle_context = MerkleContext {
        tree_type: 0,
        tree: Default::default(),
    };
    let merkle_proof = MerkleProof {
        leaf: value(100),
        merkle_context: merkle_context.clone(),
        path: vec![value(1), value(2)],
        leaf_index: 5,
        root: value(101),
        root_seq: 102,
        root_index: 103,
    };
    let non_inclusion = NonInclusionProof {
        leaf: value(110),
        merkle_context,
        path: vec![value(6), value(7), value(8)],
        low_element: value(3),
        low_element_index: 9,
        high_element: value(4),
        high_element_index: 111,
        root: value(112),
        root_seq: 113,
        root_index: 114,
    };
    (merkle_proof, non_inclusion)
}

fn entry(key: &str, values: &[&str]) -> (String, Vec<String>) {
    (
        key.to_string(),
        values.iter().map(|value| value.to_string()).collect(),
    )
}

#[test]
fn utxo_read_proof_inputs_map_the_paths_and_the_low_leaf() {
    let (merkle_proof, non_inclusion) = proofs();

    assert_eq!(
        utxo_read_proof_inputs(&merkle_proof, &non_inclusion, "Read"),
        vec![
            entry("Read_StatePathElements", &["1", "2"]),
            entry("Read_StatePathIndex", &["5"]),
            entry("Read_NullifierLowValue", &["3"]),
            entry("Read_NullifierNextValue", &["4"]),
            entry("Read_NullifierLowPathElements", &["6", "7", "8"]),
            entry("Read_NullifierLowPathIndex", &["9"]),
        ]
    );
}
