use num_bigint::BigUint;
use zolana_hasher::{Hasher, Keccak, Poseidon, Sha256};
use zolana_merkle_tree::{indexed::IndexedMerkleTree, MerkleTree};

const HEIGHT: usize = 4;
const CANOPY_DEPTH: usize = 1;

fn main() {
    let hashers = [
        hasher_vector::<Poseidon>("poseidon"),
        hasher_vector::<Sha256>("sha256"),
        hasher_vector::<Keccak>("keccak"),
    ];
    let indexed = [
        indexed_vector::<Poseidon>("poseidon"),
        indexed_vector::<Sha256>("sha256"),
        indexed_vector::<Keccak>("keccak"),
    ];
    println!(
        "{{\"hashers\":[{}],\"indexed\":[{}]}}",
        hashers.join(","),
        indexed.join(",")
    );
}

fn hasher_vector<H: Hasher>(name: &str) -> String {
    let raw_inputs = [[1u8; 32], [2; 32], [3; 32], [4; 32]];
    let leaves = raw_inputs.map(|input| H::hash(&input).expect("hash leaf"));
    let pair_hash = H::hashv(&[&raw_inputs[0], &raw_inputs[1]]).expect("hash pair");
    let mut tree = MerkleTree::<H>::new(HEIGHT, CANOPY_DEPTH);
    let empty_root = tree.root();
    let mut root_history = Vec::new();
    for leaf in &leaves {
        tree.append(leaf).expect("append leaf");
        root_history.push(tree.root());
    }

    let proofs = leaves
        .iter()
        .enumerate()
        .map(|(index, leaf)| {
            let path = tree.get_path_of_leaf(index, true).expect("full path");
            let proof = tree.get_proof_of_leaf(index, true).expect("full proof");
            let canopy_proof = tree
                .get_proof_of_leaf(index, false)
                .expect("canopy proof");
            assert!(tree.verify(leaf, &proof, index).expect("verify proof"));
            format!(
                "{{\"canopyProofBytes\":{},\"id\":\"merkle-{name}-leaf-{index}\",\"index\":\"{index}\",\"pathBytes\":{},\"proofBytes\":{},\"verified\":true}}",
                hex_array(&canopy_proof),
                hex_array(&path),
                hex_array(&proof)
            )
        })
        .collect::<Vec<_>>();

    let proof = tree.get_proof_of_leaf(0, true).expect("error proof");
    let invalid_length = tree
        .verify(&leaves[0], &proof[..HEIGHT - 1], 0)
        .expect_err("short proof");
    let invalid_index = tree
        .verify(&leaves[0], &proof, 1 << HEIGHT)
        .expect_err("out-of-range index");
    let missing_leaf = tree.get_leaf(9).expect_err("missing leaf");
    let missing_history = tree
        .get_history_root_index()
        .expect_err("history is not configured");
    let mut full = MerkleTree::<H>::new(2, 0);
    for leaf in leaves {
        full.append(&leaf).expect("fill tree");
    }
    let capacity = full.append(&[9; 32]).expect_err("tree capacity");

    format!(
        concat!(
            "{{",
            "\"errors\":{{",
            "\"capacity\":\"{capacity:?}\",",
            "\"invalidIndex\":\"{invalid_index:?}\",",
            "\"invalidProofLength\":\"{invalid_length:?}\",",
            "\"missingHistory\":\"{missing_history:?}\",",
            "\"missingLeaf\":\"{missing_leaf:?}\"",
            "}},",
            "\"hasher\":\"{name}\",",
            "\"hasherId\":\"{}\",",
            "\"height\":\"{HEIGHT}\",",
            "\"id\":\"merkle-{name}\",",
            "\"canopyDepth\":\"{CANOPY_DEPTH}\",",
            "\"emptyRootBytes\":\"{}\",",
            "\"leafInputBytes\":{},",
            "\"leafHashBytes\":{},",
            "\"pairHashInputBytes\":{},",
            "\"pairHashBytes\":\"{}\",",
            "\"proofs\":[{}],",
            "\"rootBytes\":\"{}\",",
            "\"rootHistoryBytes\":{}",
            "}}"
        ),
        H::ID,
        hex(&empty_root),
        hex_array(&raw_inputs),
        hex_array(&leaves),
        hex_array(&raw_inputs[..2]),
        hex(&pair_hash),
        proofs.join(","),
        hex(&tree.root()),
        hex_array(&root_history),
        capacity = capacity,
        invalid_index = invalid_index,
        invalid_length = invalid_length,
        missing_history = missing_history,
        missing_leaf = missing_leaf,
        name = name,
        HEIGHT = HEIGHT,
        CANOPY_DEPTH = CANOPY_DEPTH
    )
}

fn indexed_vector<H: Hasher>(name: &str) -> String {
    let insertions = [30u32, 10, 20];
    let mut tree = IndexedMerkleTree::<H, usize>::new(HEIGHT, 0).expect("create indexed tree");
    let mut root_history = vec![tree.root()];
    for value in insertions {
        tree.append(&BigUint::from(value))
            .expect("append indexed value");
        root_history.push(tree.root());
    }

    let elements = tree
        .indexed_array
        .elements
        .iter()
        .map(|element| {
            let next_value = if element.next_index == 0 {
                &tree.indexed_array.highest_value
            } else {
                &tree.indexed_array.elements[element.next_index].value
            };
            format!(
                "{{\"index\":\"{}\",\"leafHashBytes\":\"{}\",\"nextIndex\":\"{}\",\"nextValue\":\"{}\",\"value\":\"{}\"}}",
                element.index,
                hex(&tree.merkle_tree.leaf(element.index)),
                element.next_index,
                next_value,
                element.value
            )
        })
        .collect::<Vec<_>>();
    let mut ordered = tree.indexed_array.elements.iter().collect::<Vec<_>>();
    ordered.sort();
    let ordered_values = ordered
        .iter()
        .map(|element| format!("\"{}\"", element.value))
        .collect::<Vec<_>>();
    let ordered_indices = ordered
        .iter()
        .map(|element| format!("\"{}\"", element.index))
        .collect::<Vec<_>>();

    let queries = [5u32, 15, 25, 35]
        .into_iter()
        .map(|value| {
            let proof = tree
                .get_non_inclusion_proof(&BigUint::from(value))
                .expect("non-inclusion proof");
            tree.verify_non_inclusion_proof(&proof)
                .expect("verify non-inclusion proof");
            format!(
                concat!(
                    "{{",
                    "\"higherValueBytes\":\"{}\",",
                    "\"id\":\"indexed-{name}-query-{value}\",",
                    "\"leafIndex\":\"{}\",",
                    "\"lowerValueBytes\":\"{}\",",
                    "\"nextIndex\":\"{}\",",
                    "\"proofBytes\":{},",
                    "\"rootBytes\":\"{}\",",
                    "\"valueBytes\":\"{}\",",
                    "\"verified\":true",
                    "}}"
                ),
                hex(&proof.leaf_higher_range_value),
                proof.leaf_index,
                hex(&proof.leaf_lower_range_value),
                proof.next_index,
                hex_array(&proof.merkle_proof),
                hex(&proof.root),
                hex(&proof.value),
                name = name,
                value = value
            )
        })
        .collect::<Vec<_>>();

    let existing = tree
        .get_non_inclusion_proof(&BigUint::from(20u32))
        .expect_err("existing value");
    let mut lower = tree
        .get_non_inclusion_proof(&BigUint::from(15u32))
        .expect("lower-bound fixture");
    lower.value = lower.leaf_lower_range_value;
    let lower_error = tree
        .verify_non_inclusion_proof(&lower)
        .expect_err("lower-bound violation");
    let mut higher = tree
        .get_non_inclusion_proof(&BigUint::from(15u32))
        .expect("higher-bound fixture");
    higher.value = higher.leaf_higher_range_value;
    let higher_error = tree
        .verify_non_inclusion_proof(&higher)
        .expect_err("higher-bound violation");

    format!(
        concat!(
            "{{",
            "\"errors\":{{",
            "\"existingValue\":\"{existing:?}\",",
            "\"higherBound\":\"{higher_error:?}\",",
            "\"lowerBound\":\"{lower_error:?}\"",
            "}},",
            "\"elements\":[{}],",
            "\"hasher\":\"{name}\",",
            "\"id\":\"indexed-{name}\",",
            "\"insertions\":[\"30\",\"10\",\"20\"],",
            "\"nonInclusionProofs\":[{}],",
            "\"orderedIndices\":[{}],",
            "\"orderedValues\":[{}],",
            "\"rootBytes\":\"{}\",",
            "\"rootHistoryBytes\":{}",
            "}}"
        ),
        elements.join(","),
        queries.join(","),
        ordered_indices.join(","),
        ordered_values.join(","),
        hex(&tree.root()),
        hex_array(&root_history),
        existing = existing,
        higher_error = higher_error,
        lower_error = lower_error,
        name = name
    )
}

fn hex_array(values: &[[u8; 32]]) -> String {
    format!(
        "[{}]",
        values
            .iter()
            .map(|value| format!("\"{}\"", hex(value)))
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
