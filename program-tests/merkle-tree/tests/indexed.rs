use light_hasher::{bigint::bigint_to_be_bytes_array, Poseidon};
use light_indexed_array::HIGHEST_ADDRESS_PLUS_ONE;
use light_merkle_tree_reference::indexed::IndexedMerkleTree;
use num_bigint::{BigUint, ToBigUint};
use num_traits::Num;

const MERKLE_TREE_HEIGHT: usize = 4;
const MERKLE_TREE_CANOPY: usize = 0;

#[test]
pub fn functional_non_inclusion_test() {
    // appends the first element
    let mut relayer_merkle_tree =
        IndexedMerkleTree::<Poseidon, usize>::new(MERKLE_TREE_HEIGHT, MERKLE_TREE_CANOPY).unwrap();
    let nullifier1 = 30_u32.to_biguint().unwrap();
    relayer_merkle_tree.append(&nullifier1).unwrap();
    // indexed array:
    // element: 0
    // value: 0
    // next_value: 30
    // index: 0
    // element: 1
    // value: 30
    // next_value: 0
    // index: 1
    // merkle tree:
    // leaf index: 0 = H(value=0, next_index=1, next_value=30)
    // leaf index: 1 = H(value=30, next_index=0, next_value=HIGHEST_ADDRESS_PLUS_ONE)
    //   (the highest element wraps to the anchor; its hashed `next_value` is
    //   the indexed-array sentinel, not 0.)
    let indexed_array_element_0 = relayer_merkle_tree.indexed_array.get(0).unwrap();
    assert_eq!(indexed_array_element_0.value, 0_u32.to_biguint().unwrap());
    assert_eq!(indexed_array_element_0.next_index, 1);
    assert_eq!(indexed_array_element_0.index, 0);
    let indexed_array_element_1 = relayer_merkle_tree.indexed_array.get(1).unwrap();
    assert_eq!(indexed_array_element_1.value, 30_u32.to_biguint().unwrap());
    assert_eq!(indexed_array_element_1.next_index, 0);
    assert_eq!(indexed_array_element_1.index, 1);

    // Recompute each leaf through `IndexedElement::hash` so the test tracks the
    // implementation's (value, next_index, next_value) layout instead of
    // hardcoding a hand-rolled `Poseidon::hashv` call. The `next_value` for the
    // highest element is the indexed-array sentinel `HIGHEST_ADDRESS_PLUS_ONE`.
    let leaf_0 = relayer_merkle_tree.merkle_tree.leaf(0);
    let leaf_1 = relayer_merkle_tree.merkle_tree.leaf(1);
    let highest_address_plus_one = BigUint::from_str_radix(HIGHEST_ADDRESS_PLUS_ONE, 10).unwrap();
    assert_eq!(
        leaf_0,
        indexed_array_element_0
            .hash::<Poseidon>(&30_u32.to_biguint().unwrap())
            .unwrap()
    );
    assert_eq!(
        leaf_1,
        indexed_array_element_1
            .hash::<Poseidon>(&highest_address_plus_one)
            .unwrap()
    );

    let non_inclusion_proof = relayer_merkle_tree
        .get_non_inclusion_proof(&10_u32.to_biguint().unwrap())
        .unwrap();
    assert_eq!(non_inclusion_proof.root, relayer_merkle_tree.root());
    assert_eq!(
        non_inclusion_proof.value,
        bigint_to_be_bytes_array::<32>(&10_u32.to_biguint().unwrap()).unwrap()
    );
    assert_eq!(non_inclusion_proof.leaf_lower_range_value, [0; 32]);
    assert_eq!(
        non_inclusion_proof.leaf_higher_range_value,
        bigint_to_be_bytes_array::<32>(&30_u32.to_biguint().unwrap()).unwrap()
    );
    assert_eq!(non_inclusion_proof.leaf_index, 0);

    relayer_merkle_tree
        .verify_non_inclusion_proof(&non_inclusion_proof)
        .unwrap();
}
