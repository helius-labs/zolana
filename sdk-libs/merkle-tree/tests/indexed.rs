use std::sync::atomic::{AtomicBool, Ordering};

use num_bigint::{BigUint, ToBigUint};
use num_traits::Num;
use zolana_hasher::{
    bigint::bigint_to_be_bytes_array, zero_bytes::ZeroBytes, Hasher, HasherError, Poseidon,
};
use zolana_indexed_array::HIGHEST_ADDRESS_PLUS_ONE;
use zolana_merkle_tree::{
    indexed::{IndexedMerkleTree, IndexedReferenceMerkleTreeError},
    ReferenceMerkleTreeError,
};

const MERKLE_TREE_HEIGHT: usize = 4;
const MERKLE_TREE_CANOPY: usize = 0;
static FAIL_HASHING: AtomicBool = AtomicBool::new(false);

struct FailingHasher;

impl Hasher for FailingHasher {
    const ID: u8 = Poseidon::ID;

    fn hash(value: &[u8]) -> Result<[u8; 32], HasherError> {
        if FAIL_HASHING.load(Ordering::Relaxed) {
            return Err(HasherError::InvalidNumFields);
        }
        Poseidon::hash(value)
    }

    fn hashv(values: &[&[u8]]) -> Result<[u8; 32], HasherError> {
        if FAIL_HASHING.load(Ordering::Relaxed) {
            return Err(HasherError::InvalidNumFields);
        }
        Poseidon::hashv(values)
    }

    fn zero_bytes() -> ZeroBytes {
        Poseidon::zero_bytes()
    }
}

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
    // leaf index: 0 = H(0, 1, 30) //Hash(value, next_index, next_value)
    // leaf index: 1 = H(30, highest_address_plus_one)
    let indexed_array_element_0 = relayer_merkle_tree.indexed_array.get(0).unwrap();
    assert_eq!(indexed_array_element_0.value, 0_u32.to_biguint().unwrap());
    assert_eq!(indexed_array_element_0.next_index, 1);
    assert_eq!(indexed_array_element_0.index, 0);
    let indexed_array_element_1 = relayer_merkle_tree.indexed_array.get(1).unwrap();
    assert_eq!(indexed_array_element_1.value, 30_u32.to_biguint().unwrap());
    assert_eq!(indexed_array_element_1.next_index, 0);
    assert_eq!(indexed_array_element_1.index, 1);

    let leaf_0 = relayer_merkle_tree.merkle_tree.leaf(0);
    let leaf_1 = relayer_merkle_tree.merkle_tree.leaf(1);
    assert_eq!(
        leaf_0,
        Poseidon::hashv(&[
            &bigint_to_be_bytes_array::<32>(&0_u32.to_biguint().unwrap()).unwrap(),
            &bigint_to_be_bytes_array::<32>(&30_u32.to_biguint().unwrap()).unwrap()
        ])
        .unwrap()
    );
    assert_eq!(
        leaf_1,
        Poseidon::hashv(&[
            &bigint_to_be_bytes_array::<32>(&30_u32.to_biguint().unwrap()).unwrap(),
            &bigint_to_be_bytes_array::<32>(
                &BigUint::from_str_radix(HIGHEST_ADDRESS_PLUS_ONE, 10).unwrap()
            )
            .unwrap()
        ])
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

#[test]
fn non_inclusion_verifier_rejects_untrusted_roots_and_paths() {
    let mut tree =
        IndexedMerkleTree::<Poseidon, usize>::new(MERKLE_TREE_HEIGHT, MERKLE_TREE_CANOPY).unwrap();
    tree.append(&30_u32.to_biguint().unwrap()).unwrap();

    let mut wrong_root = tree
        .get_non_inclusion_proof(&10_u32.to_biguint().unwrap())
        .unwrap();
    wrong_root.root[0] ^= 1;
    assert_eq!(
        tree.verify_non_inclusion_proof(&wrong_root),
        Err(IndexedReferenceMerkleTreeError::NonInclusionProofFailed)
    );

    let mut wrong_path = tree
        .get_non_inclusion_proof(&10_u32.to_biguint().unwrap())
        .unwrap();
    wrong_path.merkle_proof[0][0] ^= 1;
    assert_eq!(
        tree.verify_non_inclusion_proof(&wrong_path),
        Err(IndexedReferenceMerkleTreeError::NonInclusionProofFailed)
    );
}

#[test]
fn non_inclusion_verifier_requires_the_tree_height() {
    let tree =
        IndexedMerkleTree::<Poseidon, usize>::new(MERKLE_TREE_HEIGHT, MERKLE_TREE_CANOPY).unwrap();
    let mut proof = tree
        .get_non_inclusion_proof(&10_u32.to_biguint().unwrap())
        .unwrap();
    proof.merkle_proof.pop();

    assert_eq!(
        tree.verify_non_inclusion_proof(&proof),
        Err(IndexedReferenceMerkleTreeError::Reference(
            ReferenceMerkleTreeError::InvalidProofLength(
                MERKLE_TREE_HEIGHT - 1,
                MERKLE_TREE_HEIGHT
            )
        ))
    );
}

#[test]
fn indexed_capacity_and_hash_errors_are_atomic() {
    FAIL_HASHING.store(false, Ordering::Relaxed);
    let mut hash_tree = IndexedMerkleTree::<FailingHasher, usize>::new(2, 0).unwrap();
    hash_tree.append(&BigUint::from(20u32)).unwrap();
    let hash_root = hash_tree.root();
    let hash_elements = hash_tree.indexed_array.elements.clone();
    let hash_next_index = hash_tree.merkle_tree.get_next_index();

    FAIL_HASHING.store(true, Ordering::Relaxed);
    assert!(hash_tree.append(&BigUint::from(10u32)).is_err());
    FAIL_HASHING.store(false, Ordering::Relaxed);
    assert_eq!(hash_tree.root(), hash_root);
    assert_eq!(hash_tree.indexed_array.elements, hash_elements);
    assert_eq!(hash_tree.merkle_tree.get_next_index(), hash_next_index);

    let mut full_tree = IndexedMerkleTree::<Poseidon, usize>::new(1, 0).unwrap();
    full_tree.append(&BigUint::from(10u32)).unwrap();
    let full_root = full_tree.root();
    let full_elements = full_tree.indexed_array.elements.clone();

    assert!(full_tree.append(&BigUint::from(20u32)).is_err());
    assert_eq!(full_tree.root(), full_root);
    assert_eq!(full_tree.indexed_array.elements, full_elements);
    assert_eq!(full_tree.merkle_tree.get_next_index(), 2);
}
