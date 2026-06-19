//! Verifies the precomputed indexed-tree init-root constants against the
//! canonical `light-merkle-tree-reference` implementation, and documents how
//! the nullifier-tree init root (BN254 `p-1` sentinel) is generated.

use ark_bn254::Fr;
use ark_ff::PrimeField;
use light_batched_merkle_tree::constants::{
    ADDRESS_TREE_INIT_ROOT_40, NULLIFIER_TREE_INIT_ROOT_40,
};
use light_hasher::Poseidon;
use light_merkle_tree_reference::indexed::IndexedMerkleTree;
use num_bigint::BigUint;
use num_traits::Num;

const HEIGHT: usize = 40;

/// `2^248 - 1`, the highest 248-bit address; the indexed-tree sentinel used for
/// address trees (`light_indexed_array::HIGHEST_ADDRESS_PLUS_ONE`).
const HIGHEST_ADDRESS_PLUS_ONE: &str =
    "452312848583266388373324160190187140051835877600158453279131187530910662655";

/// BN254 scalar field modulus minus one: the highest valid nullifier value,
/// used as the indexed-tree sentinel (`HIGHEST_ADDRESS_PLUS_ONE`) for nullifier
/// trees.
fn bn254_field_size_minus_one() -> BigUint {
    let modulus: BigUint = Fr::MODULUS.into();
    modulus - 1u32
}

#[test]
fn address_tree_init_root_matches_reference() {
    let next_value = BigUint::from_str_radix(HIGHEST_ADDRESS_PLUS_ONE, 10).unwrap();
    let tree =
        IndexedMerkleTree::<Poseidon, usize>::new_with_next_value(HEIGHT, 0, next_value).unwrap();
    assert_eq!(
        tree.root(),
        ADDRESS_TREE_INIT_ROOT_40,
        "ADDRESS_TREE_INIT_ROOT_40 does not match reference"
    );
}

#[test]
fn nullifier_tree_init_root_matches_reference() {
    let next_value = bn254_field_size_minus_one();
    let tree =
        IndexedMerkleTree::<Poseidon, usize>::new_with_next_value(HEIGHT, 0, next_value).unwrap();
    println!("NULLIFIER_TREE_INIT_ROOT_40 = {:?}", tree.root());
    assert_eq!(
        tree.root(),
        NULLIFIER_TREE_INIT_ROOT_40,
        "NULLIFIER_TREE_INIT_ROOT_40 does not match reference"
    );
}
