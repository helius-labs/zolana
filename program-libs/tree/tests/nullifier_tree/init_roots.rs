//! Verifies the precomputed nullifier-tree init-root constant (BN254 `p-1`
//! sentinel) against the canonical `zolana-merkle-tree` implementation.

use ark_bn254::Fr;
use ark_ff::PrimeField;
use num_bigint::BigUint;
use zolana_hasher::Poseidon;
use zolana_merkle_tree::indexed::IndexedMerkleTree;
use zolana_tree::nullifier_tree::constants::NULLIFIER_TREE_INIT_ROOT_40;

const HEIGHT: usize = 40;

/// BN254 scalar field modulus minus one: the highest valid nullifier value,
/// used as the indexed-tree sentinel (`HIGHEST_ADDRESS_PLUS_ONE`) for nullifier
/// trees.
fn bn254_field_size_minus_one() -> BigUint {
    let modulus: BigUint = Fr::MODULUS.into();
    modulus - 1u32
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
