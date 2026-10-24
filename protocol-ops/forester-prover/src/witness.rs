use crate::BatchAddressAppendInputs;
use anyhow::{anyhow, bail, Result};
use num_bigint::BigUint;
use num_traits::Num;
use zolana_hasher::{hash_chain::create_hash_chain_4_from_slice, Poseidon};
use zolana_merkle_tree::indexed::IndexedMerkleTree;
pub type ReferenceNullifierTree = IndexedMerkleTree<Poseidon, usize>;
const NULLIFIER_INIT_NEXT_VALUE_DEC: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495616";

/// Build the batch address-append witness for one zkp-batch, appending its
/// values into `reference`. The root and next index must describe its current state.
pub fn build_inputs(
    reference: &mut ReferenceNullifierTree,
    next_index: u64,
    height: u32,
    leaves_hash_chain: [u8; 32],
    old_root: [u8; 32],
    batch_values: &[[u8; 32]],
) -> Result<(BatchAddressAppendInputs, [u8; 32])> {
    let batch_size = u32::try_from(batch_values.len())?;
    let first_index = usize::try_from(next_index)?;
    if reference.merkle_tree.height != height as usize
        || reference.merkle_tree.rightmost_index != first_index
        || reference.root() != old_root
    {
        bail!("batch inputs do not match the reference tree's height, next index, or root");
    }
    let mut low_element_values = Vec::with_capacity(batch_values.len());
    let mut low_element_indices = Vec::with_capacity(batch_values.len());
    let mut low_element_next_values = Vec::with_capacity(batch_values.len());
    let mut new_element_values = Vec::with_capacity(batch_values.len());
    let mut low_element_proofs = Vec::with_capacity(batch_values.len());
    let mut new_element_proofs = Vec::with_capacity(batch_values.len());

    for (offset, value_bytes) in batch_values.iter().enumerate() {
        let value = BigUint::from_bytes_be(value_bytes);
        let non_inclusion = reference
            .get_non_inclusion_proof(&value)
            .map_err(|err| anyhow!("non-inclusion proof: {err:?}"))?;
        low_element_values.push(BigUint::from_bytes_be(
            &non_inclusion.leaf_lower_range_value,
        ));
        low_element_indices.push(BigUint::from(non_inclusion.leaf_index as u64));
        low_element_next_values.push(BigUint::from_bytes_be(
            &non_inclusion.leaf_higher_range_value,
        ));
        low_element_proofs.push(path_to_biguint(non_inclusion.merkle_proof));
        new_element_values.push(value.clone());

        reference
            .append(&value)
            .map_err(|err| anyhow!("append nullifier: {err:?}"))?;
        let new_index = first_index
            .checked_add(offset)
            .ok_or_else(|| anyhow!("batch leaf index overflow"))?;
        let new_proof = reference
            .get_proof_of_leaf(new_index, true)
            .map_err(|err| anyhow!("proof of leaf {new_index}: {err:?}"))?;
        new_element_proofs.push(path_to_biguint(new_proof));
    }

    let new_root = reference.root();
    let mut start_index_bytes = [0u8; 32];
    start_index_bytes[24..].copy_from_slice(&next_index.to_be_bytes());
    let public_input_hash =
        create_hash_chain_4_from_slice(&[old_root, new_root, leaves_hash_chain, start_index_bytes])
            .map_err(|err| anyhow!("public input hash chain: {err:?}"))?;

    Ok((
        BatchAddressAppendInputs {
            public_input_hash: BigUint::from_bytes_be(&public_input_hash),
            old_root: BigUint::from_bytes_be(&old_root),
            new_root: BigUint::from_bytes_be(&new_root),
            hashchain_hash: BigUint::from_bytes_be(&leaves_hash_chain),
            start_index: next_index,
            low_element_values,
            low_element_indices,
            low_element_next_values,
            new_element_values,
            low_element_proofs,
            new_element_proofs,
            tree_height: height,
            batch_size,
        },
        new_root,
    ))
}

pub fn reference_nullifier_tree(height: u32) -> Result<ReferenceNullifierTree> {
    let init_next_value = BigUint::from_str_radix(NULLIFIER_INIT_NEXT_VALUE_DEC, 10)
        .map_err(|error| anyhow!("invalid nullifier sentinel: {error}"))?;
    IndexedMerkleTree::<Poseidon, usize>::new_with_next_value(height as usize, 0, init_next_value)
        .map_err(|err| anyhow!("init reference nullifier tree: {err:?}"))
}

fn path_to_biguint(path: Vec<[u8; 32]>) -> Vec<BigUint> {
    path.into_iter()
        .map(|node| BigUint::from_bytes_be(&node))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mismatched_batch_context_is_rejected_before_appending() {
        let mut reference = reference_nullifier_tree(40).unwrap();
        let root = reference.root();
        for (next_index, height, old_root) in [(2, 40, root), (1, 39, root), (1, 40, [0; 32])] {
            let rejected = build_inputs(
                &mut reference,
                next_index,
                height,
                [0; 32],
                old_root,
                &[[1; 32]],
            );
            assert!(rejected
                .unwrap_err()
                .to_string()
                .contains("do not match the reference tree"));
            assert_eq!(
                (reference.root(), reference.merkle_tree.rightmost_index),
                (root, 1)
            );
        }
    }
}
