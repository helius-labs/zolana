use std::collections::HashMap;

use light_hasher::Poseidon;
use light_merkle_tree_reference::indexed::IndexedMerkleTree;
use light_merkle_tree_reference::MerkleTree;
use num_bigint::BigUint;
use zolana_client::field::BN254_MODULUS_DEC;
use zolana_client::{
    ClientError, InputCommitment, NullifierNonInclusionProof, ProofResolver, SpendProof,
    StateInclusionProof, NULLIFIER_TREE_HEIGHT, STATE_TREE_HEIGHT,
};

/// Wraps a Poseidon state tree (UTXO inclusion) and an indexed Poseidon nullifier
/// tree (nullifier non-inclusion) so it can answer [`ProofResolver`] queries with
/// proofs consistent under one root each.
pub struct TestIndexer {
    state_tree: MerkleTree<Poseidon>,
    nullifier_tree: IndexedMerkleTree<Poseidon, usize>,
    leaf_index: HashMap<[u8; 32], usize>,
}

fn nullifier_upper_bound() -> BigUint {
    BigUint::parse_bytes(BN254_MODULUS_DEC.as_bytes(), 10).expect("modulus") - 1u32
}

impl TestIndexer {
    pub fn new() -> Self {
        let state_tree = MerkleTree::<Poseidon>::new(STATE_TREE_HEIGHT, 0);
        let nullifier_tree = IndexedMerkleTree::<Poseidon, usize>::new_with_next_value(
            NULLIFIER_TREE_HEIGHT,
            0,
            nullifier_upper_bound(),
        )
        .expect("indexed nullifier tree");
        Self {
            state_tree,
            nullifier_tree,
            leaf_index: HashMap::new(),
        }
    }

    /// Append a UTXO hash as a state-tree leaf so its inclusion proof can be served.
    pub fn add_utxo(&mut self, utxo_hash: [u8; 32]) {
        let index = self.state_tree.leaves().len();
        self.state_tree
            .append(&utxo_hash)
            .expect("append state leaf");
        self.leaf_index.insert(utxo_hash, index);
    }
}

impl Default for TestIndexer {
    fn default() -> Self {
        Self::new()
    }
}

impl ProofResolver for TestIndexer {
    fn resolve(&mut self, commitment: &InputCommitment) -> Result<SpendProof, ClientError> {
        let leaf_index = *self
            .leaf_index
            .get(&commitment.utxo_hash)
            .expect("utxo hash not indexed; call add_utxo first");
        let path_elements = self
            .state_tree
            .get_proof_of_leaf(leaf_index, true)
            .expect("state proof")
            .try_into()
            .expect("state path length");
        let state = StateInclusionProof {
            path_elements,
            leaf_index: leaf_index as u64,
            root: self.state_tree.root(),
        };

        let proof = self
            .nullifier_tree
            .get_non_inclusion_proof(&BigUint::from_bytes_be(&commitment.nullifier))
            .expect("nullifier non-inclusion proof");
        let low_path_elements = proof
            .merkle_proof
            .try_into()
            .expect("nullifier path length");
        let nullifier = NullifierNonInclusionProof {
            low_value: proof.leaf_lower_range_value,
            next_value: proof.leaf_higher_range_value,
            low_path_elements,
            low_leaf_index: proof.leaf_index as u64,
            root: proof.root,
        };

        Ok(SpendProof { state, nullifier })
    }
}
