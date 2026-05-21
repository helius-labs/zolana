use borsh::{BorshDeserialize, BorshSerialize};

/// Inputs for `batch_update_address_tree`. The public-input hash and
/// pending-batch bookkeeping are computed inside the shielded-pool program
/// from the tree's on-disk state, so callers only supply the proposed root
/// and the Groth16 proof (compressed form).
#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct BatchUpdateAddressTreeData {
    pub new_root: [u8; 32],
    pub compressed_proof_a: [u8; 32],
    pub compressed_proof_b: [u8; 64],
    pub compressed_proof_c: [u8; 32],
}
