use borsh::{BorshDeserialize, BorshSerialize};

/// Inputs for `batch_update_address_tree`. The public-input hash and
/// pending-batch bookkeeping are computed inside the shielded-pool program
/// from the tree's on-disk state, so callers only supply the proposed root,
/// the Groth16 proof (compressed form), and the registry's CPI authority PDA
/// bump so shielded-pool can derive and validate the expected signer.
#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct BatchUpdateAddressTreeData {
    pub cpi_authority_bump: u8,
    pub new_root: [u8; 32],
    pub compressed_proof_a: [u8; 32],
    pub compressed_proof_b: [u8; 64],
    pub compressed_proof_c: [u8; 32],
}
