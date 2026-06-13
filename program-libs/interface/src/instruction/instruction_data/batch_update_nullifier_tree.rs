use borsh::{BorshDeserialize, BorshSerialize};

/// Inputs for Forester maintenance of the nullifier tree. The tree's pending
/// queue and public-input bookkeeping live in the on-chain tree account, so the
/// caller supplies only the proposed root and compressed Groth16 proof.
#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct BatchUpdateNullifierTreeData {
    pub new_root: [u8; 32],
    pub compressed_proof_a: [u8; 32],
    pub compressed_proof_b: [u8; 64],
    pub compressed_proof_c: [u8; 32],
}
