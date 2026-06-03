use borsh::{BorshDeserialize, BorshSerialize};

/// Inputs for `batch_update_nullifier_tree`.
///
/// The address-tree proof is verified by the embedded Light address queue and
/// consumes the pending queue batch. The SPP nullifier proof is verified
/// against the same queued-value hashchain and advances SPP's full-field
/// indexed nullifier root cache.
#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct BatchUpdateNullifierTreeData {
    pub address_new_root: [u8; 32],
    pub address_compressed_proof_a: [u8; 32],
    pub address_compressed_proof_b: [u8; 64],
    pub address_compressed_proof_c: [u8; 32],
    pub nullifier_new_root: [u8; 32],
    pub nullifier_compressed_proof_a: [u8; 32],
    pub nullifier_compressed_proof_b: [u8; 64],
    pub nullifier_compressed_proof_c: [u8; 32],
}
