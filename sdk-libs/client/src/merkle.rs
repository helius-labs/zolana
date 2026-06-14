pub const STATE_TREE_HEIGHT: usize = 26;
pub const NULLIFIER_TREE_HEIGHT: usize = 40;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateInclusionProof {
    pub path_elements: [[u8; 32]; STATE_TREE_HEIGHT],
    pub leaf_index: u64,
    pub root: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NullifierNonInclusionProof {
    pub low_value: [u8; 32],
    pub next_value: [u8; 32],
    pub low_path_elements: [[u8; 32]; NULLIFIER_TREE_HEIGHT],
    pub low_leaf_index: u64,
    pub root: [u8; 32],
}
