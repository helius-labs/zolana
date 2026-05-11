use borsh::{BorshDeserialize, BorshSerialize};

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct BatchUpdateAddressTreeData {
    pub start_index: u64,
    pub new_root: [u8; 32],
    pub proof_hash: [u8; 32],
}
