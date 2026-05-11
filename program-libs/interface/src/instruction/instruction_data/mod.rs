use borsh::{BorshDeserialize, BorshSerialize};

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct CreateAddressTreeData {
    pub height: u8,
    pub queue_capacity: u32,
    pub canopy_depth: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct InsertAddressesData {
    pub addresses: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct BatchUpdateAddressTreeData {
    pub start_index: u64,
    pub new_root: [u8; 32],
    pub proof_hash: [u8; 32],
}
