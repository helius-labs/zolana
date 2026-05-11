use borsh::{BorshDeserialize, BorshSerialize};

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct CreateAddressTreeData {
    pub height: u8,
    pub queue_capacity: u32,
    pub canopy_depth: u8,
}
