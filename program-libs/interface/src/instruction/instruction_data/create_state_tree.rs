use borsh::{BorshDeserialize, BorshSerialize};

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct CreateStateTreeData {
    pub height: u8,
    pub canopy_depth: u8,
}
