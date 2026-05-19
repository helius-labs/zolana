use borsh::{BorshDeserialize, BorshSerialize};

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct AppendStateLeavesData {
    pub leaves: Vec<[u8; 32]>,
}
