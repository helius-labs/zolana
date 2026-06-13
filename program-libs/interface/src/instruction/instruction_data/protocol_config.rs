use borsh::{BorshDeserialize, BorshSerialize};

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct CreateProtocolConfigData {
    pub authority: [u8; 32],
    pub merge_authorities: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct UpdateProtocolConfigData {
    pub authority: [u8; 32],
    pub merge_authorities: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct PauseTreeData {
    pub paused: bool,
}
