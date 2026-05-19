use borsh::{BorshDeserialize, BorshSerialize};

/// Append-only sparse-merkle-tree configuration. State trees take no queue
/// because new leaves are committed directly during the append instruction.
#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct StateTreeConfig {
    pub height: u8,
    pub canopy_depth: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct StateTreeHeader {
    pub authority: [u8; 32],
    pub merkle_tree: [u8; 32],
    pub config: StateTreeConfig,
}
