use borsh::{BorshDeserialize, BorshSerialize};

/// Configuration recorded against an address-tree account. Address trees are
/// implemented as batched address merkle trees with an in-account input queue,
/// so no separate queue account is required.
#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct AddressTreeConfig {
    pub height: u8,
    pub queue_capacity: u32,
    pub canopy_depth: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct AddressTreeHeader {
    pub authority: [u8; 32],
    pub merkle_tree: [u8; 32],
    pub config: AddressTreeConfig,
}
