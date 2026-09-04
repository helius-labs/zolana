#[cfg(feature = "borsh")]
use borsh::{BorshDeserialize, BorshSerialize};
use bytemuck::{Pod, Zeroable};
use solana_address::Address;

#[cfg_attr(feature = "borsh", derive(BorshDeserialize, BorshSerialize))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct CreateProtocolConfigData {
    pub protocol_authority: Address,
    pub tree_creation_authority: Address,
    pub tree_creation_is_permissionless: u8,
    pub forester_authority: Address,
    pub ring_creation_authority: Address,
    pub ring_creation_is_permissionless: u8,
    pub spl_interface_creation_is_permissionless: u8,
    pub fee_authority: Address,
}

#[cfg_attr(feature = "borsh", derive(BorshDeserialize, BorshSerialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpdateProtocolConfigData {
    ProtocolAuthority(Address),
    TreeCreationAuthority(Address),
    ForesterAuthority(Address),
    RingCreationAuthority(Address),
    TreeCreationPermissionless(bool),
    RingCreationPermissionless(bool),
    SplInterfaceCreationPermissionless(bool),
    FeeAuthority(Address),
}

#[cfg_attr(feature = "borsh", derive(BorshDeserialize, BorshSerialize))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct PauseTreeData {
    pub paused: u8,
}
