use borsh::{BorshDeserialize, BorshSerialize};
use bytemuck::{Pod, Zeroable};
use solana_address::Address;

#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize, Pod, Zeroable)]
#[repr(C)]
pub struct CreateProtocolConfigData {
    pub protocol_authority: Address,
    pub tree_creation_authority: Address,
    pub tree_creation_is_permissionless: u8,
    pub forester_authority: Address,
    pub zone_creation_authority: Address,
    pub zone_creation_is_permissionless: u8,
    pub spl_interface_creation_is_permissionless: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub enum UpdateProtocolConfigData {
    ProtocolAuthority(Address),
    TreeCreationAuthority(Address),
    ForesterAuthority(Address),
    ZoneCreationAuthority(Address),
    TreeCreationPermissionless(bool),
    ZoneCreationPermissionless(bool),
    SplInterfaceCreationPermissionless(bool),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize, Pod, Zeroable)]
#[repr(C)]
pub struct PauseTreeData {
    pub paused: u8,
}
