#[cfg(feature = "borsh")]
use borsh::{BorshDeserialize, BorshSerialize};
use bytemuck::{Pod, Zeroable};
use solana_address::Address;

#[cfg_attr(feature = "borsh", derive(BorshDeserialize, BorshSerialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateRingConfigData {
    pub program_id: Address,
    pub authority: Address,
}

#[cfg_attr(feature = "borsh", derive(BorshDeserialize, BorshSerialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateRingConfigData {
    pub paused: bool,
}

/// Written only by `set_ring_activation`, signed by
/// `ProtocolConfig::ring_creation_authority`, in either direction at any time
/// after creation; the ring's own `update_ring_config` can reach neither field.
#[cfg_attr(feature = "borsh", derive(BorshDeserialize, BorshSerialize))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct SetRingActivationData {
    pub activated: u8,
    pub ring_authority_transact_is_enabled: u8,
}
