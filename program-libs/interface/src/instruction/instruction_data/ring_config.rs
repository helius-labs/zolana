#[cfg(feature = "borsh")]
use borsh::{BorshDeserialize, BorshSerialize};
use solana_address::Address;

#[cfg_attr(feature = "borsh", derive(BorshDeserialize, BorshSerialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateRingConfigData {
    pub program_id: Address,
    pub authority: Address,
    pub ring_authority_transact_is_enabled: bool,
}

#[cfg_attr(feature = "borsh", derive(BorshDeserialize, BorshSerialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateRingConfigData {
    pub ring_authority_transact_is_enabled: bool,
    pub paused: bool,
}
