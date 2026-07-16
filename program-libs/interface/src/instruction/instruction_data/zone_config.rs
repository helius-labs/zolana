#[cfg(feature = "borsh")]
use borsh::{BorshDeserialize, BorshSerialize};
use solana_address::Address;

#[cfg_attr(feature = "borsh", derive(BorshDeserialize, BorshSerialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateZoneConfigData {
    pub program_id: Address,
    pub authority: Address,
    pub zone_authority_transact_is_enabled: bool,
}

#[cfg_attr(feature = "borsh", derive(BorshDeserialize, BorshSerialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateZoneConfigOwnerData {
    pub new_authority: Address,
}

#[cfg_attr(feature = "borsh", derive(BorshDeserialize, BorshSerialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateZoneConfigData {
    pub zone_authority_transact_is_enabled: bool,
}
