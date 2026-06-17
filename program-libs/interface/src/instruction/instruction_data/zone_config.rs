use borsh::{BorshDeserialize, BorshSerialize};
use solana_address::Address;

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct CreateZoneConfigData {
    pub program_id: Address,
    pub zone_auth_bump: u8,
    pub authority: Address,
    pub zone_authority_transact_is_enabled: bool,
    pub zone_config_bump: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct UpdateZoneConfigOwnerData {
    pub new_authority: Address,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct UpdateZoneConfigData {
    pub zone_authority_transact_is_enabled: bool,
}
