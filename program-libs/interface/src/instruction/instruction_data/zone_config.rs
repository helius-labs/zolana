use borsh::{BorshDeserialize, BorshSerialize};

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct CreateZoneConfigData {
    pub policy_program_id: [u8; 32],
    pub zone_auth_bump: u8,
    pub authority: [u8; 32],
    pub zone_authority_transact_is_enabled: bool,
    pub zone_config_bump: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct UpdateZoneConfigOwnerData {
    pub new_authority: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct UpdateZoneConfigData {
    pub zone_authority_transact_is_enabled: bool,
}
