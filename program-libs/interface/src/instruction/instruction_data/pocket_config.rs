use borsh::{BorshDeserialize, BorshSerialize};

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct CreatePocketConfigData {
    pub policy_program_id: [u8; 32],
    pub pocket_auth_bump: u8,
    pub authority: [u8; 32],
    pub pocket_authority_transact_is_enabled: bool,
    pub pocket_config_bump: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct UpdatePocketConfigOwnerData {
    pub new_authority: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct UpdatePocketConfigData {
    pub pocket_authority_transact_is_enabled: bool,
}
