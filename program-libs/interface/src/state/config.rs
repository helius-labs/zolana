use borsh::{BorshDeserialize, BorshSerialize};

pub const PROTOCOL_CONFIG_ACCOUNT_LEN: usize = 40;
pub const POCKET_CONFIG_ACCOUNT_LEN: usize = 42;

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct ProtocolConfig {
    pub authority: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct SppPocketConfig {
    pub authority: [u8; 32],
    pub pocket_authority_transact_is_enabled: bool,
    pub bump: u8,
}
