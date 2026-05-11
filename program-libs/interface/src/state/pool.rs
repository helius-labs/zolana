use borsh::{BorshDeserialize, BorshSerialize};

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct ShieldedPoolConfig {
    pub authority: [u8; 32],
    pub registry_program: [u8; 32],
    pub bump: u8,
}
