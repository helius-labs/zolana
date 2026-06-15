use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{instruction::tag, SHIELDED_POOL_PROGRAM_ID};

pub struct CreateSplInterfaceAccounts {
    pub authority: Pubkey,
    pub protocol_config: Pubkey,
    pub asset_counter: Pubkey,
    pub registry: Pubkey,
    pub mint: Pubkey,
    pub vault: Pubkey,
    pub cpi_authority: Pubkey,
    pub system_program: Pubkey,
    pub token_program: Pubkey,
}

pub fn create_spl_interface(accounts: CreateSplInterfaceAccounts) -> Instruction {
    Instruction {
        program_id: Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        accounts: vec![
            AccountMeta::new(accounts.authority, true),
            AccountMeta::new_readonly(accounts.protocol_config, false),
            AccountMeta::new(accounts.asset_counter, false),
            AccountMeta::new(accounts.registry, false),
            AccountMeta::new_readonly(accounts.mint, false),
            AccountMeta::new(accounts.vault, false),
            AccountMeta::new_readonly(accounts.cpi_authority, false),
            AccountMeta::new_readonly(accounts.system_program, false),
            AccountMeta::new_readonly(accounts.token_program, false),
        ],
        data: vec![tag::CREATE_SPL_INTERFACE],
    }
}
