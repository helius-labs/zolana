use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::tag, SHIELDED_POOL_PROGRAM_ID, SPL_ASSET_COUNTER_PDA_SEED,
    SPL_ASSET_REGISTRY_PDA_SEED, SPL_ASSET_VAULT_PDA_SEED, SPL_TOKEN_PROGRAM_ID,
};

use super::protocol_config_pda;

pub fn create_spl_interface(authority: Pubkey, mint: Pubkey) -> Instruction {
    Instruction {
        program_id: Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        accounts: vec![
            AccountMeta::new(authority, true),
            AccountMeta::new_readonly(protocol_config_pda(), false),
            AccountMeta::new(spl_asset_counter_pda(), false),
            AccountMeta::new(spl_asset_registry_pda(&mint), false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new(spl_asset_vault_pda(&mint), false),
            AccountMeta::new_readonly(Pubkey::default(), false),
            AccountMeta::new_readonly(Pubkey::new_from_array(SPL_TOKEN_PROGRAM_ID), false),
        ],
        data: vec![tag::CREATE_SPL_INTERFACE],
    }
}

fn spl_asset_counter_pda() -> Pubkey {
    Pubkey::find_program_address(
        &[SPL_ASSET_COUNTER_PDA_SEED],
        &Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
    )
    .0
}

fn spl_asset_registry_pda(mint: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(
        &[SPL_ASSET_REGISTRY_PDA_SEED, mint.as_ref()],
        &Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
    )
    .0
}

fn spl_asset_vault_pda(mint: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(
        &[SPL_ASSET_VAULT_PDA_SEED, mint.as_ref()],
        &Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
    )
    .0
}
