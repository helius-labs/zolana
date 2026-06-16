use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{instruction::tag, pda, SHIELDED_POOL_PROGRAM_ID, SPL_TOKEN_PROGRAM_ID};

pub fn create_spl_interface(authority: Pubkey, mint: Pubkey) -> Instruction {
    Instruction {
        program_id: Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        accounts: vec![
            AccountMeta::new(authority, true),
            AccountMeta::new_readonly(pda::protocol_config(), false),
            AccountMeta::new(pda::spl_asset_counter(), false),
            AccountMeta::new(pda::spl_asset_registry(&mint), false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new(pda::spl_asset_vault(&mint), false),
            AccountMeta::new_readonly(Pubkey::default(), false),
            AccountMeta::new_readonly(Pubkey::new_from_array(SPL_TOKEN_PROGRAM_ID), false),
        ],
        data: vec![tag::CREATE_SPL_INTERFACE],
    }
}
